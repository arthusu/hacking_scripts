import requests
import json
import uuid
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# --- 1. CONFIGURACIÓN: Constantes extraídas de tu DSN ---
# DSN Completo: https://8888888@7777777.ingest.us.sentry.io/3333333
# recomiendo probar con 3000 solicitudes para saber si el servidor bloquea o no tus solicitudes

# La clave pública que identifica tu proyecto
PUBLIC_KEY = "8888888"
# El host específico de Sentry donde se envían los eventos
SENTRY_HOST = "7777777.ingest.us.sentry.io"
# El ID numérico de tu proyecto
PROJECT_ID = "3333333"

# La URL completa del endpoint de Sentry para recibir eventos
SENTRY_STORE_URL = f"https://{SENTRY_HOST}/api/{PROJECT_ID}/store/"


def send_sentry_event(message: str, event_num: int):
    """
    Construye y envía un único evento de error a Sentry.
    Esta función es el objetivo de cada trabajador del pool de hilos.
    """
    event_id = uuid.uuid4().hex
    timestamp = datetime.now(timezone.utc).isoformat()

    # Encabezado de autenticación requerido por el endpoint /store/
    auth_header = (
        f"Sentry sentry_version=7, sentry_key={PUBLIC_KEY}, "
        f"sentry_client=python-requests/1.0"
    )

    # El cuerpo del evento de error en formato JSON
    payload = {
        "event_id": event_id,
        "timestamp": timestamp,
        "level": "error",
        "message": f"{message} (#{event_num})",
        "culprit": "sentry_flood.py",
        "tags": {
            "script_run": "flood_test",
            "event_number": event_num,
        },
    }

    try:
        response = requests.post(
            SENTRY_STORE_URL,
            headers={"Content-Type": "application/json", "X-Sentry-Auth": auth_header},
            json=payload,
            timeout=5 # Timeout de 5 segundos
        )
        # Lanza una excepción si la respuesta es un error (4xx o 5xx)
        response.raise_for_status()
        return f"✅ Evento #{event_num} enviado con éxito. ID: {event_id}"
    except requests.exceptions.RequestException as e:
        return f"❌ Error enviando evento #{event_num}: {e}"


if __name__ == "__main__":
    # --- 2. Configuración de Argumentos de la Terminal ---
    parser = argparse.ArgumentParser(
        description="Envía eventos a Sentry de forma paralela para pruebas de carga."
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=100,
        help="Número total de eventos a enviar."
    )
    parser.add_argument(
        "-m", "--message",
        type=str,
        default="Evento de prueba de carga",
        help="Mensaje base para cada evento."
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Número de hilos paralelos a utilizar."
    )
    args = parser.parse_args()

    print(f"🚀 Iniciando envío de {args.count} eventos a Sentry...")
    print(f"   - Hilos paralelos: {args.threads}")
    print(f"   - Mensaje base: '{args.message}'")

    # --- 3. Ejecución Paralela con ThreadPoolExecutor ---
    # Creamos un pool de hilos con el número especificado de trabajadores
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Enviamos todas las tareas al pool de hilos
        futures = [
            executor.submit(send_sentry_event, args.message, i + 1)
            for i in range(args.count)
        ]

        # Procesamos los resultados a medida que se completan
        for future in as_completed(futures):
            print(future.result())

    print("\n🏁 Proceso completado. Todos los eventos han sido enviados.")