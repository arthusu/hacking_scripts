#!/usr/bin/env python3
"""
REDIS SECURITY ANALYZER - Advanced Penetration Testing Tool
===========================================================
ETHICAL SECURITY TESTING ONLY - DO NOT MISUSE

Advanced Redis reconnaissance and data extraction tool
Author: Security Assessment Team
Version: 2.0
"""

import socket
import sys
import json
import argparse
import time
from datetime import datetime
import re
from collections import defaultdict

class RedisAnalyzer:
    def __init__(self, host, port=6379, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        self.connected = False
        self.server_info = {}
        
    def connect(self):
        """Connect to Redis server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            self.connected = True
            return True
        except Exception as e:
            print(f"❌ Connection failed to {self.host}:{self.port}")
            print(f"   Error: {str(e)}")
            return False
    
    def disconnect(self):
        """Close connection"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.connected = False
    
    def send_command(self, command):
        """Send Redis command and return response"""
        if not self.connected:
            return None
            
        try:
            cmd = f"{command}\r\n"
            self.socket.send(cmd.encode())
            response = self.socket.recv(8192).decode('utf-8', errors='ignore')
            return response
        except Exception as e:
            print(f"⚠️  Command failed: {command}")
            return None
    
    def test_connection(self):
        """Test basic connectivity with PING"""
        print(f"🔍 Testing connection to {self.host}:{self.port}")
        
        if not self.connect():
            return False
            
        response = self.send_command("PING")
        if response and "+PONG" in response:
            print("✅ SUCCESS: Redis server accessible without authentication!")
            return True
        elif response and "NOAUTH" in response:
            print("🔒 Authentication required (server is secured)")
            return False
        else:
            print(f"❓ Unexpected response: {response}")
            return False
    
    def get_server_info(self):
        """Get comprehensive server information"""
        print(f"\n📊 Gathering server information...")
        
        # Get server info
        info_response = self.send_command("INFO server")
        if info_response:
            self.parse_info_response(info_response, "server")
        
        # Get keyspace info
        keyspace_response = self.send_command("INFO keyspace")
        if keyspace_response:
            self.parse_info_response(keyspace_response, "keyspace")
            
        # Get memory info
        memory_response = self.send_command("INFO memory")
        if memory_response:
            self.parse_info_response(memory_response, "memory")
            
        # Get stats info
        stats_response = self.send_command("INFO stats")
        if stats_response:
            self.parse_info_response(stats_response, "stats")
        
        self.display_server_info()
    
    def parse_info_response(self, response, section):
        """Parse INFO command response"""
        if section not in self.server_info:
            self.server_info[section] = {}
            
        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            if ':' in line and not line.startswith('#'):
                key, value = line.split(':', 1)
                self.server_info[section][key] = value
    
    def display_server_info(self):
        """Display formatted server information"""
        print("\n" + "="*60)
        print("📋 REDIS SERVER INFORMATION")
        print("="*60)
        
        if 'server' in self.server_info:
            server = self.server_info['server']
            print(f"🖥️  Server Details:")
            print(f"   • Redis Version: {server.get('redis_version', 'Unknown')}")
            print(f"   • OS: {server.get('os', 'Unknown')}")
            print(f"   • Architecture: {server.get('arch_bits', 'Unknown')} bits")
            print(f"   • Process ID: {server.get('process_id', 'Unknown')}")
            print(f"   • Uptime: {server.get('uptime_in_days', 'Unknown')} days")
            print(f"   • Config File: {server.get('config_file', 'Unknown')}")
        
        if 'memory' in self.server_info:
            memory = self.server_info['memory']
            print(f"\n💾 Memory Usage:")
            used_memory = memory.get('used_memory_human', 'Unknown')
            max_memory = memory.get('maxmemory_human', 'Not set')
            print(f"   • Used Memory: {used_memory}")
            print(f"   • Max Memory: {max_memory}")
        
        if 'stats' in self.server_info:
            stats = self.server_info['stats']
            print(f"\n📈 Statistics:")
            print(f"   • Total Connections: {stats.get('total_connections_received', 'Unknown')}")
            print(f"   • Total Commands: {stats.get('total_commands_processed', 'Unknown')}")
            print(f"   • Keyspace Hits: {stats.get('keyspace_hits', 'Unknown')}")
            print(f"   • Keyspace Misses: {stats.get('keyspace_misses', 'Unknown')}")
        
        if 'keyspace' in self.server_info:
            keyspace = self.server_info['keyspace']
            print(f"\n🗄️  Database Information:")
            total_keys = 0
            for db_name, db_info in keyspace.items():
                if db_name.startswith('db'):
                    # Parse db info: keys=X,expires=Y,avg_ttl=Z
                    keys_match = re.search(r'keys=(\d+)', db_info)
                    expires_match = re.search(r'expires=(\d+)', db_info)
                    if keys_match:
                        keys = int(keys_match.group(1))
                        expires = int(expires_match.group(1)) if expires_match else 0
                        total_keys += keys
                        print(f"   • {db_name}: {keys:,} keys ({expires:,} with expiration)")
            
            if total_keys > 0:
                print(f"   • TOTAL KEYS: {total_keys:,}")
                print(f"   • ⚠️  CRITICAL: {total_keys:,} records potentially exposed!")
    
    def analyze_database(self, db_number, sample_size=20, pattern="*"):
        """Analyze specific database"""
        print(f"\n🔍 Analyzing database {db_number}...")
        
        # Select database
        select_response = self.send_command(f"SELECT {db_number}")
        if not select_response or not select_response.startswith("+OK"):
            print(f"❌ Could not select database {db_number}")
            return
        
        print(f"✅ Connected to database {db_number}")
        
        # Get database size
        dbsize_response = self.send_command("DBSIZE")
        if dbsize_response and dbsize_response.startswith(':'):
            total_keys = int(dbsize_response[1:].strip())
            print(f"📊 Database size: {total_keys:,} keys")
        else:
            total_keys = 0
        
        # Get sample keys
        keys_response = self.send_command(f"KEYS {pattern}")
        if keys_response and keys_response.startswith('*'):
            keys = self.parse_array_response(keys_response)
            
            if keys:
                print(f"🗝️  Found {len(keys):,} keys matching pattern '{pattern}'")
                
                # Analyze key patterns
                self.analyze_key_patterns(keys[:sample_size])
                
                # Sample some key values
                self.sample_key_values(keys[:sample_size], db_number)
            else:
                print("ℹ️  No keys found matching pattern")
        else:
            print("❌ Could not retrieve keys")
    
    def analyze_key_patterns(self, keys):
        """Analyze patterns in key names"""
        print(f"\n🔍 Key Pattern Analysis:")
        
        patterns = defaultdict(int)
        categories = {
            'user': ['user', 'hero', 'customer', 'account'],
            'session': ['session', 'token', 'auth', 'login'],
            'email': ['email', '@', 'mail'],
            'config': ['config', 'setting', 'def'],
            'cache': ['cache', 'temp', 'tmp'],
            'id': [':id', '_id', 'idx']
        }
        
        category_counts = defaultdict(int)
        
        for key in keys:
            key_lower = key.lower()
            
            # Count by category
            for category, keywords in categories.items():
                if any(keyword in key_lower for keyword in keywords):
                    category_counts[category] += 1
            
            # Extract pattern (before first colon or number)
            pattern = re.split(r'[:0-9]', key)[0]
            if pattern:
                patterns[pattern] += 1
        
        # Display categories
        if category_counts:
            print("   📁 Key Categories:")
            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(keys)) * 100
                print(f"      • {category.title()}: {count} keys ({percentage:.1f}%)")
        
        # Display top patterns
        if patterns:
            print("   🏷️  Top Key Patterns:")
            for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / len(keys)) * 100
                print(f"      • {pattern}: {count} keys ({percentage:.1f}%)")
    
    def sample_key_values(self, keys, db_number):
        """Sample values from keys to understand data types"""
        print(f"\n📄 Sample Data from Database {db_number}:")
        
        for i, key in enumerate(keys[:10]):  # Limit to first 10 for display
            key_type = self.get_key_type(key)
            value = self.get_key_value(key, key_type)
            
            # Truncate long values for display
            if isinstance(value, str) and len(value) > 100:
                display_value = value[:100] + "..."
            else:
                display_value = str(value)
            
            print(f"   [{i+1:2d}] {key}")
            print(f"        Type: {key_type} | Value: {display_value}")
    
    def get_key_type(self, key):
        """Get the type of a Redis key"""
        response = self.send_command(f"TYPE {key}")
        if response and response.startswith('+'):
            return response[1:].strip()
        return "unknown"
    
    def get_key_value(self, key, key_type):
        """Get value for a specific key based on its type"""
        try:
            if key_type == "string":
                response = self.send_command(f"GET {key}")
                return self.parse_bulk_string(response)
            elif key_type == "list":
                response = self.send_command(f"LRANGE {key} 0 4")  # First 5 items
                return self.parse_array_response(response)
            elif key_type == "set":
                response = self.send_command(f"SMEMBERS {key}")
                return self.parse_array_response(response)
            elif key_type == "hash":
                response = self.send_command(f"HGETALL {key}")
                return self.parse_hash_response(response)
            elif key_type == "zset":
                response = self.send_command(f"ZRANGE {key} 0 4 WITHSCORES")
                return self.parse_array_response(response)
            else:
                return f"[{key_type} - not sampled]"
        except Exception as e:
            return f"[Error: {str(e)}]"
    
    def parse_array_response(self, response):
        """Parse Redis array response"""
        if not response or not response.startswith('*'):
            return []
        
        lines = response.strip().split('\n')
        if not lines:
            return []
        
        try:
            count = int(lines[0][1:])
            items = []
            i = 1
            
            while i < len(lines) and len(items) < count:
                if lines[i].startswith('$'):
                    if i + 1 < len(lines):
                        items.append(lines[i + 1])
                    i += 2
                else:
                    i += 1
            
            return items
        except:
            return []
    
    def parse_bulk_string(self, response):
        """Parse Redis bulk string response"""
        if not response:
            return None
        
        lines = response.split('\n')
        for i, line in enumerate(lines):
            if line.startswith('$'):
                if i + 1 < len(lines):
                    return lines[i + 1].strip()
        return None
    
    def parse_hash_response(self, response):
        """Parse Redis hash response"""
        items = self.parse_array_response(response)
        hash_dict = {}
        
        for i in range(0, len(items), 2):
            if i + 1 < len(items):
                hash_dict[items[i]] = items[i + 1]
        
        return hash_dict
    
    def search_sensitive_data(self, db_number, patterns=None):
        """Search for potentially sensitive data patterns"""
        print(f"\n🔎 Searching for sensitive data in database {db_number}...")
        
        if patterns is None:
            patterns = [
                "*email*", "*mail*", "*user*", "*password*", "*token*", 
                "*session*", "*auth*", "*login*", "*key*", "*secret*",
                "*customer*", "*account*", "*admin*", "*api*"
            ]
        
        # Select database
        self.send_command(f"SELECT {db_number}")
        
        sensitive_findings = {}
        
        for pattern in patterns:
            print(f"   Searching pattern: {pattern}")
            keys_response = self.send_command(f"KEYS {pattern}")
            
            if keys_response and keys_response.startswith('*'):
                keys = self.parse_array_response(keys_response)
                
                if keys:
                    sensitive_findings[pattern] = len(keys)
                    print(f"   ✅ Found {len(keys)} keys matching '{pattern}'")
                    
                    # Show some examples
                    for key in keys[:3]:
                        print(f"      • {key}")
                    
                    if len(keys) > 3:
                        print(f"      • ... and {len(keys) - 3} more")
        
        if sensitive_findings:
            print(f"\n🚨 SENSITIVE DATA SUMMARY:")
            total_sensitive = sum(sensitive_findings.values())
            print(f"   • Total potentially sensitive keys: {total_sensitive}")
            
            for pattern, count in sorted(sensitive_findings.items(), key=lambda x: x[1], reverse=True):
                print(f"   • {pattern}: {count} keys")
        else:
            print("   ✅ No obvious sensitive data patterns found")
    
    def full_analysis(self, target_databases=None, sample_size=20):
        """Perform comprehensive analysis"""
        print("🚀 Starting comprehensive Redis analysis...")
        print("=" * 60)
        
        if not self.test_connection():
            return
        
        # Get server info
        self.get_server_info()
        
        # Determine which databases to analyze
        if target_databases is None:
            # Auto-detect databases from keyspace info
            target_databases = []
            if 'keyspace' in self.server_info:
                for db_name in self.server_info['keyspace'].keys():
                    if db_name.startswith('db'):
                        db_num = int(db_name[2:])
                        target_databases.append(db_num)
            
            if not target_databases:
                target_databases = [0]  # Default to db0
        
        # Analyze each database
        for db_num in target_databases:
            print(f"\n{'='*60}")
            print(f"🗄️  ANALYZING DATABASE {db_num}")
            print("="*60)
            
            self.analyze_database(db_num, sample_size)
            self.search_sensitive_data(db_num)
        
        # Summary
        self.print_security_summary()
    
    def print_security_summary(self):
        """Print final security assessment summary"""
        print(f"\n{'='*60}")
        print("🚨 SECURITY ASSESSMENT SUMMARY")
        print("="*60)
        
        print(f"📍 Target: {self.host}:{self.port}")
        print(f"⏰ Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Calculate total keys across all databases
        total_keys = 0
        if 'keyspace' in self.server_info:
            for db_info in self.server_info['keyspace'].values():
                keys_match = re.search(r'keys=(\d+)', db_info)
                if keys_match:
                    total_keys += int(keys_match.group(1))
        
        print(f"\n🔍 FINDINGS:")
        print(f"   ✅ Unauthenticated access: YES")
        print(f"   📊 Total exposed records: {total_keys:,}")
        print(f"   🖥️  Redis version: {self.server_info.get('server', {}).get('redis_version', 'Unknown')}")
        print(f"   ⏳ Server uptime: {self.server_info.get('server', {}).get('uptime_in_days', 'Unknown')} days")
        
        print(f"\n🚨 RISK ASSESSMENT:")
        if total_keys > 100000:
            risk_level = "CRITICAL"
        elif total_keys > 10000:
            risk_level = "HIGH"
        elif total_keys > 1000:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        print(f"   • Risk Level: {risk_level}")
        print(f"   • Data Exposure: {total_keys:,} records accessible")
        print(f"   • Authentication: NONE REQUIRED")
        
        print(f"\n💡 RECOMMENDATIONS:")
        print("   1. Enable Redis authentication (requirepass)")
        print("   2. Bind Redis to localhost (bind 127.0.0.1)")
        print("   3. Use firewall to restrict network access")
        print("   4. Enable Redis TLS encryption")
        print("   5. Implement network segmentation")
        print("   6. Regular security audits")
        
        print(f"\n⚠️  This analysis was conducted for authorized security testing purposes only.")

def main():
    parser = argparse.ArgumentParser(
        description="Redis Security Analyzer - Advanced Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis of Redis server
  python3 redis_analyzer.py -H 172.20.2.142

  # Analyze specific databases
  python3 redis_analyzer.py -H 172.20.2.142 -d 0,1,3

  # Search for sensitive data patterns
  python3 redis_analyzer.py -H 172.20.2.142 -s

  # Custom port and timeout
  python3 redis_analyzer.py -H 172.20.2.142 -p 6380 -t 15

  # Analyze with larger sample size
  python3 redis_analyzer.py -H 172.20.2.142 --sample-size 50

⚠️  FOR AUTHORIZED SECURITY TESTING ONLY
        """
    )
    
    parser.add_argument('-H', '--host', required=True,
                       help='Redis server IP address')
    parser.add_argument('-p', '--port', type=int, default=6379,
                       help='Redis server port (default: 6379)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-d', '--databases',
                       help='Comma-separated list of database numbers to analyze (e.g., 0,1,3)')
    parser.add_argument('--sample-size', type=int, default=20,
                       help='Number of keys to sample per database (default: 20)')
    parser.add_argument('-s', '--sensitive-only', action='store_true',
                       help='Focus on searching for sensitive data patterns')
    parser.add_argument('--info-only', action='store_true',
                       help='Only gather server information')
    parser.add_argument('-o', '--output',
                       help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Parse target databases
    target_databases = None
    if args.databases:
        try:
            target_databases = [int(db.strip()) for db in args.databases.split(',')]
        except ValueError:
            print("❌ Invalid database numbers. Use comma-separated integers (e.g., 0,1,3)")
            sys.exit(1)
    
    # Initialize analyzer
    analyzer = RedisAnalyzer(args.host, args.port, args.timeout)
    
    try:
        if args.info_only:
            # Just get server info
            if analyzer.test_connection():
                analyzer.get_server_info()
        elif args.sensitive_only:
            # Focus on sensitive data search
            if analyzer.test_connection():
                analyzer.get_server_info()
                
                dbs_to_search = target_databases or [0]
                for db_num in dbs_to_search:
                    analyzer.search_sensitive_data(db_num)
        else:
            # Full analysis
            analyzer.full_analysis(target_databases, args.sample_size)
        
        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(analyzer.server_info, f, indent=2)
            print(f"\n💾 Results saved to: {args.output}")
    
    except KeyboardInterrupt:
        print("\n\n⏹️  Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
    finally:
        analyzer.disconnect()

if __name__ == "__main__":
    main()
