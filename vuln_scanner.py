# vuln_scanner.py
"""
VulnScanner - Web Application Security Scanner

Author: xuanchengning
Repository: https://github.com/xuanchengning/planetnet

For authorized security testing only.
Unauthorized use is prohibited by law.
"""

import requests
import json
import sys
from urllib.parse import urljoin, urlparse
from datetime import datetime


class VulnScanner:
    """Web vulnerability scanner"""

    def __init__(self, target_url, timeout=5):
        self.target = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }
        self.stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    def _request(self, url):
        try:
            return self.session.get(url, timeout=self.timeout)
        except:
            return None

    def check_sql_injection(self):
        findings = []
        payloads = ["'", '"', "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        error_patterns = ['sql', 'mysql', 'syntax error', 'unclosed quotation', 'warning']

        parsed = urlparse(self.target)
        if not parsed.query:
            return findings

        params = [p.split('=')[0] for p in parsed.query.split('&') if '=' in p]

        for param in params:
            for payload in payloads:
                test_url = f"{self.target}?{param}={payload}"
                resp = self._request(test_url)
                if resp and any(p in resp.text.lower() for p in error_patterns):
                    findings.append({
                        'type': 'SQL Injection',
                        'severity': 'critical',
                        'url': test_url,
                        'parameter': param,
                        'payload': payload
                    })
                    break
        return findings

    def check_xss(self):
        findings = []
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>"
        ]

        parsed = urlparse(self.target)
        if not parsed.query:
            return findings

        params = [p.split('=')[0] for p in parsed.query.split('&') if '=' in p]

        for param in params:
            for payload in payloads:
                test_url = f"{self.target}?{param}={payload}"
                resp = self._request(test_url)
                if resp and payload in resp.text:
                    findings.append({
                        'type': 'XSS',
                        'severity': 'critical',
                        'url': test_url,
                        'parameter': param,
                        'payload': payload[:30]
                    })
                    break
        return findings

    def check_sensitive_files(self):
        findings = []
        files = [
            '.git/config', '.env', 'wp-config.php',
            '.htaccess', 'robots.txt', 'composer.json',
            'backup.sql', 'config.php'
        ]

        for file_path in files:
            test_url = urljoin(self.target, file_path)
            resp = self._request(test_url)
            if resp and resp.status_code == 200:
                findings.append({
                    'type': 'Sensitive File Exposure',
                    'severity': 'high',
                    'url': test_url,
                    'status': '200 OK'
                })
        return findings

    def check_security_headers(self):
        findings = []
        required_headers = {
            'Strict-Transport-Security': 'HSTS header missing',
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME sniffing protection missing',
            'Content-Security-Policy': 'CSP header missing'
        }

        resp = self._request(self.target)
        if not resp:
            return [{'type': 'Connection Error', 'severity': 'high', 'detail': 'Cannot get headers'}]

        for header, desc in required_headers.items():
            if header not in resp.headers:
                findings.append({
                    'type': 'Missing Security Header',
                    'severity': 'medium',
                    'header': header,
                    'description': desc
                })
        return findings

    def check_admin_paths(self):
        findings = []
        paths = [
            'admin/', 'administrator/', 'wp-admin/',
            'phpmyadmin/', 'dashboard/', 'login/'
        ]

        for path in paths:
            test_url = urljoin(self.target, path)
            resp = self._request(test_url)
            if resp and resp.status_code == 200:
                findings.append({
                    'type': 'Admin Panel Exposure',
                    'severity': 'medium',
                    'url': test_url,
                    'status': '200 OK'
                })
        return findings

    def scan(self):
        print(f"\nVulnScanner")
        print(f"Target: {self.target}")
        print("=" * 50)

        modules = [
            ('SQL Injection', self.check_sql_injection),
            ('XSS', self.check_xss),
            ('Sensitive Files', self.check_sensitive_files),
            ('Security Headers', self.check_security_headers),
            ('Admin Paths', self.check_admin_paths)
        ]

        for name, func in modules:
            print(f"\nChecking {name}...")
            try:
                result = func()
                if result:
                    print(f"  Found {len(result)} issues")
                    for item in result:
                        severity = item.get('severity', 'unknown')
                        self.results['vulnerabilities'].append(item)
                        self.stats[severity] = self.stats.get(severity, 0) + 1
                        print(f"    - {item.get('type', 'Unknown')} [{severity}]")
                        if 'url' in item:
                            print(f"      URL: {item['url']}")
                else:
                    print("  No issues found")
            except Exception as e:
                print(f"  Error: {str(e)}")

        self._print_summary()
        return self.results

    def _print_summary(self):
        print("\n" + "=" * 50)
        print("Scan Complete")
        print("=" * 50)
        print(f"Critical: {self.stats.get('critical', 0)}")
        print(f"High:     {self.stats.get('high', 0)}")
        print(f"Medium:   {self.stats.get('medium', 0)}")
        print(f"Low:      {self.stats.get('low', 0)}")
        print("=" * 50)

    def export_json(self):
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print(f"\nJSON report exported: {filename}")

    def export_html(self):
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        html_content = f"""<!DOCTYPE html>
<html>
<head><title>Vulnerability Scan Report</title>
<style>
body {{ font-family: Arial; margin: 40px; background: #f0f0f0; }}
.container {{ max-width: 900px; margin: auto; background: white; padding: 30px; }}
.critical {{ color: red; }}
.high {{ color: #ff4500; }}
.medium {{ color: #ff8c00; }}
.low {{ color: blue; }}
</style>
</head>
<body>
<div class="container">
    <h1>Vulnerability Scan Report</h1>
    <p><strong>Target:</strong> {self.target}</p>
    <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <h2>Findings</h2>"""

        for v in self.results['vulnerabilities']:
            severity = v.get('severity', 'unknown')
            color = 'red' if severity in ['critical', 'high'] else 'orange' if severity == 'medium' else 'blue'
            html_content += f"""
    <div style="border-left: 4px solid {color}; padding: 10px; margin:5px 0; background:#f5f5f5;">
        <strong>{v.get('type', 'Unknown')}</strong> [{severity}]
        <br/><small>{v.get('url', v.get('detail', ''))}</small>
    </div>"""

        html_content += """
</div>
</body>
</html>"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"HTML report exported: {filename}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python vuln_scanner.py <target_url>")
        print("Example: python vuln_scanner.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    scanner = VulnScanner(target)
    scanner.scan()
    scanner.export_json()
    scanner.export_html()


if __name__ == '__main__':
    main()