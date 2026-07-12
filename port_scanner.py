# port_scanner.py

"""
作者: xuanchengning
仓库: https://github.com/xuanchengning/planetnet

本工具仅供安全研究和授权测试使用
未经授权扫描他人网站属于违法行为
"""


import socket
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# 常见端口与服务映射
SERVICE_MAP = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

class PortScanner:
    def __init__(self, target, timeout=1.5, threads=100):
        """
        target: IP地址或域名
        timeout: 连接超时（秒）
        threads: 并发线程数
        """
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.total_ports = 0
        
    def scan_port(self, port):
        """扫描单个端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = SERVICE_MAP.get(port, "Unknown")
                return (port, service, "OPEN")
            else:
                return (port, None, "CLOSED")
        except Exception:
            return (port, None, "ERROR")
    
    def scan_range(self, start_port=1, end_port=1024):
        """扫描端口范围"""
        print(f"\n🔍 开始扫描 {self.target}")
        print(f"📡 端口范围: {start_port}-{end_port}")
        print(f"⚡ 并发线程: {self.threads}")
        print(f"⏱️  超时设置: {self.timeout}s")
        print("-" * 50)
        
        start_time = time.time()
        self.total_ports = end_port - start_port + 1
        scanned = 0
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.scan_port, port): port 
                for port in range(start_port, end_port + 1)
            }
            
            for future in as_completed(futures):
                port, service, status = future.result()
                scanned += 1
                
                if status == "OPEN":
                    open_ports.append((port, service))
                    print(f"  ✅ 端口 {port}: OPEN  [{service}]")
                elif scanned % 50 == 0:  # 每50个端口显示进度
                    print(f"  ⏳ 进度: {scanned}/{self.total_ports}")
        
        self.open_ports = open_ports
        
        # 统计结果
        elapsed = time.time() - start_time
        print("-" * 50)
        print(f"\n✅ 扫描完成!")
        print(f"📊 扫描端口: {self.total_ports}")
        print(f"🟢 开放端口: {len(open_ports)}")
        print(f"⏱️  耗时: {elapsed:.2f}秒")
        
        return open_ports
    
    def export_json(self, filename=None):
        """导出为JSON"""
        if not filename:
            filename = f"scan_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "open_ports": [
                {"port": p, "service": s} for p, s in self.open_ports
            ],
            "total_scanned": self.total_ports
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"💾 结果已导出: {filename}")

# ========== 命令行入口 ==========
if __name__ == "__main__":
    import sys
    
    # 默认扫描本地
    target = "127.0.0.1"
    start_port = 1
    end_port = 1024
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    if len(sys.argv) > 2:
        start_port = int(sys.argv[2])
    if len(sys.argv) > 3:
        end_port = int(sys.argv[3])
    
    scanner = PortScanner(target, timeout=1.5, threads=50)
    scanner.scan_range(start_port, end_port)
    scanner.export_json()