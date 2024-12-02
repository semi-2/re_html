import asyncio
from service_scan.scan_ftp import scan_ftp
from service_scan.scan_ssh import scan_ssh
from service_scan.scan_dns import scan_dns
from service_scan.scan_http import scan_http
from service_scan.scan_https import scan_https
from service_scan.scan_imap import scan_imap
from service_scan.scan_mssql import scan_mssql
from service_scan.scan_mysql import scan_mysql
from service_scan.scan_telnet import scan_telnet

# 스캔 함수 매핑
SCAN_FUNCTIONS = {
    20: scan_ftp,
    21: scan_ftp,
    22: scan_ssh,
    23: scan_telnet,
    53: scan_dns,
    80: scan_http,
    143: scan_imap,
    443: scan_https,
    1433: scan_mssql,
    3306: scan_mysql
}

# 포트 정보 매핑
PORT_INFO = {
    20: "FTP 데이터 전송 (File Transfer Protocol Data)",
    21: "FTP 제어 (File Transfer Protocol Control)",
    22: "SSH (Secure Shell)",
    53: "DNS (Domain Name System)",
    80: "HTTP (HyperText Transfer Protocol)",
    143: "IMAP (Internet Message Access Protocol)",
    443: "HTTPS (HTTP Secure)",
    1433: "MSSQL (Microsoft SQL Server)",
    3306: "MySQL (MySQL Database)"
}

async def async_scan(scan_func, ip_address, port):
    """비동기 포트 스캔 함수"""
    port_info = PORT_INFO.get(port, "Unknown Service")

    try:
        # 비동기 스캔 실행
        result = await asyncio.to_thread(scan_func, ip_address, port=port)
        port_result = result.get(port, {})
        return {
            "port": port,
            "service": port_result.get("name", "unknown"),
            "status": port_result.get("state", "unknown"),
            "details": port_result.get("details", "정보가 없습니다."),
            "description": port_info
        }
    except Exception as e:
        return {
            "port": port,
            "service": "unknown",
            "status": "오류 발생",
            "details": str(e),
            "description": port_info
        }

async def scan_ports(ip_address, ports, scan_functions):
    """비동기 포트 스캔 실행"""
    tasks = [
        async_scan(scan_functions.get(port), ip_address, port)
        for port in ports if port in scan_functions
    ]
    return await asyncio.gather(*tasks)
