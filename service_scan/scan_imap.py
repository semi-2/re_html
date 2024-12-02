import socket

def scan_imap(ip, port=143, timeout=3):
    """IMAP 포트 스캔"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return {port: {"state": "closed", "name": "IMAP", "message": "포트가 닫혀 있습니다."}}
        
        # 포트가 열려있다면 배너와 응답 수신
        response = send_imap_command(ip, port, timeout)
        if response and "banner" in response:
            return {
                port: {
                    "state": "open",
                    "name": "IMAP",
                    "banner": response["banner"],  # 배너 추가
                    "capabilities": response.get("capabilities", []),
                    "details": response["banner"]  # 세부정보에 배너 추가
                }
            }
        else:
            return {port: {"state": "open", "name": "IMAP", "message": "IMAP 응답 없음"}}
    except Exception as e:
        return {port: {"state": "error", "name": "IMAP", "message": str(e)}}


def send_imap_command(ip, port=143, timeout=10):
    """IMAP 명령 전송 및 응답 처리"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode(errors="ignore").strip()

            # CAPABILITY 명령 전송
            capability_command = "A001 CAPABILITY\r\n"
            sock.sendall(capability_command.encode())

            # 응답 수신
            response = b""
            while True:
                chunk = sock.recv(1024)
                response += chunk
                if not chunk or b"OK" in chunk or b"BAD" in chunk:
                    break

            # 응답 파싱
            capabilities = parse_imap_capabilities(response.decode(errors="ignore"))
            return {"banner": banner, "capabilities": capabilities}
    except Exception as e:
        return {"error": str(e)}


def parse_imap_capabilities(response):
    """IMAP CAPABILITY 응답에서 지원 기능 추출"""
    capabilities = []
    for line in response.split("\r\n"):
        if "CAPABILITY" in line.upper():
            capabilities_line = line.strip().split(" ")
            capabilities.extend(capabilities_line[2:])
    return capabilities
