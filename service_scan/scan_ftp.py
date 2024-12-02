import socket

def scan_ftp(ip, port=21, timeout=3):
    """FTP 포트 스캔"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return {port: {"state": "closed", "name": "FTP", "message": "포트가 닫혀 있습니다."}}

        # 포트가 열려있다면 배너와 응답 수신
        response = send_ftp_command(ip, port, timeout)
        if response and "banner" in response:
            return {
                port: {
                    "state": "open",
                    "name": "FTP",
                    "banner": response["banner"],  # 배너 추가
                    "features": response.get("features", []),  # 추가 기능
                    "details": response["banner"]  # 세부정보에 배너 추가
                }
            }
        else:
            return {port: {"state": "open", "name": "FTP", "message": "FTP 응답 없음"}}
    except Exception as e:
        return {port: {"state": "error", "name": "FTP", "message": str(e)}}


def send_ftp_command(ip, port=21, timeout=10):
    """FTP 명령 전송 및 응답 처리"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode(errors="ignore").strip()

            # FEAT 명령 전송 (FTP 지원 기능 확인)
            feat_command = "FEAT\r\n"
            sock.sendall(feat_command.encode())

            # 응답 수신
            response = b""
            while True:
                chunk = sock.recv(1024)
                response += chunk
                if not chunk or b"211 End" in chunk:  # FTP 서버에서 명령 종료
                    break

            # 응답 파싱
            features = parse_ftp_features(response.decode(errors="ignore"))
            return {"banner": banner, "features": features}
    except Exception as e:
        return {"error": str(e)}


def parse_ftp_features(response):
    """FTP FEAT 응답에서 지원 기능 추출"""
    features = []
    for line in response.split("\r\n"):
        if line.startswith(" "):  # 기능은 공백으로 시작
            features.append(line.strip())
    return features
