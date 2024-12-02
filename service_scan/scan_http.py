import socket

def scan_http(ip, port=80, timeout=3):
    """
    HTTP(80번 포트) 서비스 스캔 및 정보 분석.

    Args:
        ip (str): 스캔할 대상 IP 주소.
        port (int): 스캔할 포트 번호.
        timeout (int): 소켓 연결 타임아웃 (초 단위).

    Returns:
        dict: 포트 상태 및 HTTP 응답 정보.
    """
    try:
        # TCP 연결로 포트가 열려 있는지 확인
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return {port: {"state": "closed", "name": "HTTP", "message": "포트가 닫혀 있습니다."}}

        # HTTP 요청 전송 및 응답 수신
        response = send_http_request(ip, port, timeout)
        if response:
            parsed_response = parse_http_response(response)
            return {
                port: {
                    "state": "open",
                    "name": "HTTP",
                    "banner": parsed_response.get("headers", ""),
                    "details": parsed_response.get("server_info", "No server info available"),
                }
            }
        else:
            return {port: {"state": "open", "name": "HTTP", "message": "HTTP 응답 없음"}}

    except socket.error as e:
        return {port: {"state": "error", "name": "HTTP", "message": str(e)}}
    except Exception as e:
        return {port: {"state": "error", "name": "HTTP", "message": str(e)}}


def send_http_request(ip, port=80, timeout=3):
    """
    HTTP 요청을 전송하고 응답을 반환.

    Args:
        ip (str): 대상 IP 주소.
        port (int): 대상 포트 번호.
        timeout (int): 소켓 연결 타임아웃 (초 단위).

    Returns:
        str: HTTP 응답 데이터.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            # 서버에 연결
            sock.connect((ip, port))

            # HTTP GET 요청 전송
            http_request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                "User-Agent: PortScanner/1.0\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.sendall(http_request.encode())

            # 응답 수신
            response = b""
            while True:
                chunk = sock.recv(4096)  # 최대 4096 바이트 읽기
                if not chunk:
                    break
                response += chunk

            return response.decode(errors="ignore")  # 텍스트로 디코딩
    except Exception as e:
        return None


def parse_http_response(response):
    """
    HTTP 응답 데이터를 파싱하여 분석.

    Args:
        response (str): HTTP 응답 데이터.

    Returns:
        dict: 응답 헤더 및 서버 정보.
    """
    # 응답 헤더와 본문 분리
    headers, _, body = response.partition("\r\n\r\n")

    # 서버 정보 추출
    server_info = None
    for line in headers.split("\r\n"):
        if line.lower().startswith("server:"):
            server_info = line.split(":", 1)[1].strip()
            break

    return {"headers": headers, "server_info": server_info}


