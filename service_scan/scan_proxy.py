import socket

def http_proxy_scan(ip, port=8080, timeout=5):
    """
    HTTP Proxy(8080번 포트) 서비스 스캔 및 정보 분석.

    Args:
        ip (str): 스캔할 대상 IP 주소.
        port (int): 스캔할 포트 번호 (기본값: 8080).
        timeout (int): 소켓 연결 제한 시간(초) (기본값: 3초).

    Returns:
        dict: 포트 상태 및 HTTP 프록시 응답 정보.
    """
    try:
        # TCP 소켓 생성 및 연결
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # HTTP 요청 전송 및 응답 수신
            response = send_http_request(sock, ip, port)
            if response:
                parsed_response = parse_http_response(response)
                return {
                    port: {
                        "state": "open",
                        "name": "HTTP Proxy",
                        "banner": parsed_response.get("headers", ""),
                        "details": parsed_response.get("server_info", "No server info available")
                    }
                }
            else:
                return {
                    port: {
                        "state": "open",
                        "name": "HTTP Proxy",
                        "message": "HTTP 응답 없음"
                    }
                }
    except socket.timeout:
        return {port: {"state": "timeout", "name": "HTTP Proxy", "message": "연결 시간 초과"}}
    except Exception as e:
        return {port: {"state": "error", "name": "HTTP Proxy", "message": str(e)}}


def send_http_request(sock, ip, port):
    """
    HTTP 요청을 전송하고 응답을 반환.

    Args:
        sock (socket): TCP 소켓 객체.
        ip (str): 대상 IP 주소.
        port (int): 대상 포트 번호.

    Returns:
        str: HTTP 응답 데이터.
    """
    try:
        # HTTP GET 요청 생성
        http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            "User-Agent: PortScanner/1.0\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(http_request.encode())

        # 응답 수신
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        return response.decode(errors="ignore")
    except Exception as e:
        return None


def parse_http_response(response):
    """
    HTTP 응답 데이터를 파싱.

    Args:
        response (str): HTTP 응답 데이터.

    Returns:
        dict: 응답 헤더 및 서버 정보.
    """
    try:
        # 응답 헤더와 본문 분리
        headers, _, body = response.partition("\r\n\r\n")

        # 서버 정보 추출
        server_info = None
        for line in headers.split("\r\n"):
            if line.lower().startswith("server:"):
                server_info = line.split(":", 1)[1].strip()
                break

        return {
            "headers": headers,
            "server_info": server_info
        }
    except Exception as e:
        return {"error": f"응답 파싱 중 에러 발생: {e}"}


# 테스트 실행
if __name__ == "__main__":
    result = http_proxy_scan("192.168.1.1")
    print(result)
