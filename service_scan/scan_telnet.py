import socket

def scan_telnet(ip, port=23, timeout=3):
    """
    Telnet(23번 포트) 서비스 스캔 및 초기 배너 수집.

    Args:
        ip (str): 스캔할 대상 IP 주소.
        port (int): 스캔할 포트 번호 (기본값: 23).
        timeout (int): 소켓 연결 제한 시간 (초 단위) (기본값: 3초).

    Returns:
        dict: 포트 상태 및 Telnet 배너 정보.
    """
    try:
        # TCP 소켓 생성 및 연결
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # 초기 배너 수집
            try:
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                banner = "No banner received"

            return {
                port: {
                    "state": "open",
                    "name": "Telnet",
                    "banner": banner,
                    "details": banner
                }
            }
    except socket.timeout:
        return {
            port: {
                "state": "timeout",
                "name": "Telnet",
                "message": "연결 시간 초과"
            }
        }
    except Exception as e:
        return {
            port: {
                "state": "error",
                "name": "Telnet",
                "message": str(e)
            }
        }


# 테스트 실행
if __name__ == "__main__":
    result = scan_telnet("127.0.0.1")
    print(result)
