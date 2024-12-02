import socket

def scan_ssh(target_ip, port=22, timeout=3):
    """
    SSH 서비스 스캔.

    Args:
        target_ip (str): 스캔할 대상 IP 주소.
        port (int): 스캔할 포트 번호 (기본값: 22).
        timeout (int): 소켓 연결 제한 시간(초) (기본값: 3초).

    Returns:
        dict: 포트 상태 및 SSH 배너 정보.
    """
    try:
        # TCP 연결 시도
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            connection_result = s.connect_ex((target_ip, port))

            if connection_result == 0:  # 포트가 열려 있는 경우
                # 배너 정보 수집
                try:
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                except socket.timeout:
                    banner = "No banner received"

                return {
                    port: {
                        "state": "open",
                        "name": "SSH",
                        "banner": banner,
                        "details": banner
                    }
                }
            else:
                return {
                    port: {
                        "state": "closed",
                        "name": "SSH",
                        "message": "포트가 닫혀 있습니다."
                    }
                }
    except Exception as e:
        return {
            port: {
                "state": "error",
                "name": "SSH",
                "message": str(e)
            }
        }


# 테스트 실행
if __name__ == "__main__":
    result = scan_ssh("192.168.1.1")
    print(result)
