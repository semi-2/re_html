import socket

def scan_mysql(ip, port=3306, timeout=3):
    """
    MySQL(3306번 포트) 서비스 스캔 및 초기 핸드셰이크 데이터 분석.

    Args:
        ip (str): 스캔할 대상 IP 주소.
        port (int): 스캔할 포트 번호 (기본값: 3306).
        timeout (int): 소켓 연결 제한 시간 (초 단위) (기본값: 3초).

    Returns:
        dict: 포트 상태 및 MySQL 핸드셰이크 데이터 분석 결과.
    """
    try:
        # TCP 소켓 생성 및 연결
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # MySQL 초기 핸드셰이크 응답 수신
            handshake_data = sock.recv(1024)

            if handshake_data:
                # 핸드셰이크 데이터 파싱
                parsed_handshake = parse_mysql_handshake(handshake_data)
                return {
                    port: {
                        "state": "open",
                        "name": "MySQL",
                        "details": parsed_handshake
                    }
                }
            else:
                return {
                    port: {
                        "state": "open",
                        "name": "MySQL",
                        "message": "MySQL 초기 응답 없음"
                    }
                }
    except socket.timeout:
        return {
            port: {
                "state": "timeout",
                "name": "MySQL",
                "message": "연결 시간 초과"
            }
        }
    except Exception as e:
        return {
            port: {
                "state": "error",
                "name": "MySQL",
                "message": str(e)
            }
        }


def parse_mysql_handshake(data):
    """
    MySQL 초기 핸드셰이크 응답 데이터를 파싱.

    Args:
        data (bytes): 핸드셰이크 데이터.

    Returns:
        dict: 파싱된 MySQL 서버 정보.
    """
    try:
        # 프로토콜 버전
        protocol_version = data[0]

        # 서버 버전
        server_version_end = data.find(b'\x00', 1)  # Null 문자로 구분된 서버 버전
        server_version = data[1:server_version_end].decode(errors="ignore")

        # Thread ID
        thread_id_start = server_version_end + 1
        thread_id_end = thread_id_start + 4
        thread_id = int.from_bytes(data[thread_id_start:thread_id_end], byteorder="little")

        # 인증 플러그인
        auth_plugin_data_start = data.find(b'\x00', thread_id_end) + 13
        auth_plugin_name = data[auth_plugin_data_start:].decode(errors="ignore").strip('\x00')

        return {
            "protocol_version": protocol_version,
            "server_version": server_version,
            "thread_id": thread_id,
            "auth_plugin": auth_plugin_name
        }
    except Exception as e:
        return {"error": f"MySQL 핸드셰이크 데이터 파싱 중 에러 발생: {e}"}


# 테스트 실행
if __name__ == "__main__":
    result = scan_mysql("127.0.0.1")
    print(result)
