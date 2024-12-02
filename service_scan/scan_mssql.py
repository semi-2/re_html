import socket
import struct

def scan_mssql(ip, port=1433, timeout=3):
    """
    MS SQL Server(1433번 포트) 서비스 스캔 및 TDS 응답 데이터 분석.

    Args:
        ip (str): 스캔할 대상 IP 주소.
        port (int): 스캔할 포트 번호 (기본값: 1433).
        timeout (int): 소켓 연결 제한 시간 (초 단위) (기본값: 3초).

    Returns:
        dict: 포트 상태 및 TDS 응답 데이터 분석 결과.
    """
    try:
        # TCP 소켓 생성 및 연결
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # TDS 초기 요청 전송
            tds_response = send_tds_prelogin(sock)

            if tds_response:
                # TDS 응답 데이터 파싱
                parsed_response = parse_tds_response(tds_response)
                return {
                    port: {
                        "state": "open",
                        "name": "MSSQL",
                        "details": parsed_response
                    }
                }
            else:
                return {
                    port: {
                        "state": "open",
                        "name": "MSSQL",
                        "message": "TDS 응답 없음"
                    }
                }
    except socket.timeout:
        return {
            port: {
                "state": "timeout",
                "name": "MSSQL",
                "message": "연결 시간 초과"
            }
        }
    except Exception as e:
        return {
            port: {
                "state": "error",
                "name": "MSSQL",
                "message": str(e)
            }
        }


def send_tds_prelogin(sock):
    """
    MS SQL Server에 TDS Prelogin 요청을 전송하고 응답 반환.

    Args:
        sock (socket): TCP 소켓 객체.

    Returns:
        bytes: TDS 응답 데이터.
    """
    try:
        # TDS Prelogin 요청 패킷 생성
        tds_prelogin_packet = create_tds_prelogin_packet()
        sock.sendall(tds_prelogin_packet)

        # 응답 수신
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        return response
    except Exception as e:
        return None


def create_tds_prelogin_packet():
    """
    TDS Prelogin 요청 패킷 생성.

    Returns:
        bytes: TDS Prelogin 요청 패킷.
    """
    tds_header = struct.pack(">BBHHBB", 0x12, 0x01, 0x0000, 0x0000, 0x00, 0x00)
    tds_data = b"\x00\x01\x00\x00\x00\x00\x00\x00"  # Prelogin 옵션

    # 데이터 길이 갱신
    packet_length = len(tds_header) + len(tds_data)
    tds_header = struct.pack(">BBHHBB", 0x12, 0x01, packet_length, 0x0000, 0x00, 0x00)

    return tds_header + tds_data


def parse_tds_response(response):
    """
    TDS 응답 데이터를 파싱하여 MS SQL Server 정보를 추출.

    Args:
        response (bytes): TDS 응답 데이터.

    Returns:
        dict: 파싱된 MS SQL Server 정보.
    """
    try:
        if response[:2] == b"\x04\x01":  # TDS 패킷 유형 확인
            # TDS 헤더 이후에 버전 정보가 포함됨
            version_data = response[9:14]
            version = version_data.decode(errors="ignore").strip()
            return {
                "version": version,
                "raw_data": response.hex()
            }
        else:
            return {
                "error": "TDS 응답 데이터가 예상과 다릅니다.",
                "raw_data": response.hex()
            }
    except Exception as e:
        return {"error": f"TDS 응답 파싱 중 에러 발생: {e}"}


# 테스트 실행
if __name__ == "__main__":
    result = scan_mssql("127.0.0.1")
    print(result)
