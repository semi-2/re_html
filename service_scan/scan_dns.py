import socket
import struct

def scan_dns(target_ip, port=53, timeout=3):
    """
    DNS(53번 포트) 서비스 스캔 및 정보 분석.

    Args:
        target_ip (str): 스캔할 대상 IP 주소.
        port (int): 스캔할 포트 번호.
        timeout (int): 소켓 연결 타임아웃 (초 단위).

    Returns:
        dict: 포트 상태 및 DNS 응답 정보.
    """
    try:
        # 포트가 열려 있는지 TCP 연결로 확인
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((target_ip, port)) != 0:
                return {port: {"state": "closed", "name": "DNS", "message": "포트가 닫혀 있습니다."}}

        # DNS 쿼리 전송 및 응답 수신
        dns_response = send_dns_query(target_ip, "example.com", port, timeout)
        if dns_response:
            parsed_response = parse_dns_response(dns_response)
            return {
                port: {
                    "state": "open",
                    "name": "DNS",
                    "response": parsed_response
                }
            }
        else:
            return {port: {"state": "open", "name": "DNS", "message": "DNS 응답 없음"}}

    except Exception as e:
        return {port: {"state": "error", "name": "DNS", "message": str(e)}}


def send_dns_query(target_ip, domain, port=53, timeout=3):
    """
    DNS 쿼리를 전송하고 응답을 반환 (UDP).

    Args:
        target_ip (str): 대상 IP 주소.
        domain (str): 조회할 도메인 이름.
        port (int): 대상 포트 번호.
        timeout (int): 소켓 연결 타임아웃 (초 단위).

    Returns:
        bytes: DNS 응답 데이터.
    """
    dns_query = create_dns_query(domain)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(dns_query, (target_ip, port))
            response, _ = sock.recvfrom(512)  # 최대 512바이트 수신
            return response
        except socket.timeout:
            return None


def create_dns_query(domain):
    """
    DNS 쿼리 생성 (A 레코드 요청).

    Args:
        domain (str): 조회할 도메인 이름.

    Returns:
        bytes: DNS 쿼리 패킷.
    """
    transaction_id = b"\x12\x34"  # Transaction ID
    flags = b"\x01\x00"           # Standard query
    questions = b"\x00\x01"       # Questions: 1
    answer_rrs = b"\x00\x00"      # Answer RRs: 0
    authority_rrs = b"\x00\x00"   # Authority RRs: 0
    additional_rrs = b"\x00\x00"  # Additional RRs: 0

    # 도메인을 DNS 형식으로 변환
    domain_parts = domain.split(".")
    qname = b"".join(len(part).to_bytes(1, "big") + part.encode() for part in domain_parts) + b"\x00"
    qtype = b"\x00\x01"  # Type: A
    qclass = b"\x00\x01" # Class: IN

    return transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + qname + qtype + qclass


def parse_dns_response(response):
    """
    DNS 응답 데이터를 파싱.

    Args:
        response (bytes): DNS 응답 데이터.

    Returns:
        dict: 파싱된 DNS 응답 정보.
    """
    try:
        transaction_id = response[:2].hex()
        flags = response[2:4].hex()
        qdcount = struct.unpack(">H", response[4:6])[0]
        ancount = struct.unpack(">H", response[6:8])[0]
        nscount = struct.unpack(">H", response[8:10])[0]
        arcount = struct.unpack(">H", response[10:12])[0]

        # 응답 데이터 구조화
        return {
            "transaction_id": transaction_id,
            "flags": flags,
            "questions_count": qdcount,
            "answers_count": ancount,
            "authority_rrs": nscount,
            "additional_rrs": arcount
        }
    except Exception as e:
        return {"error": f"응답 파싱 중 에러 발생: {e}"}


# 테스트 실행
if __name__ == "__main__":
    result = scan_dns("8.8.8.8")
    print(result)
