import socket
import ssl
from datetime import timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def scan_https(ip, port=443, timeout=10):
    """
    HTTPS 서비스 스캔 함수.
    - IP와 포트를 입력받아 HTTPS 상태 및 SSL/TLS 인증서 및 응답 데이터를 반환.
    """
    result = {
        "name": "HTTPS",
        "state": "closed",
        "details": {
            "certificate": None,
            "response": None
        },
    }

    try:
        # TCP 연결 생성
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # TLS/SSL 연결 설정
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                result["state"] = "open"

                # SSL 인증서 정보 가져오기
                cert = ssock.getpeercert(binary_form=True)
                if cert:
                    result["details"]["certificate"] = parse_ssl_certificate_binary(cert)

                # HTTPS 요청 전송 및 응답 데이터 수집
                response_data = send_https_request(ssock, ip)
                result["details"]["response"] = response_data
    except socket.timeout:
        result["state"] = "timeout"
        result["details"] = {"error": "연결 시간 초과"}
    except ssl.SSLError as e:
        result["state"] = "error"
        result["details"] = {"error": f"SSL/TLS 에러: {str(e)}"}
    except Exception as e:
        result["state"] = "error"
        result["details"] = {"error": f"스캔 중 에러 발생: {str(e)}"}

    return {port: result}


def parse_ssl_certificate_binary(cert):
    """
    SSL 인증서 바이너리 데이터를 파싱하여 정보를 반환.
    """
    try:
        x509_cert = x509.load_der_x509_certificate(cert, default_backend())
        return {
            "issuer": x509_cert.issuer.rfc4514_string(),
            "subject": x509_cert.subject.rfc4514_string(),
            "serial_number": str(x509_cert.serial_number),
            "valid_from": x509_cert.not_valid_before_utc.isoformat(),
            "valid_to": x509_cert.not_valid_after_utc.isoformat(),
        }
    except Exception as e:
        return {"error": f"인증서 파싱 에러: {str(e)}"}

def send_https_request(ssock, ip):
    """
    HTTPS 요청을 전송하고 응답 데이터를 반환.
    """
    try:
        # GET 요청 전송
        http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            "User-Agent: PortScanner/1.0\r\n"
            "Connection: close\r\n\r\n"
        )
        ssock.sendall(http_request.encode())

        # 응답 수신
        response = b""
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            response += chunk

        # 응답 헤더와 본문 분리
        response_text = response.decode(errors="ignore")
        headers, _, body = response_text.partition("\r\n\r\n")

        # JSON 형식으로 응답 반환
        return {
            "headers": headers,
            "body_preview": body[:500],  # 본문 미리 보기 (최대 500자)
        }
    except Exception as e:
        return {"error": f"HTTPS 요청 에러: {str(e)}"}

