import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def https_scan(ip, port=443, timeout=10):
    # HTTPS(443번 포트) 서비스 스캔 및 SSL/TLS 정보 분석
    try:
        # 1. TCP 연결 생성
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # 2. TLS/SSL 래핑
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                print(f"[INFO] {ip}:{port} - HTTPS 포트가 열려 있습니다.")

                # 3. SSL/TLS 인증서 정보 가져오기
                cert = ssock.getpeercert(binary_form=True)
                if cert:
                    print("\n[INFO] SSL 인증서 정보:")
                    parse_ssl_certificate_binary(cert)
                else:
                    print("[INFO] SSL 인증서를 가져올 수 없습니다.")

                # 4. HTTP 요청 전송 (Optional)
                send_https_request(ssock, ip)

    except socket.timeout:
        print(f"[INFO] {ip}:{port} - 연결 시간 초과.")
    except ssl.SSLError as e:
        print(f"[ERROR] {ip}:{port} - SSL/TLS 에러: {e}")
    except Exception as e:
        print(f"[ERROR] {ip}:{port} - 스캔 중 에러 발생: {e}")

def parse_ssl_certificate_binary(cert):
    # SSL 인증서 정보 파싱 및 출력
    try:
        # 바이너리 인증서를 x509 객체로 변환
        x509_cert = x509.load_der_x509_certificate(cert, default_backend())
        
        # 인증서의 주요 정보 출력
        print(f"Issuer: {x509_cert.issuer}")
        print(f"Subject: {x509_cert.subject}")
        print(f"Serial Number: {x509_cert.serial_number}")
        print(f"Valid From: {x509_cert.not_valid_before_utc.isoformat()}")
        print(f"Valid To: {x509_cert.not_valid_after_utc.isoformat()}")


    except Exception as e:
        print(f"[ERROR] 인증서 파싱 중 에러 발생: {e}")

def send_https_request(ssock, ip):
    # HTTPS 요청을 전송하고 응답 출력
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

        print("\n[HTTPS Response]")
        print(response.decode(errors="ignore")[:500])  # 최대 500자 출력
    except Exception as e:
        print(f"[ERROR] HTTPS 요청 중 에러 발생: {e}")

https_scan("52.91.120.160")