import asyncio
from flask import Flask, render_template, jsonify, request
from nscan.nmap_scan import nmap_scan
from scan_utils import scan_ports, SCAN_FUNCTIONS
from cve_utils import attach_cve_data

app = Flask(__name__)

@app.route("/")
def index():
    """Main Page"""
    return render_template('index.html')


@app.route("/port")
def port_scan_page():
    """포트 스캔 페이지"""
    return render_template("port.html")

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.json
        ip_address = data.get("ip")
        scan_method = data.get("method")

        scan_method_map = {
            "Syn": "-sS",
            "TCP": "-sT",
            "UDP": "-sU",
            "Service_Scan": "-sV",
        }
        nmap_arguments = scan_method_map.get(scan_method)

        if not ip_address or not nmap_arguments:
            return jsonify({"error": "IP 주소와 스캔방식을 선택해주세요."}), 400

        # 포트 범위를 사용자 입력으로 확장하거나 하드코딩된 범위를 사용
        open_ports = nmap_scan(ip_address, 1, 23, nmap_arguments)

        result = {
            "ip": ip_address,
            "method": scan_method,
            "open_ports": open_ports,  # 스캔 결과 추가
            "state": "success",
            "message": f"{ip_address}에 대한 {scan_method} 스캔 결과입니다."
        }

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/service_scan")
def service_scan_page():
    """서비스 스캔 페이지"""
    return render_template("service_scan.html")


@app.route('/service_scan', methods=['POST'])
async def service_scan():
    try:
        data = request.json
        ip_address = data.get("ip")
        ports = data.get("ports", [])

        if not ip_address or not ports:
            return jsonify({"error": "유효한 IP 주소와 포트 목록을 제공하세요."}), 400

        # 포트 스캔 실행
        scan_results = await scan_ports(ip_address, ports, SCAN_FUNCTIONS)

        # CVE 데이터 추가
        results_with_cve = await attach_cve_data(scan_results)

        return jsonify({"ip": ip_address, "results": results_with_cve}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)