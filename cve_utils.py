import requests

CIRCL_API_URL = "https://cve.circl.lu/api/search/"

async def attach_cve_data(scan_results):
    """
    스캔 결과에 CIRCL API를 통해 CVE 데이터를 추가합니다.
    :param scan_results: 포트 스캔 결과 리스트
    :return: CVE 데이터를 포함한 스캔 결과
    """
    enriched_results = []

    for result in scan_results:
        service_name = result.get("service", "unknown")
        result_with_cve = result.copy()

        if result["status"] == "open" and service_name != "unknown":
            # CIRCL API에서 CVE 데이터 가져오기
            try:
                response = requests.get(f"{CIRCL_API_URL}{service_name}")
                if response.status_code == 200:
                    cve_data = response.json().get("results", [])
                    result_with_cve["cve"] = cve_data
                else:
                    result_with_cve["cve"] = []
            except Exception as e:
                result_with_cve["cve"] = []
                result_with_cve["error"] = f"CVE 데이터를 가져오는 중 오류 발생: {e}"
        else:
            result_with_cve["cve"] = []

        enriched_results.append(result_with_cve)

    return enriched_results
