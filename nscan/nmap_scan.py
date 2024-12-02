import nmap
import threading


def scan_port_thread(target_ip, port, scan_type, nm, open_ports):
    try:
        nm.scan(hosts=target_ip, ports=str(port), arguments=scan_type)
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                port_data = nm[host][proto].get(port, {})
                if port_data.get('state') == 'open':
                    open_ports.append({
                        "port": port,
                        "service": port_data.get('name', 'unknown')
                    })
    except Exception as e:
        print(f"포트 {port} 스캔 중 오류 발생: {e}")


def nmap_scan(target_ip, start_port, end_port, scan_type):
    nm = nmap.PortScanner()
    open_ports = []

    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port_thread, args=(target_ip, port, scan_type, nm, open_ports))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports
