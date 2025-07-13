import nmap
import os
import datetime
from config import Config  # Теперь должен работать

def run_nmap_scan(target, scan_type):
    # Настройки сканирования
    scan_params = {
        'quick': '-T4 -F',
        'full': '-T4 -A -v',
        'vuln': '-T4 --script vuln'
    }.get(scan_type, '-T4')
    
    # Запуск сканирования
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments=scan_params)
    
    # Генерация отчёта
    report_id = f"scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    report_path = os.path.join(Config.SCAN_RESULTS_DIR, f'{report_id}.html')
    
    with open(report_path, 'w') as f:
        f.write("<h1>Отчёт сканирования</h1>")
        f.write(f"<p>Цель: {target}</p>")
        f.write(f"<p>Тип сканирования: {scan_type}</p>")
        f.write("<h2>Результаты:</h2>")
        
        for host in scanner.all_hosts():
            f.write(f"<h3>Хост: {host}</h3>")
            f.write(f"<p>Статус: {scanner[host].state()}</p>")
            
            for proto in scanner[host].all_protocols():
                f.write(f"<h4>Протокол: {proto}</h4>")
                ports = scanner[host][proto].keys()
                
                for port in ports:
                    state = scanner[host][proto][port]['state']
                    service = scanner[host][proto][port]['name']
                    f.write(f"<p>Порт: {port} | Состояние: {state} | Сервис: {service}</p>")
    
    return report_id