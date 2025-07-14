import sys
import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory

# Добавляем текущую директорию в путь поиска
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from scanner import run_nmap_scan

app = Flask(__name__)
app.config.from_object(Config)

# Остальной код без изменений
@app.route('/')
def index():
    return render_template('index.html')

# Страница запуска сканирования
@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        target = request.form['target']
        scan_type = request.form['scan_type']
        
        # Проверка разрешённых целей
        #if target not in app.config['ALLOWED_TARGETS']:
            #return "Недопустимая цель сканирования", 400
            
        report_id = run_nmap_scan(target, scan_type)
        return redirect(url_for('report', report_id=report_id))
    
    return render_template('scan.html')

# Страница отчёта
@app.route('/report/<report_id>')
def report(report_id):
    report_path = os.path.join(app.config['SCAN_RESULTS_DIR'], f'{report_id}.html')
    return render_template('report.html', report_path=report_path)

# Скачивание отчёта
@app.route('/download/<report_id>')
def download_report(report_id):
    return send_from_directory(
        app.config['SCAN_RESULTS_DIR'],
        f'{report_id}.html',
        as_attachment=True
    )

if __name__ == '__main__':
    os.makedirs(app.config['SCAN_RESULTS_DIR'], exist_ok=True)
    app.run(host='0.0.0.0', port=5000)