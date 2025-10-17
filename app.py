import sys
import os
import psycopg2
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
from passlib.hash import pbkdf2_sha256
import logging
from zapv2 import ZAPv2  # Импорт библиотеки для ZAP, хотя используем requests
import time
import requests

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)

# Инициализация Flask
app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Ключ безопасности
from config import Config
app.config.from_object(Config)

# Инициализация Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Добавляем текущую директорию в путь поиска
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Модель пользователя для Flask-Login
class User(UserMixin):
    def __init__(self, id, email, username, role):
        self.id = id
        self.email = email
        self.username = username
        self.role = role

# Функция для подключения к PostgreSQL
def get_db_connection():
    conn = psycopg2.connect(
        dbname="hackerapp",
        user="hackeruser",
        password="hackerpassword",
        host="localhost",  # Измените на IP сервера, если база удалённая
        port="5432"
    )
    return conn

# Инициализация базы данных
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # Создаём администратора, если он ещё не существует
    cur.execute('SELECT * FROM users WHERE email = %s', ('admin@example.com',))
    admin = cur.fetchone()
    if not admin:
        password_hash = pbkdf2_sha256.hash('admin_password')  # Замените на безопасный пароль
        cur.execute('''
            INSERT INTO users (email, username, password_hash, role)
            VALUES (%s, %s, %s, %s)
        ''', ('admin@example.com', 'Admin', password_hash, 'admin'))
        conn.commit()
        logging.info("Создан администратор: admin@example.com.")
    # Создаём таблицу scan_reports, если её нет
    cur.execute('''
        CREATE TABLE IF NOT EXISTS public.scan_reports (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            report_content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

# Загрузка пользователя для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cur.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2], user[4])  # id, email, username, role
    return None

# Декоратор для проверки роли администратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Доступ запрещён. Требуются права администратора.', 'error')
            user_info = current_user.email if current_user.is_authenticated else 'анонимный пользователь'
            logging.error(f"Пользователь {user_info} попытался получить доступ к админ-панели.")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Декоратор для проверки авторизации
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Пожалуйста, войдите в систему.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Страница регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        username = request.form.get('username')
        
        if not email or not password or not username:
            flash('Все поля должны быть заполнены.', 'error')
            logging.error("Ошибка: не все поля формы регистрации заполнены.")
            return redirect(url_for('register'))
        
        try:
            password_hash = pbkdf2_sha256.hash(password)
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE email = %s', (email,))
            existing_user = cur.fetchone()
            if existing_user:
                flash('Пользователь с таким email уже существует.', 'error')
                conn.close()
                return redirect(url_for('register'))
            
            cur.execute('''
                INSERT INTO users (email, username, password_hash, role)
                VALUES (%s, %s, %s, %s)
            ''', (email, username, password_hash, 'user'))
            conn.commit()
            conn.close()
            flash('Регистрация успешна! Теперь войдите.', 'success')
            logging.info(f"Пользователь {email} успешно зарегистрирован.")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Ошибка регистрации: {str(e)}', 'error')
            logging.error(f"Ошибка регистрации: {str(e)}")
            return redirect(url_for('register'))
    
    logging.debug("Отображение страницы регистрации.")
    return render_template('auth.html', form_type='register')

# Страница авторизации
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cur.fetchone()
            conn.close()
            
            if user and pbkdf2_sha256.verify(password, user[3]):  # password_hash
                user_obj = User(user[0], user[1], user[2], user[4])  # id, email, username, role
                login_user(user_obj)
                session['username'] = user[2]  # username
                flash('Вы успешно вошли!', 'success')
                logging.info(f"Пользователь {email} успешно вошёл.")
                return redirect(url_for('index'))
            else:
                flash('Неверный email или пароль.', 'error')
                logging.error(f"Ошибка входа: неверный email или пароль для {email}")
                return redirect(url_for('login'))
        except Exception as e:
            flash(f'Ошибка входа: {str(e)}', 'error')
            logging.error(f"Ошибка входа: {str(e)}")
            return redirect(url_for('login'))
    
    logging.debug("Отображение страницы логина.")
    return render_template('auth.html', form_type='login')

# Выход из системы
@app.route('/logout')
def logout():
    logout_user()
    session.pop('username', None)
    flash('Вы вышли из системы.', 'success')
    logging.info("Пользователь вышел из системы.")
    return redirect(url_for('login'))

# Главная страница
@app.route('/')
@login_required
def index():
    try:
        logging.debug(f"Отображение главной страницы для пользователя {current_user.username}")
        return render_template('index.html', username=current_user.username, is_logged_in=current_user.is_authenticated)
    except Exception as e:
        flash(f'Ошибка загрузки главной страницы: {str(e)}', 'error')
        logging.error(f"Ошибка загрузки главной страницы: {str(e)}")
        return redirect(url_for('login'))

# Функция проверки версии ZAP
def check_zap_version(zap_port):
    url = f'http://127.0.0.1:{zap_port}/JSON/core/view/version'
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json().get('version')
    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка подключения к ZAP: {str(e)}")
        return None

# Функция запуска спайдера
def start_spider(zap_port, target):
    url = f'http://127.0.0.1:{zap_port}/JSON/spider/action/scan/?url={target}&maxChildren=10&recurse=True'
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json().get('scan')
    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка запуска спайдера: {str(e)}")
        return None

# Страница запуска сканирования
@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        target = request.form.get('target')
        scan_type = request.form.get('scan_type')
        
        logging.debug(f"Полученные данные: target={target}, scan_type={scan_type}")
        
        if not target or not scan_type:
            flash('Укажите цель и тип сканирования.', 'error')
            logging.error("Ошибка: не указана цель или тип сканирования.")
            return redirect(url_for('scan'))
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
            logging.debug(f"Добавлен протокол: {target}")
            
        try:
            # Проверка доступности ZAP
            zap_port = 8081
            logging.debug(f"Проверка ZAP API на порте {zap_port}...")
            version = check_zap_version(zap_port)
            if not version:
                flash('OWASP ZAP не запущен или недоступен.', 'error')
                logging.error("ZAP не отвечает.")
                return redirect(url_for('scan'))
            logging.debug(f"ZAP версия: {version}")

            # Проверка доступности цели
            logging.debug(f"Проверка доступности цели: {target}")
            try:
                response = requests.get(target, timeout=5)
                if response.status_code >= 400:
                    flash(f'Целевой URL недоступен (код: {response.status_code}).', 'error')
                    logging.error(f"Целевой URL недоступен: {target}, код: {response.status_code}")
                    return redirect(url_for('scan'))
            except requests.exceptions.RequestException as e:
                flash(f'Ошибка доступа к цели {target}: {str(e)}', 'error')
                logging.error(f"Ошибка доступа к цели {target}: {str(e)}")
                return redirect(url_for('scan'))

            # Открытие целевого URL
            logging.debug("Открытие URL...")
            url = f'http://127.0.0.1:{zap_port}/JSON/core/action/accessUrl/?url={target}'
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            time.sleep(2)

            # Запуск спайдера
            logging.debug("Запуск спайдера...")
            spider_id = start_spider(zap_port, target)
            if not spider_id:
                flash('Ошибка запуска спайдера.', 'error')
                logging.error("Не удалось запустить спайдер.")
                return redirect(url_for('scan'))
            while True:
                status_url = f'http://127.0.0.1:{zap_port}/JSON/spider/view/status/?scanId={spider_id}'
                status = requests.get(status_url, timeout=5).json().get('status')
                logging.debug(f"Прогресс спайдера: {status}%")
                if int(status) >= 100:
                    break
                time.sleep(5)

            # Запуск активного сканирования
            logging.debug("Запуск активного сканирования...")
            scan_url = f'http://127.0.0.1:{zap_port}/JSON/ascan/action/scan/?url={target}&recurse=True&inScopeOnly=True'
            scan_id = requests.get(scan_url, timeout=5).json().get('scan')
            if not scan_id:
                flash('Ошибка запуска сканирования.', 'error')
                logging.error("Не удалось запустить сканирование.")
                return redirect(url_for('scan'))
            if scan_type == 'quick':
                duration_url = f'http://127.0.0.1:{zap_port}/JSON/ascan/action/setOptionMaxScanDurationInMins/?minutes=5'
                requests.get(duration_url, timeout=5)
            elif scan_type == 'full':
                duration_url = f'http://127.0.0.1:{zap_port}/JSON/ascan/action/setOptionMaxScanDurationInMins/?minutes=30'
                requests.get(duration_url, timeout=5)
            elif scan_type == 'vuln':
                duration_url = f'http://127.0.0.1:{zap_port}/JSON/ascan/action/setOptionMaxScanDurationInMins/?minutes=15'
                requests.get(duration_url, timeout=5)

            while True:
                status_url = f'http://127.0.0.1:{zap_port}/JSON/ascan/view/status/?scanId={scan_id}'
                status = requests.get(status_url, timeout=5).json().get('status')
                logging.debug(f"Прогресс сканирования: {status}%")
                if int(status) >= 100:
                    break
                time.sleep(10)

            # Получение отчета
            logging.debug("Получение отчета...")
            report_url = f'http://127.0.0.1:{zap_port}/OTHER/core/other/htmlreport/'
            report_content = requests.get(report_url, timeout=5).text
            if not report_content:
                flash('Не удалось получить отчет от ZAP.', 'error')
                logging.error("Отчет пустой.")
                return redirect(url_for('scan'))
            logging.debug(f"Отчет получен, длина: {len(report_content)}")

            # Сохранение отчета в базу данных
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('''
                INSERT INTO scan_reports (user_id, report_content)
                VALUES (%s, %s) RETURNING id
            ''', (current_user.id, report_content))
            report_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()

            if report_id:
                logging.info(f"Сканирование завершено, report_id: {report_id}")
                return redirect(url_for('report', report_id=report_id))
            else:
                flash('Ошибка при сохранении отчета.', 'error')
                logging.error("report_id не получен.")
                return redirect(url_for('scan'))
        except requests.exceptions.RequestException as e:
            flash(f'Ошибка подключения к ZAP или цели: {str(e)}', 'error')
            logging.error(f"Ошибка подключения: {str(e)}")
            return redirect(url_for('scan'))
        except Exception as e:
            flash(f'Ошибка сканирования: {str(e)}', 'error')
            logging.error(f"Ошибка сканирования: {str(e)}")
            return redirect(url_for('scan'))
      
    logging.debug("Отображение страницы сканирования.")
    return render_template('scan.html')

# Страница отчёта
@app.route('/report/<report_id>')
@login_required
def report(report_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            SELECT report_content FROM scan_reports WHERE id = %s AND user_id = %s
        ''', (report_id, current_user.id))
        report = cur.fetchone()
        conn.close()

        if not report:
            flash('Отчёт не найден или доступ запрещён.', 'error')
            logging.error(f"Отчёт не найден для report_id: {report_id}, user_id: {current_user.id}")
            return redirect(url_for('scan'))
        
        report_content = report[0]
        logging.debug(f"Отображение отчёта: report_id={report_id}, длина контента: {len(report_content)}")
        return render_template('report.html', report_content=report_content, report_id=report_id)
    except Exception as e:
        flash(f'Ошибка загрузки отчёта: {str(e)}', 'error')
        logging.error(f"Ошибка загрузки отчёта: {str(e)}")
        return redirect(url_for('scan'))

# Скачивание отчёта
@app.route('/download/<report_id>')
@login_required
def download_report(report_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            SELECT report_content FROM scan_reports WHERE id = %s AND user_id = %s
        ''', (report_id, current_user.id))
        report = cur.fetchone()
        conn.close()

        if not report:
            flash('Отчёт не найден или доступ запрещён.', 'error')
            logging.error(f"Отчёт не найден для report_id: {report_id}, user_id: {current_user.id}")
            return redirect(url_for('scan'))
        
        report_content = report[0]
        logging.info(f"Скачивание отчёта: {report_id}")
        return app.response_class(
            report_content,
            mimetype='text/html',
            headers={'Content-Disposition': f'attachment;filename=report_{report_id}.html'}
        )
    except Exception as e:
        flash(f'Ошибка загрузки отчёта: {str(e)}', 'error')
        logging.error(f"Ошибка загрузки отчёта: {str(e)}")
        return redirect(url_for('scan'))

# Админ-панель: список пользователей
@app.route('/admin/users')
@admin_required
def admin_users():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT id, email, username, role FROM users')
        users = cur.fetchall()
        conn.close()
        print(f"Количество пользователей: {len(users)}")  # Отладочный вывод
        logging.debug("Отображение админ-панели: список пользователей.")
        return render_template('admin_users.html', users=users)
    except Exception as e:
        flash(f'Ошибка загрузки списка пользователей: {str(e)}', 'error')
        logging.error(f"Ошибка загрузки списка пользователей: {str(e)}")
        return redirect(url_for('index'))

# Личный кабинет пользователя
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            SELECT id, user_id, report_content, created_at FROM scan_reports WHERE user_id = %s
            ORDER BY created_at DESC
        ''', (current_user.id,))
        scans = cur.fetchall()
        conn.close()
        logging.debug(f"Отображение личного кабинета для пользователя {current_user.username}")
        return render_template('dashboard.html', scans=scans, username=current_user.username, email=current_user.email)
    except Exception as e:
        flash(f'Ошибка загрузки личного кабинета: {str(e)}', 'error')
        logging.error(f"Ошибка загрузки личного кабинета: {str(e)}")
        return redirect(url_for('index'))

if __name__ == '__main__':
    os.makedirs(app.config['SCAN_RESULTS_DIR'], exist_ok=True)
    init_db()  # Инициализация базы данных

    app.run(host='0.0.0.0', port=5000, debug=True)
