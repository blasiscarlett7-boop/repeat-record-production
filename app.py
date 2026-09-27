import os
import csv
import io
import re
import secrets
from datetime import datetime, timezone
from functools import wraps
from zoneinfo import ZoneInfo

from flask import Flask, jsonify, render_template, request, session, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

ET = ZoneInfo('America/New_York')

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='staff')
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_number = db.Column(db.String(160), nullable=False)
    normalized_number = db.Column(db.String(80), unique=True, nullable=False, index=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_by_name = db.Column(db.String(120), nullable=False)
    channel = db.Column(db.String(120), nullable=False, default='')  # legacy compatibility; no longer used
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    status = db.Column(db.String(20), nullable=False, default='正常')
    duplicate_count = db.Column(db.Integer, nullable=False, default=0)

class DuplicateEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    record_id = db.Column(db.Integer, db.ForeignKey('record.id'), nullable=False, index=True)
    attempted_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attempted_by_name = db.Column(db.String(120), nullable=False)
    attempted_number = db.Column(db.String(160), nullable=False)
    channel = db.Column(db.String(120), nullable=False, default='')  # legacy compatibility; no longer used
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///repeat_records.db').replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('COOKIE_SECURE', '0') == '1'
    app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 12
    db.init_app(app)

    with app.app_context():
        db.create_all()
        bootstrap_admin()

    @app.after_request
    def security_headers(resp):
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['Referrer-Policy'] = 'same-origin'
        resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return resp

    @app.get('/')
    def index():
        return render_template('index.html')

    @app.post('/api/login')
    def login():
        data = request.get_json(silent=True) or {}
        username = str(data.get('username', '')).strip()
        password = str(data.get('password', ''))
        user = User.query.filter_by(username=username, is_active=True).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify(error='账号或密码错误'), 401
        session.clear()
        session['user_id'] = user.id
        session['csrf_token'] = secrets.token_urlsafe(32)
        session.permanent = True
        return jsonify(user=serialize_user(user), csrf_token=session['csrf_token'])

    @app.before_request
    def csrf_guard():
        if request.method in {'POST', 'PATCH', 'DELETE'} and request.path != '/api/login':
            token = request.headers.get('X-CSRF-Token', '')
            if not token or token != session.get('csrf_token'):
                return jsonify(error='请求验证失败，请刷新页面后重试'), 403

    @app.get('/api/health')
    def health():
        return jsonify(ok=True)

    @app.post('/api/logout')
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get('/api/me')
    @login_required
    def me():
        return jsonify(user=serialize_user(current_user()), csrf_token=session.get('csrf_token'))

    @app.get('/api/stats')
    @login_required
    def stats():
        now_et = datetime.now(ET)
        start_et = now_et.replace(hour=0, minute=0, second=0, microsecond=0)
        start_utc = start_et.astimezone(timezone.utc)
        total = Record.query.count()
        today = Record.query.filter(Record.created_at >= start_utc).count()
        normal = Record.query.filter_by(status='正常').count()
        repeats = db.session.query(func.coalesce(func.sum(Record.duplicate_count), 0)).scalar() or 0
        return jsonify(total=total, today=today, normal=normal, repeats=int(repeats))

    @app.post('/api/search')
    @login_required
    def search():
        data = request.get_json(silent=True) or {}
        q = data.get('q', '')
        normalized = normalize_number(q)
        if not normalized:
            return jsonify(error='请输入号码'), 400
        record = Record.query.filter_by(normalized_number=normalized).first()
        if not record:
            return jsonify(found=False, normalized=normalized)
        return jsonify(found=True, record=serialize_record(record, limited=True))

    @app.post('/api/records/batch')
    @login_required
    def add_batch():
        data = request.get_json(silent=True) or {}
        raw_numbers = data.get('numbers', [])
        if isinstance(raw_numbers, str):
            raw_numbers = split_numbers(raw_numbers)
        if not isinstance(raw_numbers, list) or not raw_numbers:
            return jsonify(error='请输入至少一个号码'), 400
        if len(raw_numbers) > 10000:
            return jsonify(error='单次最多提交 10,000 个号码'), 400

        user = current_user()
        results = []
        for raw in raw_numbers:
            raw = str(raw).strip()
            normalized = normalize_number(raw)
            if not normalized:
                results.append({'number': raw, 'result': 'invalid', 'message': '号码无有效数字'})
                continue

            existing = Record.query.filter_by(normalized_number=normalized).first()
            if existing:
                existing.duplicate_count += 1
                evt = DuplicateEvent(
                    record_id=existing.id,
                    attempted_by_user_id=user.id,
                    attempted_by_name=user.display_name,
                    attempted_number=raw,
                )
                db.session.add(evt)
                results.append({
                    'number': raw,
                    'normalized': normalized,
                    'result': 'duplicate',
                    'owner': existing.created_by_name,
                    'duplicate_count': existing.duplicate_count,
                    'original_created_at': format_et(existing.created_at),
                })
                continue

            rec = Record(
                customer_number=raw,
                normalized_number=normalized,
                created_by_user_id=user.id,
                created_by_name=user.display_name,
                status='正常',
            )
            db.session.add(rec)
            try:
                db.session.flush()
                results.append({'number': raw, 'normalized': normalized, 'result': 'added'})
            except Exception:
                db.session.rollback()
                existing = Record.query.filter_by(normalized_number=normalized).first()
                if existing:
                    existing.duplicate_count += 1
                    db.session.add(DuplicateEvent(
                        record_id=existing.id,
                        attempted_by_user_id=user.id,
                        attempted_by_name=user.display_name,
                        attempted_number=raw,
                    ))
                    results.append({
                        'number': raw,
                        'normalized': normalized,
                        'result': 'duplicate',
                        'owner': existing.created_by_name,
                        'duplicate_count': existing.duplicate_count,
                        'original_created_at': format_et(existing.created_at),
                    })
                else:
                    raise
        db.session.commit()
        return jsonify(results=results)

    @app.post('/api/records/search')
    @admin_required
    def list_records():
        data = request.get_json(silent=True) or {}
        q = str(data.get('q', '')).strip()
        status = str(data.get('status', '')).strip()
        query = Record.query
        if q:
            nq = normalize_number(q)
            pattern = f'%{q}%'
            if nq:
                query = query.filter(db.or_(Record.normalized_number.contains(nq), Record.created_by_name.ilike(pattern)))
            else:
                query = query.filter(Record.created_by_name.ilike(pattern))
        if status:
            query = query.filter_by(status=status)
        rows = query.order_by(Record.id.desc()).limit(5000).all()
        return jsonify(records=[serialize_record(r) for r in rows])

    @app.patch('/api/records/<int:record_id>')
    @admin_required
    def update_record(record_id):
        rec = db.session.get(Record, record_id)
        if not rec:
            return jsonify(error='记录不存在'), 404
        data = request.get_json(silent=True) or {}
        if 'status' in data:
            status = str(data['status'])
            if status not in {'正常', '重粉', '停用'}:
                return jsonify(error='无效状态'), 400
            rec.status = status
        db.session.commit()
        return jsonify(record=serialize_record(rec))

    @app.delete('/api/records/<int:record_id>')
    @admin_required
    def delete_record(record_id):
        rec = db.session.get(Record, record_id)
        if not rec:
            return jsonify(error='记录不存在'), 404
        DuplicateEvent.query.filter_by(record_id=record_id).delete()
        db.session.delete(rec)
        db.session.commit()
        return jsonify(ok=True)

    @app.get('/api/records/export.csv')
    @admin_required
    def export_records():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['客户号码', '录入人', '录入时间(ET)', '状态', '重粉次数'])
        for r in Record.query.order_by(Record.id.asc()).all():
            writer.writerow([r.customer_number, r.created_by_name, format_et(r.created_at), r.status, r.duplicate_count])
        csv_bytes = '\ufeff' + output.getvalue()
        return Response(csv_bytes, mimetype='text/csv; charset=utf-8', headers={'Content-Disposition':'attachment; filename=repeat-records.csv'})

    @app.get('/api/users')
    @admin_required
    def users_list():
        return jsonify(users=[serialize_user(u) for u in User.query.order_by(User.id.asc()).all()])

    @app.post('/api/users')
    @admin_required
    def create_user_api():
        data = request.get_json(silent=True) or {}
        username = str(data.get('username', '')).strip()
        password = str(data.get('password', ''))
        display_name = str(data.get('display_name', '')).strip()
        role = str(data.get('role', 'staff')).strip()
        if not re.fullmatch(r'[A-Za-z0-9_.-]{3,40}', username):
            return jsonify(error='账号需为 3-40 位字母、数字、点、下划线或横线'), 400
        if len(password) < 8:
            return jsonify(error='密码至少 8 位'), 400
        if not display_name:
            return jsonify(error='请输入显示名称'), 400
        if role not in {'staff', 'admin'}:
            return jsonify(error='角色无效'), 400
        if User.query.filter_by(username=username).first():
            return jsonify(error='账号已存在'), 409
        u = User(username=username, password_hash=generate_password_hash(password), display_name=display_name, role=role)
        db.session.add(u)
        db.session.commit()
        return jsonify(user=serialize_user(u)), 201

    @app.delete('/api/users/<int:user_id>')
    @admin_required
    def delete_user_api(user_id):
        me = current_user()
        u = db.session.get(User, user_id)
        if not u:
            return jsonify(error='账号不存在'), 404
        if u.id == me.id:
            return jsonify(error='不能删除当前登录账号'), 400
        if u.role == 'admin' and User.query.filter_by(role='admin', is_active=True).count() <= 1:
            return jsonify(error='至少需要保留一个管理员'), 400
        u.is_active = False
        db.session.commit()
        return jsonify(ok=True)

    return app


def bootstrap_admin():
    if User.query.count() > 0:
        return
    username = os.getenv('ADMIN_USERNAME', 'admin')
    password = os.getenv('ADMIN_PASSWORD', 'ChangeMe123!')
    display_name = os.getenv('ADMIN_DISPLAY_NAME', '管理员')
    db.session.add(User(username=username, password_hash=generate_password_hash(password), display_name=display_name, role='admin'))
    db.session.commit()


def normalize_number(value):
    raw = str(value or '').strip()
    if not raw:
        return ''
    digits = re.sub(r'\D', '', raw)
    if digits.startswith('00'):
        digits = digits[2:]
    return digits


def split_numbers(text):
    # Keep each line/commas/semicolons as record separators; spaces remain legal inside numbers.
    chunks = re.split(r'[\n,;，；]+', str(text or ''))
    return [c.strip() for c in chunks if c.strip()]


def format_et(dt):
    if not dt:
        return ''
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(ET).strftime('%Y-%m-%d %H:%M:%S %Z')


def serialize_user(u):
    return {'id': u.id, 'username': u.username, 'display_name': u.display_name, 'role': u.role, 'is_active': u.is_active}


def serialize_record(r, limited=False):
    data = {
        'id': r.id,
        'customer_number': r.customer_number,
        'created_by': r.created_by_name,
        'created_at': format_et(r.created_at),
        'status': r.status,
        'duplicate_count': r.duplicate_count,
    }
    return data


def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return db.session.get(User, uid)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_active:
            session.clear()
            return jsonify(error='请先登录'), 401
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_active:
            session.clear()
            return jsonify(error='请先登录'), 401
        if u.role != 'admin':
            return jsonify(error='无权限'), 403
        return fn(*args, **kwargs)
    return wrapper

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '8000')), debug=False)
