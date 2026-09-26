# -*- coding: utf-8 -*-
"""WIN FRUIT 本地服务：共享站点文件 + 登录/资料/日志 API"""
import os, json, hashlib, secrets, time, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, 'data', 'users.json')
LOGS_DIR = os.path.join(BASE_DIR, 'data', 'logs')
PORT = 8000

os.makedirs(os.path.join(BASE_DIR, 'data', 'logs'), exist_ok=True)

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def write_log(name, line):
    try:
        with open(os.path.join(LOGS_DIR, name), 'a', encoding='utf-8') as f:
            f.write(time.strftime('[%Y-%m-%d %H:%M:%S] ') + line + '\n')
    except Exception:
        pass

sessions = {}
sessions_lock = threading.Lock()

def make_session(username):
    token = secrets.token_hex(16)
    with sessions_lock:
        sessions[token] = {'user': username, 'exp': time.time() + 86400}
    return token

def get_session_user(token):
    with sessions_lock:
        s = sessions.get(token)
        if not s:
            return None
        if s['exp'] < time.time():
            sessions.pop(token, None)
            return None
        return s['user']

class Handler(BaseHTTPRequestHandler):
    server_version = 'WINFruit/1.0'

    def log_message(self, fmt, *args):
        write_log('access.log', '%s %s' % (self.client_address[0], fmt % args))

    def _send(self, code, body, ctype='application/json; charset=utf-8', extra=None):
        data = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode('utf-8', 'ignore')
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _cookie_token(self):
        cookie = self.headers.get('Cookie', '')
        for part in cookie.split(';'):
            part = part.strip()
            if part.startswith('wf_session='):
                return part[len('wf_session='):]
        return None

    # ---------- 静态文件 ----------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith('/api/'):
            self.handle_api_get(path, parsed.query)
            return
        if path == '/':
            path = '/index.html'
        fp = os.path.normpath(os.path.join(BASE_DIR, path.lstrip('/')))
        if not fp.startswith(BASE_DIR) or not os.path.isfile(fp):
            self._send(404, 'Not Found', 'text/plain; charset=utf-8')
            return
        ctype = {
            '.html': 'text/html; charset=utf-8',
            '.css': 'text/css; charset=utf-8',
            '.js': 'text/javascript; charset=utf-8',
            '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
            '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
            '.exe': 'application/octet-stream', '.mp4': 'video/mp4',
            '.json': 'application/json; charset=utf-8',
        }.get(os.path.splitext(fp)[1].lower(), 'application/octet-stream')
        try:
            with open(fp, 'rb') as f:
                body = f.read()
        except OSError:
            self._send(404, 'Not Found', 'text/plain; charset=utf-8')
            return
        self._send(200, body, ctype)

    def handle_api_get(self, path, query):
        # /api/me
        if path == '/api/me':
            token = self._cookie_token()
            user = get_session_user(token) if token else None
            if not user:
                self._send(401, json.dumps({'ok': False, 'msg': '未登录'}))
                return
            users = load_users()
            u = users.get(user)
            if not u:
                self._send(401, json.dumps({'ok': False, 'msg': '用户不存在'}))
                return
            self._send(200, json.dumps({'ok': True, 'username': user, 'role': u.get('role', 'user'), 'bio': u.get('bio', '')}, ensure_ascii=False))
            return
        # /api/users  (admin only)
        if path == '/api/users':
            token = self._cookie_token()
            user = get_session_user(token) if token else None
            users = load_users()
            u = users.get(user) if user else None
            if not u or u.get('role') != 'admin':
                self._send(403, json.dumps({'ok': False, 'msg': '仅管理员可查看'}))
                return
            out = [{'username': name, 'role': u2.get('role', 'user'), 'bio': u2.get('bio', '')} for name, u2 in users.items()]
            self._send(200, json.dumps({'ok': True, 'users': out}, ensure_ascii=False))
            return
        # /api/logs  (admin only)
        if path == '/api/logs':
            token = self._cookie_token()
            user = get_session_user(token) if token else None
            users = load_users()
            u = users.get(user) if user else None
            if not u or u.get('role') != 'admin':
                self._send(403, json.dumps({'ok': False, 'msg': '仅管理员可查看'}))
                return
            out = {}
            for name in ('access.log', 'login.log'):
                fp = os.path.join(LOGS_DIR, name)
                if os.path.exists(fp):
                    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.read().splitlines()
                    out[name] = lines[-200:]
                else:
                    out[name] = []
            self._send(200, json.dumps({'ok': True, 'logs': out}, ensure_ascii=False))
            return
        self._send(404, json.dumps({'ok': False, 'msg': 'no api'}))

    # ---------- POST API ----------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        data = self._read_json()
        if path == '/api/login':
            self.api_login(data)
            return
        if path == '/api/register':
            self.api_register(data)
            return
        if path == '/api/profile':
            self.api_profile(data)
            return
        if path == '/api/logout':
            token = self._cookie_token()
            if token:
                with sessions_lock:
                    sessions.pop(token, None)
            self._send(200, json.dumps({'ok': True}), extra={'Set-Cookie': 'wf_session=; Path=/; Max-Age=0'})
            return
        self._send(404, json.dumps({'ok': False, 'msg': 'no api'}))

    def api_login(self, data):
        username = (data.get('username') or '').strip()
        passhash = (data.get('passhash') or '').strip()
        if not username or not passhash:
            self._send(400, json.dumps({'ok': False, 'msg': '账号或密码为空'}))
            return
        users = load_users()
        u = users.get(username)
        if not u or u.get('passhash') != passhash:
            write_log('login.log', '登录失败 user=%s ip=%s' % (username, self.client_address[0]))
            self._send(401, json.dumps({'ok': False, 'msg': '账号或密码错误'}))
            return
        token = make_session(username)
        write_log('login.log', '登录成功 user=%s role=%s ip=%s' % (username, u.get('role', 'user'), self.client_address[0]))
        self._send(200, json.dumps({'ok': True, 'username': username, 'role': u.get('role', 'user'), 'bio': u.get('bio', '')}, ensure_ascii=False),
                   extra={'Set-Cookie': 'wf_session=%s; Path=/; Max-Age=86400; SameSite=Lax' % token})

    def api_register(self, data):
        username = (data.get('username') or '').strip()
        passhash = (data.get('passhash') or '').strip()
        if not username or not passhash:
            self._send(400, json.dumps({'ok': False, 'msg': '账号或密码为空'}))
            return
        if len(username) < 2 or len(username) > 20:
            self._send(400, json.dumps({'ok': False, 'msg': '用户名长度 2-20 位'}))
            return
        users = load_users()
        if username in users:
            self._send(400, json.dumps({'ok': False, 'msg': '该用户名已被注册'}))
            return
        users[username] = {'role': 'user', 'passhash': passhash, 'bio': ''}
        save_users(users)
        token = make_session(username)
        write_log('login.log', '注册成功 user=%s ip=%s' % (username, self.client_address[0]))
        self._send(200, json.dumps({'ok': True, 'username': username, 'role': 'user', 'bio': ''}, ensure_ascii=False),
                   extra={'Set-Cookie': 'wf_session=%s; Path=/; Max-Age=86400; SameSite=Lax' % token})

    def api_profile(self, data):
        token = self._cookie_token()
        user = get_session_user(token) if token else None
        if not user:
            self._send(401, json.dumps({'ok': False, 'msg': '未登录'}))
            return
        bio = (data.get('bio') or '').strip()
        if len(bio) > 200:
            self._send(400, json.dumps({'ok': False, 'msg': '简介最长 200 字'}))
            return
        users = load_users()
        if user not in users:
            self._send(401, json.dumps({'ok': False, 'msg': '用户不存在'}))
            return
        users[user]['bio'] = bio
        save_users(users)
        write_log('login.log', '资料修改 user=%s ip=%s' % (user, self.client_address[0]))
        self._send(200, json.dumps({'ok': True, 'msg': '已保存'}))

if __name__ == '__main__':
    # 首次运行：写入管理员账号
    users = load_users()
    if 'admin' not in users:
        users['admin'] = {
            'role': 'admin',
            'passhash': '9f8c9af5f76c0b9dfedd1b2338106a14dd93c17173cffd55a2aaae37eedb721d',
            'bio': '站长'
        }
        save_users(users)
        print('已初始化管理员 admin')
    print('WIN FRUIT 本地服务已启动: http://127.0.0.1:%d' % PORT)
    print('访问站点: http://127.0.0.1:%d/index.html  登录页: http://127.0.0.1:%d/login.html' % (PORT, PORT))
    ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
