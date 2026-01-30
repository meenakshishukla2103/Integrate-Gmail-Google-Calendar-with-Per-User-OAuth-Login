from flask import Flask, redirect, request, jsonify, session, send_from_directory
from flask_session import Session
import os, sqlite3, requests, secrets, urllib.parse, threading, time
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder='public', static_url_path='')
app.config.update({
    'SECRET_KEY': os.getenv('SESSION_SECRET', 'your-secret-key-change-this'),
    'SESSION_TYPE': 'filesystem', 'SESSION_PERMANENT': False,
    'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False,
    'SESSION_COOKIE_SAMESITE': 'Lax'
})
Session(app)

CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:3000/auth/google/callback')
DB_FILE = os.getenv('DB_FILE', 'database.db')
CLEANUP_INTERVAL_HOURS = int(os.getenv('CLEANUP_INTERVAL_HOURS', '1'))
CREDENTIALS_STALE_DAYS = int(os.getenv('CREDENTIALS_STALE_DAYS', '30'))

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, internal_user_id VARCHAR(255) UNIQUE NOT NULL, email VARCHAR(255), name VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS google_credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, access_token TEXT NOT NULL, refresh_token TEXT, token_expiry TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id VARCHAR(255) UNIQUE NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP NOT NULL);
        """)
        conn.commit()
        print("Database initialized")
    finally:
        conn.close()

init_db()

# remove expired sessions and old credentials so the DB doesn't grow forever.
def cleanup_expired_sessions():
    conn = get_db()
    try:
        cur = conn.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now(),))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()

def cleanup_old_credentials():  # (1) Expired tokens with no refresh. (2) Creds for users with no session for many days.
    conn = get_db()
    try:
        now = datetime.now()
        cur = conn.execute("""
            DELETE FROM google_credentials
            WHERE token_expiry < ? AND (refresh_token IS NULL OR refresh_token = '')
        """, (now,))
        n1 = cur.rowcount
        stale = now - timedelta(days=CREDENTIALS_STALE_DAYS)
        cur = conn.execute("""
            DELETE FROM google_credentials
            WHERE user_id NOT IN (SELECT user_id FROM sessions WHERE expires_at > ?)
            AND updated_at < ?
        """, (now, stale))
        n2 = cur.rowcount
        conn.commit()
        return n1 + n2
    finally:
        conn.close()

def run_cleanup():
    try:
        s = cleanup_expired_sessions()
        c = cleanup_old_credentials()
        if s or c:
            print(f"Cleanup: removed {s} expired session(s), {c} old credential(s)")
    except Exception as e:
        print("Cleanup error:", e)

def _cleanup_loop():
    time.sleep(60)
    while True:
        run_cleanup()
        time.sleep(CLEANUP_INTERVAL_HOURS * 3600)

_cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True)
_cleanup_thread.start()

def is_session_valid():
    if 'session_id' not in session:
        return False
    conn = get_db()
    try:
        row = conn.execute("SELECT expires_at FROM sessions WHERE session_id = ?", (session['session_id'],)).fetchone()
        if not row:
            return False
        exp = row['expires_at']
        if isinstance(exp, str):
            exp = datetime.fromisoformat(exp)
        return datetime.now() < exp
    finally:
        conn.close()

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return (jsonify({'error': 'Authentication required'}), 401) if request.path.startswith('/api/') else redirect('/')
        if not is_session_valid():
            session.clear()
            return (jsonify({'error': 'Session expired'}), 401) if request.path.startswith('/api/') else redirect('/?error=session_expired')
        return f(*args, **kwargs)
    return wrap

def get_creds(user_id):
    conn = get_db()
    try:
        row = conn.execute("SELECT access_token, refresh_token, token_expiry FROM google_credentials WHERE user_id = ?", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def refresh_token(refresh_tok):
    r = requests.post('https://oauth2.googleapis.com/token', data={'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'refresh_token': refresh_tok, 'grant_type': 'refresh_token'})
    return r.json() if r.status_code == 200 else None

def save_new_token(user_id, access_tok, expires_in):
    conn = get_db()
    try:
        conn.execute("UPDATE google_credentials SET access_token = ?, token_expiry = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", (access_tok, datetime.now() + timedelta(seconds=expires_in), user_id))
        conn.commit()
    finally:
        conn.close()

def revoke_at_google(token):
    requests.post('https://oauth2.googleapis.com/revoke', params={'token': token})

def get_valid_token(user_id):  # Return a valid token; if expired, refresh it first.
    creds = get_creds(user_id)
    if not creds:
        return None
    expiry = creds['token_expiry']
    if expiry:
        exp = datetime.fromisoformat(expiry) if isinstance(expiry, str) else expiry
        if datetime.now() >= exp:
            if creds.get('refresh_token'):
                new = refresh_token(creds['refresh_token'])
                if new and 'access_token' in new:
                    save_new_token(user_id, new['access_token'], new.get('expires_in', 3600))
                    return new['access_token']
            return None
    return creds['access_token']

def new_session_id():
    return f"user_{int(datetime.now().timestamp())}_{secrets.token_urlsafe(9)}"

def exchange_code_for_tokens(code):
    r = requests.post('https://oauth2.googleapis.com/token', data={'code': code, 'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'redirect_uri': REDIRECT_URI, 'grant_type': 'authorization_code'})
    return r.json() if r.status_code == 200 else None

def fetch_user_info(access_tok):
    r = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers={'Authorization': f'Bearer {access_tok}'})
    return r.json() if r.status_code == 200 else None

# API routes using this get a valid token; if refresh fails we revoke at Google, delete creds, and return 401.
def require_token(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        tok = get_valid_token(session['user_id'])
        if not tok:
            uid = session.get('user_id')
            if uid:
                c = get_creds(uid)
                if c:
                    if c.get('access_token'):
                        revoke_at_google(c['access_token'])
                    if c.get('refresh_token'):
                        revoke_at_google(c['refresh_token'])
                conn = get_db()
                try:
                    conn.execute("DELETE FROM google_credentials WHERE user_id = ?", (uid,))
                    conn.commit()
                finally:
                    conn.close()
            session.clear()
            return jsonify({'error': 'Your Google credentials have expired. Please sign in again.', 'requires_reauth': True}), 401
        return f(tok, *args, **kwargs)
    return wrap

def logout_user(user_id=None, revoke_google_token=False):  
    # Clear session; optionally revoke at Google and delete stored creds.
    if not user_id and 'user_id' in session:
        user_id = session['user_id']
    if revoke_google_token and user_id:
        c = get_creds(user_id)
        if c:
            if c.get('access_token'):
                revoke_at_google(c['access_token'])
            if c.get('refresh_token'):
                revoke_at_google(c['refresh_token'])
            conn = get_db()
            try:
                conn.execute("DELETE FROM google_credentials WHERE user_id = ?", (user_id,))
                conn.commit()
            finally:
                conn.close()
    if 'session_id' in session:
        conn = get_db()
        try:
            conn.execute("DELETE FROM sessions WHERE session_id = ?", (session['session_id'],))
            conn.commit()
        finally:
            conn.close()
    session.clear()

def google_api(method, url, tok, **kwargs):
    headers = kwargs.get('headers', {})
    headers['Authorization'] = f'Bearer {tok}'
    if method in ('POST', 'PUT'):
        headers['Content-Type'] = 'application/json'
    kwargs['headers'] = headers
    if method == 'GET':
        r = requests.get(url, **kwargs)
    elif method == 'POST':
        r = requests.post(url, **kwargs)
    elif method == 'PUT':
        r = requests.put(url, **kwargs)
    else:
        r = requests.delete(url, **kwargs)
    if r.status_code == 204:
        return jsonify({'success': True})
    if r.status_code in (200, 201):
        return jsonify(r.json()), 201 if r.status_code == 201 else 200
    return jsonify({'error': 'Request failed', 'details': r.text}), r.status_code

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/auth/google')
def auth_google():
    if 'user_id' not in session:
        session['user_id'] = new_session_id()
    # state = session id so Google sends it back and we know which browser session this is.
    scopes = [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/calendar.events',
        'https://www.googleapis.com/auth/tasks',
    ]
    params = {'client_id': CLIENT_ID, 'redirect_uri': REDIRECT_URI, 'response_type': 'code', 'scope': ' '.join(scopes), 'access_type': 'offline', 'prompt': 'consent', 'state': session['user_id']}
    return redirect('https://accounts.google.com/o/oauth2/v2/auth?' + urllib.parse.urlencode(params))

@app.route('/auth/google/callback')  # Get tokens and user from Google, create or find user, save creds and session.
def auth_google_callback():
    code = request.args.get('code')
    if not code:
        return redirect('/?error=authentication_failed')
    tokens = exchange_code_for_tokens(code)
    if not tokens or 'access_token' not in tokens:
        return redirect('/?error=authentication_failed')
    user_info = fetch_user_info(tokens['access_token'])
    if not user_info or 'email' not in user_info:
        return redirect('/?error=authentication_failed')
    email, name = user_info['email'], user_info.get('name', '')
    conn = get_db()
    try:
        cur = conn.cursor()
        row = cur.execute("SELECT id, internal_user_id FROM users WHERE email = ?", (email,)).fetchone()
        if row:
            user_id, internal_id = row[0], row[1]
            cur.execute("UPDATE users SET name = ? WHERE id = ?", (name, user_id))
        else:
            internal_id = new_session_id()
            cur.execute("INSERT INTO users (internal_user_id, email, name) VALUES (?, ?, ?)", (internal_id, email, name))
            user_id = cur.lastrowid
        token_expiry = datetime.now() + timedelta(seconds=tokens.get('expires_in', 3600))
        existing = cur.execute("SELECT id FROM google_credentials WHERE user_id = ?", (user_id,)).fetchone()
        if existing:
            cur.execute("UPDATE google_credentials SET access_token = ?, refresh_token = ?, token_expiry = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", (tokens['access_token'], tokens.get('refresh_token'), token_expiry, user_id))
        else:
            cur.execute("INSERT INTO google_credentials (user_id, access_token, refresh_token, token_expiry) VALUES (?, ?, ?, ?)", (user_id, tokens['access_token'], tokens.get('refresh_token'), token_expiry))
        session.update({'user_id': user_id, 'internal_user_id': internal_id, 'email': email, 'name': name})
        sid = session.get('session_id', secrets.token_urlsafe(32))
        session['session_id'] = sid
        cur.execute("INSERT OR REPLACE INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)", (sid, user_id, datetime.now() + timedelta(hours=24)))
        conn.commit()
    finally:
        conn.close()
    return redirect('/dashboard')

@app.route('/dashboard')
@login_required
def dashboard():
    if not get_valid_token(session['user_id']):
        logout_user(revoke_google_token=True)
        return redirect('/?error=token_expired')
    return send_from_directory('public', 'dashboard.html')

@app.route('/api/user')
@login_required
def api_user():
    conn = get_db()
    try:
        row = conn.execute("SELECT u.id, u.internal_user_id, u.email, u.name, gc.token_expiry, gc.updated_at as credentials_updated FROM users u LEFT JOIN google_credentials gc ON u.id = gc.user_id WHERE u.id = ?", (session['user_id'],)).fetchone()
        if not row:
            return jsonify({'error': 'User not found'}), 404
        out = dict(row)
        for k in ('token_expiry', 'credentials_updated'):
            if out.get(k):
                out[k] = str(out[k])
        return jsonify(out)
    finally:
        conn.close()

@app.route('/api/google/calendar/events', methods=['GET'])
@login_required
@require_token
def list_calendar_events(tok):
    params = {k: request.args.get(k) for k in ('maxResults', 'timeMin', 'timeMax') if request.args.get(k)}
    return google_api('GET', 'https://www.googleapis.com/calendar/v3/calendars/primary/events', tok, params=params)

@app.route('/api/google/calendar/events', methods=['POST'])
@login_required
@require_token
def create_calendar_event(tok):
    event = request.json
    if not event or 'summary' not in event:
        return jsonify({'error': 'Event summary is required'}), 400
    return google_api('POST', 'https://www.googleapis.com/calendar/v3/calendars/primary/events', tok, json=event)

@app.route('/api/google/calendar/events/<event_id>', methods=['PUT'])
@login_required
@require_token
def update_calendar_event(tok, event_id):
    return google_api('PUT', f'https://www.googleapis.com/calendar/v3/calendars/primary/events/{event_id}', tok, json=request.json)

@app.route('/api/google/calendar/events/<event_id>', methods=['DELETE'])
@login_required
@require_token
def delete_calendar_event(tok, event_id):
    return google_api('DELETE', f'https://www.googleapis.com/calendar/v3/calendars/primary/events/{event_id}', tok)

@app.route('/api/google/reminders', methods=['GET'])
@login_required
@require_token
def list_reminders(tok):
    return google_api('GET', 'https://www.googleapis.com/tasks/v1/lists/@default/tasks', tok)

@app.route('/api/google/reminders', methods=['POST'])
@login_required
@require_token
def create_reminder(tok):
    task = request.json
    if not task or 'title' not in task:
        return jsonify({'error': 'Task title is required'}), 400
    return google_api('POST', 'https://www.googleapis.com/tasks/v1/lists/@default/tasks', tok, json=task)

@app.route('/api/google/reminders/<task_id>', methods=['PUT'])
@login_required
@require_token
def update_reminder(tok, task_id):
    return google_api('PUT', f'https://www.googleapis.com/tasks/v1/lists/@default/tasks/{task_id}', tok, json=request.json)

@app.route('/api/logout', methods=['POST'])
def api_logout():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    logout_user(revoke_google_token=request.json.get('revoke_google_token', False) if request.json else False)
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/logout/force', methods=['POST'])
def api_logout_force():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    logout_user(revoke_google_token=True)
    return jsonify({'success': True, 'message': 'Forced logout completed'})

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    if not CLIENT_ID or not CLIENT_SECRET:
        print("Error: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env")
        exit(1)
    port = int(os.getenv('PORT', 3000))
    print("Server on http://localhost:" + str(port))
    app.run(host='0.0.0.0', port=port, debug=True)
