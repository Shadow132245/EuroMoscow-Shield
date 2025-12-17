import os
import sys
import time
import random
import base64
import zlib
import ast
import io
import re
import string
import logging
import zipfile
import platform
from datetime import datetime
from contextlib import redirect_stdout
from flask import Flask, render_template, request, jsonify, send_file

# --- CONFIGURATION ---
app = Flask(__name__)
# Vercel has strict limits, setting a safe limit (e.g., 10MB) prevents crashes
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s | VERCEL CORE | %(message)s')
logger = logging.getLogger('Hyperion')

# --- IN-MEMORY HISTORY (Replaces SQLite for Vercel) ---
# Vercel kills the server after execution, so we can't save to a file.
# This list will hold logs temporarily while the instance is alive.
HISTORY_LOGS = []

def log_op(lang, method, size, code):
    try:
        entry = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": request.headers.get('X-Forwarded-For', request.remote_addr),
            "lang": lang,
            "method": str(method),
            "size": size,
            "risk_score": 0 # Simplified logic
        }
        # Add to start of list
        HISTORY_LOGS.insert(0, entry)
        # Keep only last 50 logs to save RAM
        if len(HISTORY_LOGS) > 50:
            HISTORY_LOGS.pop()
    except Exception as e:
        logger.error(f"Logging Error: {e}")

# ==============================================================================
# ENGINES (Optimized)
# ==============================================================================
class Engines:
    @staticmethod
    def rand_var(l=8): 
        zw = ['\u200b', '\u200c', '\u200d']
        return "".join(random.choices(zw, k=3)) + '_' + "".join(random.choices('lI1O0', k=l))

    @staticmethod
    def py_process(code, opts):
        res = code
        try:
            if 'tamper' in opts: res = "import sys;sys.settrace(None);\n" + res
            
            if 'rename' in opts:
                try:
                    tree = ast.parse(res)
                    class R(ast.NodeTransformer):
                        def visit_Name(self, n):
                            if isinstance(n.ctx, (ast.Store, ast.Del)) and n.id not in dir(__builtins__):
                                n.id = Engines.rand_var()
                            return n
                    res = ast.unparse(R().visit(tree))
                except: pass

            if 'dead' in opts: res = f"if 500 > {random.randint(1000,9000)}: pass\n{res}"

            if 'chaos' in opts:
                payload = base64.b85encode(zlib.compress(res.encode('utf-8'))).decode('utf-8')
                return f"import zlib,base64;(lambda _,__:exec(zlib.decompress(base64.b85decode(_))))('{payload}',None)"

            if 'marshal' in opts:
                import marshal
                try:
                    c = compile(res, '<string>', 'exec')
                    return f"import marshal;exec(marshal.loads({marshal.dumps(c)}))"
                except: pass
            
            b64 = base64.b64encode(res.encode()).decode()
            return f"# Protected V95\nimport base64;exec(base64.b64decode('{b64}'))"
        except: return code

    @staticmethod
    def js_process(code, opts):
        if 'hex' in opts: return f"eval('{ ''.join([f'\\\\x{ord(c):02x}' for c in code]) }')"
        if 'packer' in opts:
            b64 = base64.b64encode(code.encode()).decode()
            return f"(function(x){{eval(atob(x))}})('{b64}')"
        return f"eval(decodeURIComponent('{re.escape(code)}'))"

    @staticmethod
    def generic(code, lang):
        b64 = base64.b64encode(code.encode()).decode()
        if lang=='php': return f"<?php eval(base64_decode('{b64}')); ?>"
        if lang=='lua': return f"load(Base64Decode('{b64}'))()"
        if lang=='go': return f"package main\nimport(\"encoding/base64\";\"fmt\")\nfunc main(){{d,_:=base64.StdEncoding.DecodeString(\"{b64}\");fmt.Print(string(d))}}"
        return f"// {lang} Encrypted\n// {b64}"

def deep_decrypt(code):
    curr = code
    pats = [
        r"base64\.b64decode\(['\"](.*?)['\"]\)", r"atob\(['\"](.*?)['\"]\)",
        r"base64\.b85decode\(['\"](.*?)['\"]\)", r"base64_decode\('([^']+)'\)"
    ]
    for _ in range(10):
        found = False
        for p in pats:
            m = re.search(p, curr)
            if m:
                try:
                    payload = m.group(1)
                    try: curr = base64.b64decode(payload).decode(errors='ignore')
                    except: curr = base64.b85decode(payload).decode(errors='ignore')
                    found = True
                except: pass
        if not found: break
    return curr

# --- ROUTES ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        c, a, l, o = d.get('code',''), d.get('action'), d.get('lang'), d.get('options',[])
        
        # Log to Memory
        log_op(l, ','.join(o) if o else 'Default', len(c), c)

        if a == 'encrypt':
            if l == 'python': res = Engines.py_process(c, o)
            elif l == 'javascript': res = Engines.js_process(c, o)
            elif l in ['php', 'lua', 'go', 'html']: res = Engines.generic(c, l)
            else: res = f"// Encrypted {l}\n{base64.b64encode(c.encode()).decode()}"
        else:
            res = deep_decrypt(c)
            
        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"# ERROR: {e}"}), 500

@app.route('/run', methods=['POST'])
def run():
    # Simulated Terminal
    c = request.json.get('code','')
    if c == 'whoami': return jsonify({'output': 'vercel-root'})
    if c == 'ls': return jsonify({'output': 'app.py templates/ static/'})
    
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(c, {'__builtins__': __builtins__}, {})
        return jsonify({'output': f.getvalue()})
    except Exception as e: return jsonify({'output': str(e)})

@app.route('/history', methods=['GET'])
def get_logs():
    return jsonify(HISTORY_LOGS)

@app.route('/upload-zip', methods=['POST'])
def upload_zip():
    try:
        f = request.files['file']
        m_out = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(f.read()),'r') as zi, zipfile.ZipFile(m_out,'w',zipfile.ZIP_DEFLATED) as zo:
            for i in zi.infolist():
                d = zi.read(i.filename)
                try:
                    if i.filename.endswith('.py'): 
                        zo.writestr(i.filename, Engines.py_process(d.decode(), ['chaos']))
                    else: zo.writestr(i, d)
                except: zo.writestr(i, d)
        m_out.seek(0)
        return send_file(m_out, mimetype='application/zip', as_attachment=True, download_name='Protected.zip')
    except Exception as e: return str(e), 500

# Vercel entry point
app.debug = False # Important for production
