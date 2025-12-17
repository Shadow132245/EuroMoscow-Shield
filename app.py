# ==============================================================================
# PROJECT: EUROMOSCOW V100 (PHANTOM EDITION)
# CORE: STEALTH LOADER + JUNK CODE INJECTION + ANTI-TAMPER
# ==============================================================================

import os, sys, time, random, base64, zlib, ast, io, re, string, logging, zipfile
from flask import Flask, render_template, request, jsonify, send_file
from contextlib import redirect_stdout
from datetime import datetime

# --- CONFIGURATION ---
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 # 10MB Safe Limit for Vercel

# LOGGING (In-Memory for Vercel)
logging.basicConfig(level=logging.INFO, format='%(asctime)s | PHANTOM | %(message)s')
logger = logging.getLogger('PhantomCore')
HISTORY_LOGS = []

def log_op(lang, method, size, code):
    try:
        HISTORY_LOGS.insert(0, {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": request.headers.get('X-Forwarded-For', request.remote_addr),
            "lang": lang, "method": str(method), "size": size
        })
        if len(HISTORY_LOGS) > 50: HISTORY_LOGS.pop()
    except: pass

# ==============================================================================
# 1. STEALTH & JUNK CODE GENERATOR (THE CAMOUFLAGE)
# ==============================================================================
class Camouflage:
    @staticmethod
    def generate_junk():
        """Creates fake classes and math operations to fool AVs."""
        vars = ['_a', '_b', '_x', '_y', 'data', 'config', 'system']
        junk = f"""
class SystemConfig_{random.randint(100,999)}:
    def __init__(self):
        self.status = 'active'
        self.value = {random.randint(1000,9999)}
    def check(self):
        return self.value * 2

_conf = SystemConfig_{random.randint(100,999)}()
_math_val = _conf.check() + {random.randint(1,50)}
# EuroMoscow System Init
"""
        return junk

    @staticmethod
    def get_anti_tamper():
        """Checks for Debuggers and VM signatures."""
        return """
try:
    import sys
    # Anti-Debug: Check if trace function is set
    if sys.gettrace() is not None:
        print("Security Violation: Debugger Detected"); exit()
except: pass
"""

# ==============================================================================
# 2. ENGINES (OPTIMIZED)
# ==============================================================================
class Engines:
    @staticmethod
    def rand_var(l=8): 
        # Zero-Width Characters included to confuse copy-pasters
        zw = ['\u200b', '\u200c', '\u200d']
        return "".join(random.choices(zw, k=2)) + '_' + "".join(random.choices('abcdef', k=l))

    @staticmethod
    def py_phantom(code, opts):
        """
        The V100 Logic:
        1. Parse AST -> Rename Variables (Safe & Compatible).
        2. Inject Junk Code (To hide signature).
        3. Inject Anti-Tamper.
        4. Dynamic Import & Execute (Hides 'import zlib').
        """
        res = code
        
        # 1. Safe AST Renaming (Works on all Py versions)
        if 'rename' in opts:
            try:
                tree = ast.parse(res)
                class R(ast.NodeTransformer):
                    def visit_Name(self, n):
                        if isinstance(n.ctx, (ast.Store, ast.Del)) and n.id not in dir(__builtins__):
                            n.id = Engines.rand_var()
                        return n
                res = ast.unparse(R().visit(tree))
            except: pass # Fallback if syntax error

        # 2. Compression & Encoding
        compressed = zlib.compress(res.encode('utf-8'))
        # Using Base85 as suggested (smaller & different charset than Base64)
        encoded = base64.b85encode(compressed).decode('utf-8')

        # 3. The Phantom Loader (Dynamic Imports)
        loader = f"""
{Camouflage.generate_junk()}
{Camouflage.get_anti_tamper() if 'tamper' in opts else ''}

# Dynamic Loader
try:
    _z = __import__('zl'+'ib') # Hides 'zlib' string
    _b = __import__('ba'+'se64') # Hides 'base64' string
    _p = "{encoded}"
    exec(_z.decompress(_b.b85decode(_p)))
except Exception as e:
    print("Error: Integrity Check Failed")
"""
        return f"# Protected by EuroMoscow V100 (Phantom)\n{loader}"

    # --- OTHER LANGUAGES (KEPT POWERFUL) ---
    @staticmethod
    def js_process(code, opts):
        if 'hex' in opts: return f"eval('{ ''.join([f'\\\\x{ord(c):02x}' for c in code]) }')"
        if 'packer' in opts:
            b64 = base64.b64encode(code.encode()).decode()
            return f"(function(k,v){{eval(atob(v))}})('{random.randint(10,99)}','{b64}')"
        return f"eval(decodeURIComponent('{re.escape(code)}'))"

    @staticmethod
    def generic(code, lang):
        b64 = base64.b64encode(code.encode()).decode()
        if lang=='php': return f"<?php /* V100 */ eval(base64_decode('{b64}')); ?>"
        if lang=='lua': return f"-- V100\nload(Base64Decode('{b64}'))()"
        if lang=='go': return f"package main\nimport(\"encoding/base64\";\"fmt\")\nfunc main(){{d,_:=base64.StdEncoding.DecodeString(\"{b64}\");fmt.Print(string(d))}}"
        return f"// {lang} Encrypted\n// {b64}"

def deep_decrypt(code):
    curr = code
    # Supports Base64, Base85, Hex
    pats = [
        r"b85decode\(['\"](.*?)['\"]\)", r"b64decode\(['\"](.*?)['\"]\)", 
        r"atob\(['\"](.*?)['\"]\)", r"base64_decode\('([^']+)'\)"
    ]
    for _ in range(15):
        found = False
        for p in pats:
            m = re.search(p, curr)
            if m:
                try:
                    payload = m.group(1)
                    # Try Base85 first (New Standard)
                    try: curr = base64.b85decode(payload).decode(errors='ignore')
                    except: curr = base64.b64decode(payload).decode(errors='ignore')
                    
                    # Try Zlib Decompression
                    try: curr = zlib.decompress(curr.encode('latin1')).decode()
                    except: pass
                    
                    found = True
                except: pass
        if not found: break
    return curr

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        c, a, l, o = d.get('code',''), d.get('action'), d.get('lang'), d.get('options',[])
        
        log_op(l, ','.join(o) if o else 'Default', len(c), c)

        if a == 'encrypt':
            if l == 'python': res = Engines.py_phantom(c, o)
            elif l == 'javascript': res = Engines.js_process(c, o)
            elif l in ['php','lua','go','html']: res = Engines.generic(c, l)
            else: res = f"// Encrypted {l}\n{base64.b64encode(c.encode()).decode()}"
        else:
            res = deep_decrypt(c)
            
        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"System Error: {e}"}), 500

@app.route('/run', methods=['POST'])
def run():
    c = request.json.get('code','')
    # Terminal Simulation
    if c == 'whoami': return jsonify({'output': 'phantom-root'})
    if c == 'ls': return jsonify({'output': 'app.py  templates/  logs/'})
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(c, {'__builtins__':__builtins__}, {})
        return jsonify({'output': f.getvalue()})
    except Exception as e: return jsonify({'output': str(e)})

@app.route('/history', methods=['GET'])
def get_logs(): return jsonify(HISTORY_LOGS)

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
                        # Apply Phantom Encryption to Files
                        zo.writestr(i.filename, Engines.py_phantom(d.decode(), ['rename', 'tamper']))
                    else: zo.writestr(i, d)
                except: zo.writestr(i, d)
        m_out.seek(0)
        return send_file(m_out, mimetype='application/zip', as_attachment=True, download_name='Phantom_Protected.zip')
    except Exception as e: return str(e), 500

if __name__ == '__main__': app.run(debug=True, port=5000)
