# ==============================================================================
# PROJECT: EUROMOSCOW V95 (HYPERION INFINITE CORE)
# ARCHITECT: HASSAN
# SYSTEM: MULTI-LAYER OBFUSCATION + SYMBOLIC ENGINES + UNLIMITED DB
# ==============================================================================

import os, sys, time, random, base64, zlib, ast, io, re, sqlite3, string, logging, zipfile, platform, binascii
from flask import Flask, render_template, request, jsonify, send_file, g
from contextlib import redirect_stdout

# --- CONFIGURATION ---
class Config:
    BRAND = f"# PROTECTED BY EUROMOSCOW V95 :: INFINITE CORE\n"
    MAX_CONTENT_LENGTH = None  # ♾️ UNLIMITED SIZE
    DB_NAME = "hyperion_v95.db"

app = Flask(__name__)
app.config.from_object(Config)

logging.basicConfig(level=logging.INFO, format='%(asctime)s | V95 CORE | %(message)s')
logger = logging.getLogger('Hyperion')

# ==============================================================================
# 1. ADVANCED DATABASE (HISTORY & ANALYTICS)
# ==============================================================================
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(Config.DB_NAME)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT, ip TEXT, lang TEXT, method TEXT, size INTEGER, risk_score INTEGER
        )''')
        db.commit()

@app.teardown_appcontext
def close_db(e):
    db = getattr(g, '_database', None)
    if db is not None: db.close()

def log_op(lang, method, size, code):
    try:
        # Calculate Mock Risk Score based on keywords
        risk = 0
        if 'import' in code: risk += 10
        if 'os.' in code or 'eval' in code: risk += 50
        if 'subprocess' in code: risk += 30
        
        db = get_db()
        db.execute('INSERT INTO logs (date, ip, lang, method, size, risk_score) VALUES (?, ?, ?, ?, ?, ?)',
                   (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr, lang, str(method), size, risk))
        db.commit()
    except: pass

# ==============================================================================
# 2. INFINITE ENGINES (NEW METHODS)
# ==============================================================================

class Engines:
    
    # --- UTILS ---
    @staticmethod
    def rand_var(l=8): 
        # Zero-width + Confusing characters
        zw = ['\u200b', '\u200c', '\u200d']
        return "".join(random.choices(zw, k=3)) + '_' + "".join(random.choices('lI1O0', k=l))

    # --- PYTHON ENGINES ---
    @staticmethod
    def py_emoji(code):
        # Encodes code to bytes, then maps to emoji string (Simulation)
        # This wraps the code in an exec that decodes base64
        b64 = base64.b64encode(code.encode()).decode()
        return f"# 🐍 EMOJI MODE\nimport base64;exec(base64.b64decode('{b64}'))"

    @staticmethod
    def py_chaos(code):
        # Recursive Lambda + Zlib + B85
        payload = base64.b85encode(zlib.compress(code.encode('utf-8'))).decode('utf-8')
        return f"import zlib,base64;(lambda _,__:exec(zlib.decompress(base64.b85decode(_))))('{payload}',None)"

    @staticmethod
    def py_marsh(code):
        # Classic Marshal
        try:
            c = compile(code, '<string>', 'exec')
            import marshal
            data = marshal.dumps(c)
            return f"import marshal;exec(marshal.loads({data}))"
        except: return Engines.py_chaos(code)

    @staticmethod
    def py_process(code, opts):
        res = code
        # 1. Anti-Tamper
        if 'tamper' in opts: res = "import sys;sys.settrace(None);\n" + res
        
        # 2. Renaming
        if 'rename' in opts:
            try:
                tree = ast.parse(res)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                        if node.id not in dir(__builtins__): node.id = Engines.rand_var()
                res = ast.unparse(tree)
            except: pass

        # 3. Dead Code
        if 'dead' in opts: res = f"if 500 > {random.randint(1000,9000)}: pass\n{res}"

        # 4. Final Encoding (Selector)
        if 'chaos' in opts: return Engines.py_chaos(res)
        if 'marshal' in opts: return Engines.py_marsh(res)
        
        # Default Base64
        return f"{Config.BRAND}import base64;exec(base64.b64decode('{base64.b64encode(res.encode()).decode()}'))"

    # --- JAVASCRIPT ENGINES ---
    @staticmethod
    def js_symbolic(code):
        # JJEncode Simulation (Symbols only)
        # For stability, we use a Hex-Symbol hybrid wrapper
        h = ''.join([f'\\x{ord(c):02x}' for c in code])
        return f"/* V95 Symbolic */\n$=~[];$={{___:++$,$$$$:(![]+'')[$$]}};__=$['$$$$'];eval('{h}')"

    @staticmethod
    def js_packer(code):
        b64 = base64.b64encode(code.encode()).decode()
        return f"/* V95 Packed */\n(function(p,a,c,k,e,d){{eval(atob(p))}})('{b64}')"

    # --- LUA ENGINES ---
    @staticmethod
    def lua_xor(code):
        key = random.randint(1, 255)
        bytes_arr = [ord(c) ^ key for c in code]
        table = "{" + ",".join(map(str, bytes_arr)) + "}"
        return f"-- V95 XOR\nlocal k={key};local b={table};local s='';for i=1,#b do s=s..string.char(bit32.bxor(b[i],k)) end;load(s)()"

    # --- PHP ENGINES ---
    @staticmethod
    def php_octal(code):
        # Convert to Octal Escape Sequences
        octal = ""
        for char in code: octal += "\\" + oct(ord(char))[2:]
        return f"<?php eval(\"{octal}\"); ?>"

    # --- GO ENGINES ---
    @staticmethod
    def go_hex(code):
        hx = binascii.hexlify(code.encode()).decode()
        return f"""package main
import("encoding/hex";"fmt")
func main(){{
    h:="{hx}"
    b,_:=hex.DecodeString(h)
    fmt.Printf("%s", b)
}}"""

# ==============================================================================
# 3. UNIVERSAL DECRYPTOR (DEEP SCAN)
# ==============================================================================
def deep_decrypt(code):
    curr = code
    patterns = [
        r"base64\.b64decode\(['\"](.*?)['\"]\)", r"atob\(['\"](.*?)['\"]\)",
        r"base64\.b85decode\(['\"](.*?)['\"]\)", r"hex\.DecodeString\(['\"](.*?)['\"]\)",
        r"eval\(['\"](\\x.*?)['\"]\)"
    ]
    for _ in range(25):
        found = False
        for p in patterns:
            m = re.search(p, curr)
            if m:
                try:
                    payload = m.group(1)
                    # Attempt multiple decoding methods
                    try: dec = base64.b64decode(payload).decode()
                    except: 
                        try: dec = base64.b85decode(payload).decode()
                        except: dec = codecs.decode(payload.replace('\\x',''), 'hex').decode()
                    
                    # Check for nested zlib
                    try: dec = zlib.decompress(dec.encode('latin1')).decode()
                    except: pass
                    
                    curr = dec
                    found = True
                except: pass
        if not found: break
    return curr

# ==============================================================================
# 4. FLASK ROUTES
# ==============================================================================
from datetime import datetime

@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_code():
    try:
        d = request.json
        c, a, l, o = d.get('code',''), d.get('action'), d.get('lang'), d.get('options',[])
        
        # Log to DB
        log_op(l, ','.join(o) if o else 'Default', len(c), c)

        if a == 'encrypt':
            if l == 'python': res = Engines.py_process(c, o)
            elif l == 'javascript': 
                if 'hex' in o: res = Engines.js_symbolic(c) # Mapped symbolic to hex logic
                elif 'packer' in o: res = Engines.js_packer(c)
                else: res = f"eval(atob('{base64.b64encode(c.encode()).decode()}'))"
            elif l == 'lua': 
                if 'vm' in o: res = Engines.lua_xor(c)
                else: res = f"load('{c}')()"
            elif l == 'php': 
                if 'ghost' in o: res = Engines.php_octal(c)
                else: res = f"<?php eval(base64_decode('{base64.b64encode(c.encode()).decode()}')); ?>"
            elif l == 'go': res = Engines.go_hex(c)
            else: res = f"// Encrypted {l}\n{base64.b64encode(c.encode()).decode()}"
        else:
            res = deep_decrypt(c)
            
        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"# CRITICAL ERROR: {e}"}), 500

@app.route('/run', methods=['POST'])
def run_term():
    c = request.json.get('code','')
    # Terminal Simulation
    if c == 'whoami': return jsonify({'output': 'root'})
    if c == 'ls': return jsonify({'output': 'logs.db  app.py  templates/'})
    if c.startswith('rm'): return jsonify({'output': 'Permission Denied: System Protected'})
    
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(c, {'__builtins__':__builtins__}, {})
        return jsonify({'output': f.getvalue()})
    except Exception as e: return jsonify({'output': str(e)})

@app.route('/history', methods=['GET'])
def get_logs():
    db = get_db()
    rows = db.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/upload-zip', methods=['POST'])
def zip_handler():
    f = request.files['file']
    m_out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(f.read()),'r') as zi, zipfile.ZipFile(m_out,'w',zipfile.ZIP_DEFLATED) as zo:
        for i in zi.infolist():
            d = zi.read(i.filename)
            try:
                if i.filename.endswith('.py'): zo.writestr(i.filename, Engines.py_process(d.decode(),['chaos']))
                elif i.filename.endswith('.php'): zo.writestr(i.filename, Engines.php_octal(d.decode()))
                else: zo.writestr(i,d)
            except: zo.writestr(i,d)
    m_out.seek(0)
    return send_file(m_out, mimetype='application/zip', as_attachment=True, download_name='Hyperion_Secure.zip')

# DB Init
with app.app_context(): init_db()

if __name__ == '__main__':
    print(" >>> V95 INFINITE CORE INITIALIZED.")
    app.run(debug=True, port=5000)
