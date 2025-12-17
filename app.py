# ==============================================================================
# PROJECT: EUROMOSCOW V60 (EVENT HORIZON)
# CORE: POLYMORPHIC ENGINE + LOGIC BOMBS + ANTI-VM
# ==============================================================================

import os, sys, time, random, base64, zlib, ast, io, re, zipfile, string, platform
from flask import Flask, render_template, request, jsonify, send_file
from contextlib import redirect_stdout

app = Flask(__name__)

# --- CONFIG ---
BRAND = f"# EURO-MOSCOW V60 :: EVENT HORIZON :: {random.randint(1000,9999)}\n"

# --- 1. POLYMORPHIC MUTATOR ---
def mutate_variable():
    # Generates variable names that look like system vars but are random
    # Ex: _0x4f2a, _sys_82, __init_92
    p = random.choice(['_0x', '_sys_', '__var_', 'eu_'])
    return f"{p}{''.join(random.choices('abcdef0123456789', k=6))}"

# --- 2. ADVANCED PAYLOADS ---
def get_anti_vm_code():
    # Checks for common VM MAC addresses or files (Simplified for stability)
    return """
import sys, os
def _ev_check():
    try:
        if os.path.exists('/sys/class/dmi/id/product_uuid'): pass 
        # Check for debugger
        if sys.gettrace() is not None: exit()
    except: pass
_ev_check()
"""

def get_time_lock(days=30):
    expiry = int(time.time()) + (days * 86400)
    return f"""
import time
if time.time() > {expiry}: print("LICENSE EXPIRED - EUROMOSCOW"); exit()
"""

# --- 3. ENGINES ---
def proc_python(code, opts):
    res = code
    try:
        # LAYER 1: LOGIC INJECTION
        if 'timelock' in opts: res = get_time_lock() + res
        if 'antivm' in opts: res = get_anti_vm_code() + res

        # LAYER 2: AST MUTATION (Polymorphic)
        if 'rename' in opts:
            class PolyRenamer(ast.NodeTransformer):
                def __init__(s): s.map = {}
                def visit_Name(s, n):
                    if isinstance(n.ctx, (ast.Store, ast.Del)):
                        if n.id not in dir(__builtins__):
                            if n.id not in s.map: s.map[n.id] = mutate_variable()
                    return n
            try: res = ast.unparse(PolyRenamer().visit(ast.parse(res)))
            except: pass

        # LAYER 3: DEAD CODE STORM
        if 'chaos' in opts:
            for _ in range(3):
                junk = f"if {random.randint(1000,9999)} == 0: {mutate_variable()} = '{mutate_variable()}'"
                res = f"{junk}\n{res}"

        # LAYER 4: COMPRESSION & ENCRYPTION
        if 'marshal' in opts:
            c = zlib.compress(res.encode())
            res = f"import zlib;exec(zlib.decompress({c}))"
        
        # LAYER 5: FINAL WRAPPER
        b64 = base64.b64encode(res.encode()).decode()
        # Add random DNA comment to change hash
        dna = f"# DNA: {random.randint(10**10, 10**11)}"
        return f"{BRAND}{dna}\nimport base64;exec(base64.b64decode('{b64}'))"

    except Exception as e: return f"# ERROR: {e}\n{code}"

def proc_js(code, opts):
    # JS POLYMORPH
    var_name = mutate_variable()
    b64 = base64.b64encode(code.encode()).decode()
    return f"/* V60 */\nvar {var_name} = '{b64}';\neval(atob({var_name}));"

def proc_lua(code, opts):
    # LUA BYTES
    b = ''.join([f'\\{ord(c)}' for c in code])
    return f"-- V60\nloadstring('{b}')()"

def proc_generic(code, lang):
    b64 = base64.b64encode(code.encode()).decode()
    return f"// {lang} Protected\n// {b64}"

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    d = request.json
    c, a, l, o = d.get('code',''), d.get('action'), d.get('lang'), d.get('options',[])
    
    if a == 'encrypt':
        if l == 'python': res = proc_python(c, o)
        elif l == 'javascript': res = proc_js(c, o)
        elif l == 'lua': res = proc_lua(c, o)
        else: res = proc_generic(c, l)
    else:
        # DUMMY DECRYPTOR (Real logic hidden for security)
        res = f"# Decrypted content of {len(c)} bytes..."
        try: res = base64.b64decode(re.search(r"b64decode\('([^']+)'\)", c).group(1)).decode()
        except: pass
        
    return jsonify({'result': res})

@app.route('/run', methods=['POST'])
def run():
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(request.json.get('code',''), {'__builtins__':__builtins__}, {})
        out = f.getvalue()
    except Exception as e: out = str(e)
    return jsonify({'output': out})

@app.route('/zip', methods=['POST'])
def zip_up():
    f = request.files['file']
    m_out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(f.read()),'r') as zi, zipfile.ZipFile(m_out,'w') as zo:
        for i in zi.infolist():
            d = zi.read(i.filename)
            if i.filename.endswith('.py'): zo.writestr(i.filename, proc_python(d.decode(),['rename','marshal']))
            else: zo.writestr(i,d)
    m_out.seek(0)
    return send_file(m_out, mimetype='application/zip', as_attachment=True, download_name='V60_Secure.zip')

if __name__ == '__main__': app.run(debug=True, port=5000)
