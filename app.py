# ==============================================================================
# PROJECT: EUROMOSCOW V70 (QUANTUM SINGULARITY)
# ARCHITECT: HASSAN
# CORE: 12-LANG POLYMORPHIC ENGINE + INVISIBLE INK + IP LOCK
# ==============================================================================

import os, sys, time, random, base64, zlib, ast, io, re, zipfile, string, platform
from flask import Flask, render_template, request, jsonify, send_file
from contextlib import redirect_stdout

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024 # 64MB Support

BRAND = f"# EURO-MOSCOW V70 :: QUANTUM CORE :: {random.randint(10000,99999)}\n"

# --- 1. QUANTUM UTILS ---
def invisible_var(length=10):
    # Uses Zero Width Characters to make variables invisible/confusing
    zwc = ['\u200b', '\u200c', '\u200d', '\u2060']
    return "".join(random.choices(zwc, k=length)) + "_" + "".join(random.choices(string.ascii_letters, k=5))

def quantum_compress(data):
    return base64.b85encode(zlib.compress(data.encode('utf-8'))).decode('utf-8')

# --- 2. ADVANCED ENGINES ---

# PYTHON: INVISIBLE INK & CHAOS LAMBDA
def proc_python(code, opts):
    try:
        res = code
        # Layer 1: Anti-Tamper
        if 'tamper' in opts:
            res = "import sys; sys.settrace(None)\n" + res
            
        # Layer 2: Invisible Renaming (AST)
        if 'invisible' in opts:
            class InvisibleRenamer(ast.NodeTransformer):
                def __init__(self): self.map = {}
                def visit_Name(self, node):
                    if isinstance(node.ctx, (ast.Store, ast.Del)) and node.id not in dir(__builtins__):
                        if node.id not in self.map: self.map[node.id] = invisible_var()
                    return node
            try: res = ast.unparse(InvisibleRenamer().visit(ast.parse(res)))
            except: pass

        # Layer 3: Chaos Lambda (One-Liner Hell)
        if 'chaos' in opts:
            payload = quantum_compress(res)
            res = f"import zlib,base64; (lambda _q: exec(zlib.decompress(base64.b85decode(_q))))('{payload}')"
        
        # Layer 4: IP Lock
        if 'iplock' in opts:
            # Gets public IP via external service simulation code
            locker = """
import urllib.request
try:
    if 'YOUR_IP' not in urllib.request.urlopen('https://api.ipify.org').read().decode(): exit()
except: exit()
"""
            res = locker + res

        final = base64.b64encode(res.encode()).decode()
        return f"{BRAND}import base64;exec(base64.b64decode('{final}'))"
    except Exception as e: return f"# Error: {e}\n{code}"

# JS: OBFUSCATOR.IO STYLE SIMULATION
def proc_js(code, opts):
    # Rotates strings into a hex array
    encoded = [f"\\x{ord(c):02x}" for c in code]
    var_name = f"_0x{random.randint(1000,9999)}"
    return f"/* V70 Quantum */\nvar {var_name}=['{''.join(encoded)}'];\neval({var_name}[0]);"

# C++ / C# / RUST / SWIFT (Wrapper Mode)
def proc_compiled(code, lang):
    # Wraps code in a decoder for that language
    b64 = base64.b64encode(code.encode()).decode()
    if lang == 'cpp':
        return f"// V70 C++ Protected\n#include <iostream>\n#include <string>\n// DECODE LOGIC HERE\nstd::string payload = \"{b64}\";"
    if lang == 'csharp':
        return f"// V70 C# Protected\nusing System;\nclass Program {{ static void Main() {{ string p = \"{b64}\"; }} }}"
    return f"// {lang} Encrypted Container\n// {b64}"

# --- 3. UNIVERSAL DECRYPTOR (RECURSIVE) ---
def deep_decrypt(code):
    curr = code
    # Regex for B64, Hex, B85, Rot13
    patterns = [
        r"base64\.b64decode\(['\"](.*?)['\"]\)", r"atob\(['\"](.*?)['\"]\)", 
        r"base64\.b85decode\(['\"](.*?)['\"]\)", r"fromhex\(['\"](.*?)['\"]\)"
    ]
    for _ in range(20): # Dig 20 layers deep
        found = False
        for p in patterns:
            m = re.search(p, curr)
            if m:
                try:
                    payload = m.group(1)
                    # Attempt decode
                    try: res = base64.b64decode(payload).decode()
                    except: 
                        try: res = base64.b85decode(payload).decode()
                        except: res = bytes.fromhex(payload).decode()
                    
                    # Check if result is zlib
                    try: res = zlib.decompress(res.encode('latin1')).decode()
                    except: pass
                    
                    curr = res
                    found = True
                except: pass
        if not found: break
    return curr

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
        elif l in ['cpp', 'csharp', 'java', 'rust', 'swift', 'ruby', 'perl']: res = proc_compiled(c, l)
        elif l == 'lua': res = f"-- V70 Lua\nload(Base64Decode('{base64.b64encode(c.encode()).decode()}'))()"
        else: res = f"// Generic Protection\n{base64.b64encode(c.encode()).decode()}"
    else:
        res = deep_decrypt(c)
        
    return jsonify({'result': res})

@app.route('/run', methods=['POST'])
def run():
    # Simulated Root Terminal
    cmd = request.json.get('code','')
    if cmd.startswith('sudo'): return jsonify({'output': 'Access Granted. Root privileges active.'})
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(cmd, {'__builtins__':__builtins__}, {})
        out = f.getvalue()
    except Exception as e: out = f"Error: {e}"
    return jsonify({'output': out})

if __name__ == '__main__': app.run(debug=True, port=5000)
