# ==========================================
# Project: EuroMoscow Shield V50 (GOD MODE)
# Core: Multi-Language Advanced Obfuscation
# ==========================================

import os, sys, random, base64, zlib, ast, io, codecs, re, urllib.parse, zipfile, string
from flask import Flask, render_template, request, jsonify, send_file
from contextlib import redirect_stdout

app = Flask(__name__)
SERVER_KEY = random.randint(1000, 9999) # Session Key

BRAND = "# Protected by EuroMoscow V50 (God Mode)\n"

# --- HELPER FUNCTIONS ---
def rand_str(l=8): return ''.join(random.choices(string.ascii_letters, k=l))
def rand_hex(l=4): return ''.join(random.choices('0123456789ABCDEF', k=l))

# ==========================================
# 1. PYTHON ENGINES (CHAOS & NIGHTMARE)
# ==========================================
def proc_python(code, opts):
    res = code
    try:
        # CHAOS LAMBDA (New in V50)
        # يحول الكود لسطر واحد معقد جداً
        if 'chaos' in opts:
            b64 = base64.b64encode(zlib.compress(res.encode())).decode()
            res = f"import zlib,base64;((lambda _0x:exec(zlib.decompress(base64.b64decode(_0x))))('{b64}'))"

        # Standard AST Renaming
        if 'rename' in opts:
            class R(ast.NodeTransformer):
                def __init__(s): s.m={}
                def visit_Name(s,n):
                    if isinstance(n.ctx,(ast.Store,ast.Del)) and n.id not in dir(__builtins__):
                        if n.id not in s.m: s.m[n.id]=f"_{rand_hex(6)}"
                    return n
            try: res = ast.unparse(R().visit(ast.parse(res)))
            except: pass

        # Dead Code
        if 'dead' in opts:
            junk = f"if {random.randint(10,99)}=={random.randint(100,999)}: pass"
            res = f"{junk}\n{res}"

        # Final Armor (Marshal + Base64)
        if 'marshal' in opts:
            c = zlib.compress(res.encode()); b=list(c)
            res = f"import zlib;exec(zlib.decompress(bytes({b})),globals())"
        
        final = base64.b64encode(res.encode()).decode()
        return f"{BRAND}import base64;exec(base64.b64decode('{final}'))"
    except: return code

# ==========================================
# 2. JAVASCRIPT ENGINES (SPECTRAL PACKER)
# ==========================================
def proc_js(code, opts):
    res = code
    # SPECTRAL PACKER (New in V50)
    # يغلف الكود داخل دالة فورية التنفيذ مع تشفير
    if 'packer' in opts:
        b64 = base64.b64encode(res.encode()).decode()
        # دالة فك تشفير تبدو معقدة
        wrapper = f"""(function(_0x, _0y){{
    var _0z = function(_0a){{ return atob(_0a); }};
    eval(_0z(_0x));
}})('{b64}', '{rand_str(5)}');"""
        return f"/* V50 Spectral */\n{wrapper}"

    if 'hex' in opts:
        h = ''.join([f'\\x{ord(c):02x}' for c in res])
        return f"eval('{h}')"
        
    return f"eval(decodeURIComponent('{urllib.parse.quote(res)}'))"

# ==========================================
# 3. LUA ENGINES (ABYSS VM)
# ==========================================
def proc_lua(code, opts):
    # ABYSS VM SIMULATION (New in V50)
    if 'vm' in opts:
        # يحول الكود لـ Bytecode ثم يضعه في جدول أرقام
        b = [str(ord(c)) for c in code]
        table = "{" + ",".join(b) + "}"
        loader = f"""
local _0x = {table}
local _0y = ''
for _,v in ipairs(_0x) do _0y=_0y..string.char(v) end
load(_0y)()
"""
        return f"-- V50 Abyss VM\n{loader}"

    # Basic Hex Loader
    h = "".join([f"\\{ord(c)}" for c in code])
    return f"loadstring('{h}')()"

# ==========================================
# 4. PHP & GO ENGINES (PHANTOM & ARMOR)
# ==========================================
def proc_php(code, opts):
    # PHANTOM MODE
    if 'ghost' in opts:
        b64 = base64.b64encode(gz_enc := zlib.compress(code.encode())).decode()
        # استخدام دوال متغيرة الاسم
        return f"<?php $_a='base64_decode';$_b='gzuncompress';eval($_b($_a('{b64}'))); ?>"
    return f"<?php eval(base64_decode('{base64.b64encode(code.encode()).decode()}')); ?>"

def proc_go(code, opts):
    # BINARY ARMOR
    b64 = base64.b64encode(code.encode()).decode()
    return f"""package main
import("encoding/base64";"fmt";"os")
func main(){{
    d,_ := base64.StdEncoding.DecodeString("{b64}")
    // V50 Armor
    fmt.Println(string(d))
}}"""

# ==========================================
# 5. UNIVERSAL DECRYPTOR
# ==========================================
def universal_decrypt(code):
    curr = code
    pats = [
        r"base64\.b64decode\(['\"](.*?)['\"]\)", r"atob\(['\"](.*?)['\"]\)", 
        r"base64_decode\('([^']+)'\)", r"DecodeString\(\"([^\"]+)\"\)",
        r"zlib\.decompress\(base64\.b64decode\(['\"](.*?)['\"]\)\)"
    ]
    for _ in range(15):
        found = False
        for p in pats:
            m = re.search(p, curr)
            if m:
                try:
                    payload = m.group(1)
                    # Try Base64 then Zlib
                    try: decoded = zlib.decompress(base64.b64decode(payload)).decode()
                    except: decoded = base64.b64decode(payload).decode(errors='ignore')
                    
                    curr = decoded
                    found = True
                except: pass
        if not found: break
    return curr

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    d=request.json; c=d.get('code',''); a=d.get('action'); l=d.get('lang'); o=d.get('options',[])
    if a == 'encrypt':
        if l=='python': res=proc_python(c,o)
        elif l=='javascript': res=proc_js(c,o)
        elif l=='lua': res=proc_lua(c,o)
        elif l=='php': res=proc_php(c,o)
        elif l=='go': res=proc_go(c,o)
        else: res=c
    else: res=universal_decrypt(c)
    return jsonify({'result':res})

@app.route('/run', methods=['POST'])
def run():
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(request.json.get('code',''), {'__builtins__':__builtins__}, {})
        return jsonify({'output': f.getvalue()})
    except Exception as e: return jsonify({'output': str(e)})

@app.route('/upload-zip', methods=['POST'])
def zip_up():
    try:
        f=request.files['file']; m=io.BytesIO(f.read()); out=io.BytesIO(); o=request.form.get('options','').split(',')
        with zipfile.ZipFile(m,'r') as zi, zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as zo:
            for i in zi.infolist():
                d=zi.read(i.filename)
                try:
                    if i.filename.endswith('.py'): zo.writestr(i.filename, proc_python(d.decode(),o))
                    elif i.filename.endswith('.js'): zo.writestr(i.filename, proc_js(d.decode(),o))
                    else: zo.writestr(i,d)
                except: zo.writestr(i,d)
        out.seek(0); return send_file(out, mimetype='application/zip', as_attachment=True, download_name='Protected_V50.zip')
    except: return "Error", 500

if __name__ == '__main__': app.run(debug=True, port=5000)
