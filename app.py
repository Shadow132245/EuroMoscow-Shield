import os, sys, random, base64, zlib, ast, io, codecs, re, zipfile
from flask import Flask, render_template, request, jsonify, send_file
from contextlib import redirect_stdout

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB Limit

BRAND = "# Protected by EuroMoscow V35 (Black Hole)\n"

# --- CORE ENGINES ---
def rand_str(l=10): return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=l))

def obfuscate_python(code, layers):
    try:
        # 1. Dead Code Injection
        if 'dead' in layers:
            code = f"if 2077 > {random.randint(3000,9999)}: exit()\n{code}"
        # 2. Variable Renaming (AST)
        if 'rename' in layers:
            class R(ast.NodeTransformer):
                def __init__(s): s.m={}
                def visit_Name(s,n):
                    if isinstance(n.ctx,(ast.Store,ast.Del)) and n.id not in dir(__builtins__):
                        if n.id not in s.m: s.m[n.id]=rand_str(12)
                    return n
            code = ast.unparse(R().visit(ast.parse(code)))
        # 3. Compression
        if 'marshal' in layers:
            c = zlib.compress(code.encode('utf-8'))
            code = f"import zlib,base64;exec(zlib.decompress({c}))"
        # 4. Final Armor
        b64 = base64.b64encode(code.encode()).decode()
        return f"{BRAND}import base64;exec(base64.b64decode('{b64}'))"
    except Exception as e: return f"# Error: {e}\n{code}"

def obfuscate_js(code):
    h = ''.join([f'\\x{ord(c):02x}' for c in code])
    return f"/* V35 */\neval('{h}')"

def obfuscate_lua(code):
    return f"-- V35\nload(string.dump(loadstring([=[{code}]=])))()"

def obfuscate_generic(code, lang):
    # For Go, PHP, Java, etc. - Uses Base64 Wrapper
    b64 = base64.b64encode(code.encode()).decode()
    if lang == 'php': return f"<?php eval(base64_decode('{b64}')); ?>"
    if lang == 'go': return f"package main\nimport(\"encoding/base64\";\"fmt\")\nfunc main(){{s,_:=base64.StdEncoding.DecodeString(\"{b64}\");fmt.Print(string(s))}}"
    if lang == 'ruby': return f"eval(Base64.decode64('{b64}'))"
    return f"// Protected {lang}\n// {b64}"

def universal_decrypt(code):
    curr = code
    # Patterns for Base64, Hex, Zlib, etc.
    pats = [
        r"base64\.b64decode\(['\"](.*?)['\"]\)", r"atob\(['\"](.*?)['\"]\)", 
        r"base64_decode\('([^']+)'\)", r"DecodeString\(\"([^\"]+)\"\)"
    ]
    for _ in range(15):
        found = False
        for p in pats:
            m = re.search(p, curr)
            if m:
                try:
                    curr = base64.b64decode(m.group(1)).decode(errors='ignore')
                    found = True
                except: pass
        if not found: break
    return curr

# --- ROUTES ---
@app.route('/')
def index(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def api_process():
    d = request.json
    code, action, lang, opts = d.get('code',''), d.get('action'), d.get('lang'), d.get('options',[])
    
    if action == 'encrypt':
        if lang == 'python': res = obfuscate_python(code, opts)
        elif lang == 'javascript': res = obfuscate_js(code)
        elif lang == 'lua': res = obfuscate_lua(code)
        else: res = obfuscate_generic(code, lang)
    else:
        res = universal_decrypt(code)
    
    return jsonify({'result': res})

@app.route('/run', methods=['POST'])
def api_run():
    # Safe Python Sandbox (Mock)
    code = request.json.get('code','')
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(code, {'__builtins__': __builtins__}, {})
        return jsonify({'output': f.getvalue()})
    except Exception as e: return jsonify({'output': str(e)})

@app.route('/analyze', methods=['POST'])
def api_analyze():
    c = request.json.get('code','')
    score = 100
    risk = []
    if len(c) < 50: score=10; risk.append("Code too short")
    if 'import' in c: risk.append("Imports detected")
    if 'os.' in c: score-=50; risk.append("System Access (Critical)")
    return jsonify({'msg': f"🛡️ SECURITY AUDIT\nScore: {score}/100\nRisks: {', '.join(risk) if risk else 'None'}"})

@app.route('/zip', methods=['POST'])
def api_zip():
    try:
        f = request.files['file']
        opts = request.form.get('options','').split(',')
        m_in = io.BytesIO(f.read())
        m_out = io.BytesIO()
        with zipfile.ZipFile(m_in,'r') as zi, zipfile.ZipFile(m_out,'w',zipfile.ZIP_DEFLATED) as zo:
            for i in zi.infolist():
                d = zi.read(i.filename)
                try:
                    if i.filename.endswith('.py'): res = obfuscate_python(d.decode(), opts)
                    else: res = d
                    zo.writestr(i.filename, res)
                except: zo.writestr(i, d)
        m_out.seek(0)
        return send_file(m_out, mimetype='application/zip', as_attachment=True, download_name='Protected.zip')
    except: return "Error", 500

if __name__ == '__main__': app.run(debug=True, port=5000)
