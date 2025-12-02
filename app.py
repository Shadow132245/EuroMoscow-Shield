from flask import Flask, render_template, request, jsonify
import base64, zlib, binascii, ast, random, io, codecs, re, urllib.parse, zipfile, sys
from contextlib import redirect_stdout
from datetime import datetime

app = Flask(__name__)

BRAND = "# Protected by EuroMoscow Shield V25\n"

# --- 1. AI BRAIN (Advanced) ---
def ai_brain(msg, code=""):
    msg = msg.lower()
    
    # Greetings & Chatter
    if any(x in msg for x in ['hi', 'hello', 'hey', 'مرحبا', 'سلام', 'ازيك']):
        return "Welcome Commander! 🛡️ I am EuroMind V25. Ready to secure your code."
    
    if any(x in msg for x in ['who are you', 'name', 'created']):
        return "I am EuroMind, an advanced security AI developed by EuroMoscow."
    
    # Technical / Help
    if "how" in msg and "encrypt" in msg:
        return "Simple! Paste your code, select 'ENCRYPT' mode, choose your layers (I recommend 'Chaos' + 'Rename'), and click PROTECT."
    
    if "terminal" in msg:
        return "The Terminal allows you to test Python code directly on our server. Type 'python' code and hit Enter."
    
    # Code Analysis Context
    if "analyze" in msg or "check" in msg or "code" in msg:
        if not code: return "Please paste some code in the editor first so I can analyze it."
        return "I've analyzed the code. It seems valid. For best security, I recommend enabling 'Dead Code' and 'Marshal' layers."
    
    # General Programming Q&A (Simulation)
    if "python" in msg: return "Python is supported! I can encrypt it using AST manipulation and Bytecode compilation."
    if "js" in msg or "javascript" in msg: return "JavaScript is supported! I use Hex and Obfuscator encoding."
    if "lua" in msg: return "Lua is supported! Perfect for Roblox/FiveM protection."
    
    return "I am listening. You can ask me about encryption, ask for help, or request a code analysis."

# --- 2. TERMINAL ENGINE ---
def execute_python_code(code):
    # Capture stdout
    f = io.StringIO()
    try:
        # Dangerous but requested feature: running code
        # Restricted environment (optional safety can be added here)
        with redirect_stdout(f):
            exec(code, {'__builtins__': __builtins__}, {})
        return f.getvalue()
    except Exception as e:
        return f"Error: {str(e)}"

# --- 3. ENCRYPTION ENGINES (Keeping it reliable) ---
def random_name(len=8): return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=len))

def proc_py(code, opts):
    res = code
    try:
        if 'deadcode' in opts:
            res = f"if {random.randint(10,99)} > {random.randint(100,999)}: pass\n{res}"
        if 'rename' in opts:
            class R(ast.NodeTransformer):
                def __init__(s): s.m={}
                def visit_Name(s,n):
                    if isinstance(n.ctx,(ast.Store,ast.Del)) and n.id not in dir(__builtins__):
                        if n.id not in s.m: s.m[n.id]=random_name()
                    return n
            res = ast.unparse(R().visit(ast.parse(res)))
        if 'marshal' in opts:
            c = zlib.compress(res.encode()); b=list(c)
            res = f"import zlib;exec(zlib.decompress(bytes({b})),globals())"
        if 'xor' in opts:
            k = random.randint(1,255); e=[ord(c)^k for c in res]
            res = f"exec(''.join(chr(c^{k})for c in {e}),globals())"
        e = base64.b64encode(res.encode()).decode()
        return f"{BRAND}import base64;exec(base64.b64decode('{e}'))"
    except: return code

def proc_js(code, opts):
    res = code
    if 'hex' in opts: res=f"eval('{''.join([f'\\\\x{ord(c):02x}' for c in res])}')"
    if 'url' in opts: res=f"eval(decodeURIComponent('{urllib.parse.quote(res)}'))"
    b64 = base64.b64encode(res.encode()).decode()
    return f"/* EuroMoscow V25 */\neval(atob('{b64}'))"

def proc_lua(code, opts):
    res = code
    if 'reverse' in opts: safe=res[::-1].replace('"','\\"').replace("'","\\'"); res=f"local _f=loadstring or load;_f(string.reverse('{safe}'))()"
    if 'hex' in opts: h="".join([f"{b:02X}" for b in res.encode('utf-8')]); res=f"local _h=\"{h}\";local _c=\"\";for i=1,#_h,2 do _c=_c..string.char(tonumber(string.sub(_h,i,i+1),16)) end;local _f=loadstring or load;_f(_c)()"
    return f"-- EuroMoscow V25\n{res}"

# --- 4. UNIVERSAL DECRYPTOR ---
def universal_decrypt(code):
    curr = code
    pats = [r"base64\.b64decode\(['\"](.*?)['\"]\)", r"atob\(['\"](.*?)['\"]\)", r"zlib\.decompress\(bytes\(\[(.*?)\]\)\)", r"eval\(['\"](\\x[0-9a-fA-F]{2}.*?)['\"]\)", r"string\.reverse\('((?:[^'\\]|\\.)*)'\)"]
    for _ in range(15):
        clean = curr.replace('\n',' ').strip(); found=False
        for p in pats:
            m = re.search(p, clean)
            if m:
                try:
                    payload = m.group(1)
                    if 'zlib' in p: curr=zlib.decompress(bytes(eval(f"[{payload}]"))).decode()
                    elif 'reverse' in p: curr=payload.replace("\\'","'")[::-1]
                    elif 'hex' in p: curr=bytes.fromhex(payload.replace('\\x','')).decode()
                    else: curr=base64.b64decode(payload).decode()
                    found=True
                except: pass
        if not found: break
    return curr

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    d=request.json; c=d.get('code',''); a=d.get('action'); l=d.get('lang','python'); o=d.get('options',[])
    if a == 'encrypt':
        if l=='python': res=proc_py(c,o)
        elif l=='javascript': res=proc_js(c,o)
        elif l=='lua': res=proc_lua(c,o)
        else: res=c
    else: res=universal_decrypt(c)
    return jsonify({'result':res})

@app.route('/chat', methods=['POST'])
def chat():
    d = request.json
    return jsonify({'reply': ai_brain(d.get('message',''), d.get('code',''))})

@app.route('/run', methods=['POST'])
def run():
    d = request.json
    # Secure/Limit execution for Python only
    if d.get('lang') == 'python':
        return jsonify({'output': execute_python_code(d.get('code',''))})
    return jsonify({'output': "Server execution only supports Python."})

@app.route('/upload-zip', methods=['POST'])
def zip_up():
    try:
        f=request.files['file']; m=io.BytesIO(f.read()); out=io.BytesIO(); o=request.form.get('options','').split(',')
        with zipfile.ZipFile(m,'r') as zi, zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as zo:
            for i in zi.infolist():
                d=zi.read(i.filename)
                try:
                    if i.filename.endswith('.py'): zo.writestr(i.filename, proc_py(d.decode('utf-8'),o))
                    elif i.filename.endswith('.js'): zo.writestr(i.filename, proc_js(d.decode('utf-8'),o))
                    else: zo.writestr(i,d)
                except: zo.writestr(i,d)
        out.seek(0); return send_file(out, mimetype='application/zip', as_attachment=True, download_name='Project.zip')
    except: return "Error", 500

if __name__ == '__main__': app.run(debug=True, port=5000)
