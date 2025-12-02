from flask import Flask, render_template, request, jsonify, send_file
import base64, zlib, binascii, ast, random, io, codecs, re, urllib.parse, zipfile, sys, requests
from contextlib import redirect_stdout
from datetime import datetime

app = Flask(__name__)

BRAND = "# Protected by EuroMoscow Shield V25\n"

# 🔴 ضع مفتاحك هنا (Google Gemini API)
GEMINI_API_KEY = "AIzaSyAS34mpmUNnNbWkWlM5b6_TOqhOEC8Q0Nc"

# --- 1. AI ENGINE (Real Gemini + Fallback) ---
def ask_gemini(prompt, code_context=""):
    # لو مفيش مفتاح او المفتاح لسه النص الافتراضي، نستخدم الرد المحلي
    if "AIzaSyAS34mpmUNnNbWkWlM5b6_TOqhOEC8Q0Nc" in GEMINI_API_KEY:
        return local_ai_brain(prompt)
        
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"
        headers = {'Content-Type': 'application/json'}
        text = f"You are EuroMind, a coding security expert. User asks: {prompt}"
        if code_context: text += f"\n\nCode Context:\n{code_context}"
        
        data = {"contents": [{"parts": [{"text": text}]}]}
        res = requests.post(url, headers=headers, json=data)
        
        if res.status_code == 200:
            return res.json()['candidates'][0]['content']['parts'][0]['text']
        else:
            return f"AI Error ({res.status_code}): Please check your API Key."
    except Exception as e:
        return local_ai_brain(prompt) # لو حصل خطأ في الاتصال، نرجع للمحلي

def local_ai_brain(msg):
    msg = msg.lower()
    if "hello" in msg: return "Welcome to EuroMoscow V25! (Add API Key for Real AI)"
    if "analyze" in msg: return "Your code structure looks valid. Use 'Max' settings for safety."
    return "I am EuroMind. Please add a valid Google API Key in app.py to unlock my full potential."

# --- 2. ENCRYPTION ENGINES ---
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
            c = zlib.compress(res.encode('utf-8')); b=list(c)
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

def proc_php(code, opts):
    cln = code.replace('<?php','').replace('?>','').strip()
    b64 = base64.b64encode(zlib.compress(cln.encode())).decode()
    return f"<?php /* V25 */ eval(gzuncompress(base64_decode('{b64}'))); ?>"

def proc_html(code, opts):
    enc = urllib.parse.quote(code)
    return f"<script>document.write(decodeURIComponent('{enc}'));</script>"

# --- 3. DECRYPTOR ---
def universal_decrypt(code):
    curr = code
    pats = [r"base64\.b64decode\(['\"](.*?)['\"]\)", r"atob\(['\"](.*?)['\"]\)", r"zlib\.decompress\(bytes\(\[(.*?)\]\)\)", r"eval\(['\"](\\x[0-9a-fA-F]{2}.*?)['\"]\)", r"string\.reverse\('((?:[^'\\]|\\.)*)'\)", r"base64_decode\('([^']+)'\)", r"decodeURIComponent\('([^']+)'\)"]
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
                    elif 'decodeURIComponent' in p: curr=urllib.parse.unquote(payload)
                    else: curr=base64.b64decode(payload).decode()
                    found=True
                except: pass
        if not found: break
    return curr

# --- 4. TERMINAL EXECUTION ---
def execute_code(code):
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(code, {'__builtins__': __builtins__}, {})
        return f.getvalue()
    except Exception as e: return f"Error: {str(e)}"

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
        elif l=='php': res=proc_php(c,o)
        else: res=proc_html(c,o)
    else: res=universal_decrypt(c)
    return jsonify({'result':res})

@app.route('/chat', methods=['POST']) # ✅ تم التأكد من وجود هذا المسار
def chat():
    d = request.json
    return jsonify({'reply': ask_gemini(d.get('message',''), d.get('code',''))})

@app.route('/analyze', methods=['POST'])
def analyze():
    d = request.json
    # نستخدم الذكاء الاصطناعي للتحليل
    analysis = ask_gemini("Analyze the security of this code and give a score out of 100:", d.get('code',''))
    return jsonify({'msg': analysis})

@app.route('/run', methods=['POST']) # مسار التيرمينال
def run():
    return jsonify({'output': execute_code(request.json.get('code',''))})

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

