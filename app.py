from flask import Flask, render_template, request, jsonify, send_file
import base64, zlib, binascii, ast, random, io, codecs, re, urllib.parse, zipfile, sys
from contextlib import redirect_stdout
from datetime import datetime

app = Flask(__name__)

BRAND = "# Protected by EuroMoscow Shield V25\n"

# --- UTILS ---
def random_name(len=8): return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=len))

# --- ENGINES ---
def proc_py(code, opts):
    res = code
    try:
        if 'deadcode' in opts:
            dead = f"if {random.randint(100,999)}==0: print('EuroShield')"
            res = f"{dead}\n{res}"
        if 'rename' in opts:
            class R(ast.NodeTransformer):
                def __init__(s): s.map={}
                def visit_Name(x,n):
                    if isinstance(n.ctx,(ast.Store,ast.Del)) and n.id not in dir(__builtins__):
                        if n.id not in x.map: x.map[n.id]=random_name()
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

# --- EXECUTION ---
def execute_code(code):
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(code, {'__builtins__': __builtins__}, {})
        return f.getvalue()
    except Exception as e: return f"Error: {str(e)}"

def analyze_code(code):
    score = 100; msg = []
    if len(code)<20: return {"score":10, "msg":"Code too short."}
    if 'import' in code: msg.append("Libraries detected.")
    if 'os.' in code: score-=30; msg.append("System calls found.")
    return {"score":score, "msg":" | ".join(msg) if msg else "Clean."}

def chat_ai(msg): return "I am EuroMind V25. Ready to assist."

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

@app.route('/run', methods=['POST'])
def run(): return jsonify({'output': execute_code(request.json.get('code',''))})

@app.route('/analyze', methods=['POST'])
def analyze(): return jsonify(analyze_code(request.json.get('code','')))

@app.route('/chat', methods=['POST'])
def chat(): return jsonify({'reply': chat_ai(request.json.get('message',''))})

@app.route('/upload-zip', methods=['POST'])
def zip_up():
    try:
        f=request.files['file']; m=io.BytesIO(f.read()); out=io.BytesIO(); o=request.form.get('options','').split(',')
        with zipfile.ZipFile(m,'r') as zi, zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as zo:
            for i in zi.infolist():
                d=zi.read(i.filename)
                try:
                    if i.filename.endswith('.py'): zo.writestr(i.filename, proc_py(d.decode('utf-8'),o))
                    else: zo.writestr(i,d)
                except: zo.writestr(i,d)
        out.seek(0); return send_file(out, mimetype='application/zip', as_attachment=True, download_name='Project.zip')
    except: return "Error", 500

if __name__ == '__main__': app.run(debug=True, port=5000)
