from flask import Flask, render_template, request, jsonify
import base64, zlib, binascii, ast, random, io, codecs, re, urllib.parse, zipfile, os, sys
from contextlib import redirect_stdout
from datetime import datetime

app = Flask(__name__)

BRAND_HEADER = f"# Protected by EuroMoscow Shield V25\n# https://euro-moscow-shield.vercel.app\n\n"

# --- 1. EURO-MIND AI BRAIN (The Smart Core) ---
def euro_brain(msg, code, lang):
    msg = msg.lower()
    
    # --- Intent Detection (فهم النية) ---
    
    # 1. Greeting / ترحيب
    if any(w in msg for w in ['hi', 'hello', 'hey', 'ازيك', 'مرحبا', 'السلام', 'هلا']):
        return "مرحباً بك يا قائد! 🤖 أنا يورو مايند، ذكاؤك الاصطناعي الخاص. كيف يمكنني مساعدتك اليوم؟\n\nHello Commander! I am EuroMind. How can I assist you?"

    # 2. Action: Encrypt / تشفير
    if any(w in msg for w in ['encrypt', 'protect', 'lock', 'obfuscate', 'شفر', 'حماية', 'اقفل']):
        if not code.strip(): return "من فضلك ضع الكود في المحرر أولاً لكي أقوم بتشفيره.\nPlease paste the code in the editor first."
        
        # Perform Encryption based on lang
        if lang == 'python': res = proc_py(code, ['rename', 'marshal', 'xor'])
        elif lang == 'javascript': res = proc_js(code, ['hex', 'base64'])
        elif lang == 'lua': res = proc_lua(code, ['byte', 'reverse'])
        else: res = code
        
        return f"✅ **تم التشفير بنجاح!**\nإليك النتيجة:\n\n{res[:100]}...\n(تم تطبيق أفضل إعدادات الحماية تلقائياً)"

    # 3. Action: Decrypt / فك تشفير
    if any(w in msg for w in ['decrypt', 'decode', 'unlock', 'فك', 'افتح']):
        res = universal_decrypt(code)
        if res == code: return "عذراً، لم أستطع التعرف على نوع التشفير. تأكد أن الكود مدعوم.\nCould not detect encryption type."
        return f"🔓 **تم فك التشفير!**\nالكود الأصلي:\n\n{res[:200]}..."

    # 4. Analyze / تحليل
    if any(w in msg for w in ['analyze', 'check', 'scan', 'فحص', 'حلل', 'شوف']):
        score = 100
        issues = []
        if len(code) < 50: score -= 20; issues.append("الكود قصير جداً (Code too short).")
        if 'os.' in code or 'system' in code: score -= 15; issues.append("استدعاءات نظام خطرة (System calls).")
        if 'eval' in code or 'exec' in code: score -= 25; issues.append("دوال تنفيذ مباشرة (Unsafe Eval).")
        
        report = f"📊 **تقرير الأمان:**\nنسبة الأمان الحالية: {score}%\n"
        if issues: report += "⚠️ **الملاحظات:** " + ", ".join(issues)
        else: report += "✅ الكود يبدو نظيفاً وجاهزاً للتشفير."
        return report

    # 5. Help / مساعدة
    if any(w in msg for w in ['help', 'مساعدة', 'تعمل ايه', 'what can you do']):
        return "أنا يمكنني:\n1. تشفير الكود (فقط قل 'شفر هذا').\n2. فك التشفير (قل 'فك هذا').\n3. تحليل الكود.\n4. الإجابة عن أسئلة برمجية.\n\nI can Encrypt, Decrypt, and Analyze your code. Just ask!"

    # Default / رد افتراضي ذكي
    return "لست متأكدًا تماماً، ولكن يمكنك تجربة أزرار التحكم في القائمة الجانبية، أو أعد صياغة سؤالك.\nI'm not sure, try rephrasing or use the sidebar controls."

# --- 2. ENGINES (PY, JS, LUA) ---
def random_name(len=8): return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=len))

def inject_dead_code(tree):
    try:
        class DeadInjector(ast.NodeTransformer):
            def visit_FunctionDef(self, node):
                try:
                    u = ast.If(test=ast.Constant(value=False), body=[ast.Expr(value=ast.Call(func=ast.Name(id='print', ctx=ast.Load()), args=[ast.Constant(value="EM Shield")], keywords=[]))], orelse=[])
                    node.body.insert(0, u)
                except: pass
                return node
        return DeadInjector().visit(tree)
    except: return tree

class SafeRenamer(ast.NodeTransformer):
    def __init__(self, ignore): self.map = {}; self.ignore = ignore | {'self','args','kwargs','main','__init__'}
    def get(self, n):
        if n in self.ignore or n.startswith('__'): return n
        if n not in self.map: self.map[n] = random_name()
        return self.map[n]
    def visit_FunctionDef(self, n): 
        if n.name not in self.ignore: n.name = self.get(n.name)
        self.generic_visit(n); return n
    def visit_ClassDef(self, n):
        if n.name not in self.ignore: n.name = self.get(n.name)
        self.generic_visit(n); return n
    def visit_Name(self, n):
        if isinstance(n.ctx, (ast.Load, ast.Store, ast.Del)):
            if n.id in self.map: n.id = self.map[n.id]
        return n

def proc_py(code, opts):
    res = code
    try:
        if 'rename' in opts or 'deadcode' in opts:
            tree = ast.parse(res)
            if 'deadcode' in opts: tree = inject_dead_code(tree)
            if 'rename' in opts: tree = SafeRenamer(set(dir(__builtins__))).visit(tree)
            if hasattr(ast,'unparse'): res = ast.unparse(tree)
    except: pass
    if 'marshal' in opts: c=zlib.compress(res.encode('utf-8')); b=list(c); res=f"import zlib;exec(zlib.decompress(bytes({b})),globals())"
    if 'zlib' in opts: e=base64.b64encode(zlib.compress(res.encode())).decode(); res=f"import zlib,base64;exec(zlib.decompress(base64.b64decode({e!r})),globals())"
    if 'rot13' in opts: e=codecs.encode(res,'rot13'); res=f"import codecs;exec(codecs.decode({e!r},'rot13'),globals())"
    if 'xor' in opts: k=random.randint(1,255); e=[ord(c)^k for c in res]; res=f"exec(''.join(chr(c^{k})for c in {e}),globals())"
    if 'base64' in opts: e=base64.b64encode(res.encode()).decode(); res=f"import base64;exec(base64.b64decode({e!r}),globals())"
    return BRAND_HEADER + res

def proc_js(code, opts):
    res = code
    if 'hex' in opts: res=f"eval('{''.join([f'\\\\x{ord(c):02x}' for c in res])}')"
    if 'charcode' in opts: res=f"eval(String.fromCharCode({','.join([str(ord(c)) for c in res])}))"
    if 'url' in opts: res=f"eval(decodeURIComponent('{urllib.parse.quote(res)}'))"
    if 'base64' in opts: res=f"eval(atob('{base64.b64encode(res.encode()).decode()}'))"
    return JS_HEADER + res

def proc_lua(code, opts, exp=''):
    res = code
    if exp:
        try: ts=int(datetime.strptime(exp,"%Y-%m-%d").timestamp()); res=f"if os.time()>{ts} then error('Expired') end\n{res}"
        except: pass
    if 'reverse' in opts: safe=res[::-1].replace('"','\\"').replace("'","\\'"); res=f"local _f=loadstring or load;_f(string.reverse('{safe}'))()"
    if 'hex' in opts: h="".join([f"{b:02X}" for b in res.encode('utf-8')]); res=f"local _h=\"{h}\";local _c=\"\";for i=1,#_h,2 do _c=_c..string.char(tonumber(string.sub(_h,i,i+1),16)) end;local _f=loadstring or load;_f(_c)()"
    if 'byte' in opts: b=" ".join([str(b) for b in res.encode('utf-8')]); res=f"local _b=\"{b}\";local _t={{}};for w in string.gmatch(_b,\"%d+\")do table.insert(_t,string.char(tonumber(w))) end;local _f=loadstring or load;_f(table.concat(_t))()"
    return LUA_HEADER + res

def proc_php(code, opts):
    cln = code.replace('<?php','').replace('?>','').strip()
    b64 = base64.b64encode(zlib.compress(cln.encode())).decode()
    return f"<?php /* EuroMoscow */ eval(gzuncompress(base64_decode('{b64}'))); ?>"

def proc_html(code, opts):
    enc = urllib.parse.quote(code)
    return f"<script>document.write(decodeURIComponent('{enc}'));</script>"

# --- 3. UNIVERSAL DECRYPTOR ---
def universal_decrypt(code):
    curr = code
    pats = [
        r"base64\.b64decode\(['\"](.*?)['\"]\)", r"atob\(['\"](.*?)['\"]\)", 
        r"zlib\.decompress\(bytes\(\[(.*?)\]\)\)", r"eval\(['\"](\\x[0-9a-fA-F]{2}.*?)['\"]\)",
        r"string\.reverse\('((?:[^'\\]|\\.)*)'\)", r"base64_decode\('([^']+)'\)",
        r"decodeURIComponent\('([^']+)'\)"
    ]
    for _ in range(20):
        clean = curr.replace('\n',' ').strip(); found=False
        for p in pats:
            m = re.search(p, clean)
            if m:
                try:
                    payload = m.group(1)
                    if 'zlib' in p and 'bytes' in p: curr=zlib.decompress(bytes(eval(f"[{payload}]"))).decode()
                    elif 'zlib' in p and 'base64' in p: curr=zlib.decompress(base64.b64decode(payload)).decode()
                    elif 'reverse' in p: curr=payload.replace("\\'","'")[::-1]
                    elif 'hex' in p: curr=bytes.fromhex(payload.replace('\\x','')).decode()
                    elif 'decodeURIComponent' in p: curr=urllib.parse.unquote(payload)
                    else: curr=base64.b64decode(payload).decode()
                    found=True
                except: pass
        if not found: break
    return curr

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
    try:
        d=request.json; c=d.get('code',''); a=d.get('action'); l=d.get('lang'); o=d.get('options',[]); e=d.get('expiry','')
        if a == 'encrypt':
            if l=='python': res=proc_py(c,o)
            elif l=='javascript': res=proc_js(c,o)
            elif l=='lua': res=proc_lua(c,o,e)
            elif l=='php': res=proc_php(c,o)
            else: res=proc_html(c,o)
        else: res=universal_decrypt(c)
        return jsonify({'result':res})
    except: return jsonify({'result':c})

@app.route('/chat', methods=['POST'])
def chat():
    d = request.json
    reply = euro_brain(d.get('message',''), d.get('code',''), d.get('lang','python'))
    return jsonify({'reply': reply})

@app.route('/run', methods=['POST'])
def run(): return jsonify({'output': execute_code(request.json.get('code',''))})

@app.route('/upload-zip', methods=['POST'])
def zip_up():
    try:
        f=request.files['file']; m=io.BytesIO(f.read()); out=io.BytesIO(); o=request.form.get('options','').split(',')
        with zipfile.ZipFile(m,'r') as zi, zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as zo:
            for i in zi.infolist():
                d=zi.read(i.filename)
                try:
                    if i.filename.endswith('.py'): zo.writestr(i.filename, proc_py(d.decode(),o))
                    elif i.filename.endswith('.js'): zo.writestr(i.filename, proc_js(d.decode(),o))
                    else: zo.writestr(i,d)
                except: zo.writestr(i,d)
        out.seek(0); return send_file(out, mimetype='application/zip', as_attachment=True, download_name='Project.zip')
    except Exception as x: return str(x),500

if __name__ == '__main__': app.run(debug=True, port=5000)
