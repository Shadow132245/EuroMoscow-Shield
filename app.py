from flask import Flask, render_template, request, jsonify, send_file
import base64, zlib, binascii, ast, random, io, codecs, re, urllib.parse, zipfile, os
from datetime import datetime

app = Flask(__name__)

BRAND_HEADER = f"# Protected by EuroMoscow Shield\n# https://euromoscow.com\n\n"
JS_HEADER = f"/* Protected by EuroMoscow Shield */\n"
LUA_HEADER = f"-- Protected by EuroMoscow Shield\n"

# =======================
# 1. PYTHON UTILS
# =======================
def inject_dead_code(tree):
    try:
        class DeadInjector(ast.NodeTransformer):
            def visit_FunctionDef(self, node):
                try:
                    # إضافة كود وهمي في بداية كل دالة
                    useless = ast.If(
                        test=ast.Constant(value=False), 
                        body=[ast.Expr(value=ast.Call(func=ast.Name(id='print', ctx=ast.Load()), args=[ast.Constant(value="EM Shield")], keywords=[]))], 
                        orelse=[]
                    )
                    node.body.insert(0, useless)
                except: pass
                return node
        return DeadInjector().visit(tree)
    except: return tree

def random_name(len=8): 
    return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=len))

class SafeRenamer(ast.NodeTransformer):
    def __init__(self, ignore): 
        self.map = {}
        self.ignore = ignore | {'self','args','kwargs','main','__init__'}
        
    def get(self, n):
        if n in self.ignore or n.startswith('__'): return n
        if n not in self.map: self.map[n] = random_name()
        return self.map[n]
        
    def visit_FunctionDef(self, n): 
        if n.name not in self.ignore: n.name = self.get(n.name)
        self.generic_visit(n)
        return n
        
    def visit_ClassDef(self, n):
        if n.name not in self.ignore: n.name = self.get(n.name)
        self.generic_visit(n)
        return n
        
    def visit_Name(self, n):
        if isinstance(n.ctx, (ast.Load, ast.Store, ast.Del)):
            if n.id in self.map: n.id = self.map[n.id]
        return n

def proc_py(code, opts):
    res = code
    if 'rename' in opts or 'deadcode' in opts:
        try:
            tree = ast.parse(res)
            if 'deadcode' in opts: tree = inject_dead_code(tree)
            if 'rename' in opts: tree = SafeRenamer(set(dir(__builtins__))).visit(tree)
            if hasattr(ast,'unparse'): res = ast.unparse(tree)
        except: pass
        
    if 'marshal' in opts: 
        c = zlib.compress(res.encode('utf-8'))
        b = list(c)
        res = f"import zlib;exec(zlib.decompress(bytes({b})),globals())"
        
    if 'zlib' in opts: 
        e = base64.b64encode(zlib.compress(res.encode())).decode()
        res = f"import zlib,base64;exec(zlib.decompress(base64.b64decode({e!r})),globals())"
        
    if 'rot13' in opts: 
        e = codecs.encode(res,'rot13')
        res = f"import codecs;exec(codecs.decode({e!r},'rot13'),globals())"
        
    if 'xor' in opts: 
        k = random.randint(1,255)
        e = [ord(c)^k for c in res]
        res = f"exec(''.join(chr(c^{k})for c in {e}),globals())"
        
    if 'base64' in opts: 
        e = base64.b64encode(res.encode()).decode()
        res = f"import base64;exec(base64.b64decode({e!r}),globals())"
        
    return BRAND_HEADER + res

def dec_py(code):
    curr = code
    pats = {
        'b64':r"base64\.b64decode\((['\"].*?['\"])\)", 
        'zlib':r"zlib\.decompress\((?:base64\.b64decode\((['\"].*?['\"])\)|(['\"].*?['\"]))\)", 
        'rot':r"codecs\.decode\((['\"].*?['\"]),\s*['\"]rot13['\"]\)", 
        'xor':r"c\^(\d+).*?in\s+(\[.*?\])", 
        'blob':r"zlib\.decompress\(bytes\(\[(.*?)\]\)\)"
    }
    
    def se(s): 
        try: return ast.literal_eval(s)
        except: return s.strip("'").strip('"')
    
    for _ in range(25):
        dec = False
        clean = '\n'.join([l for l in curr.split('\n') if not l.strip().startswith('#')]).strip()
        
        m = re.search(pats['b64'], clean)
        if m: 
            try: curr=base64.b64decode(se(m.group(1))).decode(); dec=True
            except: pass
        if not dec:
            m = re.search(pats['zlib'], clean)
            if m: 
                try: curr=zlib.decompress(base64.b64decode(se(m.group(1) or m.group(2)))).decode(); dec=True
                except: pass
        if not dec:
            m = re.search(pats['rot'], clean)
            if m: 
                try: curr=codecs.decode(se(m.group(1)),'rot13'); dec=True
                except: pass
        if not dec:
            m = re.search(pats['xor'], clean)
            if m: 
                try: curr=''.join(chr(c^int(m.group(1))) for c in eval(m.group(2))); dec=True
                except: pass
        if not dec:
            m = re.search(pats['blob'], clean)
            if m: 
                try: curr=zlib.decompress(bytes(eval(f"[{m.group(1)}]"))).decode(); dec=True
                except: pass
        if not dec: break
        
    return curr

# =======================
# 2. JS UTILS
# =======================
def proc_js(code, opts):
    res = code
    if 'hex' in opts: res=f"eval('{''.join([f'\\\\x{ord(c):02x}' for c in res])}')"
    if 'charcode' in opts: res=f"eval(String.fromCharCode({','.join([str(ord(c)) for c in res])}))"
    if 'url' in opts: res=f"eval(decodeURIComponent('{urllib.parse.quote(res)}'))"
    if 'base64' in opts: res=f"eval(atob('{base64.b64encode(res.encode()).decode()}'))"
    return JS_HEADER + res

def dec_js(code):
    curr = code
    pats={
        'b64':r"eval\(atob\(['\"](.*?)['\"]\)\)", 
        'url':r"eval\(decodeURIComponent\(['\"](.*?)['\"]\)\)", 
        'hex':r"eval\(['\"](\\x[0-9a-fA-F]{2}.*?)['\"]\)", 
        'char':r"eval\(String\.fromCharCode\((.*?)\)\)"
    }
    
    for _ in range(25):
        dec = False
        clean = '\n'.join([l for l in curr.split('\n') if not l.strip().startswith('/*')]).strip()
        
        m = re.search(pats['b64'], clean)
        if m: try: curr=base64.b64decode(m.group(1)).decode(); dec=True; except: pass
        
        if not dec:
            m = re.search(pats['url'], clean)
            if m: try: curr=urllib.parse.unquote(m.group(1)); dec=True; except: pass
            
        if not dec:
            m = re.search(pats['hex'], clean)
            if m: try: curr=bytes.fromhex(m.group(1).replace('\\x','')).decode(); dec=True; except: pass
            
        if not dec:
            m = re.search(pats['char'], clean)
            if m: try: curr="".join([chr(int(n)) for n in m.group(1).split(',')]); dec=True; except: pass
            
        if not dec: break
        
    return curr

# =======================
# 3. LUA UTILS
# =======================
def proc_lua(code, opts, exp=''):
    res = code
    # Time Bomb
    if exp:
        try: 
            ts = int(datetime.strptime(exp,"%Y-%m-%d").timestamp())
            res = f"if os.time()>{ts} then error('Expired') end\n{res}"
        except: pass
        
    if 'reverse' in opts: 
        safe = res[::-1].replace('"','\\"').replace("'","\\'")
        res = f"local _f=loadstring or load;_f(string.reverse('{safe}'))()"
        
    if 'hex' in opts: 
        h = "".join([f"{b:02X}" for b in res.encode('utf-8')])
        res = f"local _h=\"{h}\";local _c=\"\";for i=1,#_h,2 do _c=_c..string.char(tonumber(string.sub(_h,i,i+1),16)) end;local _f=loadstring or load;_f(_c)()"
        
    if 'byte' in opts: 
        b = " ".join([str(b) for b in res.encode('utf-8')])
        res = f"local _b=\"{b}\";local _t={{}};for w in string.gmatch(_b,\"%d+\")do table.insert(_t,string.char(tonumber(w))) end;local _f=loadstring or load;_f(table.concat(_t))()"
        
    return LUA_HEADER + res

def dec_lua(code):
    curr = code
    pats = {
        'rev':r"string\.reverse\('((?:[^'\\]|\\.)*)'\)", 
        'hex':r'local _h="([0-9A-Fa-f]+)"', 
        'byte':r'local _b="([\d\s]+)"'
    }
    
    for _ in range(25):
        dec = False
        clean = curr.replace('\n',' ').strip()
        
        m = re.search(pats['rev'], clean)
        # تم إصلاح خطأ المسافات هنا [::-1]
        if m: 
            try: curr=m.group(1).replace("\\'","'").replace('\\"','"')[: : -1].replace(' ',''); curr=curr[::-1]; dec=True
            except: 
                 # محاولة أخرى بدون تنظيف
                 try: curr=m.group(1).replace("\\'","'").replace('\\"','"')[::-1]; dec=True
                 except: pass
        
        if not dec:
            m = re.search(pats['hex'], clean)
            if m: try: curr=bytes.fromhex(m.group(1)).decode('utf-8'); dec=True; except: pass
            
        if not dec:
            m = re.search(pats['byte'], clean)
            if m: try: curr=bytes([int(x) for x in m.group(1).split()]).decode('utf-8'); dec=True; except: pass
            
        if not dec: break
        
    return curr

# =======================
# ROUTES
# =======================
@app.route('/')
def home(): return render_template('index.html')

@app.route('/decryptor')
def pyd(): return render_template('decrypt.html')

@app.route('/js-shield')
def jse(): return render_template('js_encrypt.html')

@app.route('/js-decryptor')
def jsd(): return render_template('js_decrypt.html')

@app.route('/lua-shield')
def lue(): return render_template('lua_encrypt.html')

@app.route('/lua-decryptor')
def lud(): return render_template('lua_decrypt.html')

@app.route('/terminal')
def term(): return render_template('terminal.html')

@app.route('/docs')
def docs(): return render_template('api_docs.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        c = d.get('code','')
        a = d.get('action')
        l = d.get('lang','python')
        o = d.get('options',[])
        e = d.get('expiry','')
        
        res = ""
        if a == 'encrypt':
            if l == 'python': res = proc_py(c, o)
            elif l == 'javascript': res = proc_js(c, o)
            elif l == 'lua': res = proc_lua(c, o, e)
        else:
            if l == 'javascript': res = dec_js(c)
            elif l == 'lua': res = dec_lua(c)
            else: res = dec_py(c)
            
        return jsonify({'result': res})
    except Exception as x: 
        return jsonify({'result': f"Error: {str(x)}"}), 500

@app.route('/upload-zip', methods=['POST'])
def zip_up():
    try:
        f = request.files['file']
        # استخدام الذاكرة بدلاً من الملفات المؤقتة
        mem_zip = io.BytesIO(f.read())
        out_zip = io.BytesIO()
        opts = request.form.get('options','').split(',')
        
        with zipfile.ZipFile(mem_zip, 'r') as zin:
            with zipfile.ZipFile(out_zip, 'w', zipfile.ZIP_DEFLATED) as zo:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    # Check if file is text to avoid decoding errors on images
                    try:
                        if item.filename.endswith('.py'):
                            zo.writestr(item.filename, proc_py(data.decode('utf-8'), opts))
                        elif item.filename.endswith('.js'):
                            zo.writestr(item.filename, proc_js(data.decode('utf-8'), opts))
                        else:
                            zo.writestr(item, data)
                    except:
                        # If decoding fails (binary file), copy as is
                        zo.writestr(item, data)
                        
        out_zip.seek(0)
        return send_file(
            out_zip, 
            mimetype='application/zip', 
            as_attachment=True, 
            download_name='Project_Encrypted.zip'
        )
    except Exception as x: return str(x), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
