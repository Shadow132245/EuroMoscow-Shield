# ==========================================
# Project: EuroMoscow Shield (V11 Final - Full Suite)
# Developer: EuroMoscow
# ==========================================

from flask import Flask, render_template, request, jsonify, send_file
import base64, zlib, binascii, ast, random, io, codecs, re, urllib.parse, zipfile, os
from datetime import datetime

app = Flask(__name__)

BRAND_HEADER = f"# Protected by EuroMoscow Shield\n# https://euro-moscow-shield.vercel.app\n\n"
JS_HEADER = f"/* Protected by EuroMoscow Shield */\n"
LUA_HEADER = f"-- Protected by EuroMoscow Shield\n"

# --- HELPER: DEAD CODE ---
def inject_dead_code(tree):
    try:
        class DeadCodeInjector(ast.NodeTransformer):
            def visit_FunctionDef(self, node):
                try:
                    useless = ast.If(test=ast.Constant(value=False), body=[ast.Expr(value=ast.Call(func=ast.Name(id='print', ctx=ast.Load()), args=[ast.Constant(value="EM Shield")], keywords=[]))], orelse=[])
                    node.body.insert(0, useless)
                except: pass
                return node
        return DeadCodeInjector().visit(tree)
    except: return tree

# --- HELPER: RENAMING ---
def random_var_name(length=8):
    return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=length))

class SafeObfuscator(ast.NodeTransformer):
    def __init__(self, ignore):
        self.mapping = {}; self.ignore = ignore | {'self', 'args', 'kwargs', 'main', '__init__'}
    def get_name(self, name):
        if name in self.ignore or name.startswith('__'): return name
        if name not in self.mapping: self.mapping[name] = random_var_name()
        return self.mapping[name]
    def visit_FunctionDef(self, node):
        if node.name not in self.ignore: node.name = self.get_name(node.name)
        self.generic_visit(node); return node
    def visit_ClassDef(self, node):
        if node.name not in self.ignore: node.name = self.get_name(node.name)
        self.generic_visit(node); return node
    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Load, ast.Store, ast.Del)):
            if node.id in self.mapping: node.id = self.mapping[node.id]
        return node

# --- PYTHON ENGINE ---
def process_python(code, methods):
    result = code
    if 'rename' in methods or 'deadcode' in methods:
        try:
            tree = ast.parse(result)
            if 'deadcode' in methods: tree = inject_dead_code(tree)
            if 'rename' in methods: tree = SafeObfuscator(set(dir(__builtins__))).visit(tree)
            if hasattr(ast, 'unparse'): result = ast.unparse(tree)
        except: pass
    
    if 'marshal' in methods: 
        c = zlib.compress(result.encode('utf-8')); b = list(c)
        result = f"import zlib;exec(zlib.decompress(bytes({b})), globals())"
    if 'zlib' in methods:
        e = base64.b64encode(zlib.compress(result.encode())).decode()
        result = f"import zlib,base64;exec(zlib.decompress(base64.b64decode({e!r})), globals())"
    if 'rot13' in methods:
        e = codecs.encode(result, 'rot13')
        result = f"import codecs;exec(codecs.decode({e!r}, 'rot13'), globals())"
    if 'xor' in methods:
        k = random.randint(1, 255); e = [ord(c) ^ k for c in result]
        result = f"exec(''.join(chr(c^{k})for c in {e}), globals())"
    if 'base64' in methods:
        e = base64.b64encode(result.encode()).decode()
        result = f"import base64;exec(base64.b64decode({e!r}), globals())"
    return BRAND_HEADER + result

def smart_py_decrypt(code):
    curr = code; max_l = 25
    pats = {'b64':r"base64\.b64decode\((['\"].*?['\"])\)", 'zlib':r"zlib\.decompress\((?:base64\.b64decode\((['\"].*?['\"])\)|(['\"].*?['\"]))\)", 'rot':r"codecs\.decode\((['\"].*?['\"]),\s*['\"]rot13['\"]\)", 'xor':r"c\^(\d+).*?in\s+(\[.*?\])", 'blob':r"zlib\.decompress\(bytes\(\[(.*?)\]\)\)"}
    def s_eval(s): 
        try: return ast.literal_eval(s) 
        except: return s.strip("'").strip('"')
    
    for _ in range(max_l):
        dec = False; clean = '\n'.join([l for l in curr.split('\n') if not l.strip().startswith('#')]).strip()
        m = re.search(pats['b64'], clean)
        if m: 
            try: curr = base64.b64decode(s_eval(m.group(1))).decode(); dec = True
            except: pass
        if not dec:
            m = re.search(pats['zlib'], clean)
            if m:
                try: curr = zlib.decompress(base64.b64decode(s_eval(m.group(1) or m.group(2)))).decode(); dec = True
                except: pass
        if not dec:
            m = re.search(pats['rot'], clean)
            if m: 
                try: curr = codecs.decode(s_eval(m.group(1)), 'rot13'); dec = True
                except: pass
        if not dec:
            m = re.search(pats['xor'], clean)
            if m:
                try: curr = ''.join(chr(c ^ int(m.group(1))) for c in eval(m.group(2))); dec = True
                except: pass
        if not dec:
            m = re.search(pats['blob'], clean)
            if m:
                try: curr = zlib.decompress(bytes(eval(f"[{m.group(1)}]"))).decode(); dec = True
                except: pass
        if not dec: break
    return curr

# --- JS ENGINE ---
def process_js_code(code, methods):
    res = code
    if 'hex' in methods: res = f"eval('{''.join([f'\\\\x{ord(c):02x}' for c in res])}')"
    if 'charcode' in methods: res = f"eval(String.fromCharCode({','.join([str(ord(c)) for c in res])}))"
    if 'url' in methods: res = f"eval(decodeURIComponent('{urllib.parse.quote(res)}'))"
    if 'base64' in methods: res = f"eval(atob('{base64.b64encode(res.encode()).decode()}'))"
    return JS_HEADER + res

def smart_js_decrypt(code):
    curr = code; max_l = 25
    pats = {'b64': r"eval\(atob\(['\"](.*?)['\"]\)\)", 'url': r"eval\(decodeURIComponent\(['\"](.*?)['\"]\)\)", 'hex': r"eval\(['\"](\\x[0-9a-fA-F]{2}.*?)['\"]\)", 'char': r"eval\(String\.fromCharCode\((.*?)\)\)"}
    for _ in range(max_l):
        dec = False; clean = '\n'.join([l for l in curr.split('\n') if not l.strip().startswith('/*')]).strip()
        m = re.search(pats['b64'], clean)
        if m: 
            try: curr = base64.b64decode(m.group(1)).decode(); dec = True 
            except: pass
        if not dec:
            m = re.search(pats['url'], clean)
            if m: 
                try: curr = urllib.parse.unquote(m.group(1)); dec = True 
                except: pass
        if not dec:
            m = re.search(pats['hex'], clean)
            if m: 
                try: curr = bytes.fromhex(m.group(1).replace('\\x', '')).decode(); dec = True 
                except: pass
        if not dec:
            m = re.search(pats['char'], clean)
            if m: 
                try: curr = "".join([chr(int(n)) for n in m.group(1).split(',')]); dec = True 
                except: pass
        if not dec: break
    return curr

# --- LUA ENGINE ---
def process_lua_code(code, methods, expiry=''):
    res = code
    # Time Bomb
    if expiry:
        try:
            ts = int(datetime.strptime(expiry, "%Y-%m-%d").timestamp())
            res = f"if os.time()>{ts} then error('License Expired') end\n{res}"
        except: pass
        
    if 'reverse' in methods:
        safe_rev = res[::-1].replace('"', '\\"').replace("'", "\\'")
        res = f"local _f=loadstring or load;_f(string.reverse('{safe_rev}'))()"
    if 'hex' in methods:
        h = "".join([f"{b:02X}" for b in res.encode('utf-8')])
        res = f"local _h=\"{h}\";local _c=\"\";for i=1,#_h,2 do _c=_c..string.char(tonumber(string.sub(_h,i,i+1),16)) end;local _f=loadstring or load;_f(_c)()"
    if 'byte' in methods:
        b = " ".join([str(b) for b in res.encode('utf-8')])
        res = f"local _b=\"{b}\";local _t={{}};for w in string.gmatch(_b,\"%d+\")do table.insert(_t,string.char(tonumber(w))) end;local _f=loadstring or load;_f(table.concat(_t))()"
    return LUA_HEADER + res

def smart_lua_decrypt(code):
    curr = code; max_l = 25
    pats = {
        'rev': r"string\.reverse\('((?:[^'\\]|\\.)*)'\)",
        'hex': r'local _h="([0-9A-Fa-f]+)"',
        'byte': r'local _b="([\d\s]+)"'
    }
    for _ in range(max_l):
        dec = False; clean = curr.replace('\n', ' ').strip()
        m = re.search(pats['rev'], clean)
        if m:
            try: curr = m.group(1).replace("\\'", "'").replace('\\"', '"')[::-1]; dec = True
            except: pass
        if not dec:
            m = re.search(pats['hex'], clean)
            if m:
                try: curr = bytes.fromhex(m.group(1)).decode('utf-8'); dec = True
                except: pass
        if not dec:
            m = re.search(pats['byte'], clean)
            if m:
                try: curr = bytes([int(x) for x in m.group(1).split()]).decode('utf-8'); dec = True
                except: pass
        if not dec: break
    return curr

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')
@app.route('/decryptor')
def py_dec(): return render_template('decrypt.html')
@app.route('/js-shield')
def js_enc(): return render_template('js_encrypt.html')
@app.route('/js-decryptor')
def js_dec(): return render_template('js_decrypt.html')
@app.route('/lua-shield')
def lua_enc(): return render_template('lua_encrypt.html')
@app.route('/lua-decryptor') # NEW
def lua_dec(): return render_template('lua_decrypt.html')
@app.route('/terminal')
def term(): return render_template('terminal.html')
@app.route('/docs')
def docs(): return render_template('api_docs.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json; code = d.get('code',''); act = d.get('action'); lang = d.get('lang','python'); opts = d.get('options',[]); exp = d.get('expiry','')
        res = ""
        if act == 'encrypt':
            if lang == 'python': res = process_python(code, opts)
            elif lang == 'javascript': res = process_js_code(code, opts)
            elif lang == 'lua': res = process_lua_code(code, opts, exp)
        else:
            if lang == 'javascript': res = smart_js_decrypt(code)
            elif lang == 'lua': res = smart_lua_decrypt(code)
            else: res = smart_py_decrypt(code)
        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"Error: {str(e)}"}), 500

@app.route('/upload-zip', methods=['POST'])
def upload_zip():
    # Zip handling logic same as before (shortened for brevity but keep original logic)
    try:
        f = request.files['file']; m = io.BytesIO()
        with zipfile.ZipFile(f,'r') as zin, zipfile.ZipFile(m,'w',zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename.endswith('.py'):
                    try: zout.writestr(item.filename, process_python(data.decode(), ['rename','marshal']))
                    except: zout.writestr(item, data)
                else: zout.writestr(item, data)
        m.seek(0); return send_file(m, mimetype='application/zip', as_attachment=True, download_name='Protected.zip')
    except Exception as e: return str(e), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
