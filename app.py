from flask import Flask, render_template, request, jsonify, send_file
import base64
import zlib
import binascii
import ast
import random
import io
import codecs
import re
import urllib.parse
import zipfile
import os
from datetime import datetime

app = Flask(__name__)

BRAND_HEADER = "# Protected by EuroMoscow Shield V21\n# https://euro-moscow-shield.vercel.app\n\n"
JS_HEADER = "/* Protected by EuroMoscow Shield V21 */\n"
LUA_HEADER = "-- Protected by EuroMoscow Shield V21\n"

# --- UTILS ---
def random_name(len=8):
    return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=len))

# --- 1. ENGINES ---

# Python Processing
def proc_py(code, opts):
    res = code
    try:
        if 'rename' in opts or 'deadcode' in opts:
            try:
                tree = ast.parse(res)
                
                # Dead Code Injection
                if 'deadcode' in opts:
                    class DeadInjector(ast.NodeTransformer):
                        def visit_FunctionDef(self, node):
                            try:
                                useless = ast.If(
                                    test=ast.Constant(value=False),
                                    body=[ast.Expr(value=ast.Call(func=ast.Name(id='print', ctx=ast.Load()), args=[ast.Constant(value="EM Shield")], keywords=[]))],
                                    orelse=[]
                                )
                                node.body.insert(0, useless)
                            except: pass
                            return node
                    tree = DeadInjector().visit(tree)

                # Variable Renaming
                if 'rename' in opts:
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
                    
                    tree = SafeRenamer(set(dir(__builtins__))).visit(tree)

                if hasattr(ast, 'unparse'):
                    res = ast.unparse(tree)
            except:
                pass

        if 'marshal' in opts:
            c = zlib.compress(res.encode('utf-8'))
            b = list(c)
            res = f"import zlib;exec(zlib.decompress(bytes({b})),globals())"
        
        if 'zlib' in opts:
            e = base64.b64encode(zlib.compress(res.encode())).decode()
            res = f"import zlib,base64;exec(zlib.decompress(base64.b64decode({e!r})),globals())"
        
        if 'rot13' in opts:
            e = codecs.encode(res, 'rot13')
            res = f"import codecs;exec(codecs.decode({e!r},'rot13'),globals())"
        
        if 'xor' in opts:
            k = random.randint(1, 255)
            e = [ord(c) ^ k for c in res]
            res = f"exec(''.join(chr(c^{k})for c in {e}),globals())"
        
        if 'base64' in opts:
            e = base64.b64encode(res.encode()).decode()
            res = f"import base64;exec(base64.b64decode({e!r}),globals())"
            
        return BRAND_HEADER + res
    except:
        return code

# Python Decrypt
def dec_py(code):
    curr = code
    pats = {
        'b64': r"base64\.b64decode\((['\"].*?['\"])\)",
        'zlib': r"zlib\.decompress\((?:base64\.b64decode\((['\"].*?['\"])\)|(['\"].*?['\"]))\)",
        'rot': r"codecs\.decode\((['\"].*?['\"]),\s*['\"]rot13['\"]\)",
        'xor': r"c\^(\d+).*?in\s+(\[.*?\])",
        'blob': r"zlib\.decompress\(bytes\(\[(.*?)\]\)\)"
    }
    
    def se(s):
        try:
            return ast.literal_eval(s)
        except:
            return s.strip("'").strip('"')
    
    for _ in range(25):
        dec = False
        clean = '\n'.join([l for l in curr.split('\n') if not l.strip().startswith('#')]).strip()
        
        m = re.search(pats['b64'], clean)
        if m:
            try:
                curr = base64.b64decode(se(m.group(1))).decode()
                dec = True
            except: pass
        
        if not dec:
            m = re.search(pats['zlib'], clean)
            if m:
                try:
                    curr = zlib.decompress(base64.b64decode(se(m.group(1) or m.group(2)))).decode()
                    dec = True
                except: pass
                
        if not dec:
            m = re.search(pats['rot'], clean)
            if m:
                try:
                    curr = codecs.decode(se(m.group(1)), 'rot13')
                    dec = True
                except: pass
                
        if not dec:
            m = re.search(pats['xor'], clean)
            if m:
                try:
                    curr = ''.join(chr(c ^ int(m.group(1))) for c in eval(m.group(2)))
                    dec = True
                except: pass
                
        if not dec:
            m = re.search(pats['blob'], clean)
            if m:
                try:
                    curr = zlib.decompress(bytes(eval(f"[{m.group(1)}]"))).decode()
                    dec = True
                except: pass
                
        if not dec: break
    return curr

# JS Engine
def proc_js(code, opts):
    res = code
    if 'hex' in opts:
        res = f"eval('{''.join([f'\\\\x{ord(c):02x}' for c in res])}')"
    if 'charcode' in opts:
        res = f"eval(String.fromCharCode({','.join([str(ord(c)) for c in res])}))"
    if 'url' in opts:
        res = f"eval(decodeURIComponent('{urllib.parse.quote(res)}'))"
    if 'base64' in opts:
        res = f"eval(atob('{base64.b64encode(res.encode()).decode()}'))"
    return JS_HEADER + res

def dec_js(code):
    curr = code
    pats = {
        'b64': r"eval\(atob\(['\"](.*?)['\"]\)\)",
        'url': r"eval\(decodeURIComponent\(['\"](.*?)['\"]\)\)",
        'hex': r"eval\(['\"](\\x[0-9a-fA-F]{2}.*?)['\"]\)",
        'char': r"eval\(String\.fromCharCode\((.*?)\)\)"
    }
    for _ in range(25):
        dec = False
        clean = '\n'.join([l for l in curr.split('\n') if not l.strip().startswith('/*')]).strip()
        
        m = re.search(pats['b64'], clean)
        if m:
            try:
                curr = base64.b64decode(m.group(1)).decode()
                dec = True
            except: pass
            
        if not dec:
            m = re.search(pats['url'], clean)
            if m:
                try:
                    curr = urllib.parse.unquote(m.group(1))
                    dec = True
                except: pass
                
        if not dec:
            m = re.search(pats['hex'], clean)
            if m:
                try:
                    curr = bytes.fromhex(m.group(1).replace('\\x', '')).decode()
                    dec = True
                except: pass
                
        if not dec:
            m = re.search(pats['char'], clean)
            if m:
                try:
                    curr = "".join([chr(int(n)) for n in m.group(1).split(',')])
                    dec = True
                except: pass
        
        if not dec: break
    return curr

# Lua Engine
def proc_lua(code, opts, exp=''):
    res = code
    if exp:
        try:
            ts = int(datetime.strptime(exp, "%Y-%m-%d").timestamp())
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
        'rev': r"string\.reverse\('((?:[^'\\]|\\.)*)'\)",
        'hex': r'local _h="([0-9A-Fa-f]+)"',
        'byte': r'local _b="([\d\s]+)"'
    }
    for _ in range(25):
        dec = False
        clean = curr.replace('\n', ' ').strip()
        
        m = re.search(pats['rev'], clean)
        if m:
            try:
                curr = m.group(1).replace("\\'", "'").replace('\\"', '"')[::-1]
                dec = True
            except: pass
            
        if not dec:
            m = re.search(pats['hex'], clean)
            if m:
                try:
                    curr = bytes.fromhex(m.group(1)).decode('utf-8')
                    dec = True
                except: pass
                
        if not dec:
            m = re.search(pats['byte'], clean)
            if m:
                try:
                    curr = bytes([int(x) for x in m.group(1).split()]).decode('utf-8')
                    dec = True
                except: pass
                
        if not dec: break
    return curr

# PHP & HTML Engine
def proc_php(code, opts):
    try:
        cln = code.replace('<?php', '').replace('?>', '').strip()
        b64 = base64.b64encode(zlib.compress(cln.encode())).decode()
        return f"<?php /* EuroMoscow */ eval(gzuncompress(base64_decode('{b64}'))); ?>"
    except: return code

def dec_php(code):
    try:
        m = re.search(r"base64_decode\('([^']+)'\)", code)
        if m:
            return zlib.decompress(base64.b64decode(m.group(1))).decode('utf-8')
    except: pass
    return code

def proc_html(code, opts):
    try:
        enc = urllib.parse.quote(code)
        return f"<script>document.write(decodeURIComponent('{enc}'));</script>"
    except: return code

def dec_html(code):
    try:
        m = re.search(r"decodeURIComponent\('([^']+)'\)", code)
        if m:
            return urllib.parse.unquote(m.group(1))
    except: pass
    return code

# --- AI ENGINE ---
def analyze_code(code, lang):
    score = 100
    msg = []
    if len(code) < 20: return {"score": 10, "msg": "Code too short."}
    if 'import' in code: msg.append("Libraries detected.")
    if 'os.' in code or 'eval' in code:
        score -= 30
        msg.append("⚠️ Unsafe functions found.")
    return {"score": score, "msg": " | ".join(msg) if msg else "Clean code structure."}

def chat_ai(msg):
    msg = msg.lower()
    if "hello" in msg: return "Welcome to EuroMoscow Shield V21! 🛡️"
    if "analyze" in msg: return "Use the 'AI SCAN' button to check code."
    return "I am EuroMind. I secure code using polymorphic layers."

# --- ROUTES ---
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
        c = d.get('code', '')
        a = d.get('action')
        l = d.get('lang', 'python')
        o = d.get('options', [])
        e = d.get('expiry', '')
        
        res = ""
        if a == 'encrypt':
            if l == 'python': res = proc_py(c, o)
            elif l == 'javascript': res = proc_js(c, o)
            elif l == 'lua': res = proc_lua(c, o, e)
            elif l == 'php': res = proc_php(c, o)
            elif l == 'html': res = proc_html(c, o)
        else:
            if l == 'javascript': res = dec_js(c)
            elif l == 'lua': res = dec_lua(c)
            elif l == 'php': res = dec_php(c)
            elif l == 'html': res = dec_html(c)
            else: res = dec_py(c)
        return jsonify({'result': res})
    except Exception as x:
        return jsonify({'result': f"Error: {str(x)}"}), 500

@app.route('/analyze', methods=['POST'])
def analyze():
    return jsonify(analyze_code(request.json.get('code', ''), request.json.get('lang', 'python')))

@app.route('/chat', methods=['POST'])
def chat():
    return jsonify({'reply': chat_ai(request.json.get('message', ''))})

@app.route('/upload-zip', methods=['POST'])
def zip_up():
    try:
        f = request.files['file']
        m = io.BytesIO(f.read())
        out = io.BytesIO()
        opts = request.form.get('options', '').split(',')
        
        with zipfile.ZipFile(m, 'r') as zi:
            with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zo:
                for i in zi.infolist():
                    d = zi.read(i.filename)
                    try:
                        if i.filename.endswith('.py'):
                            zo.writestr(i.filename, proc_py(d.decode('utf-8'), opts))
                        elif i.filename.endswith('.js'):
                            zo.writestr(i.filename, proc_js(d.decode('utf-8'), opts))
                        else:
                            zo.writestr(i, d)
                    except:
                        zo.writestr(i, d)
        
        out.seek(0)
        return send_file(out, mimetype='application/zip', as_attachment=True, download_name='Project_Encrypted.zip')
    except Exception as x:
        return str(x), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
