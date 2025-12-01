from flask import Flask, render_template, request, jsonify
import base64, zlib, binascii, ast, random, codecs, urllib.parse

app = Flask(__name__)

# --- ENGINES ---
def random_name(len=8): 
    return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=len))

# 1. PYTHON ENGINE
def proc_py(code, level):
    res = code
    try:
        # Rename (Balanced/Max)
        if level in ['balanced', 'max']:
            class Renamer(ast.NodeTransformer):
                def __init__(self): self.map={}
                def visit_Name(self, n):
                    if isinstance(n.ctx, (ast.Store, ast.Del)) and n.id not in dir(__builtins__):
                        if n.id not in self.map: self.map[n.id] = random_name()
                    return n
            res = ast.unparse(Renamer().visit(ast.parse(res)))

        # Dead Code (Max Only)
        if level == 'max':
            tree = ast.parse(res)
            useless = ast.If(test=ast.Constant(value=False), body=[ast.Expr(value=ast.Call(func=ast.Name(id='print', ctx=ast.Load()), args=[ast.Constant(value="EM Shield")], keywords=[]))], orelse=[])
            tree.body.insert(0, useless)
            res = ast.unparse(tree)
        
        # Encryption
        if level == 'max':
            c = zlib.compress(res.encode()); b=list(c)
            res = f"import zlib;exec(zlib.decompress(bytes({b})),globals())"
        
        e = base64.b64encode(res.encode()).decode()
        return f"# Protected by EuroMoscow V13\nimport base64;exec(base64.b64decode('{e}'))"
    except: return code

# 2. JS ENGINE
def proc_js(code, level):
    try:
        res = code
        if level == 'max': # Hex
            res = f"eval('{''.join([f'\\\\x{ord(c):02x}' for c in res])}')"
        b64 = base64.b64encode(res.encode()).decode()
        return f"/* EuroMoscow V13 */\neval(atob('{b64}'))"
    except: return code

# 3. LUA ENGINE
def proc_lua(code, level):
    try:
        res = code
        if level == 'max': # Reverse
             res = f"local _f=loadstring or load;_f(string.reverse('{res[::-1]}'))()"
        b = " ".join([str(ord(c)) for c in res])
        loader = f"""local _b="{b}";local _t={{}};for w in string.gmatch(_b,"%d+")do table.insert(_t,string.char(tonumber(w))) end;local _f=loadstring or load;_f(table.concat(_t))()"""
        return f"-- EuroMoscow V13\n{loader}"
    except: return code

# 4. PHP & HTML
def proc_php(code, level):
    try:
        clean = code.replace('<?php', '').replace('?>', '').strip()
        b64 = base64.b64encode(clean.encode()).decode()
        return f"<?php /* EuroMoscow V13 */ eval(base64_decode('{b64}')); ?>"
    except: return code

def proc_html(code, level):
    return f"<script>document.write(decodeURIComponent('{urllib.parse.quote(code)}'));</script>"

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/docs')
def api_docs(): return render_template('api_docs.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json; c = d.get('code', ''); lang = d.get('lang', 'python'); level = d.get('level', 'balanced')
        
        if lang == 'python': res = proc_py(c, level)
        elif lang == 'javascript': res = proc_js(c, level)
        elif lang == 'lua': res = proc_lua(c, level)
        elif lang == 'php': res = proc_php(c, level)
        elif lang == 'html': res = proc_html(c, level)
        else: res = c
        
        return jsonify({'result': res})
    except: return jsonify({'result': c})

if __name__ == '__main__': app.run(debug=True, port=5000)
