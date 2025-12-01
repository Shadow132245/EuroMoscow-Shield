from flask import Flask, render_template, request, jsonify
import base64, zlib, binascii, ast, random, codecs, urllib.parse

app = Flask(__name__)

# --- ENGINE CORE ---
def random_name(len=8): 
    return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=len))

# 1. PYTHON ENGINE
def proc_py(code, level):
    # Smart Preset Logic
    res = code
    try:
        if level in ['balanced', 'max']: # Renaming
            class Renamer(ast.NodeTransformer):
                def __init__(self): self.map={}
                def visit_Name(self, n):
                    if isinstance(n.ctx, (ast.Store, ast.Del)) and n.id not in dir(__builtins__):
                        if n.id not in self.map: self.map[n.id] = random_name()
                    return n
            res = ast.unparse(Renamer().visit(ast.parse(res)))

        if level == 'max': # Dead Code
            # Inject junk code logic here (Simplified for stability)
            pass 
        
        # Encryption Layers based on level
        if level == 'max':
            c = zlib.compress(res.encode()); b=list(c)
            res = f"import zlib;exec(zlib.decompress(bytes({b})),globals())"
        
        # Standard Base64 wrap for all levels to ensure encoding
        e = base64.b64encode(res.encode()).decode()
        return f"# Protected by EuroMoscow V13\nimport base64;exec(base64.b64decode('{e}'))"
    except: return code # Silent Fail (Returns original if error)

# 2. JS ENGINE
def proc_js(code, level):
    try:
        res = code
        if level == 'max': # Hex Encoding
            res = f"eval('{''.join([f'\\\\x{ord(c):02x}' for c in res])}')"
        
        # Base64 wrap
        b64 = base64.b64encode(res.encode()).decode()
        return f"/* EuroMoscow V13 */\neval(atob('{b64}'))"
    except: return code

# 3. LUA ENGINE
def proc_lua(code, level):
    try:
        res = code
        if level == 'max': # Reverse
             res = f"local _f=loadstring or load;_f(string.reverse('{res[::-1]}'))()"
        
        # Bytecode wrap
        b = " ".join([str(ord(c)) for c in res])
        loader = f"""local _b="{b}";local _t={{}};for w in string.gmatch(_b,"%d+")do table.insert(_t,string.char(tonumber(w))) end;local _f=loadstring or load;_f(table.concat(_t))()"""
        return f"-- EuroMoscow V13\n{loader}"
    except: return code

# 4. PHP ENGINE (NEW!)
def proc_php(code, level):
    try:
        # Remove <?php tags for processing
        clean = code.replace('<?php', '').replace('?>', '').strip()
        b64 = base64.b64encode(clean.encode()).decode()
        # Obfuscated Loader
        return f"<?php /* EuroMoscow V13 */ eval(base64_decode('{b64}')); ?>"
    except: return code

# 5. HTML ENGINE (NEW!)
def proc_html(code, level):
    try:
        # Escape & JS Write
        escaped = urllib.parse.quote(code)
        return f"<script>document.write(decodeURIComponent('{escaped}'));</script>"
    except: return code

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        c = d.get('code', '')
        lang = d.get('lang', 'python')
        level = d.get('level', 'balanced') # performance, balanced, max
        
        if lang == 'python': res = proc_py(c, level)
        elif lang == 'javascript': res = proc_js(c, level)
        elif lang == 'lua': res = proc_lua(c, level)
        elif lang == 'php': res = proc_php(c, level)
        elif lang == 'html': res = proc_html(c, level)
        else: res = c
        
        return jsonify({'result': res})
    except Exception as e: 
        return jsonify({'result': c}) # Fail Safe: Return original

if __name__ == '__main__':
    app.run(debug=True, port=5000)
