# ==========================================
# Project: EuroMoscow Shield (V10 Ultimate - Lua & ZIP Support)
# Developer: EuroMoscow
# ==========================================

from flask import Flask, render_template, request, jsonify, send_file, make_response
import base64, zlib, binascii, ast, random, io, codecs, re, urllib.parse, zipfile, os

app = Flask(__name__)

# --- Configuration ---
BRAND_HEADER = f"# Protected by EuroMoscow Shield\n# https://euro-moscow-shield.vercel.app\n\n"
JS_HEADER = f"/* Protected by EuroMoscow Shield */\n"
LUA_HEADER = f"-- Protected by EuroMoscow Shield\n"

# ==========================================
# PART 1: PYTHON ENGINE (+ DEAD CODE)
# ==========================================

def inject_dead_code(tree):
    """Adds useless code/logic to confuse readers"""
    class DeadCodeInjector(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            # Create a fake random operation
            useless_op = ast.If(
                test=ast.Constant(value=False),
                body=[ast.Expr(value=ast.Call(
                    func=ast.Name(id='print', ctx=ast.Load()),
                    args=[ast.Constant(value="EuroMoscow Logic Check")],
                    keywords=[]
                ))],
                orelse=[]
            )
            # Insert at the beginning of the function
            node.body.insert(0, useless_op)
            return node
    
    transformer = DeadCodeInjector()
    new_tree = transformer.visit(tree)
    ast.fix_missing_locations(new_tree)
    return new_tree

# ... (Previous renaming logic kept simple for stability) ...
def random_var_name(length=8):
    return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=length))

class SafeObfuscator(ast.NodeTransformer):
    def __init__(self, ignore_list):
        self.mapping = {}
        self.ignore = ignore_list | {'self', 'args', 'kwargs', 'main', '__name__', '__init__'}
    def get_new_name(self, name):
        if name in self.ignore or name.startswith('__'): return name
        if name in self.mapping: return self.mapping[name]
        self.mapping[name] = random_var_name()
        return self.mapping[name]
    def visit_FunctionDef(self, node):
        if node.name not in self.ignore: node.name = self.get_new_name(node.name)
        self.generic_visit(node)
        return node
    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Load, ast.Store, ast.Del)):
            if node.id in self.mapping: node.id = self.mapping[node.id]
        return node

def process_python(code, methods):
    result = code
    
    # Dead Code Injection (New!)
    if 'deadcode' in methods:
        try:
            tree = ast.parse(result)
            tree = inject_dead_code(tree)
            result = ast.unparse(tree)
        except: pass

    # Renaming
    if 'rename' in methods:
        try:
            tree = ast.parse(result)
            transformer = SafeObfuscator(set(dir(__builtins__)))
            tree = transformer.visit(tree)
            result = ast.unparse(tree)
        except: pass

    # Encryption Layers
    if 'marshal' in methods: 
        compressed = zlib.compress(result.encode('utf-8')); blob = list(compressed)
        result = f"import zlib;exec(zlib.decompress(bytes({blob})), globals())"
    if 'zlib' in methods:
        enc = base64.b64encode(zlib.compress(result.encode())).decode()
        result = f"import zlib,base64;exec(zlib.decompress(base64.b64decode({enc!r})), globals())"
    if 'rot13' in methods:
        encoded = codecs.encode(result, 'rot13')
        result = f"import codecs;exec(codecs.decode({encoded!r}, 'rot13'), globals())"
    if 'xor' in methods:
        key = random.randint(1, 255); encrypted_chars = [ord(c) ^ key for c in result]
        result = f"exec(''.join(chr(c^{key})for c in {encrypted_chars}), globals())"
    if 'base64' in methods:
        enc = base64.b64encode(result.encode()).decode()
        result = f"import base64;exec(base64.b64decode({enc!r}), globals())"
    
    return BRAND_HEADER + result

def smart_py_decrypt(code):
    # ... (Same logic as before) ...
    current = code; max_l = 25
    patterns = { 'b64': r"base64\.b64decode\((['\"].*?['\"])\)", 'zlib': r"zlib\.decompress\((?:base64\.b64decode\((['\"].*?['\"])\)|(['\"].*?['\"]))\)", 'rot13': r"codecs\.decode\((['\"].*?['\"]),\s*['\"]rot13['\"]\)", 'xor': r"c\^(\d+).*?in\s+(\[.*?\])", 'blob': r"zlib\.decompress\(bytes\(\[(.*?)\]\)\)" }
    def safe_eval(s):
        try: return ast.literal_eval(s)
        except: return s.strip("'").strip('"')
    for _ in range(max_l):
        decoded = False; clean = '\n'.join([l for l in current.split('\n') if not l.strip().startswith('#')]).strip()
        m = re.search(patterns['b64'], clean)
        if m: 
            try: current = base64.b64decode(safe_eval(m.group(1))).decode(); decoded = True
            except: pass
        if not decoded:
            m = re.search(patterns['zlib'], clean)
            if m:
                try: current = zlib.decompress(base64.b64decode(safe_eval(m.group(1) or m.group(2)))).decode(); decoded = True
                except: pass
        if not decoded:
            m = re.search(patterns['rot13'], clean)
            if m: 
                try: current = codecs.decode(safe_eval(m.group(1)), 'rot13'); decoded = True
                except: pass
        if not decoded:
            m = re.search(patterns['xor'], clean)
            if m:
                try: current = ''.join(chr(c ^ int(m.group(1))) for c in eval(m.group(2))); decoded = True
                except: pass
        if not decoded:
            m = re.search(patterns['blob'], clean)
            if m:
                try: current = zlib.decompress(bytes(eval(f"[{m.group(1)}]"))).decode(); decoded = True
                except: pass
        if not decoded: break
    return current

# ==========================================
# PART 2: JS ENGINE (Same as before)
# ==========================================
# ... (Standard JS functions kept for brevity, they are the same as V9) ...
def js_encrypt_hex(code): return f"eval('{''.join([f'\\\\x{ord(c):02x}' for c in code])}')"
def js_encrypt_base64(code): return f"eval(atob('{base64.b64encode(code.encode()).decode()}'))"
def js_encrypt_url(code): return f"eval(decodeURIComponent('{urllib.parse.quote(code)}'))"
def js_encrypt_charcode(code): return f"eval(String.fromCharCode({','.join([str(ord(c)) for c in code])}))"

def process_js_code(code, methods):
    result = code
    if 'hex' in methods: result = js_encrypt_hex(result)
    if 'charcode' in methods: result = js_encrypt_charcode(result)
    if 'url' in methods: result = js_encrypt_url(result)
    if 'base64' in methods: result = js_encrypt_base64(result)
    return JS_HEADER + result

def smart_js_decrypt(code):
    # ... (Same as V9) ...
    current = code; max_l = 25
    patterns = { 'base64': r"eval\(atob\(['\"](.*?)['\"]\)\)", 'url': r"eval\(decodeURIComponent\(['\"](.*?)['\"]\)\)", 'hex': r"eval\(['\"](\\x[0-9a-fA-F]{2}.*?)['\"]\)", 'charcode': r"eval\(String\.fromCharCode\((.*?)\)\)" }
    for _ in range(max_l):
        decoded = False; clean = '\n'.join([l for l in current.split('\n') if not l.strip().startswith('/*')]).strip()
        m = re.search(patterns['base64'], clean)
        if m:
            try: current = base64.b64decode(m.group(1)).decode(); decoded = True
            except: pass
        if not decoded:
            m = re.search(patterns['url'], clean)
            if m:
                try: current = urllib.parse.unquote(m.group(1)); decoded = True
                except: pass
        if not decoded:
            m = re.search(patterns['hex'], clean)
            if m:
                try: current = bytes.fromhex(m.group(1).replace('\\x', '')).decode(); decoded = True
                except: pass
        if not decoded:
            m = re.search(patterns['charcode'], clean)
            if m:
                try: current = "".join([chr(int(n)) for n in m.group(1).split(',')]); decoded = True
                except: pass
        if not decoded: break
    return current

# ==========================================
# PART 3: LUA ENGINE (NEW!)
# ==========================================

def lua_encrypt_byte(code):
    # تحويل لـ String.char
    chars = ",".join([str(ord(c)) for c in code])
    return f"load(string.char({chars}))()"

def lua_encrypt_hex(code):
    hex_code = "".join([f"\\x{ord(c):02X}" for c in code])
    return f"load('{hex_code}')()"

def lua_encrypt_reverse(code):
    rev = code[::-1]
    return f"load(string.reverse('{rev}'))()"

def process_lua_code(code, methods):
    result = code
    if 'reverse' in methods: result = lua_encrypt_reverse(result)
    if 'hex' in methods: result = lua_encrypt_hex(result)
    if 'byte' in methods: result = lua_encrypt_byte(result)
    return LUA_HEADER + result

# ==========================================
# PART 4: ZIP PROCESSOR (NEW!)
# ==========================================
def process_zip_file(file_storage, methods):
    in_memory_zip = io.BytesIO()
    
    with zipfile.ZipFile(file_storage, 'r') as z_in:
        with zipfile.ZipFile(in_memory_zip, 'w', zipfile.ZIP_DEFLATED) as z_out:
            for item in z_in.infolist():
                file_data = z_in.read(item.filename)
                
                # Check extension
                if item.filename.endswith('.py'):
                    # Obfuscate Python
                    try:
                        code_str = file_data.decode('utf-8')
                        obfuscated = process_python(code_str, methods)
                        z_out.writestr(item.filename, obfuscated)
                    except:
                        z_out.writestr(item, file_data) # Keep original if fail
                        
                elif item.filename.endswith('.js'):
                    # Obfuscate JS
                    try:
                        code_str = file_data.decode('utf-8')
                        obfuscated = process_js_code(code_str, methods)
                        z_out.writestr(item.filename, obfuscated)
                    except:
                        z_out.writestr(item, file_data)
                else:
                    # Keep other files (images, configs) as is
                    z_out.writestr(item, file_data)
    
    in_memory_zip.seek(0)
    return in_memory_zip

# ==========================================
# ROUTES
# ==========================================

@app.route('/')
def home(): return render_template('index.html')

@app.route('/js-shield')
def js_page(): return render_template('js_encrypt.html')

@app.route('/lua-shield') # New Lua Page
def lua_page(): return render_template('lua_encrypt.html')

@app.route('/decryptor')
def decrypt_page(): return render_template('decrypt.html')

@app.route('/js-decryptor')
def js_dec_page(): return render_template('js_decrypt.html')
    
@app.route('/')
def home(): return render_template('index.html')

@app.route('/terminal')
def terminal_page(): return render_template('terminal.html')

@app.route('/docs')
def api_docs(): return render_template('api_docs.html')

@app.route('/process', methods=['POST'])
def process():
    data = request.json
    code = data.get('code')
    action = data.get('action')
    lang = data.get('lang', 'python')
    options = data.get('options', [])

    result = ""
    if action == 'encrypt':
        if lang == 'python': result = process_python(code, options)
        elif lang == 'javascript': result = process_js_code(code, options)
        elif lang == 'lua': result = process_lua_code(code, options)
    else:
        if lang == 'javascript': result = smart_js_decrypt(code)
        else: result = smart_py_decrypt(code) # Lua decrypt not auto yet

    return jsonify({'result': result})

# New Route for ZIP Upload
@app.route('/upload-zip', methods=['POST'])
def upload_zip():
    if 'file' not in request.files: return "No file", 400
    file = request.files['file']
    options = request.form.get('options', '').split(',')
    
    processed_zip = process_zip_file(file, options)
    
    return send_file(
        processed_zip,
        mimetype='application/zip',
        as_attachment=True,
        download_name='EuroMoscow_Project_Protected.zip'
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)

