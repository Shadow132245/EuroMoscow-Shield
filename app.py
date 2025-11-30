# ==========================================
# Project: EuroMoscow Shield (Python + JS Edition)
# Developer: EuroMoscow
# ==========================================

from flask import Flask, render_template, request, jsonify, send_file
import base64, zlib, binascii, ast, random, io, codecs, re, urllib.parse

app = Flask(__name__)

# --- Configuration ---
BRAND_HEADER = f"# Protected by EuroMoscow Shield\n# https://euro-moscow-shield.vercel.app\n\n"
JS_HEADER = f"/* Protected by EuroMoscow Shield */\n"

# ==========================================
# PART 1: PYTHON ENGINE (نفس الكود السابق)
# ==========================================
def random_var_name(length=8):
    return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=length))

class ImportScanner(ast.NodeVisitor):
    def __init__(self): self.ignore_list = set(dir(__builtins__))
    def visit_Import(self, node):
        for alias in node.names:
            self.ignore_list.add(alias.name)
            if alias.asname: self.ignore_list.add(alias.asname)
        self.generic_visit(node)
    def visit_ImportFrom(self, node):
        if node.module: self.ignore_list.add(node.module)
        for alias in node.names:
            self.ignore_list.add(alias.name)
            if alias.asname: self.ignore_list.add(alias.asname)
        self.generic_visit(node)

class SafeObfuscator(ast.NodeTransformer):
    def __init__(self, ignore_list):
        self.mapping = {}; self.ignore = ignore_list | {'self', 'args', 'kwargs', 'main'}
    def get_new_name(self, name):
        if name in self.ignore or name.startswith('__'): return name
        if name not in self.mapping: self.mapping[name] = random_var_name()
        return self.mapping[name]
    def visit_FunctionDef(self, node):
        if node.name not in self.ignore: node.name = self.get_new_name(node.name)
        for arg in node.args.args:
            if arg.arg not in self.ignore: arg.arg = self.get_new_name(arg.arg)
        self.generic_visit(node)
        return node
    def visit_ClassDef(self, node):
        if node.name not in self.ignore: node.name = self.get_new_name(node.name)
        return node
    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Load, ast.Store, ast.Del)):
            if node.id in self.mapping: node.id = self.mapping[node.id]
        return node

def apply_obfuscation(code_str):
    try:
        tree = ast.parse(code_str); scanner = ImportScanner(); scanner.visit(tree)
        transformer = SafeObfuscator(scanner.ignore_list); new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree); return ast.unparse(new_tree)
    except: return code_str

def encrypt_portable_blob(code_str):
    compressed = zlib.compress(code_str.encode('utf-8')); blob = list(compressed)
    return f"import zlib;exec(zlib.decompress(bytes({blob})), globals())"
def encrypt_xor(code_str):
    key = random.randint(1, 255); encrypted_chars = [ord(c) ^ key for c in code_str]
    return f"exec(''.join(chr(c^{key})for c in {encrypted_chars}), globals())"
def encrypt_rot13(code_str):
    encoded = codecs.encode(code_str, 'rot13')
    return f"import codecs;exec(codecs.decode({encoded!r}, 'rot13'), globals())"

def process_python(code, methods):
    result = code
    if 'rename' in methods: result = apply_obfuscation(result)
    if 'marshal' in methods: result = encrypt_portable_blob(result)
    if 'zlib' in methods:
        enc = base64.b64encode(zlib.compress(result.encode())).decode()
        result = f"import zlib,base64;exec(zlib.decompress(base64.b64decode({enc!r})), globals())"
    if 'rot13' in methods: result = encrypt_rot13(result)
    if 'xor' in methods: result = encrypt_xor(result)
    if 'base64' in methods:
        enc = base64.b64encode(result.encode()).decode()
        result = f"import base64;exec(base64.b64decode({enc!r}), globals())"
    return BRAND_HEADER + result

def smart_py_decrypt(code):
    current = code; max_l = 25
    patterns = {
        'b64': r"base64\.b64decode\((['\"].*?['\"])\)",
        'zlib': r"zlib\.decompress\((?:base64\.b64decode\((['\"].*?['\"])\)|(['\"].*?['\"]))\)",
        'rot13': r"codecs\.decode\((['\"].*?['\"]),\s*['\"]rot13['\"]\)",
        'xor': r"c\^(\d+).*?in\s+(\[.*?\])",
        'blob': r"zlib\.decompress\(bytes\(\[(.*?)\]\)\)"
    }
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
# PART 2: JAVASCRIPT ENGINE (الجديد)
# ==========================================

def js_encrypt_hex(code):
    # تحويل الكود إلى \xNN
    hex_code = "".join([f"\\x{ord(c):02x}" for c in code])
    return f"eval('{hex_code}')"

def js_encrypt_base64(code):
    # تشفير Base64 قياسي في المتصفح
    b64 = base64.b64encode(code.encode()).decode()
    return f"eval(atob('{b64}'))"

def js_encrypt_url(code):
    # تشفير URL Encode
    quoted = urllib.parse.quote(code)
    return f"eval(decodeURIComponent('{quoted}'))"

def js_encrypt_charcode(code):
    # تحويل الكود لمصفوفة أرقام
    chars = ",".join([str(ord(c)) for c in code])
    return f"eval(String.fromCharCode({chars}))"

def process_js_code(code, methods):
    result = code
    # الترتيب: نبدأ من الداخل للخارج
    
    # 1. Hex Encoding
    if 'hex' in methods: result = js_encrypt_hex(result)
    
    # 2. CharCode (Number Array)
    if 'charcode' in methods: result = js_encrypt_charcode(result)
    
    # 3. URL Encode
    if 'url' in methods: result = js_encrypt_url(result)
    
    # 4. Base64 (الطبقة الأخيرة)
    if 'base64' in methods: result = js_encrypt_base64(result)

    return JS_HEADER + result

def smart_js_decrypt(code):
    current = code; max_l = 25
    
    # أنماط فك تشفير JS
    patterns = {
        'base64': r"eval\(atob\(['\"](.*?)['\"]\)\)",
        'url': r"eval\(decodeURIComponent\(['\"](.*?)['\"]\)\)",
        'hex': r"eval\(['\"](\\x[0-9a-fA-F]{2}.*?)['\"]\)",
        'charcode': r"eval\(String\.fromCharCode\((.*?)\)\)"
    }

    for _ in range(max_l):
        decoded = False; clean = '\n'.join([l for l in current.split('\n') if not l.strip().startswith('/*')]).strip()
        
        # Base64
        m = re.search(patterns['base64'], clean)
        if m:
            try: current = base64.b64decode(m.group(1)).decode(); decoded = True
            except: pass
            
        # URL
        if not decoded:
            m = re.search(patterns['url'], clean)
            if m:
                try: current = urllib.parse.unquote(m.group(1)); decoded = True
                except: pass
                
        # Hex
        if not decoded:
            m = re.search(patterns['hex'], clean)
            if m:
                try: 
                    # تحويل \xNN لنص عادي
                    hex_str = m.group(1).replace('\\x', '')
                    current = bytes.fromhex(hex_str).decode('utf-8')
                    decoded = True
                except: pass
        
        # CharCode
        if not decoded:
            m = re.search(patterns['charcode'], clean)
            if m:
                try:
                    nums = [int(x) for x in m.group(1).split(',')]
                    current = "".join([chr(n) for n in nums])
                    decoded = True
                except: pass
                
        if not decoded: break
    return current

# ==========================================
# ROUTES
# ==========================================

@app.route('/')
def home(): return render_template('index.html') # Python Page

@app.route('/js-shield')
def js_page(): return render_template('js_encrypt.html') # JS Page (New)

@app.route('/decryptor')
def decrypt_page(): return render_template('decrypt.html') # General Decryptor

@app.route('/docs')
def api_docs(): return render_template('api_docs.html')

@app.route('/process', methods=['POST'])
def process():
    data = request.json
    code = data.get('code')
    action = data.get('action')
    lang = data.get('lang', 'python') # Default to Python
    options = data.get('options', [])

    if lang == 'python':
        if action == 'encrypt': result = process_python(code, options)
        else: result = smart_py_decrypt(code)
    elif lang == 'javascript':
        if action == 'encrypt': result = process_js_code(code, options)
        else: result = smart_js_decrypt(code)
    else:
        result = "Unsupported Language"

    return jsonify({'result': result})

@app.route('/download', methods=['POST'])
def download_file():
    code = request.form['code']
    file_type = request.form.get('type', 'py') # py or js
    
    fname = "EuroMoscow_Protected.py" if file_type == 'py' else "EuroMoscow_Secure.js"
    mime = "text/x-python" if file_type == 'py' else "application/javascript"
    
    buffer = io.BytesIO()
    buffer.write(code.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=fname, mimetype=mime)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
