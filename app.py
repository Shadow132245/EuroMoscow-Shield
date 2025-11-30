# ==========================================
# Project: EuroMoscow Shield (V10.1 Stable Fix)
# Developer: EuroMoscow
# ==========================================

from flask import Flask, render_template, request, jsonify, send_file
import base64, zlib, binascii, ast, random, io, codecs, re, urllib.parse, zipfile, os

app = Flask(__name__)

# --- Configuration ---
BRAND_HEADER = f"# Protected by EuroMoscow Shield\n# https://euromoscow.com\n\n"
JS_HEADER = f"/* Protected by EuroMoscow Shield */\n"
LUA_HEADER = f"-- Protected by EuroMoscow Shield\n"

# ==========================================
# PART 1: PYTHON ENGINE
# ==========================================

def inject_dead_code(tree):
    """Safe Dead Code Injection"""
    try:
        class DeadCodeInjector(ast.NodeTransformer):
            def visit_FunctionDef(self, node):
                try:
                    useless_op = ast.If(
                        test=ast.Constant(value=False),
                        body=[ast.Expr(value=ast.Call(
                            func=ast.Name(id='print', ctx=ast.Load()),
                            args=[ast.Constant(value="EuroMoscow Check")],
                            keywords=[]
                        ))],
                        orelse=[]
                    )
                    node.body.insert(0, useless_op)
                except: pass
                return node
        
        transformer = DeadCodeInjector()
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)
        return new_tree
    except:
        return tree

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

    def visit_ClassDef(self, node):
        if node.name not in self.ignore: node.name = self.get_new_name(node.name)
        self.generic_visit(node)
        return node
    
    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Load, ast.Store, ast.Del)):
            if node.id in self.mapping: node.id = self.mapping[node.id]
        return node

def process_python(code, methods):
    result = code
    
    # AST Operations (Rename & DeadCode)
    if 'rename' in methods or 'deadcode' in methods:
        try:
            tree = ast.parse(result)
            
            if 'deadcode' in methods:
                tree = inject_dead_code(tree)
            
            if 'rename' in methods:
                # Basic ignore list
                ignore = set(dir(__builtins__))
                transformer = SafeObfuscator(ignore)
                tree = transformer.visit(tree)
            
            # Safe Unparse check
            if hasattr(ast, 'unparse'):
                result = ast.unparse(tree)
            else:
                # Fallback for older python versions if runtime.txt fails
                pass 
        except Exception as e:
            print(f"AST Error: {e}")
            # If AST fails, continue with original code to prevent crash
            pass

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
# PART 2: JS & LUA ENGINE (Safe)
# ==========================================

def process_js_code(code, methods):
    result = code
    if 'hex' in methods: result = f"eval('{''.join([f'\\\\x{ord(c):02x}' for c in result])}')"
    if 'charcode' in methods: result = f"eval(String.fromCharCode({','.join([str(ord(c)) for c in result])}))"
    if 'url' in methods: result = f"eval(decodeURIComponent('{urllib.parse.quote(result)}'))"
    if 'base64' in methods: result = f"eval(atob('{base64.b64encode(result.encode()).decode()}'))"
    return JS_HEADER + result

def smart_js_decrypt(code):
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

def process_lua_code(code, methods):
    result = code
    if 'reverse' in methods: result = f"load(string.reverse('{result[::-1]}'))()"
    if 'hex' in methods: 
        hex_c = "".join([f"\\x{ord(c):02X}" for c in result])
        result = f"load('{hex_c}')()"
    if 'byte' in methods: 
        chars = ",".join([str(ord(c)) for c in result])
        result = f"load(string.char({chars}))()"
    return LUA_HEADER + result

# ==========================================
# ROUTES & ZIP HANDLER
# ==========================================

@app.route('/')
def home(): return render_template('index.html')

@app.route('/js-shield')
def js_page(): return render_template('js_encrypt.html')

@app.route('/lua-shield')
def lua_page(): return render_template('lua_encrypt.html')

@app.route('/decryptor')
def decrypt_page(): return render_template('decrypt.html')

@app.route('/js-decryptor')
def js_dec_page(): return render_template('js_decrypt.html')

@app.route('/terminal')
def terminal_page(): return render_template('terminal.html')

@app.route('/docs')
def api_docs(): return render_template('api_docs.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        data = request.json
        code = data.get('code', '')
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
            else: result = smart_py_decrypt(code)

        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'result': f"Server Error: {str(e)}"}), 500

@app.route('/upload-zip', methods=['POST'])
def upload_zip():
    try:
        if 'file' not in request.files: return "No file", 400
        file = request.files['file']
        options = request.form.get('options', '').split(',')
        
        in_memory_zip = io.BytesIO()
        
        with zipfile.ZipFile(file, 'r') as z_in:
            with zipfile.ZipFile(in_memory_zip, 'w', zipfile.ZIP_DEFLATED) as z_out:
                for item in z_in.infolist():
                    file_data = z_in.read(item.filename)
                    if item.filename.endswith('.py'):
                        try:
                            code_str = file_data.decode('utf-8')
                            obfuscated = process_python(code_str, options)
                            z_out.writestr(item.filename, obfuscated)
                        except: z_out.writestr(item, file_data)
                    elif item.filename.endswith('.js'):
                        try:
                            code_str = file_data.decode('utf-8')
                            obfuscated = process_js_code(code_str, options)
                            z_out.writestr(item.filename, obfuscated)
                        except: z_out.writestr(item, file_data)
                    else:
                        z_out.writestr(item, file_data)
        
        in_memory_zip.seek(0)
        return send_file(in_memory_zip, mimetype='application/zip', as_attachment=True, download_name='EuroMoscow_Project.zip')
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
