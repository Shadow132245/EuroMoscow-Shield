# ==========================================
# Project: EuroMoscow Shield (Production Fixed)
# Developer: EuroMoscow
# ==========================================

from flask import Flask, render_template, request, jsonify, send_file
import base64, zlib, binascii, ast, random, io, marshal, codecs, re

app = Flask(__name__)

# --- Configuration ---
BRAND_HEADER = f"# Protected by EuroMoscow Shield\n# https://euromoscow.com\n\n"

# --- 1. Obfuscation Logic (Renaming) ---
def random_var_name(length=8):
    return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=length))

class ImportScanner(ast.NodeVisitor):
    def __init__(self):
        self.ignore_list = set(dir(__builtins__))
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
        self.mapping = {}
        self.ignore_list = ignore_list

    def get_new_name(self, original_name):
        if original_name in self.ignore_list: return original_name
        if original_name.startswith('__'): return original_name
        if original_name not in self.mapping:
            self.mapping[original_name] = random_var_name()
        return self.mapping[original_name]

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Load, ast.Store, ast.Del)):
            node.id = self.get_new_name(node.id)
        return node
    def visit_arg(self, node):
        node.arg = self.get_new_name(node.arg)
        return node
    def visit_FunctionDef(self, node):
        node.name = self.get_new_name(node.name)
        self.generic_visit(node)
        return node
    def visit_ClassDef(self, node):
        node.name = self.get_new_name(node.name)
        self.generic_visit(node)
        return node

def apply_obfuscation(code_str):
    try:
        tree = ast.parse(code_str)
        scanner = ImportScanner()
        scanner.visit(tree)
        transformer = SafeObfuscator(scanner.ignore_list)
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)
        return ast.unparse(new_tree)
    except:
        return code_str

# --- 2. Encryption Methods (FIXED WITH !r) ---

def encrypt_xor(code_str):
    key = random.randint(1, 255)
    encrypted_chars = [ord(c) ^ key for c in code_str]
    # استخدام repr لضمان عدم كسر النص
    inner_code = f"exec(''.join(chr(c^{key})for c in {encrypted_chars}))"
    return inner_code

def encrypt_rot13(code_str):
    encoded = codecs.encode(code_str, 'rot13')
    # التصحيح هنا: استخدام {encoded!r} بدلاً من '{encoded}'
    return f"import codecs;exec(codecs.decode({encoded!r}, 'rot13'))"

def process_encrypt(code, methods):
    result = code
    
    # الترتيب مهم: التسمية أولاً
    if 'rename' in methods: result = apply_obfuscation(result)
    
    if 'marshal' in methods:
        try:
            dumped = marshal.dumps(compile(result, '<EuroMoscow>', 'exec'))
            # استخدام !r هنا أيضاً للحماية
            result = f"import marshal;exec(marshal.loads({dumped!r}))"
        except: pass
        
    if 'zlib' in methods:
        enc = base64.b64encode(zlib.compress(result.encode())).decode()
        # التصحيح هنا: !r
        result = f"import zlib,base64;exec(zlib.decompress(base64.b64decode({enc!r})))"
        
    if 'rot13' in methods: result = encrypt_rot13(result)
    if 'xor' in methods: result = encrypt_xor(result)
    
    if 'base64' in methods:
        enc = base64.b64encode(result.encode()).decode()
        # التصحيح هنا: !r
        result = f"import base64;exec(base64.b64decode({enc!r}))"
    
    return BRAND_HEADER + result

# --- 3. Smart Auto-Decrypt ---
def smart_auto_decrypt(code):
    current_code = code
    max_layers = 25 
    
    # تم تحديث الأنماط لتتعامل مع repr (علامات ' أو ")
    patterns = {
        'base64': r"base64\.b64decode\((['\"].*?['\"])\)",
        'zlib': r"zlib\.decompress\((?:base64\.b64decode\((['\"].*?['\"])\)|(['\"].*?['\"]))\)",
        'hex': r"binascii\.unhexlify\((['\"].*?['\"])\)",
        'rot13': r"codecs\.decode\((['\"].*?['\"]),\s*['\"]rot13['\"]\)",
        'xor': r"c\^(\d+).*?in\s+(\[.*?\])",
        'marshal': r"marshal\.loads\((.*?)\)"
    }

    for _ in range(max_layers):
        decoded = False
        clean_code = '\n'.join([l for l in current_code.split('\n') if not l.strip().startswith('#')]).strip()
        
        # Helper to safely unquote strings detected by regex
        def safe_eval_str(s):
            try: return ast.literal_eval(s)
            except: return s.strip("'").strip('"')

        # 2. Check for Base64
        match = re.search(patterns['base64'], clean_code)
        if match:
            try:
                payload = safe_eval_str(match.group(1))
                current_code = base64.b64decode(payload).decode('utf-8')
                decoded = True
            except: pass

        # 3. Check for Zlib
        if not decoded:
            match = re.search(patterns['zlib'], clean_code)
            if match:
                try:
                    raw = match.group(1) or match.group(2)
                    payload = safe_eval_str(raw)
                    current_code = zlib.decompress(base64.b64decode(payload)).decode('utf-8')
                    decoded = True
                except: pass

        # 4. Check for Rot13
        if not decoded:
            match = re.search(patterns['rot13'], clean_code)
            if match:
                try:
                    payload = safe_eval_str(match.group(1))
                    current_code = codecs.decode(payload, 'rot13')
                    decoded = True
                except: pass

        # 5. Check for XOR
        if not decoded:
            match = re.search(patterns['xor'], clean_code)
            if match:
                try:
                    key = int(match.group(1))
                    char_list = eval(match.group(2))
                    current_code = ''.join(chr(c ^ key) for c in char_list)
                    decoded = True
                except: pass
        
        if not decoded and "marshal.loads" in clean_code:
            current_code = "# [STOP] Code is compiled to Python Bytecode (Marshal).\n# Logic intact but unreadable.\n" + current_code
            break

        if not decoded: break

    return current_code

# --- Routes ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/docs')
def api_docs():
    return render_template('api_docs.html')

@app.route('/process', methods=['POST'])
def process():
    data = request.json
    code = data.get('code')
    action = data.get('action')
    options = data.get('options', [])

    if action == 'encrypt':
        result = process_encrypt(code, options)
    else:
        result = smart_auto_decrypt(code)

    return jsonify({'result': result})

@app.route('/download', methods=['POST'])
def download_file():
    code = request.form['code']
    buffer = io.BytesIO()
    buffer.write(code.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="EuroMoscow_Protected.py", mimetype="text/x-python")

if __name__ == '__main__':
    app.run(debug=True, port=5000)
