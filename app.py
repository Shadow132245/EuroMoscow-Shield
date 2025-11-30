# ==========================================
# Project: EuroMoscow Shield (Logic Fixed v8)
# Developer: EuroMoscow
# ==========================================

from flask import Flask, render_template, request, jsonify, send_file
import base64, zlib, binascii, ast, random, io, codecs, re

app = Flask(__name__)

# --- Configuration ---
BRAND_HEADER = f"# Protected by EuroMoscow Shield\n# https://euro-moscow-shield.vercel.app\n\n"

# --- 1. Renaming Logic (Smart Linking) ---
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
        # إضافة الكلمات المحفوظة للقائمة المحظورة
        self.ignore = ignore_list | {'self', 'args', 'kwargs', 'main', '__name__', '__main__', '__init__'}

    def get_new_name(self, name):
        # لو الاسم في قائمة التجاهل، رجعه زي ما هو
        if name in self.ignore or name.startswith('__'):
            return name
        
        # لو الاسم ده غيرناه قبل كدة، هات الاسم الجديد بتاعه (عشان التوافق)
        if name in self.mapping:
            return self.mapping[name]
            
        # لو اسم جديد، اعمل واحد عشوائي وسجله
        self.mapping[name] = random_var_name()
        return self.mapping[name]

    def visit_FunctionDef(self, node):
        # نغير اسم الدالة
        if node.name not in self.ignore:
            node.name = self.get_new_name(node.name)
        
        # نغير أسماء الـ Arguments
        for arg in node.args.args:
            if arg.arg not in self.ignore:
                arg.arg = self.get_new_name(arg.arg)
                
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node):
        if node.name not in self.ignore:
            node.name = self.get_new_name(node.name)
        self.generic_visit(node)
        return node

    def visit_Name(self, node):
        # هذا هو الجزء الذي كان ناقصاً وتسبب في المشكلة
        # نغير الاسم فقط إذا كان موجوداً في الخريطة (تم تغييره في التعريف)
        if isinstance(node.ctx, (ast.Load, ast.Store, ast.Del)):
            if node.id in self.mapping:
                node.id = self.mapping[node.id]
        return node

def apply_obfuscation(code_str):
    try:
        tree = ast.parse(code_str)
        # 1. جمع الممنوعات (المكتبات)
        scanner = ImportScanner()
        scanner.visit(tree)
        # 2. تغيير الأسماء مع الربط الذكي
        transformer = SafeObfuscator(scanner.ignore_list)
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)
        return ast.unparse(new_tree)
    except:
        return code_str

# --- 2. Encryption Layers (Portable & Safe) ---

def encrypt_portable_blob(code_str):
    # ضغط الكود وتحويله لأرقام ليعمل على أي نسخة بايثون
    compressed = zlib.compress(code_str.encode('utf-8'))
    blob = list(compressed) 
    # استخدام globals() لتمرير المتغيرات بشكل صحيح
    loader = f"import zlib;exec(zlib.decompress(bytes({blob})), globals())"
    return loader

def encrypt_xor(code_str):
    key = random.randint(1, 255)
    encrypted_chars = [ord(c) ^ key for c in code_str]
    # استخدام !r لحماية النصوص
    inner_code = f"exec(''.join(chr(c^{key})for c in {encrypted_chars}), globals())"
    return inner_code

def encrypt_rot13(code_str):
    encoded = codecs.encode(code_str, 'rot13')
    return f"import codecs;exec(codecs.decode({encoded!r}, 'rot13'), globals())"

def process_encrypt(code, methods):
    result = code
    
    # 1. Rename (Smart Linking)
    if 'rename' in methods: 
        result = apply_obfuscation(result)
    
    # 2. Portable Blob
    if 'marshal' in methods: 
        result = encrypt_portable_blob(result)
        
    # 3. Zlib
    if 'zlib' in methods:
        enc = base64.b64encode(zlib.compress(result.encode())).decode()
        result = f"import zlib,base64;exec(zlib.decompress(base64.b64decode({enc!r})), globals())"
        
    # 4. Rot13 & XOR
    if 'rot13' in methods: result = encrypt_rot13(result)
    if 'xor' in methods: result = encrypt_xor(result)
    
    # 5. Base64
    if 'base64' in methods:
        enc = base64.b64encode(result.encode()).decode()
        result = f"import base64;exec(base64.b64decode({enc!r}), globals())"
    
    return BRAND_HEADER + result

# --- 3. Smart Auto-Decrypt ---
def smart_auto_decrypt(code):
    current_code = code
    max_layers = 25 
    
    patterns = {
        'base64': r"base64\.b64decode\((['\"].*?['\"])\)",
        'zlib': r"zlib\.decompress\((?:base64\.b64decode\((['\"].*?['\"])\)|(['\"].*?['\"]))\)",
        'rot13': r"codecs\.decode\((['\"].*?['\"]),\s*['\"]rot13['\"]\)",
        'xor': r"c\^(\d+).*?in\s+(\[.*?\])",
        'blob': r"zlib\.decompress\(bytes\(\[(.*?)\]\)\)"
    }

    def safe_eval_str(s):
        try: return ast.literal_eval(s)
        except: return s.strip("'").strip('"')

    for _ in range(max_layers):
        decoded = False
        clean_code = '\n'.join([l for l in current_code.split('\n') if not l.strip().startswith('#')]).strip()
        
        match = re.search(patterns['base64'], clean_code)
        if match:
            try:
                payload = safe_eval_str(match.group(1))
                current_code = base64.b64decode(payload).decode('utf-8')
                decoded = True
            except: pass

        if not decoded:
            match = re.search(patterns['zlib'], clean_code)
            if match:
                try:
                    raw = match.group(1) or match.group(2)
                    payload = safe_eval_str(raw)
                    current_code = zlib.decompress(base64.b64decode(payload)).decode('utf-8')
                    decoded = True
                except: pass

        if not decoded:
            match = re.search(patterns['rot13'], clean_code)
            if match:
                try:
                    payload = safe_eval_str(match.group(1))
                    current_code = codecs.decode(payload, 'rot13')
                    decoded = True
                except: pass

        if not decoded:
            match = re.search(patterns['xor'], clean_code)
            if match:
                try:
                    key = int(match.group(1))
                    char_list = eval(match.group(2))
                    current_code = ''.join(chr(c ^ key) for c in char_list)
                    decoded = True
                except: pass

        if not decoded:
            match = re.search(patterns['blob'], clean_code)
            if match:
                try:
                    num_list = eval(f"[{match.group(1)}]")
                    current_code = zlib.decompress(bytes(num_list)).decode('utf-8')
                    decoded = True
                except: pass

        if not decoded: break

    return current_code

# --- Routes ---
@app.route('/')
def home():
    # صفحة التشفير (الرئيسية)
    return render_template('index.html')

@app.route('/decryptor')
def decrypt_page():
    # صفحة فك التشفير (الجديدة)
    return render_template('decrypt.html')

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

