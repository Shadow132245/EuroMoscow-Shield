from flask import Flask, render_template, request, jsonify, send_file
import base64, zlib, binascii, ast, random, io

app = Flask(__name__)

# --- Branding Configuration ---
PROJECT_NAME = "EuroMoscow Shield"
BRAND_HEADER = f"# ==========================================\n# Protected by {PROJECT_NAME}\n# Developed by EuroMoscow\n# ==========================================\n\n"

# --- 1. Logic: Advanced Renaming (Obfuscation) ---
def random_var_name(length=8):
    return '_' + ''.join(random.choices('0123456789abcdef', k=length))

class Obfuscator(ast.NodeTransformer):
    def __init__(self):
        self.mapping = {}

    def get_new_name(self, original_name):
        """Helper to manage variable mapping consistency"""
        if original_name not in self.mapping:
            # استثناء الدوال المحفوظة والكلمات المفتاحية
            if original_name not in __builtins__:
                self.mapping[original_name] = random_var_name()
            else:
                self.mapping[original_name] = original_name
        return self.mapping[original_name]

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Load, ast.Store)):
            new_id = self.get_new_name(node.id)
            return ast.copy_location(ast.Name(id=new_id, ctx=node.ctx), node)
        return node

    # --- تصحيح الخطأ: التعامل مع وسائط الدوال ---
    def visit_arg(self, node):
        new_arg = self.get_new_name(node.arg)
        # نقوم بتحديث اسم الوسيط في مكانه
        node.arg = new_arg
        return node

    # --- تصحيح إضافي: التعامل مع الكلمات المفتاحية في الدوال ---
    def visit_FunctionDef(self, node):
        # تغيير اسم الدالة نفسها
        node.name = self.get_new_name(node.name)
        # استكمال زيارة باقي أجزاء الدالة (الوسائط والكود الداخلي)
        self.generic_visit(node)
        return node

def advanced_obfuscate(code_str):
    try:
        tree = ast.parse(code_str)
        transformer = Obfuscator()
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)
        return ast.unparse(new_tree)
    except Exception as e:
        # في حالة فشل التحليل، أعد الكود الأصلي لتجنب تحطيم البرنامج
        print(f"Obfuscation Warning: {e}")
        return code_str

# --- 2. Logic: Encryption Layers ---
def encrypt_code(code, methods):
    result = code
    
    # Apply Renaming First
    if 'rename' in methods:
        result = advanced_obfuscate(result)

    # Apply Encoding Layers
    if 'zlib' in methods:
        compressed = zlib.compress(result.encode('utf-8'))
        encoded = base64.b64encode(compressed).decode('utf-8')
        result = f"import zlib,base64;exec(zlib.decompress(base64.b64decode('{encoded}')))"
    
    if 'base64' in methods:
        encoded = base64.b64encode(result.encode('utf-8')).decode('utf-8')
        result = f"import base64;exec(base64.b64decode('{encoded}'))"

    if 'hex' in methods:
        encoded = binascii.hexlify(result.encode('utf-8')).decode('utf-8')
        result = f"import binascii;exec(binascii.unhexlify('{encoded}'))"

    # Add EuroMoscow Branding to the top of the file
    return BRAND_HEADER + result

# --- 3. Logic: Smart Recursive Decryption ---
def recursive_decrypt(code):
    max_loops = 15
    current_code = code

    for _ in range(max_loops):
        try:
            lines = current_code.split('\n')
            temp_code = '\n'.join([l for l in lines if not l.strip().startswith('#')]).strip()

            if "base64.b64decode" in temp_code and "zlib" not in temp_code:
                payload = temp_code.split("'")[1]
                current_code = base64.b64decode(payload).decode('utf-8')
            elif "binascii.unhexlify" in temp_code:
                payload = temp_code.split("'")[1]
                current_code = binascii.unhexlify(payload).decode('utf-8')
            elif "zlib" in temp_code and "base64" in temp_code:
                start = temp_code.find("'") + 1
                end = temp_code.rfind("'")
                payload = temp_code[start:end]
                current_code = zlib.decompress(base64.b64decode(payload)).decode('utf-8')
            else:
                break
        except:
            break
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
        result = encrypt_code(code, options)
    else:
        result = recursive_decrypt(code)

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
