from flask import Flask, render_template, request, jsonify, send_file
import base64, zlib, binascii, ast, random, string, io

app = Flask(__name__)

# --- 1. أدوات التشفير والتعمية المتقدمة ---

def random_var_name(length=8):
    """توليد أسماء متغيرات عشوائية صعبة القراءة"""
    return '_' + ''.join(random.choices('0123456789abcdef', k=length))

class Obfuscator(ast.NodeTransformer):
    """كلاس لتغيير أسماء المتغيرات داخل الكود دون كسر اللوجيك"""
    def __init__(self):
        self.mapping = {}

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Load, ast.Store)):
            if node.id not in self.mapping:
                # نستثني الدوال المحفوظة مثل print, range, len
                if node.id not in __builtins__: 
                    self.mapping[node.id] = random_var_name()
            
            if node.id in self.mapping:
                return ast.copy_location(ast.Name(id=self.mapping[node.id], ctx=node.ctx), node)
        return node

def advanced_obfuscate(code_str):
    """تحليل الكود وتغيير أسماء المتغيرات"""
    try:
        tree = ast.parse(code_str)
        transformer = Obfuscator()
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)
        return ast.unparse(new_tree)
    except:
        return code_str  # في حالة فشل التحليل، أعد الكود كما هو

def encrypt_code(code, methods):
    """تطبيق طبقات التشفير بناءً على اختيار المستخدم"""
    result = code
    
    # خطوة 1: التعمية (Renaming)
    if 'rename' in methods:
        result = advanced_obfuscate(result)

    # خطوة 2: طبقات التشفير
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

    return result

# --- 2. أدوات فك التشفير الذكي (Recursive) ---

def recursive_decrypt(code):
    """فك التشفير التكراري لإزالة الطبقات"""
    max_loops = 10  # لتجنب الحلقات اللانهائية
    current_code = code

    for _ in range(max_loops):
        try:
            # تنظيف الكود
            temp_code = current_code.strip()
            
            if "base64.b64decode" in temp_code and "zlib" not in temp_code:
                payload = temp_code.split("'")[1]
                current_code = base64.b64decode(payload).decode('utf-8')
                
            elif "binascii.unhexlify" in temp_code:
                payload = temp_code.split("'")[1]
                current_code = binascii.unhexlify(payload).decode('utf-8')
                
            elif "zlib" in temp_code and "base64" in temp_code:
                # استخراج الجزء المشفر بدقة أكبر
                start = temp_code.find("'") + 1
                end = temp_code.rfind("'")
                payload = temp_code[start:end]
                current_code = zlib.decompress(base64.b64decode(payload)).decode('utf-8')
            else:
                break # لا يوجد تشفير معروف، توقف
        except:
            break # حدث خطأ، توقف عند آخر نتيجة ناجحة

    return current_code

# --- 3. المسارات (Routes) ---

@app.route('/')
def home():
    return render_template('index.html')

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

# مسار لتحميل الملفات (اختياري للإضافة المستقبلية)
@app.route('/download', methods=['POST'])
def download_file():
    code = request.form['code']
    buffer = io.BytesIO()
    buffer.write(code.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="pyshield_result.py", mimetype="text/x-python")

if __name__ == '__main__':
    app.run(debug=True, port=5000)