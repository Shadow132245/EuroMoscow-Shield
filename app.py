# ==========================================
# Project: EuroMoscow Shield V27 (Architect)
# Core: Flask + Advanced Obfuscation Engines
# ==========================================

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
import sys
import os
from contextlib import redirect_stdout
from datetime import datetime

app = Flask(__name__)

# --- CONSTANTS ---
BRAND_HEADER = f"# Protected by EuroMoscow Shield V27\n# https://euro-moscow-shield.vercel.app\n\n"
JS_HEADER = f"/* Protected by EuroMoscow Shield V27 */\n"
LUA_HEADER = f"-- Protected by EuroMoscow Shield V27\n"

# --- UTILITY FUNCTIONS ---
def random_var_name(length=12):
    """Generates a strong random variable name."""
    return '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=length))

def inject_dead_code(tree):
    """Injects non-functional logic to confuse decompilers."""
    try:
        class DeadCodeInjector(ast.NodeTransformer):
            def visit_FunctionDef(self, node):
                try:
                    # Creates: if 8492 > 19291: pass
                    useless_op = ast.If(
                        test=ast.Compare(
                            left=ast.Constant(value=random.randint(1000, 9999)),
                            ops=[ast.Gt()],
                            comparators=[ast.Constant(value=random.randint(10000, 99999))]
                        ),
                        body=[ast.Pass()],
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

# ==========================================
# 1. PYTHON ENGINE (Advanced)
# ==========================================
def process_python(code, options):
    result = code
    try:
        # 1. Nightmare Mode (Combo)
        if 'nightmare' in options:
            # Apply Deadcode -> Rename -> Marshal -> Base64
            options.extend(['deadcode', 'rename', 'marshal', 'base64'])
            # Remove duplicates
            options = list(set(options))

        # 2. Syntax Analysis & AST Transformations
        if 'rename' in options or 'deadcode' in options:
            try:
                tree = ast.parse(result)
                
                if 'deadcode' in options:
                    tree = inject_dead_code(tree)
                
                if 'rename' in options:
                    class SafeRenamer(ast.NodeTransformer):
                        def __init__(self):
                            self.mapping = {}
                            self.ignore = set(dir(__builtins__)) | {'self', 'args', 'kwargs'}
                        def visit_Name(self, node):
                            if isinstance(node.ctx, (ast.Store, ast.Del)):
                                if node.id not in self.ignore and not node.id.startswith('__'):
                                    if node.id not in self.mapping:
                                        self.mapping[node.id] = random_var_name()
                            if isinstance(node.ctx, ast.Load):
                                if node.id in self.mapping:
                                    node.id = self.mapping[node.id]
                            return node
                    
                    tree = SafeRenamer().visit(tree)
                
                if hasattr(ast, 'unparse'):
                    result = ast.unparse(tree)
            except Exception as e:
                print(f"AST Error: {e}") # Log but don't crash

        # 3. Encryption Layers
        if 'marshal' in options: 
            compressed = zlib.compress(result.encode('utf-8'))
            blob = list(compressed)
            result = f"import zlib;exec(zlib.decompress(bytes({blob})),globals())"

        if 'zlib' in options:
            encoded = base64.b64encode(zlib.compress(result.encode())).decode()
            result = f"import zlib,base64;exec(zlib.decompress(base64.b64decode({encoded!r})),globals())"

        if 'rot13' in options:
            encoded = codecs.encode(result, 'rot13')
            result = f"import codecs;exec(codecs.decode({encoded!r}, 'rot13'),globals())"

        if 'xor' in options:
            key = random.randint(1, 255)
            encrypted_chars = [ord(c) ^ key for c in result]
            result = f"exec(''.join(chr(c^{key})for c in {encrypted_chars}),globals())"

        # 4. Final Wrapper
        encoded_final = base64.b64encode(result.encode()).decode()
        return f"{BRAND_HEADER}import base64;exec(base64.b64decode('{encoded_final}'))"

    except Exception as e:
        return f"# Error during obfuscation: {str(e)}\n{code}"

# ==========================================
# 2. JAVASCRIPT ENGINE
# ==========================================
def process_javascript(code, options):
    result = code
    if 'hex' in options:
        hex_encoded = ''.join([f'\\x{ord(c):02x}' for c in result])
        result = f"eval('{hex_encoded}')"
    
    if 'url' in options:
        url_encoded = urllib.parse.quote(result)
        result = f"eval(decodeURIComponent('{url_encoded}'))"
        
    if 'charcode' in options:
        char_array = ','.join([str(ord(c)) for c in result])
        result = f"eval(String.fromCharCode({char_array}))"

    # Base64 Wrap
    b64 = base64.b64encode(result.encode()).decode()
    return f"{JS_HEADER}eval(atob('{b64}'))"

# ==========================================
# 3. LUA ENGINE
# ==========================================
def process_lua(code, options):
    result = code
    if 'reverse' in options:
        reversed_code = result[::-1].replace("'", "\\'").replace('"', '\\"')
        result = f"local _f=loadstring or load;_f(string.reverse('{reversed_code}'))()"
    
    if 'hex' in options:
        hex_code = "".join([f"{b:02X}" for b in result.encode('utf-8')])
        result = f"local _h=\"{hex_code}\";local _c=\"\";for i=1,#_h,2 do _c=_c..string.char(tonumber(string.sub(_h,i,i+1),16)) end;local _f=loadstring or load;_f(_c)()"
    
    return f"{LUA_HEADER}{result}"

# ==========================================
# 4. UNIVERSAL DECRYPTOR
# ==========================================
def universal_decrypt(code):
    current_code = code
    patterns = [
        r"base64\.b64decode\(['\"](.*?)['\"]\)", 
        r"atob\(['\"](.*?)['\"]\)", 
        r"zlib\.decompress\(bytes\(\[(.*?)\]\)\)", 
        r"eval\(['\"](\\x[0-9a-fA-F]{2}.*?)['\"]\)",
        r"string\.reverse\('((?:[^'\\]|\\.)*)'\)",
        r"base64_decode\('([^']+)'\)",
        r"decodeURIComponent\('([^']+)'\)"
    ]
    
    for _ in range(20): # Max 20 layers
        clean_code = current_code.replace('\n', ' ').strip()
        found_layer = False
        
        for pat in patterns:
            match = re.search(pat, clean_code)
            if match:
                try:
                    payload = match.group(1)
                    if 'zlib' in pat and 'bytes' in pat:
                        current_code = zlib.decompress(bytes(eval(f"[{payload}]"))).decode()
                    elif 'reverse' in pat:
                        current_code = payload.replace("\\'", "'")[::-1]
                    elif 'hex' in pat:
                        current_code = bytes.fromhex(payload.replace('\\x', '')).decode()
                    elif 'decodeURIComponent' in pat:
                        current_code = urllib.parse.unquote(payload)
                    else:
                        # Standard Base64
                        current_code = base64.b64decode(payload).decode()
                    found_layer = True
                    break # Found a layer, restart loop
                except:
                    pass
        
        if not found_layer:
            break
            
    return current_code

# ==========================================
# 5. TERMINAL EXECUTOR
# ==========================================
def execute_code_server(code):
    output_buffer = io.StringIO()
    try:
        # Redirect stdout to capture print() statements
        with redirect_stdout(output_buffer):
            exec(code, {'__builtins__': __builtins__}, {})
        return output_buffer.getvalue()
    except Exception as e:
        return f"Runtime Error: {str(e)}"

# ==========================================
# ROUTES
# ==========================================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        data = request.json
        code = data.get('code', '')
        action = data.get('action', 'encrypt')
        lang = data.get('lang', 'python')
        options = data.get('options', [])
        
        result = ""
        if action == 'encrypt':
            if lang == 'python': result = process_python(code, options)
            elif lang == 'javascript': result = process_javascript(code, options)
            elif lang == 'lua': result = process_lua(code, options)
            elif lang == 'php': # PHP (Simple Base64 wrapper)
                b64 = base64.b64encode(code.encode()).decode()
                result = f"<?php eval(base64_decode('{b64}')); ?>"
            else: result = code
        else:
            result = universal_decrypt(code)
            
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'result': f"Error: {str(e)}"}), 500

@app.route('/run', methods=['POST'])
def run_code():
    data = request.json
    code = data.get('code', '')
    # Security: Only allow Python for now
    return jsonify({'output': execute_code_server(code)})

@app.route('/upload-zip', methods=['POST'])
def handle_zip():
    try:
        f = request.files['file']
        mem_zip = io.BytesIO(f.read())
        out_zip = io.BytesIO()
        opts = request.form.get('options', '').split(',')
        
        with zipfile.ZipFile(mem_zip, 'r') as zin:
            with zipfile.ZipFile(out_zip, 'w', zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    try:
                        # Auto-detect and encrypt
                        if item.filename.endswith('.py'):
                            enc_data = process_python(data.decode('utf-8'), opts)
                            zout.writestr(item.filename, enc_data)
                        elif item.filename.endswith('.js'):
                            enc_data = process_javascript(data.decode('utf-8'), opts)
                            zout.writestr(item.filename, enc_data)
                        else:
                            zout.writestr(item, data)
                    except:
                        zout.writestr(item, data)
        
        out_zip.seek(0)
        return send_file(out_zip, mimetype='application/zip', as_attachment=True, download_name='Project_Protected.zip')
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
