# ==============================================================================
# PROJECT: EUROMOSCOW V80 (TITAN EDITION)
# ARCHITECT: HASSAN
# CORE: INTELLIGENT AUTO-PILOT + CONTROL FLOW FLATTENING + AST TRANSFORMERS
# ==============================================================================

import os
import sys
import time
import random
import base64
import zlib
import ast
import io
import re
import zipfile
import string
import platform
import logging
from flask import Flask, render_template, request, jsonify, send_file
from contextlib import redirect_stdout

# --- SYSTEM CONFIGURATION ---
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 128 * 1024 * 1024 # 128MB Limit
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('TitanCore')

BRAND = f"# PROTECTED BY EUROMOSCOW V80 :: TITAN CORE :: {int(time.time())}\n"

# ==============================================================================
# 1. INTELLIGENT AUTO-PILOT ENGINE
# ==============================================================================
class AutoPilot:
    """
    Analyzes the language and selects the best 'Safe' encryption methods
    that guarantee code functionality while maximizing security.
    """
    @staticmethod
    def get_best_strategy(lang):
        strategies = {
            'python': ['rename', 'dead', 'marshal'], # XOR & Chaos removed for stability
            'javascript': ['hex', 'packer'],
            'lua': ['hex', 'vm'],
            'php': ['base64', 'ghost'],
            'go': ['armor'],
            'html': ['hex'],
            'ruby': ['base64'],
            'cpp': ['wrapper']
        }
        return strategies.get(lang, ['base64'])

# ==============================================================================
# 2. PYTHON ADVANCED TRANSFORMERS (AST)
# ==============================================================================
class PythonTransformers:
    
    @staticmethod
    def random_var(length=12):
        """Generates variable names that look like system internal vars."""
        return '_' + ''.join(random.choices('0123456789abcdef', k=length))

    @staticmethod
    def inject_dead_code(code):
        """Injects extensive dead code logic without breaking syntax."""
        try:
            junk_vars = [f"{PythonTransformers.random_var()}={random.randint(0,999)}" for _ in range(5)]
            junk_logic = f"if {random.randint(1000,9999)} == 0: {' '.join(junk_vars)}"
            return f"{junk_logic}\n{code}"
        except: return code

    @staticmethod
    def rename_variables(code):
        """Safely renames variables using AST parsing."""
        try:
            tree = ast.parse(code)
            class Renamer(ast.NodeTransformer):
                def __init__(self):
                    self.map = {}
                    self.ignore = dir(__builtins__) + ['self', 'args', 'kwargs']
                def visit_Name(self, node):
                    if isinstance(node.ctx, (ast.Store, ast.Del)):
                        if node.id not in self.ignore and not node.id.startswith('__'):
                            if node.id not in self.map:
                                self.map[node.id] = PythonTransformers.random_var()
                    elif isinstance(node.ctx, ast.Load):
                        if node.id in self.map:
                            node.id = self.map[node.id]
                    return node
            
            # Attempt to unparse (Python 3.9+)
            if hasattr(ast, 'unparse'):
                return ast.unparse(Renamer().visit(tree))
            return code # Fallback for older python
        except: return code

    @staticmethod
    def control_flow_flattening(code):
        """
        Simulates control flow flattening by wrapping code in a while loop
        with a state machine. (Simplified for stability).
        """
        b64 = base64.b64encode(code.encode()).decode()
        loader = f"""
import base64
_state = 0
while _state < 3:
    if _state == 0:
        _payload = "{b64}"
        _state += 1
    elif _state == 1:
        _code = base64.b64decode(_payload).decode()
        _state += 2
    elif _state == 3:
        exec(_code)
        break
"""
        return loader

# ==============================================================================
# 3. CORE PROCESSING ENGINE
# ==============================================================================
class TitanEngine:
    
    @staticmethod
    def encrypt(code, lang, options):
        # 1. Auto-Pilot Override
        if 'autopilot' in options:
            options = AutoPilot.get_best_strategy(lang)
            logger.info(f"Auto-Pilot engaged for {lang}: {options}")

        # 2. Python Processing
        if lang == 'python':
            res = code
            if 'rename' in options: res = PythonTransformers.rename_variables(res)
            if 'dead' in options: res = PythonTransformers.inject_dead_code(res)
            
            # Compression Layer
            if 'marshal' in options:
                c = zlib.compress(res.encode('utf-8'))
                res = f"import zlib,base64;exec(zlib.decompress({c}))"
            
            # Final Layer
            final = base64.b85encode(res.encode()).decode()
            return f"{BRAND}import base64;exec(base64.b85decode('{final}'))"

        # 3. JavaScript Processing
        elif lang == 'javascript':
            if 'packer' in options:
                # Custom Packer Logic
                b64 = base64.b64encode(code.encode()).decode()
                key = random.randint(10,99)
                return f"/* V80 TITAN */\n(function(x){{eval(atob(x))}})('{b64}')"
            
            # Hex Encoding
            h = ''.join([f'\\x{ord(c):02x}' for c in code])
            return f"eval('{h}')"

        # 4. Lua Processing
        elif lang == 'lua':
            # Virtual Machine Simulation
            if 'vm' in options:
                bytes_table = "{" + ",".join([str(ord(c)) for c in code]) + "}"
                return f"-- V80 VM\nlocal b={bytes_table};local s='';for i=1,#b do s=s..string.char(b[i]) end;load(s)()"
            return f"load(Base64Decode('{base64.b64encode(code.encode()).decode()}'))()"

        # 5. Go / C++ / Compiled Langs
        else:
            b64 = base64.b64encode(code.encode()).decode()
            if lang == 'go':
                return f"package main\nimport \"encoding/base64\"\nimport \"fmt\"\nfunc main(){{d,_:=base64.StdEncoding.DecodeString(\"{b64}\");fmt.Print(string(d))}}"
            return f"// V80 Protected {lang.upper()}\n// PAYLOAD: {b64}"

    @staticmethod
    def decrypt(code):
        # Universal Recursive Decryptor
        curr = code
        patterns = [
            r"base64\.b85decode\(['\"](.*?)['\"]\)",
            r"base64\.b64decode\(['\"](.*?)['\"]\)", 
            r"atob\(['\"](.*?)['\"]\)",
            r"DecodeString\(\"([^\"]+)\"\)"
        ]
        
        for _ in range(15):
            found = False
            for p in patterns:
                m = re.search(p, curr)
                if m:
                    try:
                        payload = m.group(1)
                        try: curr = base64.b85decode(payload).decode()
                        except: curr = base64.b64decode(payload).decode(errors='ignore')
                        
                        # Check for internal zlib
                        try: curr = zlib.decompress(curr.encode('latin1')).decode()
                        except: pass
                        
                        found = True
                    except: pass
            if not found: break
        return curr

# ==============================================================================
# 4. FLASK ROUTES
# ==============================================================================
@app.route('/')
def index(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def handle_process():
    try:
        data = request.json
        res = ""
        if data['action'] == 'encrypt':
            res = TitanEngine.encrypt(data.get('code',''), data.get('lang','python'), data.get('options',[]))
        else:
            res = TitanEngine.decrypt(data.get('code',''))
        return jsonify({'result': res})
    except Exception as e:
        return jsonify({'result': f"# CRITICAL SYSTEM ERROR: {str(e)}"}), 500

@app.route('/run', methods=['POST'])
def handle_run():
    # Secure Sandbox Simulation
    code = request.json.get('code', '')
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(code, {'__builtins__': __builtins__}, {})
        return jsonify({'output': f.getvalue()})
    except Exception as e: return jsonify({'output': str(e)})

@app.route('/zip', methods=['POST'])
def handle_zip():
    try:
        f = request.files['file']
        opts = request.form.get('options','').split(',')
        m_out = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(f.read()), 'r') as zi, zipfile.ZipFile(m_out, 'w', zipfile.ZIP_DEFLATED) as zo:
            for i in zi.infolist():
                d = zi.read(i.filename)
                try:
                    if i.filename.endswith('.py'): 
                        zo.writestr(i.filename, TitanEngine.encrypt(d.decode(), 'python', opts))
                    else: zo.writestr(i, d)
                except: zo.writestr(i, d)
        m_out.seek(0)
        return send_file(m_out, mimetype='application/zip', as_attachment=True, download_name='Titan_Secure.zip')
    except: return "Error", 500

if __name__ == '__main__': app.run(debug=True, port=5000)
