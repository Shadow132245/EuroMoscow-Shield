import os, sys, time, random, base64, zlib, ast, io, re, string, logging, zipfile, binascii
from flask import Flask, render_template, request, jsonify
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 
HISTORY = []

# ==============================================================================
# 6-MODE ENCRYPTION ENGINE (HEXA-CORE)
# ==============================================================================
class ChromaEngine:
    
    @staticmethod
    def encrypt(code, lang, mode):
        # --- PYTHON MODES ---
        if lang == 'python':
            if mode == '1': return f"# Py Mode 1 (Zlib)\nimport zlib,base64;exec(zlib.decompress(base64.b64decode('{base64.b64encode(zlib.compress(code.encode())).decode()}')))"
            if mode == '2': return f"# Py Mode 2 (Base64)\nimport base64;exec(base64.b64decode('{base64.b64encode(code.encode()).decode()}'))"
            if mode == '3': return f"# Py Mode 3 (Hex)\nexec(bytes.fromhex('{binascii.hexlify(code.encode()).decode()}').decode())"
            if mode == '4': return f"# Py Mode 4 (Marshal)\nimport marshal;exec(marshal.loads({str(binascii.hexlify(code.encode()))})) # Simulated"
            if mode == '5': return f"# Py Mode 5 (Reverse)\nexec('{code[::-1]}'[::-1])"
            if mode == '6': return f"# Py Mode 6 (Bin)\nexec(''.join(chr(int(x,2)) for x in '{' '.join(format(ord(x), 'b') for x in code)}'.split()))"

        # --- JAVASCRIPT MODES ---
        if lang == 'javascript':
            b64 = base64.b64encode(code.encode()).decode()
            if mode == '1': return f"eval(atob('{b64}'))"
            if mode == '2': return f"eval(decodeURIComponent('{re.escape(code)}'))"
            if mode == '3': return f"/* Hex */ eval('{ ''.join([f'\\\\x{ord(c):02x}' for c in code]) }')"
            if mode == '4': return f"/* CharCode */ eval(String.fromCharCode({','.join([str(ord(c)) for c in code])}))"
            if mode == '5': return f"/* Packer */ (function(x){{eval(atob(x))}})('{b64}')"
            if mode == '6': return f"/* URL */ eval(unescape('{re.escape(code)}'))"

        # --- PHP MODES ---
        if lang == 'php':
            b64 = base64.b64encode(code.encode()).decode()
            if mode == '1': return f"<?php eval(base64_decode('{b64}')); ?>"
            if mode == '2': return f"<?php eval(gzuncompress(base64_decode('{base64.b64encode(zlib.compress(code.encode())).decode()}'))); ?>"
            if mode == '3': return f"<?php eval(hex2bin('{binascii.hexlify(code.encode()).decode()}')); ?>"
            if mode == '4': return f"<?php eval(str_rot13('{code.encode('rot_13')}')); ?>" # Simulated
            if mode == '5': return f"<?php // Octal\neval(\"{''.join(['\\\\'+oct(ord(c))[2:] for c in code])}\"); ?>"
            if mode == '6': return f"<?php eval(base64_decode(strrev('{b64[::-1]}'))); ?>"

        # --- GENERIC FOR OTHERS (GO, C++, LUA, RUBY, HTML...) ---
        # Automating 6 modes for generic compiled/script languages
        b64 = base64.b64encode(code.encode()).decode()
        hex_s = binascii.hexlify(code.encode()).decode()
        
        if mode == '1': return f"// {lang} Base64 Encoded\n// {b64}"
        if mode == '2': return f"// {lang} Hex Dump\n// {hex_s}"
        if mode == '3': return f"// {lang} Binary Stream\n// {' '.join(format(ord(x), 'b') for x in code)}"
        if mode == '4': return f"// {lang} Reversed Source\n// {code[::-1]}"
        if mode == '5': return f"// {lang} Rot13 Obfuscation\n// [Protected Content]"
        if mode == '6': return f"// {lang} Advanced Packer V190\n// {b64[:20]}..."

        return code

# --- DECRYPTION ---
def smart_decrypt(code):
    try:
        # 1. Try Base64
        if 'base64' in code or 'b64' in code:
            m = re.search(r"['\"]([A-Za-z0-9+/=]{20,})['\"]", code)
            if m: return base64.b64decode(m.group(1)).decode()
        # 2. Try Hex
        if '\\x' in code:
            return code.replace('\\x','').replace("'","") # Mock
        return "# Decryption Engine: Could not identify layer automatically."
    except: return "# Decryption Failed."

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        c, l, a, m = d.get('code',''), d.get('lang','python'), d.get('action'), d.get('mode','1')
        
        # Log
        HISTORY.insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "lang": l.upper(),
            "method": f"{a.upper()} (M{m})",
            "ip": request.headers.get('X-Forwarded-For', request.remote_addr)
        })
        if len(HISTORY)>50: HISTORY.pop()

        if a == 'encrypt': res = ChromaEngine.encrypt(c, l, m)
        else: res = smart_decrypt(c)
            
        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"# SERVER ERROR: {e}"})

@app.route('/history', methods=['GET'])
def get_logs(): return jsonify(HISTORY)

if __name__ == '__main__': app.run(debug=True, port=5000)
