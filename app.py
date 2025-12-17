import os, sys, time, random, base64, zlib, ast, io, re, string, logging, zipfile, binascii
from flask import Flask, render_template, request, jsonify
from datetime import datetime
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 # 50MB
HISTORY = []

# --- CORE ENCRYPTION LOGIC (3 MODES PER LANG) ---
class OmniCrypto:
    
    # 1. PYTHON
    @staticmethod
    def py(c, m):
        if m == 'mode1': # Chaos Lambda
            p = base64.b85encode(zlib.compress(c.encode())).decode()
            return f"import zlib,base64;exec(zlib.decompress(base64.b85decode('{p}')))"
        if m == 'mode2': # Marshal
            import marshal; code_obj = compile(c, '<string>', 'exec')
            return f"import marshal;exec(marshal.loads({marshal.dumps(code_obj)}))"
        if m == 'mode3': # Fernet AES
            key = Fernet.generate_key(); f = Fernet(key)
            enc = f.encrypt(c.encode())
            return f"from cryptography.fernet import Fernet;exec(Fernet({key}).decrypt({enc}))"
        return c

    # 2. JAVASCRIPT
    @staticmethod
    def js(c, m):
        if m == 'mode1': # Hex Encoder
            return f"eval('{ ''.join([f'\\\\x{ord(x):02x}' for x in c]) }')"
        if m == 'mode2': # Base64 Packer
            return f"eval(atob('{base64.b64encode(c.encode()).decode()}'))"
        if m == 'mode3': # CharCode Logic
            chars = ",".join([str(ord(x)) for x in c])
            return f"eval(String.fromCharCode({chars}))"
        return c

    # 3. LUA
    @staticmethod
    def lua(c, m):
        if m == 'mode1': # String Byte
            return f"load(string.char({','.join([str(ord(x)) for x in c])}))()"
        if m == 'mode2': # Base64 (Fake)
            b = base64.b64encode(c.encode()).decode()
            return f"-- Lua B64\nlocal p='{b}'; -- Add decoding logic here"
        if m == 'mode3': # Reverse
            return f"load(string.reverse('{c[::-1]}'))()"
        return c

    # 4. PHP
    @staticmethod
    def php(c, m):
        b = base64.b64encode(c.encode()).decode()
        if m == 'mode1': return f"<?php eval(base64_decode('{b}')); ?>"
        if m == 'mode2': return f"<?php eval(gzuncompress(base64_decode('{base64.b64encode(zlib.compress(c.encode())).decode()}'))); ?>"
        if m == 'mode3': # Hex Bin
            h = binascii.hexlify(c.encode()).decode()
            return f"<?php eval(hex2bin('{h}')); ?>"
        return c

    # 5. GO
    @staticmethod
    def go(c, m):
        if m == 'mode1': # Hex
            h = binascii.hexlify(c.encode()).decode()
            return f"package main\nimport(\"encoding/hex\";\"fmt\")\nfunc main(){{b,_:=hex.DecodeString(\"{h}\");fmt.Println(string(b))}}"
        if m == 'mode2': # Base64
            b = base64.b64encode(c.encode()).decode()
            return f"package main\nimport(\"encoding/base64\";\"fmt\")\nfunc main(){{b,_:=base64.StdEncoding.DecodeString(\"{b}\");fmt.Println(string(b))}}"
        if m == 'mode3': # Byte Array
            arr = str(list(c.encode())).replace('[','{').replace(']','}')
            return f"package main\nimport \"fmt\"\nfunc main(){{fmt.Println(string([]byte{arr}))}}"
        return c

    # 6. C++
    @staticmethod
    def cpp(c, m):
        # XOR Cipher
        k = random.randint(1,255)
        d = ",".join([str(ord(x)^k) for x in c])
        if m == 'mode1': return f"// C++ XOR (Key {k})\nchar d[]={{{d}}};"
        if m == 'mode2': return f"// C++ Hex\n// {binascii.hexlify(c.encode()).decode()}"
        if m == 'mode3': return f"// C++ Reverse\n// {c[::-1]}"
        return c

    # GENERIC HANDLER FOR OTHERS (Java, Ruby, Rust, Swift, Perl, C#, HTML)
    @staticmethod
    def generic(c, l, m):
        b = base64.b64encode(c.encode()).decode()
        h = binascii.hexlify(c.encode()).decode()
        if m == 'mode1': return f"// {l.upper()} MODE 1 (Base64)\n// {b}"
        if m == 'mode2': return f"// {l.upper()} MODE 2 (Hex)\n// {h}"
        if m == 'mode3': return f"// {l.upper()} MODE 3 (Reverse)\n// {c[::-1]}"
        return c

# --- DECRYPTION ---
def smart_decrypt(c):
    try:
        if 'base64' in c or 'b64' in c or len(c) % 4 == 0:
            # Try finding base64 string
            m = re.search(r"['\"]([A-Za-z0-9+/=]{20,})['\"]", c)
            if m: return base64.b64decode(m.group(1)).decode()
        
        if '\\x' in c: # Hex
            h = c.replace('\\x','').replace("'","").replace('"','')
            return bytes.fromhex(h).decode()
            
        return "# Decryption Algorithm not identified. Manual analysis required."
    except: return "# Decryption Failed."

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        c, l, a, m = d.get('code',''), d.get('lang','python'), d.get('action'), d.get('mode','mode1')
        
        # Log
        HISTORY.insert(0, {"time": datetime.now().strftime("%H:%M:%S"), "lang": l, "action": f"{a}-{m}"})
        if len(HISTORY)>50: HISTORY.pop()

        if a == 'encrypt':
            if l == 'python': res = OmniCrypto.py(c, m)
            elif l == 'javascript': res = OmniCrypto.js(c, m)
            elif l == 'lua': res = OmniCrypto.lua(c, m)
            elif l == 'php': res = OmniCrypto.php(c, m)
            elif l == 'go': res = OmniCrypto.go(c, m)
            elif l == 'cpp': res = OmniCrypto.cpp(c, m)
            else: res = OmniCrypto.generic(c, l, m)
        else:
            res = smart_decrypt(c)
            
        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"# SERVER ERROR: {e}"})

@app.route('/history', methods=['GET'])
def hist(): return jsonify(HISTORY)

if __name__ == '__main__': app.run(debug=True, port=5000)
