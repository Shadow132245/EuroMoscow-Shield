import os, sys, time, random, base64, zlib, re, string, logging, binascii, urllib.parse
from flask import Flask, render_template, request, jsonify
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024 
HISTORY = []

# ==============================================================================
# SAFE ENCRYPTION ENGINE
# ==============================================================================
class ChromaEngine:
    @staticmethod
    def encrypt(code, lang, mode):
        try:
            if len(code) > 500000 and mode in ['4', '5', '6']:
                return f"# Code too large for Mode {mode}. Using Mode 2.\nimport base64;exec(base64.b64decode('{base64.b64encode(code.encode()).decode()}'))"

            # PYTHON
            if lang == 'python':
                if mode == '1': return f"import zlib,base64;exec(zlib.decompress(base64.b85decode('{base64.b85encode(zlib.compress(code.encode())).decode()}')))"
                if mode == '2': return f"import base64;exec(base64.b64decode('{base64.b64encode(code.encode()).decode()}'))"
                if mode == '3': return f"exec(bytes.fromhex('{binascii.hexlify(code.encode()).decode()}').decode())"
                if mode == '4': import marshal; return f"import marshal;exec(marshal.loads({str(marshal.dumps(compile(code, '', 'exec')))}))"
                if mode == '5': return f"exec('{code[::-1]}'[::-1])"
                if mode == '6': 
                    binary = ' '.join(format(ord(x), 'b') for x in code)
                    return f"exec(''.join(chr(int(x,2)) for x in '{binary}'.split()))"

            # JAVASCRIPT
            if lang == 'javascript':
                b64 = base64.b64encode(code.encode()).decode()
                if mode == '1': return f"eval(atob('{b64}'))"
                if mode == '2': return f"eval(decodeURIComponent('{urllib.parse.quote(code)}'))"
                if mode == '3': return f"eval('{ ''.join([f'\\\\x{ord(c):02x}' for c in code]) }')"
                if mode == '4': return f"eval(String.fromCharCode({','.join([str(ord(c)) for c in code])}))"
                if mode == '5': return f"(function(){{eval(atob('{b64}'))}})()"
                if mode == '6': return f"setTimeout(function(){{eval(atob('{b64}'))}}, 10);"

            # GENERIC FALLBACK
            b64 = base64.b64encode(code.encode()).decode()
            return f"// {lang.upper()} Encrypted\n// {b64}"

        except Exception as e: return f"# SYSTEM ERROR: {str(e)}"

# ==============================================================================
# GENIUS DECRYPTOR (UPDATED TO FIX YOUR ISSUE)
# ==============================================================================
def smart_decrypt(code):
    try:
        curr = code.strip()
        
        # 1. DETECT REVERSE MODE (Python Mode 5)
        # Pattern: exec('... '[::-1])
        if "[::-1]" in curr:
            m = re.search(r"['\"](.*?)['\"]", curr)
            if m: return m.group(1)[::-1] # Reverse it back!

        # 2. DETECT BINARY MODE (Python Mode 6)
        # Pattern: int(x,2)
        if "int(x,2)" in curr:
            m = re.search(r"['\"]([01\s]+)['\"]", curr)
            if m:
                binary_str = m.group(1)
                return "".join([chr(int(b, 2)) for b in binary_str.split()])

        # 3. DETECT HEX (Python Mode 3 / JS Mode 3)
        if "bytes.fromhex" in curr or "\\x" in curr:
            # Try to clean and decode hex
            clean_hex = re.sub(r"[^0-9a-fA-F]", "", curr)
            try: return binascii.unhexlify(clean_hex).decode()
            except: pass

        # 4. DETECT URL ENCODE (JS Mode 2)
        if "decodeURIComponent" in curr:
            m = re.search(r"['\"](.*?)['\"]", curr)
            if m: return urllib.parse.unquote(m.group(1))

        # 5. DETECT BASE64 / ZLIB (Standard)
        # Finds the longest string that looks like Base64
        b64_matches = re.findall(r"['\"]([A-Za-z0-9+/=]{20,})['\"]", curr)
        for match in b64_matches:
            try:
                # Try Zlib first (Mode 1)
                try: return zlib.decompress(base64.b85decode(match)).decode()
                except: pass
                
                # Try Standard Base64 (Mode 2)
                return base64.b64decode(match).decode()
            except: continue

        return "# Decryption Engine: Layer too complex or not supported yet."
    except Exception as e: return f"# Decryption Failed: {str(e)}"

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        c, l, a, m = d.get('code',''), d.get('lang','python'), d.get('action'), d.get('mode','1')
        
        # Log
        if len(HISTORY) > 50: HISTORY.pop()
        HISTORY.insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "lang": l.upper(),
            "method": f"{a.upper()} (M{m})",
            "ip": request.headers.get('X-Forwarded-For', request.remote_addr)
        })

        if a == 'encrypt': res = ChromaEngine.encrypt(c, l, m)
        else: res = smart_decrypt(c)
            
        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"# SERVER ERROR: {e}"})

@app.route('/history', methods=['GET'])
def get_logs(): return jsonify(HISTORY)

if __name__ == '__main__': app.run(debug=True, port=5000)
