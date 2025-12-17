import os, sys, time, random, base64, zlib, re, string, logging, binascii, urllib.parse, codecs
from flask import Flask, render_template, request, jsonify
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 # 10MB Safe Limit
HISTORY = []

# ==============================================================================
# 1. THE TITANIUM ENCRYPTOR (6 MODES PER LANGUAGE)
# ==============================================================================
class TitanEncryptor:
    
    @staticmethod
    def encrypt(code, lang, mode):
        try:
            # --- PYTHON (Special Handling) ---
            if lang == 'python':
                if mode == '1': # Zlib Compressed
                    return f"import zlib,base64;exec(zlib.decompress(base64.b85decode('{base64.b85encode(zlib.compress(code.encode())).decode()}')))"
                if mode == '2': # Hex Exec
                    return f"exec(bytes.fromhex('{binascii.hexlify(code.encode()).decode()}').decode())"
                if mode == '3': # Base64 Standard
                    return f"import base64;exec(base64.b64decode('{base64.b64encode(code.encode()).decode()}'))"
                if mode == '4': # Reverse Logic
                    return f"exec('{code[::-1]}'[::-1])"
                if mode == '5': # Binary Stream
                    b = ' '.join(format(ord(x), 'b') for x in code)
                    return f"exec(''.join(chr(int(x,2)) for x in '{b}'.split()))"
                if mode == '6': # Rot13 (Weak but annoying)
                    return f"import codecs;exec(codecs.decode('{codecs.encode(code, 'rot_13')}', 'rot_13'))"

            # --- JAVASCRIPT (Special Handling) ---
            if lang == 'javascript':
                b64 = base64.b64encode(code.encode()).decode()
                if mode == '1': return f"eval(atob('{b64}'))"
                if mode == '2': return f"eval(decodeURIComponent('{urllib.parse.quote(code)}'))"
                if mode == '3': return f"eval('{ ''.join([f'\\\\x{ord(c):02x}' for c in code]) }')" # Hex
                if mode == '4': return f"/* Packed */ (function(){{eval(atob('{b64}'))}})()"
                if mode == '5': return f"eval(unescape('{urllib.parse.quote(code)}'))"
                if mode == '6': return f"// CharCode\neval(String.fromCharCode({','.join([str(ord(c)) for c in code])}))"

            # --- PHP (Special Handling) ---
            if lang == 'php':
                b64 = base64.b64encode(code.encode()).decode()
                if mode == '1': return f"<?php eval(base64_decode('{b64}')); ?>"
                if mode == '2': return f"<?php eval(gzuncompress(base64_decode('{base64.b64encode(zlib.compress(code.encode())).decode()}'))); ?>"
                if mode == '3': return f"<?php eval(hex2bin('{binascii.hexlify(code.encode()).decode()}')); ?>"
                if mode == '4': return f"<?php eval(str_rot13('{codecs.encode(code, 'rot_13')}')); ?>"
                if mode == '5': return f"<?php // Octal\neval(\"{''.join(['\\\\'+oct(ord(c))[2:] for c in code])}\"); ?>"
                if mode == '6': return f"<?php eval(base64_decode(strrev('{b64[::-1]}'))); ?>"

            # --- GENERIC (Go, Lua, C++, C#, Java, Ruby, Rust, Swift, Perl, HTML) ---
            # Standardized 6 Modes for all compiled/other langs
            b64 = base64.b64encode(code.encode()).decode()
            hex_s = binascii.hexlify(code.encode()).decode()
            
            prefix = "//" if lang not in ['lua', 'html'] else ("--" if lang=='lua' else ""
            
            if mode == '1': return f"{prefix} {lang.upper()} Base64\n{prefix} {b64} {suffix}"
            if mode == '2': return f"{prefix} {lang.upper()} Hex\n{prefix} {hex_s} {suffix}"
            if mode == '3': return f"{prefix} {lang.upper()} Rot13\n{prefix} {codecs.encode(code, 'rot_13')} {suffix}"
            if mode == '4': return f"{prefix} {lang.upper()} Reversed\n{prefix} {code[::-1]} {suffix}"
            if mode == '5': return f"{prefix} {lang.upper()} Binary\n{prefix} {' '.join(format(ord(x), 'b') for x in code)} {suffix}"
            if mode == '6': return f"{prefix} {lang.upper()} URL Encoded\n{prefix} {urllib.parse.quote(code)} {suffix}"

            return code

        except Exception as e:
            return f"# Encryption Error: {str(e)}\n# Try a simpler mode."

# ==============================================================================
# 2. THE TITAN DECRYPTOR (INTELLIGENT RECURSIVE CLEANER)
# ==============================================================================
def titan_decrypt(code):
    curr = code.strip()
    
    # LOOP: Try to peel layers up to 5 times
    for _ in range(5):
        original = curr
        try:
            # 1. CLEAN WRAPPERS (Remove exec, eval, imports to find the payload)
            # Removes "exec(bytes.fromhex('...'))" -> keeps "..."
            # Removes "base64.b64decode('...')" -> keeps "..."
            
            # Regex to extract content inside quotes '...' or "..."
            payload_match = re.search(r"['\"]([A-Za-z0-9+/=]{10,}|[0-9a-fA-F]+|[01\s]+)['\"]", curr)
            if payload_match:
                payload = payload_match.group(1)
            else:
                payload = curr # Maybe it's raw

            # 2. ATTEMPT DECODING STRATEGIES
            
            # Strategy A: Base64 / Base85
            try:
                if re.match(r'^[A-Za-z0-9+/=]+$', payload):
                    decoded = base64.b64decode(payload).decode()
                    curr = decoded
                    continue # Success, next layer
            except: pass
            
            try:
                decoded = base64.b85decode(payload).decode()
                curr = decoded
                continue
            except: pass

            # Strategy B: Hex
            try:
                # Clean \x if present
                clean_hex = payload.replace('\\x', '').replace(' ', '')
                if re.match(r'^[0-9a-fA-F]+$', clean_hex):
                    decoded = binascii.unhexlify(clean_hex).decode()
                    curr = decoded
                    continue
            except: pass

            # Strategy C: URL Decode
            if '%' in payload:
                try:
                    decoded = urllib.parse.unquote(payload)
                    if decoded != payload:
                        curr = decoded
                        continue
                except: pass

            # Strategy D: Binary (010101)
            if re.match(r'^[01\s]+$', payload):
                try:
                    decoded = "".join([chr(int(b, 2)) for b in payload.split()])
                    curr = decoded
                    continue
                except: pass

            # Strategy E: Reverse
            if "[::-1]" in curr or "strrev" in curr:
                curr = payload[::-1]
                continue
                
            # Strategy F: Rot13
            if "rot_13" in curr or "rot13" in curr:
                try:
                    curr = codecs.decode(payload, 'rot_13')
                    continue
                except: pass
                
            # Strategy G: Zlib
            try:
                # Often zlib is inside base64, so this might trigger after a b64 decode
                curr = zlib.decompress(curr.encode('latin1')).decode()
                continue
            except: pass

        except: pass
        
        # If no change in this loop iteration, break
        if curr == original: break

    # Final Check: If result looks like garbage, return error
    if len(curr) < 5 or curr == code:
        return "# Decryption Failed: Could not identify algorithm or layer is too complex."
    
    return curr

# ==============================================================================
# 3. ROUTES
# ==============================================================================
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

        if a == 'encrypt': res = TitanEncryptor.encrypt(c, l, m)
        else: res = titan_decrypt(c)
            
        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"# SERVER ERROR: {str(e)}"})

@app.route('/history', methods=['GET'])
def get_logs(): return jsonify(HISTORY)

if __name__ == '__main__': app.run(debug=True, port=5000)
