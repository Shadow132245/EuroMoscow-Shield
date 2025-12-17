from flask import Flask, render_template, request, jsonify
import base64
import zlib
import binascii
import codecs
import random
import re
from urllib.parse import quote, unquote
from datetime import datetime

# --- CONFIGURATION ---
app = Flask(__name__)
# 5MB Limit is safer for Vercel Free Tier to avoid memory crashes
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 
HISTORY = []

# ==============================================================================
# 1. ENCRYPTION ENGINE (STABLE & POWERFUL)
# ==============================================================================
class TitanEncryptor:
    
    @staticmethod
    def encrypt(code, lang, mode):
        try:
            # --- PYTHON ---
            if lang == 'python':
                if mode == '1': # Zlib
                    p = base64.b85encode(zlib.compress(code.encode())).decode()
                    return f"import zlib,base64;exec(zlib.decompress(base64.b85decode('{p}')))"
                if mode == '2': # Hex
                    h = binascii.hexlify(code.encode()).decode()
                    return f"exec(bytes.fromhex('{h}').decode())"
                if mode == '3': # Base64
                    b = base64.b64encode(code.encode()).decode()
                    return f"import base64;exec(base64.b64decode('{b}'))"
                if mode == '4': # Reverse
                    return f"exec('{code[::-1]}'[::-1])"
                if mode == '5': # Binary
                    b = ' '.join(format(ord(x), 'b') for x in code)
                    return f"exec(''.join(chr(int(x,2)) for x in '{b}'.split()))"
                if mode == '6': # Rot13
                    r = codecs.encode(code, 'rot_13')
                    return f"import codecs;exec(codecs.decode('{r}', 'rot_13'))"

            # --- JAVASCRIPT ---
            if lang == 'javascript':
                b64 = base64.b64encode(code.encode()).decode()
                if mode == '1': return f"eval(atob('{b64}'))"
                if mode == '2': return f"eval(decodeURIComponent('{quote(code)}'))"
                if mode == '3': 
                    h = ''.join([f'\\x{ord(c):02x}' for c in code])
                    return f"eval('{h}')"
                if mode == '4': return f"(function(){{eval(atob('{b64}'))}})()"
                if mode == '5': return f"eval(unescape('{quote(code)}'))"
                if mode == '6': 
                    c = ','.join([str(ord(x)) for x in code])
                    return f"eval(String.fromCharCode({c}))"

            # --- PHP ---
            if lang == 'php':
                b64 = base64.b64encode(code.encode()).decode()
                if mode == '1': return f"<?php eval(base64_decode('{b64}')); ?>"
                if mode == '2': return f"<?php eval(gzuncompress(base64_decode('{base64.b64encode(zlib.compress(code.encode())).decode()}'))); ?>"
                if mode == '3': return f"<?php eval(hex2bin('{binascii.hexlify(code.encode()).decode()}')); ?>"
                if mode == '4': return f"<?php eval(str_rot13('{codecs.encode(code, 'rot_13')}')); ?>"
                if mode == '5': return f"<?php eval(base64_decode(strrev('{b64[::-1]}'))); ?>"
                if mode == '6': return f"<?php // Secured\n eval(base64_decode('{b64}')); ?>"

            # --- GENERIC (ALL OTHERS) ---
            b64 = base64.b64encode(code.encode()).decode()
            hex_s = binascii.hexlify(code.encode()).decode()
            
            prefix = "//"
            if lang == 'lua': prefix = "--"
            if lang == 'html': prefix = "
