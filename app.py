# ==============================================================================
# PROJECT: EUROMOSCOW V170 (THE ARCHITECT)
# CORE: MULTI-LANGUAGE CODE GENERATION & OBFUSCATION ENGINE
# ==============================================================================

import os, sys, time, random, base64, zlib, ast, io, re, string, logging, zipfile, binascii
from flask import Flask, render_template, request, jsonify
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 # 50MB Limit

# --- UTILS ---
def rand_str(l=8): return "".join(random.choices(string.ascii_letters, k=l))
def rand_hex(l=4): return "".join(random.choices("0123456789ABCDEF", k=l))

# ==============================================================================
# 1. PAYLOAD GENERATORS (THE WEAPON FACTORY)
# Generates native protection code for each language
# ==============================================================================
class Payloads:
    
    # --- PYTHON WEAPONS ---
    @staticmethod
    def py_features(opts, params):
        code = ""
        if 'geo' in opts and params.get('geo'):
            code += f"import requests;c=requests.get('http://ip-api.com/json').json()['countryCode'];\nif c!='{params['geo']}':exit()\n"
        if 'kill' in opts and params.get('kill'):
            code += f"import requests;k=requests.get('{params['kill']}').text.strip();\nif k!='RUN':exit()\n"
        if 'admin' in opts:
            code += "import ctypes;exit() if not ctypes.windll.shell32.IsUserAnAdmin() else None\n"
        if 'anti_vm' in opts:
            code += "import sys;sys.exit() if hasattr(sys, 'real_prefix') else None\n"
        return code

    # --- PHP WEAPONS ---
    @staticmethod
    def php_features(opts, params):
        code = "<?php "
        if 'geo' in opts and params.get('geo'):
            code += f"$c=json_decode(file_get_contents('http://ip-api.com/json'))->countryCode;if($c!='{params['geo']}'){{die();}}"
        if 'kill' in opts and params.get('kill'):
            code += f"$k=file_get_contents('{params['kill']}');if(trim($k)!='RUN'){{die();}}"
        return code

    # --- C++ WEAPONS (Source Injection) ---
    @staticmethod
    def cpp_features(opts, params):
        code = ""
        if 'kill' in opts: # Requires cURL (Simulated logic)
            code += f"// [PROTECTION] Kill-Switch Check Enabled for {params.get('kill')}\n"
        return code

# ==============================================================================
# 2. ENCRYPTION ENGINES (13 LANGUAGES)
# ==============================================================================
class ArchitectEngine:

    # 1. PYTHON (The Phantom)
    @staticmethod
    def encrypt_python(code, opts, params):
        # Inject Security Features First
        payload = Payloads.py_features(opts, params) + code
        
        # Obfuscation Layers
        if 'chaos' in opts:
            # Recursive Zlib+Base64 Lambda
            enc = base64.b85encode(zlib.compress(payload.encode())).decode()
            return f"import zlib,base64,sys;(lambda _,__:exec(zlib.decompress(base64.b85decode(_))))('{enc}',None)"
        
        if 'marshal' in opts:
            import marshal
            try:
                c = compile(payload, '<string>', 'exec')
                return f"import marshal;exec(marshal.loads({marshal.dumps(c)}))"
            except: pass

        # Default Base64 Wrapper
        b64 = base64.b64encode(payload.encode()).decode()
        return f"# V170 Protected\nimport base64;exec(base64.b64decode('{b64}'))"

    # 2. JAVASCRIPT (The Spectre)
    @staticmethod
    def encrypt_js(code, opts):
        # Hex Encoding
        hex_code = ''.join([f'\\x{ord(c):02x}' for c in code])
        var_n = rand_str(5)
        return f"/* V170 JS */\nvar {var_n}='{hex_code}';eval({var_n});"

    # 3. PHP (The Ghost)
    @staticmethod
    def encrypt_php(code, opts, params):
        payload = Payloads.php_features(opts, params) + code.replace('<?php', '')
        b64 = base64.b64encode(payload.encode()).decode()
        return f"<?php eval(base64_decode('{b64}')); ?>"

    # 4. C++ (XOR Cipher Generator)
    @staticmethod
    def encrypt_cpp(code, opts, params):
        # Generates a C++ source file that contains the encrypted payload and a decryptor
        key = random.randint(1, 255)
        enc_bytes = ", ".join([str(ord(c) ^ key) for c in code])
        return f"""
#include <iostream>
#include <string>
#include <vector>
// V170 C++ Protected
// {Payloads.cpp_features(opts, params)}
int main() {{
    int key = {key};
    int data[] = {{{enc_bytes}}};
    std::string s = "";
    for(int i : data) s += (char)(i ^ key);
    // Execute logic here
    std::cout << "Payload Loaded: " << s.length() << " bytes" << std::endl;
    return 0;
}}
"""

    # 5. C# (Base64 Loader)
    @staticmethod
    def encrypt_csharp(code):
        b64 = base64.b64encode(code.encode()).decode()
        return f"""
using System;
using System.Text;
class V170 {{
    static void Main() {{
        string p = "{b64}";
        byte[] b = Convert.FromBase64String(p);
        string c = Encoding.UTF8.GetString(b);
        Console.WriteLine("Code Loaded.");
    }}
}}
"""

    # 6. GO (Hex Loader)
    @staticmethod
    def encrypt_go(code):
        h = binascii.hexlify(code.encode()).decode()
        return f"""package main
import("encoding/hex";"fmt")
func main(){{ h:="{h}"; b,_:=hex.DecodeString(h); fmt.Printf("%s", b); }}"""

    # 7. LUA (Bytecode)
    @staticmethod
    def encrypt_lua(code):
        b = "\\" + "\\".join([str(ord(c)) for c in code])
        return f"-- V170 Lua\nloadstring('{b}')()"

    # 8. RUBY (Zlib)
    @staticmethod
    def encrypt_ruby(code):
        b64 = base64.b64encode(zlib.compress(code.encode())).decode()
        return f"require 'zlib';require 'base64';eval(Zlib::Inflate.inflate(Base64.decode64('{b64}')))"

    # 9. PERL (Pack)
    @staticmethod
    def encrypt_perl(code):
        h = binascii.hexlify(code.encode()).decode()
        return f"$c=pack('H*','{h}');eval($c);"

    # 10. JAVA (Reverse String)
    @staticmethod
    def encrypt_java(code):
        rev = code[::-1].replace('"', '\\"')
        return f"""
public class Main {{
    public static void main(String[] a) {{
        String s = "{rev}";
        String d = new StringBuilder(s).reverse().toString();
        System.out.println("Running...");
    }}
}}
"""

    # 11. RUST (Byte Array)
    @staticmethod
    def encrypt_rust(code):
        b = str(list(code.encode()))
        return f"fn main(){{ let b={b}; let s=String::from_utf8(b).unwrap(); println!(\"{{}}\",s); }}"

    # 12. SWIFT (Base64)
    @staticmethod
    def encrypt_swift(code):
        b64 = base64.b64encode(code.encode()).decode()
        return f"import Foundation; let d=Data(base64Encoded:\"{b64}\")!; print(String(data:d, encoding:.utf8)!)"

    # 13. HTML (Hex Entities)
    @staticmethod
    def encrypt_html(code):
        return "".join([f"&#x{ord(c):x};" for c in code])

# ==============================================================================
# 3. ROUTER
# ==============================================================================
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        c, l, a = d.get('code',''), d.get('lang','python'), d.get('action')
        opts = d.get('options', [])
        params = d.get('params', {})

        if a == 'encrypt':
            if l=='python': res = ArchitectEngine.encrypt_python(c, opts, params)
            elif l=='javascript': res = ArchitectEngine.encrypt_js(c, opts)
            elif l=='php': res = ArchitectEngine.encrypt_php(c, opts, params)
            elif l=='cpp': res = ArchitectEngine.encrypt_cpp(c, opts, params)
            elif l=='csharp': res = ArchitectEngine.encrypt_csharp(c)
            elif l=='go': res = ArchitectEngine.encrypt_go(c)
            elif l=='lua': res = ArchitectEngine.encrypt_lua(c)
            elif l=='ruby': res = ArchitectEngine.encrypt_ruby(c)
            elif l=='perl': res = ArchitectEngine.encrypt_perl(c)
            elif l=='java': res = ArchitectEngine.encrypt_java(c)
            elif l=='rust': res = ArchitectEngine.encrypt_rust(c)
            elif l=='swift': res = ArchitectEngine.encrypt_swift(c)
            elif l=='html': res = ArchitectEngine.encrypt_html(c)
            else: res = f"// Unsupported Lang\n{c}"
        else:
            # Smart Decryptor
            if 'b64decode' in c or 'atob' in c:
                m = re.search(r"['\"]([A-Za-z0-9+/=]{20,})['\"]", c)
                res = base64.b64decode(m.group(1)).decode() if m else "Decryption Failed"
            else: res = "Algorithm not recognized or needs key."

        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"# CRITICAL ERROR: {str(e)}"}), 500

if __name__ == '__main__': app.run(debug=True, port=5000)
