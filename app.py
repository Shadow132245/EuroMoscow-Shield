import os, sys, time, random, base64, zlib, ast, io, re, string, logging, zipfile, platform, binascii
from flask import Flask, render_template, request, jsonify, send_file
from contextlib import redirect_stdout
from datetime import datetime

# --- SYSTEM CONFIG ---
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 # 50MB Limit (Vercel Safe)
HISTORY_LOGS = [] # In-Memory Database (Vercel Compatible)

# --- UTILS ---
def rand_hex(l=4): return "".join(random.choices("0123456789ABCDEF", k=l))
def rand_var(l=6): return "_" + "".join(random.choices(string.ascii_letters, k=l))

# ==============================================================================
# OMNIVERSE ENGINES (13 DEDICATED ENGINES)
# ==============================================================================
class PolyglotCore:

    # 1. PYTHON (The Phantom)
    @staticmethod
    def encrypt_python(code, opts):
        res = code
        # Anti-Tamper
        if 'tamper' in opts: res = "import sys;sys.settrace(None);\n" + res
        # Chaos Lambda
        payload = base64.b85encode(zlib.compress(res.encode())).decode()
        loader = f"""
# V150 OMNIVERSE :: PYTHON
import zlib, base64
try:
    _x = lambda d: zlib.decompress(base64.b85decode(d))
    exec(_x('{payload}'))
except: exit()
"""
        return loader

    # 2. JAVASCRIPT (The Spectre)
    @staticmethod
    def encrypt_js(code):
        # Hex Encoding + Self Executing Function
        hex_code = ''.join([f'\\x{ord(c):02x}' for c in code])
        var_n = rand_var()
        return f"/* V150 JS */\nvar {var_n} = '{hex_code}';\n(function(){{ eval({var_n}); }})();"

    # 3. C++ (XOR Cipher Simulation)
    @staticmethod
    def encrypt_cpp(code):
        # Generates a valid C++ file that decrypts itself
        key = random.randint(1, 255)
        enc_bytes = [str(ord(c) ^ key) for c in code]
        array_str = ", ".join(enc_bytes)
        return f"""
// V150 C++ PROTECTED
#include <iostream>
#include <string>
#include <vector>

int main() {{
    int key = {key};
    int raw[] = {{{array_str}}};
    std::string code = "";
    for(int i : raw) {{ code += (char)(i ^ key); }}
    // In a real scenario, you would execute or load 'code' here
    std::cout << "Payload Decrypted: " << code.length() << " bytes" << std::endl;
    return 0;
}}
"""

    # 4. C# (Byte Array Loader)
    @staticmethod
    def encrypt_csharp(code):
        b64 = base64.b64encode(code.encode()).decode()
        return f"""
// V150 C# PROTECTED
using System;
using System.Text;

class EuroMoscow {{
    static void Main() {{
        string payload = "{b64}";
        byte[] data = Convert.FromBase64String(payload);
        string code = Encoding.UTF8.GetString(data);
        Console.WriteLine("System Secure.");
    }}
}}
"""

    # 5. LUA (Bytecode Array)
    @staticmethod
    def encrypt_lua(code):
        byte_str = "\\" + "\\".join([str(ord(c)) for c in code])
        return f"-- V150 LUA\nloadstring('{byte_str}')()"

    # 6. PHP (Octal Obfuscation)
    @staticmethod
    def encrypt_php(code):
        octal = ""
        for char in code: octal += "\\" + oct(ord(char))[2:]
        return f"<?php /* V150 */ eval(\"{octal}\"); ?>"

    # 7. GO (Hex Loader)
    @staticmethod
    def encrypt_go(code):
        hx = binascii.hexlify(code.encode()).decode()
        return f"""package main
import("encoding/hex";"fmt")
func main(){{ h:="{hx}"; b,_:=hex.DecodeString(h); fmt.Printf("%s", b); }}"""

    # 8. RUBY (Zlib Base64)
    @staticmethod
    def encrypt_ruby(code):
        b64 = base64.b64encode(zlib.compress(code.encode())).decode()
        return f"# V150 RUBY\nrequire 'zlib';require 'base64';eval(Zlib::Inflate.inflate(Base64.decode64('{b64}')))"

    # 9. PERL (Pack)
    @staticmethod
    def encrypt_perl(code):
        hx = binascii.hexlify(code.encode()).decode()
        return f"# V150 PERL\n$c=pack('H*','{hx}');eval($c);"

    # 10. JAVA (String Reverse)
    @staticmethod
    def encrypt_java(code):
        rev = code[::-1].replace('"', '\\"')
        return f"""
// V150 JAVA
public class Main {{
    public static void main(String[] args) {{
        String p = "{rev}";
        String c = new StringBuilder(p).reverse().toString();
        System.out.println("Executing...");
    }}
}}
"""
    
    # 11. RUST (Byte Array)
    @staticmethod
    def encrypt_rust(code):
        bytes_arr = str(list(code.encode()))
        return f"fn main() {{ let b = {bytes_arr}; let s = String::from_utf8(b).unwrap(); println!(\"{{}}\", s); }}"

    # 12. SWIFT (Base64)
    @staticmethod
    def encrypt_swift(code):
        b64 = base64.b64encode(code.encode()).decode()
        return f"import Foundation; let d = Data(base64Encoded: \"{b64}\")!; print(String(data: d, encoding: .utf8)!)"

    # 13. HTML (Hex Entities)
    @staticmethod
    def encrypt_html(code):
        return "".join([f"&#x{ord(c):x};" for c in code])

# ==============================================================================
# FLASK ROUTING
# ==============================================================================
@app.route('/')
def home(): return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        d = request.json
        code = d.get('code', '')
        lang = d.get('lang', 'python')
        opts = d.get('options', [])
        
        # Log
        HISTORY_LOGS.insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "lang": lang.upper(),
            "size": len(code),
            "ip": request.headers.get('X-Forwarded-For', request.remote_addr)
        })
        if len(HISTORY_LOGS) > 100: HISTORY_LOGS.pop()

        # Engine Router
        if lang == 'python': res = PolyglotCore.encrypt_python(code, opts)
        elif lang == 'javascript': res = PolyglotCore.encrypt_js(code)
        elif lang == 'cpp': res = PolyglotCore.encrypt_cpp(code)
        elif lang == 'csharp': res = PolyglotCore.encrypt_csharp(code)
        elif lang == 'lua': res = PolyglotCore.encrypt_lua(code)
        elif lang == 'php': res = PolyglotCore.encrypt_php(code)
        elif lang == 'go': res = PolyglotCore.encrypt_go(code)
        elif lang == 'ruby': res = PolyglotCore.encrypt_ruby(code)
        elif lang == 'perl': res = PolyglotCore.encrypt_perl(code)
        elif lang == 'java': res = PolyglotCore.encrypt_java(code)
        elif lang == 'rust': res = PolyglotCore.encrypt_rust(code)
        elif lang == 'swift': res = PolyglotCore.encrypt_swift(code)
        elif lang == 'html': res = PolyglotCore.encrypt_html(code)
        else: res = f"// UNKNOWN LANGUAGE\n{code}"

        return jsonify({'result': res})
    except Exception as e: return jsonify({'result': f"# CRITICAL ERROR: {str(e)}"}), 500

@app.route('/history', methods=['GET'])
def get_logs(): return jsonify(HISTORY_LOGS)

@app.route('/run', methods=['POST'])
def run():
    c = request.json.get('code','')
    f = io.StringIO()
    try:
        with redirect_stdout(f): exec(c, {'__builtins__':__builtins__}, {})
        return jsonify({'output': f.getvalue()})
    except Exception as e: return jsonify({'output': str(e)})

if __name__ == '__main__': app.run(debug=True, port=5000)
