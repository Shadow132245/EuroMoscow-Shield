# 🛡️ EuroMoscow Shield | Ultimate Code Obfuscator

![EuroMoscow Shield](https://euro-moscow-shield.vercel.app/static/logo.png)

**EuroMoscow Shield** is a powerful, free, and open-source tool designed to protect your **Python** and **JavaScript** source code. It uses advanced multi-layer encryption techniques to make your code unreadable while keeping it fully functional.

🔗 **Live WebSite:** [https://euro-moscow-shield.vercel.app](https://euro-moscow-shield.vercel.app)

---

## 🔥 Features

### 🐍 Python Protection
- **Safe Variable Renaming:** Smart AST parsing to rename variables without breaking logic.
- **Portable Blob:** Compresses code into a zlib integer array (Runs on any Python version 3.6+).
- **EuroMoscow XOR:** Custom XOR encryption with dynamic keys.
- **Rot13 & Base64:** Classic layers for extra confusion.
- **Import Guard:** Automatically detects and protects library imports.

### 📜 JavaScript Protection
- **Hex Encoding:** Converts code to hexadecimal strings (`\x68\x65...`).
- **Char Code Array:** Transforms logic into number arrays.
- **URL Encoding:** Percent-encoding for web compatibility.
- **Base64 Eval:** Standard web obfuscation.

### 🧠 AI Auto-Decryptor
- No need to select the algorithm! The **Smart Decryptor** scans the code and automatically detects layers (Base64, Zlib, Rot13, XOR, Blob) to restore the original source.

---

## 🚀 API Usage

You can integrate EuroMoscow Shield directly into your tools using our REST API.

## ⚠️ Legal Disclaimer

**EuroMoscow Shield** is developed strictly for educational purposes and for the protection of intellectual property (IP) of legitimate developers.

- The developer (**EuroMoscow**) is not responsible for any misuse of this tool.
- Do not use this tool to obfuscate malicious code (malware, viruses, spyware).
- Usage of this tool for illegal activities is strictly prohibited.

By using this software, you agree to these terms and hold the developer harmless from any legal consequences.

**Endpoint:** `POST /process`

### Example (Python)
```python
import requests

url = "[https://euro-moscow-shield.vercel.app/process](https://euro-moscow-shield.vercel.app/process)"

payload = {
    "code": "print('Hello World')",
    "action": "encrypt",
    "lang": "python",
    "options": ["rename", "marshal", "xor"]
}

response = requests.post(url, json=payload)
print(response.json()['result'])
