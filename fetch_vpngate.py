import urllib.request
import base64
import re
import os
import csv

# 配置项
URL = "https://www.vpngate.net/api/iphone"
OUTPUT_YAML = "vpngate.yaml"
OUTPUT_CSV = "servers.csv"

def get_existing_proxy_names(filepath):
    """读取已有的 YAML 文件，提取所有已存在的节点名称用于去重"""
    existing_names = set()
    if not os.path.exists(filepath):
        return existing_names
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        matches = re.findall(r'-\s+name:\s*["\']?([^"\'\n\r]+)["\']?', content)
        for match in matches:
            existing_names.add(match.strip())
    return existing_names

def indent_text(text, spaces=6):
    """辅助函数：处理 YAML 证书字符串的缩进格式"""
    if not text: return ""
    return "\n".join(" " * spaces + line for line in text.strip().splitlines())

def main():
    print(f"1. 正在检查本地配置文件: {OUTPUT_YAML}")
    existing_names = get_existing_proxy_names(OUTPUT_YAML)
    print(f"   -> 本地已存在 {len(existing_names)} 个节点。")

    print(f"2. 正在从 VPN Gate 拉取最新 CSV 数据...")
    req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0 \(Windows NT 10.0; Win64; x64)'})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            csv_data = response.read().decode('utf-8')
    except Exception as e:
        print(f"拉取数据失败: {e}")
        return

    # 保存原始 CSV 数据
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        f.write(csv_data)

    # 过滤注释行
    lines = [line for line in csv_data.splitlines() if not line.startswith(('*', '#'))]
    reader = csv.reader(lines)

    new_proxies = []

    print(f"3. 正在解析配置并进行去重...")
    for parts in reader:
        if len(parts) < 15:
            continue
            
        ip = parts[1]
        country_code = parts[6]
        b64_config = parts[14]

        if not b64_config:
            continue

        try:
            b64_config += "=" * ((4 - len(b64_config) % 4) % 4)
            ovpn_config = base64.b64decode(b64_config).decode('utf-8')

            port_match = re.search(r'^remote\s+(\S+)\s+(\d+)', ovpn_config, re.MULTILINE)
            proto_match = re.search(r'^proto\s+(\S+)', ovpn_config, re.MULTILINE | re.IGNORECASE)
            cipher_match = re.search(r'^cipher\s+([\w-]+)', ovpn_config, re.MULTILINE)
            auth_match = re.search(r'^auth\s+([\w-]+)', ovpn_config, re.MULTILINE)

            port = int(port_match.group(2)) if port_match else 443
            proto = proto_match.group(1).lower() if proto_match else "udp"

            proxy_name = f"VPNGate-{country_code}-{ip}-{port}-{proto}"
            if proxy_name in existing_names:
                continue

            ca_match = re.search(r'<ca>\s*(.*?)\s*</ca>', ovpn_config, re.DOTALL)
            cert_match = re.search(r'<cert>\s*(.*?)\s*</cert>', ovpn_config, re.DOTALL)
            key_match = re.search(r'<key>\s*(.*?)\s*</key>', ovpn_config, re.DOTALL)
            tls_auth_match = re.search(r'<tls-auth>\s*(.*?)\s*</tls-auth>', ovpn_config, re.DOTALL)
            tls_crypt_match = re.search(r'<tls-crypt>\s*(.*?)\s*</tls-crypt>', ovpn_config, re.DOTALL)

            proxy = {
                "name": proxy_name,
                "server": ip,
                "port": port,
                "proto": proto,
                "udp": proto == "udp",
                "data_ciphers": "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC",
                "data_ciphers_fallback": "AES-128-CBC",
                "auth": auth_match.group(1) if auth_match else "SHA256",
                "ca": ca_match.group(1) if ca_match else "",
                "cert": cert_match.group(1) if cert_match else "",
                "key": key_match.group(1) if key_match else "",
                "tls_auth": tls_auth_match.group(1) if tls_auth_match else "",
                "tls_crypt": tls_crypt_match.group(1) if tls_crypt_match else ""
            }
            new_proxies.append(proxy)
            existing_names.add(proxy_name)

        except Exception:
            continue

    print(f"   -> 发现 {len(new_proxies)} 个新节点。")

    if not new_proxies:
        print("4. 没有新增节点，操作结束。")
        return

    print("4. 正在追加新节点到 YAML 文件...")
    is_new_file = not os.path.exists(OUTPUT_YAML) or os.path.getsize(OUTPUT_YAML) == 0

    with open(OUTPUT_YAML, 'a', encoding='utf-8') as f:
        if is_new_file:
            f.write("proxies:\n")
        else:
            f.write("\n")

        for p in new_proxies:
            f.write(f"  - name: \"{p['name']}\"\n")
            f.write(f"    type: openvpn\n")
            f.write(f"    server: {p['server']}\n")
            f.write(f"    port: {p['port']}\n")
            f.write(f"    proto: {p['proto']}\n")
            f.write(f"    udp: {'true' if p['udp'] else 'false'}\n")
            f.write(f"    data-ciphers: {p['data_ciphers']}\n")
            f.write(f"    data-ciphers-fallback: {p['data_ciphers_fallback']}\n")
            f.write(f"    auth: {p['auth']}\n")
            if p['ca']: f.write(f"    ca: |\n{indent_text(p['ca'])}\n")
            if p['cert']: f.write(f"    cert: |\n{indent_text(p['cert'])}\n")
            if p['key']: f.write(f"    key: |\n{indent_text(p['key'])}\n")
            if p['tls_auth']: f.write(f"    tls-auth: |\n{indent_text(p['tls_auth'])}\n    key-direction: \"1\"\n")
            if p['tls_crypt']: f.write(f"    tls-crypt: |\n{indent_text(p['tls_crypt'])}\n")

    print(f"5. 完成！成功追加 {len(new_proxies)} 个节点至 {OUTPUT_YAML}")

if __name__ == "__main__":
    main()
