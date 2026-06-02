import urllib.request
import base64
import re
import os
import csv
from io import StringIO

# 配置项
URL = "https://www.vpngate.net/api/iphone"
OUTPUT_YAML = "vpngate.yaml"

def get_existing_proxy_names(filepath):
    """读取已有的 YAML 文件，提取所有已存在的节点名称用于去重"""
    existing_names = set()
    if not os.path.exists(filepath):
        return existing_names
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        # 匹配 - name: "节点名称"
        matches = re.findall(r'-\s+name:\s+"([^"]+)"', content)
        for match in matches:
            existing_names.add(match)
            
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
    req = urllib.request.Request(URL)
    with urllib.request.urlopen(req) as response:
        csv_data = response.read().decode('utf-8')

    # 使用 csv 模块解析，忽略注释行
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
            # 解码 Base64 配置
            ovpn_config = base64.b64decode(b64_config).decode('utf-8')
            
            # 正则匹配核心参数
            port_match = re.search(r'^remote\s+[\d\.]+\s+(\d+)', ovpn_config, re.MULTILINE)
            proto_match = re.search(r'^proto\s+(tcp|udp)', ovpn_config, re.MULTILINE)
            cipher_match = re.search(r'^cipher\s+([\w-]+)', ovpn_config, re.MULTILINE)
            auth_match = re.search(r'^auth\s+([\w-]+)', ovpn_config, re.MULTILINE)
            
            port = int(port_match.group(1)) if port_match else 443
            proto = proto_match.group(1) if proto_match else "tcp"
            
            # 生成唯一名称：VPNGate-国家代码-IP-端口-协议
            proxy_name = f"VPNGate-{country_code}-{ip}-{port}-{proto}"
            
            # 关键：去重校验
            if proxy_name in existing_names:
                continue
                
            # 提取证书块 (允许跨行)
            ca_match = re.search(r'<ca>\s*(.*?)\s*</ca>', ovpn_config, re.DOTALL)
            cert_match = re.search(r'<cert>\s*(.*?)\s*</cert>', ovpn_config, re.DOTALL)
            key_match = re.search(r'<key>\s*(.*?)\s*</key>', ovpn_config, re.DOTALL)
            
            proxy = {
                "name": proxy_name,
                "server": ip,
                "port": port,
                "proto": proto,
                "cipher": cipher_match.group(1) if cipher_match else "AES-128-CBC",
                "auth": auth_match.group(1) if auth_match else "SHA1",
                "ca": ca_match.group(1) if ca_match else "",
                "cert": cert_match.group(1) if cert_match else "",
                "key": key_match.group(1) if key_match else ""
            }
            new_proxies.append(proxy)
            existing_names.add(proxy_name) # 加入集合防止同一次拉取中的重复项
            
        except Exception as e:
            # 解析失败跳过
            continue

    print(f"   -> 发现 {len(new_proxies)} 个新节点。")

    if not new_proxies:
        print("4. 没有新增节点，操作结束。")
        return

    print("4. 正在追加新节点到 YAML 文件...")
    # 判断文件是否为空或不存在，决定是否需要写入 `proxies:` 头部
    is_new_file = not os.path.exists(OUTPUT_YAML) or os.path.getsize(OUTPUT_YAML) == 0

    # 使用追加模式 'a' 打开文件
    with open(OUTPUT_YAML, 'a', encoding='utf-8') as f:
        if is_new_file:
            f.write("proxies:\n")
        elif new_proxies:
            # 确保追加前，文件末尾有换行符
            f.write("\n")
            
        for p in new_proxies:
            f.write(f"  - name: \"{p['name']}\"\n")
            f.write(f"    type: openvpn\n")
            f.write(f"    server: {p['server']}\n")
            f.write(f"    port: {p['port']}\n")
            f.write(f"    proto: {p['proto']}\n")
            f.write(f"    udp: {'true' if p['proto'] == 'udp' else 'false'}\n")
            f.write(f"    cipher: {p['cipher']}\n")
            f.write(f"    auth: {p['auth']}\n")
            if p['ca']: f.write(f"    ca: |\n{indent_text(p['ca'])}\n")
            if p['cert']: f.write(f"    cert: |\n{indent_text(p['cert'])}\n")
            if p['key']: f.write(f"    key: |\n{indent_text(p['key'])}\n")

    print(f"5. 完成！成功追加 {len(new_proxies)} 个节点至 {OUTPUT_YAML}")

if __name__ == "__main__":
    main()
