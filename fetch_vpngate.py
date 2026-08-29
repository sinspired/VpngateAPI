#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 VPN Gate API 拉取节点，转换为 mihomo (Clash Meta 内核) 可用的 openvpn 代理配置。

用法：
    python vpngate_to_mihomo.py

输出：
    servers.csv    -- VPN Gate 原始 CSV（每次运行覆盖，便于排查）
    vpngate.yaml   -- 追加写入的 mihomo proxies 列表（已存在的节点自动跳过）
"""

import base64
import csv
import os
import re
import time
import urllib.error
import urllib.request

URL = "https://www.vpngate.net/api/iphone/"
OUTPUT_YAML = "vpngate.yaml"
OUTPUT_CSV = "servers.csv"

# mihomo 支持的 cipher 集合（AES-CBC 系列会按 AES-128-CBC 处理，见 mihomo 文档）
ALLOWED_CIPHERS = {
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
    "CHACHA20-POLY1305",
}
ALLOWED_AUTH = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}


def fetch_csv(url: str, retries: int = 3, timeout: int = 15) -> str:
    """拉取 VPN Gate CSV，带重试和编码容错。"""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
            )
        },
    )
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                # 个别行可能混入非 UTF-8 字节（比如节点 Message 字段），用 replace 容错
                return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
            print(f"  第 {attempt}/{retries} 次拉取失败：{e}")
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(f"拉取 VPN Gate CSV 最终失败：{last_err}")


def get_existing_proxy_names(filepath: str) -> set:
    """读取已有 YAML 文件，提取已存在节点名用于去重。"""
    if not os.path.exists(filepath):
        return set()
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    return {m.strip() for m in re.findall(r'-\s+name:\s*["\']?([^"\'\n\r]+)["\']?', content)}


def indent_text(text: str, spaces: int = 6) -> str:
    """给证书/密钥多行文本加缩进，用于 YAML 的 `|` 块。"""
    if not text:
        return ""
    return "\n".join(" " * spaces + line for line in text.strip().splitlines())


def parse_ovpn_block(ovpn_config: str, fallback_ip: str) -> dict | None:
    """从解码后的 .ovpn 文本里提取 mihomo 需要的字段。"""
    remote_match = re.search(r"^remote\s+(\S+)\s+(\d+)", ovpn_config, re.MULTILINE)
    proto_match = re.search(r"^proto\s+(\S+)", ovpn_config, re.MULTILINE | re.IGNORECASE)
    cipher_match = re.search(r"^cipher\s+([\w-]+)", ovpn_config, re.MULTILINE)
    auth_match = re.search(r"^auth\s+([\w-]+)", ovpn_config, re.MULTILINE)
    ca_match = re.search(r"<ca>\s*(.*?)\s*</ca>", ovpn_config, re.DOTALL)
    cert_match = re.search(r"<cert>\s*(.*?)\s*</cert>", ovpn_config, re.DOTALL)
    key_match = re.search(r"<key>\s*(?:<[^>]+>\s*)?(.*?)\s*</key>", ovpn_config, re.DOTALL)
    tls_auth_match = re.search(r"<tls-auth>\s*(.*?)\s*</tls-auth>", ovpn_config, re.DOTALL)
    tls_crypt_match = re.search(r"<tls-crypt>\s*(.*?)\s*</tls-crypt>", ovpn_config, re.DOTALL)

    if not ca_match:
        # 没有 CA 证书基本无法连接，直接跳过
        return None

    # remote 行里的地址优先于 CSV 里的 IP 列（个别节点两者不一致）
    server = remote_match.group(1) if remote_match else fallback_ip
    port = int(remote_match.group(2)) if remote_match else 443
    proto = (proto_match.group(1).lower() if proto_match else "udp")
    if proto not in ("udp", "tcp"):
        proto = "udp"

    cipher = (cipher_match.group(1).upper() if cipher_match else "AES-128-CBC")
    if cipher not in ALLOWED_CIPHERS:
        cipher = "AES-128-CBC"

    auth = (auth_match.group(1).upper() if auth_match else "SHA1")
    if auth not in ALLOWED_AUTH:
        auth = "SHA1"

    return {
        "server": server,
        "port": port,
        "proto": proto,
        "cipher": cipher,
        "auth": auth,
        "ca": ca_match.group(1),
        "cert": cert_match.group(1) if cert_match else "",
        "key": key_match.group(1) if key_match else "",
        "tls_auth": tls_auth_match.group(1) if tls_auth_match else "",
        "tls_crypt": tls_crypt_match.group(1) if tls_crypt_match else "",
    }


def build_proxies(csv_text: str, existing_names: set) -> list:
    """解析 CSV 全文，返回新增的 proxy 字典列表。"""
    lines = [line for line in csv_text.splitlines() if not line.startswith(("*", "#"))]
    reader = csv.reader(lines)
    new_proxies = []

    for parts in reader:
        if len(parts) < 15:
            continue

        ip = parts[1].strip()
        country_code = parts[6].strip() or "XX"
        b64_config = parts[14].strip()
        if not ip or not b64_config:
            continue

        try:
            padded = b64_config + "=" * ((4 - len(b64_config) % 4) % 4)
            ovpn_config = base64.b64decode(padded).decode("utf-8", errors="replace")
        except Exception as e:
            print(f"  跳过一个节点（base64 解码失败）：{e}")
            continue

        fields = parse_ovpn_block(ovpn_config, fallback_ip=ip)
        if fields is None:
            continue

        proxy_name = f"VPNGate-{country_code}-{fields['server']}-{fields['port']}-{fields['proto']}"
        if proxy_name in existing_names:
            continue

        fields["name"] = proxy_name
        new_proxies.append(fields)
        existing_names.add(proxy_name)

    return new_proxies


def write_proxies(filepath: str, proxies: list) -> None:
    """把新节点以 mihomo 格式追加写入 YAML。"""
    is_new_file = not os.path.exists(filepath) or os.path.getsize(filepath) == 0

    with open(filepath, "a", encoding="utf-8", newline="\n") as f:
        if is_new_file:
            f.write("proxies:\n")

        for p in proxies:
            f.write(f'  - name: "{p["name"]}"\n')
            f.write("    type: openvpn\n")
            f.write(f'    server: {p["server"]}\n')
            f.write(f'    port: {p["port"]}\n')
            f.write(f'    proto: {p["proto"]}\n')
            f.write(f'    udp: {"true" if p["proto"] == "udp" else "false"}\n')
            f.write(f'    cipher: {p["cipher"]}\n')
            f.write(f'    auth: {p["auth"]}\n')
            if p["ca"]:
                f.write(f"    ca: |\n{indent_text(p['ca'])}\n")
            if p["cert"]:
                f.write(f"    cert: |\n{indent_text(p['cert'])}\n")
            if p["key"]:
                f.write(f"    key: |\n{indent_text(p['key'])}\n")
            if p["tls_auth"]:
                f.write(f"    tls-auth: |\n{indent_text(p['tls_auth'])}\n    key-direction: \"1\"\n")
            if p["tls_crypt"]:
                f.write(f"    tls-crypt: |\n{indent_text(p['tls_crypt'])}\n")


def main() -> None:
    print(f"1. 检查本地配置文件: {OUTPUT_YAML}")
    existing_names = get_existing_proxy_names(OUTPUT_YAML)
    print(f"   -> 本地已有 {len(existing_names)} 个节点")

    print("2. 拉取 VPN Gate 最新 CSV 数据...")
    csv_text = fetch_csv(URL)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        f.write(csv_text)
    print(f"   -> 原始 CSV 已保存到 {OUTPUT_CSV}")

    print("3. 解析配置并去重...")
    new_proxies = build_proxies(csv_text, existing_names)
    print(f"   -> 发现 {len(new_proxies)} 个新节点")

    if not new_proxies:
        print("4. 没有新增节点，结束。")
        return

    print("4. 追加写入 YAML...")
    write_proxies(OUTPUT_YAML, new_proxies)
    print(f"5. 完成！已追加 {len(new_proxies)} 个节点到 {OUTPUT_YAML}")


if __name__ == "__main__":
    main()