#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 VPN Gate API 拉取节点，转换为 mihomo (Clash Meta 内核) 可用的 openvpn 代理配置。

设计原则：
1. 尽量"原样还原"源 .ovpn 里出现的、且 mihomo 支持的字段，不额外发明协商列表。
2. 全局按 IP 去重：同一 IP 历史无论换过多少端口，只取最新一个尝试。
3. 历史节点存活检测：引入多线程并发并发对历史节点进行 TCP 端口直连 / UDP OpenVPN 握手探测，只保留存活节点。
4. 自动修复 YAML 重复读写带来的单引号+空行膨胀问题。

依赖：
    pip install pyyaml

用法：
    python vpngate_to_mihomo.py
"""

import base64
import concurrent.futures
import csv
import os
import re
import socket
import time
import urllib.error
import urllib.request

import yaml

URL = "https://www.vpngate.net/api/iphone/"
OUTPUT_YAML = "vpngate.yaml"
OUTPUT_CSV = "servers.csv"
MAX_NODES = 300  # 最大保留节点数

ALLOWED_CIPHERS = {
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
    "CHACHA20-POLY1305",
}
ALLOWED_AUTH = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}
AUTH_ALIASES = {"SHA": "SHA1"}
ALLOWED_DEV = {"tun"}


# ---------- 格式化工具与 YAML 样式 ----------

def clean_multiline(text: str) -> str:
    """清理多行字符串，移除多余空行，修复 PyYAML 反复读写造成的单引号+空行膨胀。"""
    if not text:
        return ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines) + "\n"

class LiteralStr(str): pass
class FlowList(list): pass

def _literal_str_representer(dumper: yaml.Dumper, data: str):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")

def _flow_list_representer(dumper: yaml.Dumper, data: list):
    return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=True)

class IndentedDumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)

yaml.add_representer(LiteralStr, _literal_str_representer, Dumper=IndentedDumper)
yaml.add_representer(FlowList, _flow_list_representer, Dumper=IndentedDumper)


# ---------- 网络请求 ----------

def fetch_csv(url: str, retries: int = 3, timeout: int = 15) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    )
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"  第 {attempt}/{retries} 次拉取失败：{e}")
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError("拉取 VPN Gate CSV 最终失败")


# ---------- 读取与解析 ----------

def load_existing_proxies(filepath: str) -> "dict[str, dict]":
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return {}

    if not data or "proxies" not in data or not isinstance(data["proxies"], list):
        return {}

    result = {}
    for item in data["proxies"]:
        if isinstance(item, dict) and item.get("name"):
            for k in ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"]:
                if k in item and isinstance(item[k], str):
                    item[k] = LiteralStr(clean_multiline(item[k]))
            if "data-ciphers" in item and isinstance(item["data-ciphers"], list):
                item["data-ciphers"] = FlowList(item["data-ciphers"])
            result[item["name"]] = item
    return result

def _find(config: str, directive: str):
    pattern = rf"^{re.escape(directive)}[ \t]+(.+?)(?=[ \t]*[;#]|\r|\n|$)"
    m = re.search(pattern, config, re.MULTILINE)
    return m.group(1).strip() if m else None

def _find_bare(config: str, directive: str) -> bool:
    return re.search(rf"^{re.escape(directive)}\s*$", config, re.MULTILINE) is not None or \
        re.search(rf"^{re.escape(directive)}[ \t]", config, re.MULTILINE) is not None

def _find_tag(config: str, tag: str):
    m = re.search(rf"<{tag}>\s*(?:<[^>]+>\s*)?(.*?)\s*</{tag}>", config, re.DOTALL)
    return clean_multiline(m.group(1)) if m else None

def parse_ovpn_block(ovpn_config: str, fallback_ip: str) -> dict | None:
    ca = _find_tag(ovpn_config, "ca")
    if not ca or _find_bare(ovpn_config, "auth-user-pass"): return None 

    dev = (_find(ovpn_config, "dev") or "tun").lower()
    if dev not in ALLOWED_DEV: return None

    remote_line = re.search(r"^remote\s+(\S+)\s+(\d+)", ovpn_config, re.MULTILINE)
    server = remote_line.group(1) if remote_line else fallback_ip
    port = int(remote_line.group(2)) if remote_line else 443
    proto = (_find(ovpn_config, "proto") or "udp").lower()
    if proto not in ("udp", "tcp"): proto = "udp"

    cipher = _find(ovpn_config, "cipher")
    if cipher:
        cipher = cipher.upper()
        if cipher not in ALLOWED_CIPHERS: return None

    auth = _find(ovpn_config, "auth")
    if auth:
        auth = AUTH_ALIASES.get(auth.upper(), auth.upper())
        if auth not in ALLOWED_AUTH: return None

    data_ciphers = None
    dc_val = _find(ovpn_config, "data-ciphers")
    if dc_val:
        filtered = [c.strip().upper() for c in re.split(r"[:,]", dc_val) if c.strip().upper() in ALLOWED_CIPHERS]
        if filtered: data_ciphers = filtered

    data_ciphers_fallback = _find(ovpn_config, "data-ciphers-fallback")
    if data_ciphers_fallback and data_ciphers_fallback.strip().upper() in ALLOWED_CIPHERS:
        data_ciphers_fallback = data_ciphers_fallback.strip().upper()
    else:
        data_ciphers_fallback = None

    comp_lzo = _find(ovpn_config, "comp-lzo")
    if comp_lzo:
        comp_lzo = comp_lzo.strip().lower()
    elif re.search(r"^comp-lzo\s*$", ovpn_config, re.MULTILINE):
        comp_lzo = "yes"

    mtu_val = _find(ovpn_config, "tun-mtu") or _find(ovpn_config, "link-mtu")
    mtu = int(mtu_val) if mtu_val and mtu_val.isdigit() else None

    ping_val = _find(ovpn_config, "ping")
    ping = int(ping_val) if ping_val and ping_val.isdigit() else None

    pr_val = _find(ovpn_config, "ping-restart")
    ping_restart = int(pr_val) if pr_val and pr_val.isdigit() else None

    tls_auth = _find_tag(ovpn_config, "tls-auth")
    tls_crypt = _find_tag(ovpn_config, "tls-crypt") if not tls_auth else None
    tls_crypt_v2 = _find_tag(ovpn_config, "tls-crypt-v2") if not (tls_auth or tls_crypt) else None
    
    key_direction = _find(ovpn_config, "key-direction") if tls_auth else None
    if tls_auth and key_direction is None: key_direction = "1"

    return {
        "dev": dev, "server": server, "port": port, "proto": proto,
        "cipher": cipher, "auth": auth, "data_ciphers": data_ciphers,
        "data_ciphers_fallback": data_ciphers_fallback, "comp_lzo": comp_lzo,
        "mtu": mtu, "ping": ping, "ping_restart": ping_restart,
        "ca": ca, "cert": _find_tag(ovpn_config, "cert"), "key": _find_tag(ovpn_config, "key"),
        "tls_auth": tls_auth, "tls_crypt": tls_crypt, "tls_crypt_v2": tls_crypt_v2,
        "key_direction": key_direction,
    }

def fields_to_yaml_proxy(name: str, f: dict) -> dict:
    proxy = {
        "name": name, "type": "openvpn", "server": f["server"],
        "port": f["port"], "proto": f["proto"], "udp": f["proto"] == "udp", "dev": f["dev"],
    }
    if f["cipher"]: proxy["cipher"] = f["cipher"]
    if f["data_ciphers"]: proxy["data-ciphers"] = FlowList(f["data_ciphers"])
    if f["data_ciphers_fallback"]: proxy["data-ciphers-fallback"] = f["data_ciphers_fallback"]
    if f["auth"]: proxy["auth"] = f["auth"]
    if f["comp_lzo"]: proxy["comp-lzo"] = f["comp_lzo"]
    if f["mtu"]: proxy["mtu"] = f["mtu"]
    if f["ping"] is not None: proxy["ping"] = f["ping"]
    if f["ping_restart"] is not None: proxy["ping-restart"] = f["ping_restart"]

    proxy["ca"] = LiteralStr(f["ca"])
    if f["cert"]: proxy["cert"] = LiteralStr(f["cert"])
    if f["key"]: proxy["key"] = LiteralStr(f["key"])

    if f["tls_auth"]:
        proxy["tls-auth"] = LiteralStr(f["tls_auth"])
        if f["key_direction"] is not None: proxy["key-direction"] = str(f["key_direction"])
    elif f["tls_crypt"]: proxy["tls-crypt"] = LiteralStr(f["tls_crypt"])
    elif f["tls_crypt_v2"]: proxy["tls-crypt-v2"] = LiteralStr(f["tls_crypt_v2"])

    return proxy


# ---------- 核心检测与合并逻辑 ----------

def check_node_alive(ip: str, port: int, proto: str, timeout: int = 3) -> bool:
    """对节点进行快速存活检测。TCP直连探测；UDP利用 OpenVPN Hard Reset 伪包探测。"""
    if not ip or not port:
        return False
    try:
        if proto == "tcp":
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        else:
            # 构造 OpenVPN UDP 握手包 (Opcode: P_CONTROL_HARD_RESET_CLIENT_V2)
            # 头字节 0x38 (0x07 << 3) + 8字节全零 Session ID
            payload = b'\x38\x01\x00\x00\x00\x00\x00\x00\x00'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(payload, (ip, port))
                s.recv(1024) # 能收到服务端的 ACK 或 Reset 响应，说明对方是活着的 OpenVPN
                return True
    except Exception:
        return False


def merge_proxies(existing: "dict[str, dict]", fresh: "dict[str, dict]") -> list:
    merged = {}
    seen_ips = set()
    new_count = updated_count = retained_count = 0

    # 1. 优先处理本次最新抓取的节点
    for name, proxy in fresh.items():
        ip = proxy.get("server")
        if not ip: continue
        if ip not in seen_ips:
            seen_ips.add(ip)
            merged[name] = proxy
            if name in existing: updated_count += 1
            else: new_count += 1

    # 2. 收集历史节点，并进行严格 IP 去重（同一个 IP 历史记录再多，也只选最新一次用的端口）
    history_candidates = []
    for name, proxy in reversed(list(existing.items())):
        ip = proxy.get("server")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)  # 直接阻断该 IP 的更老历史记录
            history_candidates.append(proxy)
            
    # 3. 对历史节点进行并发存活检测
    needed = MAX_NODES - len(merged)
    if needed > 0 and history_candidates:
        # 为了不消耗太久，最多取 needed 的 2 倍送去测试
        to_test = history_candidates[:needed * 2]
        print(f"   -> 准备对 {len(to_test)} 个历史 IP 进行并发存活检测（TCP直连 / UDP握手）...")
        
        alive_proxies = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_proxy = {
                executor.submit(check_node_alive, p.get("server"), p.get("port"), p.get("proto")): p 
                for p in to_test
            }
            
            for future in concurrent.futures.as_completed(future_to_proxy):
                p = future_to_proxy[future]
                try:
                    if future.result():  # 如果节点存活
                        alive_proxies.append(p)
                except Exception:
                    pass
        
        # 按照历史原本的相对顺序（从新到旧），将存活节点合并进最终列表
        alive_names = {p["name"] for p in alive_proxies}
        for p in to_test:
            if p["name"] in alive_names:
                if len(merged) >= MAX_NODES:
                    break
                merged[p["name"]] = p
                retained_count += 1
                
        print(f"   -> 历史节点检测完毕：发现存活 {len(alive_proxies)} 个，实际补全保留 {retained_count} 个")
        
    print(f"   -> 合并汇总：新增 {new_count}，刷新 {updated_count}，存活历史 {retained_count}")
    return list(merged.values())

def write_proxies(filepath: str, proxies: list) -> None:
    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        yaml.dump(
            {"proxies": proxies}, f, Dumper=IndentedDumper,
            allow_unicode=True, sort_keys=False, default_flow_style=False, width=float("inf")
        )

def main() -> None:
    print(f"1. 读取本地历史配置文件: {OUTPUT_YAML}")
    existing = load_existing_proxies(OUTPUT_YAML)
    print(f"   -> 本地已有 {len(existing)} 个节点 (将清洗空行并去重合并)")

    print("2. 拉取 VPN Gate 最新 CSV 数据...")
    csv_text = fetch_csv(URL)
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        f.write(csv_text)

    print("3. 解析本次抓取的配置...")
    fresh = {}
    lines = [line for line in csv_text.splitlines() if not line.startswith(("*", "#"))]
    for parts in csv.reader(lines):
        if len(parts) < 15: continue
        ip, country_code, b64_config = parts[1].strip(), parts[6].strip() or "XX", parts[14].strip()
        if not ip or not b64_config: continue

        try:
            ovpn_config = base64.b64decode(b64_config + "=" * ((4 - len(b64_config) % 4) % 4)).decode("utf-8", errors="replace")
            parsed = parse_ovpn_block(ovpn_config, ip)
            if parsed:
                name = f"VPNGate-{country_code}-{parsed['server']}-{parsed['port']}-{parsed['proto']}"
                fresh[name] = fields_to_yaml_proxy(name, parsed)
        except Exception:
            pass

    print(f"   -> 本次成功解析 {len(fresh)} 个新鲜节点")

    print("4. 执行全局去重合并与历史节点测活...")
    merged = merge_proxies(existing, fresh)

    print("5. 覆写到 YAML...")
    write_proxies(OUTPUT_YAML, merged)
    print(f"6. 完成！{OUTPUT_YAML} 现共有 {len(merged)} 个高可用去重节点。")

if __name__ == "__main__":
    main()
