#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 VPN Gate API 拉取节点，转换为 mihomo (Clash Meta 内核) 可用的 openvpn 代理配置。

设计原则：
1. 尽量"原样还原"源 .ovpn 里出现的、且 mihomo 支持的字段，不额外发明协商列表。
2. 遇到 mihomo 完全不支持的算法/模式，跳过该节点，而不是替换成可能连不上的默认值。
3. 全局按 IP 去重：只保留同一 IP 下的最新可用端口配置，拒绝单一节点刷屏。
4. 限制总保留节点数 (MAX_NODES)，配合废弃清理，防止文件体积无限膨胀。
5. 自动修复 YAML 重复读写带来的单引号+空行膨胀问题。

依赖：
    pip install pyyaml

用法：
    python vpngate_to_mihomo.py

输出：
    servers.csv    -- VPN Gate 原始 CSV
    vpngate.yaml   -- 合并后的 mihomo proxies 列表
"""

import base64
import csv
import os
import re
import time
import urllib.error
import urllib.request

import yaml

URL = "https://www.vpngate.net/api/iphone/"
OUTPUT_YAML = "vpngate.yaml"
OUTPUT_CSV = "servers.csv"
MAX_NODES = 10000  # 最大保留节点数，防止历史失效节点无限制堆积膨胀

# mihomo openvpn 支持的枚举值（参见 mihomo 文档）
ALLOWED_CIPHERS = {
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
    "CHACHA20-POLY1305",
}
ALLOWED_AUTH = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}
AUTH_ALIASES = {"SHA": "SHA1"}  # OpenVPN 允许裸写 "SHA"
ALLOWED_DEV = {"tun"}


# ---------- 格式化工具与 YAML 样式 ----------

def clean_multiline(text: str) -> str:
    """
    清理多行字符串（如证书、密钥）：
    1. 移除多余的空行
    2. 去除每行首尾空白
    3. 确保以单个 \n 结尾
    可有效修复 PyYAML 反复读写造成的单引号+空行膨胀问题。
    """
    if not text:
        return ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines) + "\n"


class LiteralStr(str):
    """标记需要用 `|` 字面量块样式输出的多行字符串（证书、密钥等）。"""

class FlowList(list):
    """标记需要用 `[a, b]` 流式样式输出的列表（如 data-ciphers）。"""

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
                return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
            print(f"  第 {attempt}/{retries} 次拉取失败：{e}")
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(f"拉取 VPN Gate CSV 最终失败：{last_err}")


# ---------- 读取已有 YAML（用于合并） ----------

def load_existing_proxies(filepath: str) -> "dict[str, dict]":
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"  警告：{filepath} 解析失败（{e}），将视为空文件重新开始")
        return {}

    if not data or "proxies" not in data or not isinstance(data["proxies"], list):
        return {}

    result = {}
    for item in data["proxies"]:
        if isinstance(item, dict) and item.get("name"):
            # 还原 LiteralStr 和 FlowList 包装，并清洗掉旧配置中已累积的空行
            for k in ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"]:
                if k in item and isinstance(item[k], str):
                    item[k] = LiteralStr(clean_multiline(item[k]))
            if "data-ciphers" in item and isinstance(item["data-ciphers"], list):
                item["data-ciphers"] = FlowList(item["data-ciphers"])
            result[item["name"]] = item
    return result


# ---------- 解析单个 .ovpn 配置块 ----------

def _find(config: str, directive: str):
    pattern = rf"^{re.escape(directive)}[ \t]+(.+?)(?=[ \t]*[;#]|\r|\n|$)"
    m = re.search(pattern, config, re.MULTILINE)
    return m.group(1).strip() if m else None

def _find_bare(config: str, directive: str) -> bool:
    return re.search(rf"^{re.escape(directive)}\s*$", config, re.MULTILINE) is not None or \
        re.search(rf"^{re.escape(directive)}[ \t]", config, re.MULTILINE) is not None

def _find_tag(config: str, tag: str):
    m = re.search(rf"<{tag}>\s*(?:<[^>]+>\s*)?(.*?)\s*</{tag}>", config, re.DOTALL)
    if not m:
        return None
    return clean_multiline(m.group(1))

def parse_ovpn_block(ovpn_config: str, fallback_ip: str) -> dict | None:
    ca = _find_tag(ovpn_config, "ca")
    if not ca:
        return None 

    dev_val = _find(ovpn_config, "dev")
    dev = (dev_val or "tun").lower()
    if dev not in ALLOWED_DEV:
        return None

    remote_line = re.search(r"^remote\s+(\S+)\s+(\d+)", ovpn_config, re.MULTILINE)
    server = remote_line.group(1) if remote_line else fallback_ip
    port = int(remote_line.group(2)) if remote_line else 443

    proto_val = _find(ovpn_config, "proto")
    proto = (proto_val or "udp").lower()
    if proto not in ("udp", "tcp"):
        proto = "udp"

    if _find_bare(ovpn_config, "auth-user-pass"):
        return None

    cipher_val = _find(ovpn_config, "cipher")
    cipher = None
    if cipher_val:
        cipher_val = cipher_val.upper()
        if cipher_val not in ALLOWED_CIPHERS:
            return None
        cipher = cipher_val

    auth_val = _find(ovpn_config, "auth")
    auth = None
    if auth_val:
        auth_val = AUTH_ALIASES.get(auth_val.upper(), auth_val.upper())
        if auth_val not in ALLOWED_AUTH:
            return None
        auth = auth_val

    data_ciphers = None
    dc_val = _find(ovpn_config, "data-ciphers")
    if dc_val:
        raw_list = re.split(r"[:,]", dc_val)
        filtered = [c.strip().upper() for c in raw_list if c.strip().upper() in ALLOWED_CIPHERS]
        if filtered:
            data_ciphers = filtered

    data_ciphers_fallback = None
    dcf_val = _find(ovpn_config, "data-ciphers-fallback")
    if dcf_val:
        dcf_val = dcf_val.strip().upper()
        if dcf_val in ALLOWED_CIPHERS:
            data_ciphers_fallback = dcf_val

    comp_lzo = None
    comp_lzo_val = _find(ovpn_config, "comp-lzo")
    if comp_lzo_val:
        comp_lzo = comp_lzo_val.strip().lower()
    elif re.search(r"^comp-lzo\s*$", ovpn_config, re.MULTILINE):
        comp_lzo = "yes"

    mtu = None
    mtu_val = _find(ovpn_config, "tun-mtu") or _find(ovpn_config, "link-mtu")
    if mtu_val and mtu_val.isdigit():
        mtu = int(mtu_val)

    ping = None
    ping_val = _find(ovpn_config, "ping")
    if ping_val and ping_val.isdigit():
        ping = int(ping_val)

    ping_restart = None
    ping_restart_val = _find(ovpn_config, "ping-restart")
    if ping_restart_val and ping_restart_val.isdigit():
        ping_restart = int(ping_restart_val)

    tls_auth = _find_tag(ovpn_config, "tls-auth")
    tls_crypt = _find_tag(ovpn_config, "tls-crypt") if not tls_auth else None
    tls_crypt_v2 = _find_tag(ovpn_config, "tls-crypt-v2") if not (tls_auth or tls_crypt) else None

    key_direction = None
    if tls_auth:
        kd_val = _find(ovpn_config, "key-direction")
        key_direction = kd_val if kd_val is not None else "1"

    return {
        "dev": dev,
        "server": server,
        "port": port,
        "proto": proto,
        "cipher": cipher,
        "auth": auth,
        "data_ciphers": data_ciphers,
        "data_ciphers_fallback": data_ciphers_fallback,
        "comp_lzo": comp_lzo,
        "mtu": mtu,
        "ping": ping,
        "ping_restart": ping_restart,
        "ca": ca,
        "cert": _find_tag(ovpn_config, "cert"),
        "key": _find_tag(ovpn_config, "key"),
        "tls_auth": tls_auth,
        "tls_crypt": tls_crypt,
        "tls_crypt_v2": tls_crypt_v2,
        "key_direction": key_direction,
    }

def fields_to_yaml_proxy(name: str, f: dict) -> dict:
    proxy = {
        "name": name,
        "type": "openvpn",
        "server": f["server"],
        "port": f["port"],
        "proto": f["proto"],
        "udp": f["proto"] == "udp",
        "dev": f["dev"],
    }
    if f["cipher"]:
        proxy["cipher"] = f["cipher"]
    if f["data_ciphers"]:
        proxy["data-ciphers"] = FlowList(f["data_ciphers"])
    if f["data_ciphers_fallback"]:
        proxy["data-ciphers-fallback"] = f["data_ciphers_fallback"]
    if f["auth"]:
        proxy["auth"] = f["auth"]
    if f["comp_lzo"]:
        proxy["comp-lzo"] = f["comp_lzo"]
    if f["mtu"]:
        proxy["mtu"] = f["mtu"]
    if f["ping"] is not None:
        proxy["ping"] = f["ping"]
    if f["ping_restart"] is not None:
        proxy["ping-restart"] = f["ping_restart"]

    proxy["ca"] = LiteralStr(f["ca"])
    if f["cert"]:
        proxy["cert"] = LiteralStr(f["cert"])
    if f["key"]:
        proxy["key"] = LiteralStr(f["key"])

    if f["tls_auth"]:
        proxy["tls-auth"] = LiteralStr(f["tls_auth"])
        if f["key_direction"] is not None:
            proxy["key-direction"] = str(f["key_direction"])
    elif f["tls_crypt"]:
        proxy["tls-crypt"] = LiteralStr(f["tls_crypt"])
    elif f["tls_crypt_v2"]:
        proxy["tls-crypt-v2"] = LiteralStr(f["tls_crypt_v2"])

    return proxy

def build_proxies(csv_text: str) -> "dict[str, dict]":
    lines = [line for line in csv_text.splitlines() if not line.startswith(("*", "#"))]
    reader = csv.reader(lines)
    fresh = {}

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
        except Exception:
            continue

        parsed = parse_ovpn_block(ovpn_config, fallback_ip=ip)
        if parsed is None:
            continue

        name = f"VPNGate-{country_code}-{parsed['server']}-{parsed['port']}-{parsed['proto']}"
        fresh[name] = fields_to_yaml_proxy(name, parsed)

    return fresh


# ---------- 合并逻辑（包含核心去重算法） ----------

def merge_proxies(existing: "dict[str, dict]", fresh: "dict[str, dict]") -> list:
    """
    合并去重策略：
    1. 按 IP (server) 全局去重，防止同一 IP 因为频繁更换不同端口造成节点无限堆积。
    2. 优先保留 fresh（本次最新抓取）中的节点，确保最新可用性。
    3. 保留 existing 中未在本次出现的 IP（即历史节点），从最新的历史记录倒序取回。
    4. 限制总保留节点数 (MAX_NODES)，自动淘汰过旧的死节点。
    """
    merged = {}
    seen_ips = set()
    
    new_count = 0
    updated_count = 0
    retained_count = 0

    # 1. 优先处理最新抓取的节点
    for name, proxy in fresh.items():
        ip = proxy.get("server")
        if not ip:
            continue
        if ip not in seen_ips:
            seen_ips.add(ip)
            merged[name] = proxy
            
            if name in existing:
                if existing[name] != proxy:
                    updated_count += 1
            else:
                new_count += 1

    # 2. 补充历史节点（如果 IP 没在本次出现过）
    # 使用 reversed 从已有旧配置的尾部 (即较新加入的历史记录) 往前倒着遍历
    for name, proxy in reversed(list(existing.items())):
        if len(merged) >= MAX_NODES:
            break
        ip = proxy.get("server")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            merged[name] = proxy
            retained_count += 1

    print(f"   -> 按 IP 去重：新增 {new_count} 个节点，刷新 {updated_count} 个已有节点，保留历史节点 {retained_count} 个")
    if len(seen_ips) >= MAX_NODES:
        print(f"   -> 达到数量上限 ({MAX_NODES})，已自动丢弃更老的过期死节点")
        
    return list(merged.values())

def write_proxies(filepath: str, proxies: list) -> None:
    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        yaml.dump(
            {"proxies": proxies},
            f,
            Dumper=IndentedDumper,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            width=float("inf"),
        )

def main() -> None:
    print(f"1. 读取本地历史配置文件: {OUTPUT_YAML}")
    existing = load_existing_proxies(OUTPUT_YAML)
    print(f"   -> 本地已有 {len(existing)} 个节点 (将尝试修复并合并)")

    print("2. 拉取 VPN Gate 最新 CSV 数据...")
    csv_text = fetch_csv(URL)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        f.write(csv_text)
    print(f"   -> 原始 CSV 已保存到 {OUTPUT_CSV}")

    print("3. 解析本次抓取的配置...")
    fresh = build_proxies(csv_text)
    print(f"   -> 本次成功解析 {len(fresh)} 个节点")

    print("4. 执行全局去重合并...")
    merged = merge_proxies(existing, fresh)

    print("5. 覆写到 YAML...")
    write_proxies(OUTPUT_YAML, merged)
    print(f"6. 完成！{OUTPUT_YAML} 现共有 {len(merged)} 个高优去重节点。")

if __name__ == "__main__":
    main()
