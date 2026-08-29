#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 VPN Gate API 拉取节点，转换为 mihomo (Clash Meta 内核) 可用的 openvpn 代理配置。

设计原则：
1. 尽量"原样还原"源 .ovpn 里出现的、且 mihomo 支持的字段，不额外发明协商列表，
   也不悄悄砍掉源配置已声明的字段（如 data-ciphers）。
2. 遇到 mihomo 完全不支持的算法/模式，跳过该节点，而不是替换成可能连不上的默认值。
3. 按节点名（国家-地址-端口-协议）合并：同名节点用本次解析结果【覆盖】旧记录
   （保持原有位置，方便看 diff），全新节点追加到末尾。
   这样即使脚本逻辑之后又修好了别的字段，重新运行也能让历史记录自动补全，
   不会出现"名字已存在就永远跳过、旧数据没法更新"的问题。

依赖：
    pip install pyyaml

用法：
    python vpngate_to_mihomo.py

输出：
    servers.csv    -- VPN Gate 原始 CSV（每次运行覆盖，便于排查）
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

# mihomo openvpn 支持的枚举值（参见 mihomo 文档）
ALLOWED_CIPHERS = {
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
    "CHACHA20-POLY1305",
}
ALLOWED_AUTH = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}
AUTH_ALIASES = {"SHA": "SHA1"}  # OpenVPN 允许裸写 "SHA"，等价于 SHA1
# mihomo 目前只支持 tun；tap 暂不支持
ALLOWED_DEV = {"tun"}


# ---------- YAML 输出的自定义样式（block 字面量 / 流式列表） ----------

class LiteralStr(str):
    """标记需要用 `|` 字面量块样式输出的多行字符串（证书、密钥等）。"""


class FlowList(list):
    """标记需要用 `[a, b]` 流式样式输出的列表（如 data-ciphers）。"""


def _literal_str_representer(dumper: yaml.Dumper, data: str):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


def _flow_list_representer(dumper: yaml.Dumper, data: list):
    return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=True)


class IndentedDumper(yaml.SafeDumper):
    """让列表项相对父级键缩进（`proxies:` 下的 `- name:` 缩进 2 格），风格对齐官方示例。"""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


yaml.add_representer(LiteralStr, _literal_str_representer, Dumper=IndentedDumper)
yaml.add_representer(FlowList, _flow_list_representer, Dumper=IndentedDumper)


# ---------- 网络请求 ----------

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
                return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
            print(f"  第 {attempt}/{retries} 次拉取失败：{e}")
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(f"拉取 VPN Gate CSV 最终失败：{last_err}")


# ---------- 读取已有 YAML（用于合并） ----------

def load_existing_proxies(filepath: str) -> "dict[str, dict]":
    """
    读取已有 vpngate.yaml，返回 {节点名: proxy_dict}，保持原有顺序。
    文件不存在 / 为空 / 格式不对时返回空字典（视为全新开始）。
    """
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
            result[item["name"]] = item
    return result


# ---------- 解析单个 .ovpn 配置块 ----------

def _find(config: str, directive: str):
    """
    查找一条【未被注释】的指令并返回其参数（去除首尾空白及行内注释）。
    优化：通过前瞻断言匹配到注释符 (# 或 ;) 或者行尾前，避免把行内注释也读进去。
    """
    # 解释：匹配行首 -> 匹配指令 -> 匹配至少一个空格 -> 捕获非贪婪内容 -> 直到遇到 #, ;, 或换行符/行尾
    pattern = rf"^{re.escape(directive)}[ \t]+(.+?)(?=[ \t]*[;#]|\r|\n|$)"
    m = re.search(pattern, config, re.MULTILINE)
    return m.group(1).strip() if m else None


def _find_bare(config: str, directive: str) -> bool:
    """检测某条【无参数或有参数】指令是否被启用（未注释）。"""
    return re.search(rf"^{re.escape(directive)}\s*$", config, re.MULTILINE) is not None or \
        re.search(rf"^{re.escape(directive)}[ \t]", config, re.MULTILINE) is not None


def _find_tag(config: str, tag: str):
    """提取 XML 风格标签内的内容，修复 Windows 换行符，并清除首尾空白。"""
    m = re.search(rf"<{tag}>\s*(?:<[^>]+>\s*)?(.*?)\s*</{tag}>", config, re.DOTALL)
    if not m:
        return None
    
    # 1. 替换 Windows 回车
    # 2. .strip() 去除自带的杂乱空行
    # 3. 补上一个 "\n"，让 PyYAML 能够顺理成章地输出 `|`
    return m.group(1).replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"


def parse_ovpn_block(ovpn_config: str, fallback_ip: str) -> dict | None:
    """
    全面解析解码后的 .ovpn 文本，提取 mihomo openvpn 类型支持的所有字段。
    返回 None 表示这个节点无法（或不该）被还原为一个能用的 mihomo 节点。
    """
    ca = _find_tag(ovpn_config, "ca")
    if not ca:
        return None  # 没有 CA 基本连不上，直接跳过

    # --- dev：mihomo 目前只支持 tun，源配置若要求 tap 则跳过 ---
    dev_val = _find(ovpn_config, "dev")
    dev = (dev_val or "tun").lower()
    if dev not in ALLOWED_DEV:
        print(f"  跳过 {fallback_ip} —— dev {dev} 目前不被 mihomo 支持（仅支持 tun）")
        return None

    # --- 服务器地址 ---
    remote_line = re.search(r"^remote\s+(\S+)\s+(\d+)", ovpn_config, re.MULTILINE)
    server = remote_line.group(1) if remote_line else fallback_ip
    port = int(remote_line.group(2)) if remote_line else 443

    # --- 协议 ---
    proto_val = _find(ovpn_config, "proto")
    proto = (proto_val or "udp").lower()
    if proto not in ("udp", "tcp"):
        proto = "udp"

    # --- auth-user-pass：若被真正启用（未注释），我们不知道用户名密码，直接跳过 ---
    if _find_bare(ovpn_config, "auth-user-pass"):
        print(f"  跳过 {server}:{port} —— 该节点要求 auth-user-pass 认证，脚本无法自动获知账号密码")
        return None

    # --- cipher（不支持则整个节点跳过，不做静默替换） ---
    cipher_val = _find(ovpn_config, "cipher")
    cipher = None
    if cipher_val:
        cipher_val = cipher_val.upper()
        if cipher_val not in ALLOWED_CIPHERS:
            print(f"  跳过 {server}:{port} —— cipher {cipher_val} 不被 mihomo 支持")
            return None
        cipher = cipher_val

    # --- auth（同样：不支持就跳过整个节点） ---
    auth_val = _find(ovpn_config, "auth")
    auth = None
    if auth_val:
        auth_val = AUTH_ALIASES.get(auth_val.upper(), auth_val.upper())
        if auth_val not in ALLOWED_AUTH:
            print(f"  跳过 {server}:{port} —— auth {auth_val} 不被 mihomo 支持")
            return None
        auth = auth_val

    # --- data-ciphers：源配置真的写了才还原，原样保留声明的协商列表 ---
    data_ciphers = None
    dc_val = _find(ovpn_config, "data-ciphers")
    if dc_val:
        raw_list = re.split(r"[:,]", dc_val)
        filtered = [c.strip().upper() for c in raw_list if c.strip().upper() in ALLOWED_CIPHERS]
        if filtered:
            data_ciphers = filtered

    # --- data-ciphers-fallback：同样只在源配置真实出现时才还原 ---
    data_ciphers_fallback = None
    dcf_val = _find(ovpn_config, "data-ciphers-fallback")
    if dcf_val:
        dcf_val = dcf_val.strip().upper()
        if dcf_val in ALLOWED_CIPHERS:
            data_ciphers_fallback = dcf_val

    # --- comp-lzo（"comp-lzo" / "comp-lzo yes" / "comp-lzo adaptive" / "comp-lzo no"） ---
    comp_lzo = None
    comp_lzo_val = _find(ovpn_config, "comp-lzo")
    if comp_lzo_val:
        comp_lzo = comp_lzo_val.strip().lower()
    elif re.search(r"^comp-lzo\s*$", ovpn_config, re.MULTILINE):
        comp_lzo = "yes"

    # --- mtu（常见写法 tun-mtu，其次 link-mtu） ---
    mtu = None
    mtu_val = _find(ovpn_config, "tun-mtu") or _find(ovpn_config, "link-mtu")
    if mtu_val and mtu_val.isdigit():
        mtu = int(mtu_val)

    # --- ping / ping-restart ---
    ping = None
    ping_val = _find(ovpn_config, "ping")
    if ping_val and ping_val.isdigit():
        ping = int(ping_val)

    ping_restart = None
    ping_restart_val = _find(ovpn_config, "ping-restart")
    if ping_restart_val and ping_restart_val.isdigit():
        ping_restart = int(ping_restart_val)

    # --- tls-auth / tls-crypt / tls-crypt-v2（三者互斥，按源配置实际出现的为准） ---
    tls_auth = _find_tag(ovpn_config, "tls-auth")
    tls_crypt = _find_tag(ovpn_config, "tls-crypt") if not tls_auth else None
    tls_crypt_v2 = _find_tag(ovpn_config, "tls-crypt-v2") if not (tls_auth or tls_crypt) else None

    key_direction = None
    if tls_auth:
        kd_val = _find(ovpn_config, "key-direction")
        # 源配置没显式写方向时，VPN Gate/SoftEther 导出的 tls-auth 惯例用 "1"
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
    """把 parse_ovpn_block 的解析结果转换成最终要写入 YAML 的 dict（保持字段顺序）。"""
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
    """解析 CSV 全文，返回本次抓取到的 {节点名: proxy_dict}。"""
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
        except Exception as e:
            print(f"  跳过一个节点（base64 解码失败）：{e}")
            continue

        parsed = parse_ovpn_block(ovpn_config, fallback_ip=ip)
        if parsed is None:
            continue

        name = f"VPNGate-{country_code}-{parsed['server']}-{parsed['port']}-{parsed['proto']}"
        # 同一批 CSV 里理论上不会有完全相同的 name 重复出现；万一有，后出现的覆盖前一个即可
        fresh[name] = fields_to_yaml_proxy(name, parsed)

    return fresh


def merge_proxies(existing: "dict[str, dict]", fresh: "dict[str, dict]") -> list:
    """
    合并策略：
    - 名字在 fresh 中出现过 -> 用 fresh 的最新解析结果覆盖（位置保持原样，方便看 diff）
    - 名字只在 existing 中出现 -> 保留（VPN Gate 分页轮换，节点这次没抓到不代表已失效）
    - 名字只在 fresh 中出现 -> 追加到末尾
    """
    merged = dict(existing)  # 复制，保持原有顺序
    new_count = 0
    updated_count = 0
    for name, proxy in fresh.items():
        if name in merged:
            if merged[name] != proxy:
                updated_count += 1
            merged[name] = proxy  # 保持原位置，直接覆盖内容
        else:
            merged[name] = proxy  # dict 里的新 key 会追加在末尾
            new_count += 1
    print(f"   -> 新增 {new_count} 个节点，刷新 {updated_count} 个已存在节点的字段")
    return list(merged.values())


def write_proxies(filepath: str, proxies: list) -> None:
    """用 PyYAML 正确写出完整的 proxies 列表（覆盖整个文件）。"""
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
    print(f"1. 读取本地配置文件: {OUTPUT_YAML}")
    existing = load_existing_proxies(OUTPUT_YAML)
    print(f"   -> 本地已有 {len(existing)} 个节点")

    print("2. 拉取 VPN Gate 最新 CSV 数据...")
    csv_text = fetch_csv(URL)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        f.write(csv_text)
    print(f"   -> 原始 CSV 已保存到 {OUTPUT_CSV}")

    print("3. 解析本次抓取的配置...")
    fresh = build_proxies(csv_text)
    print(f"   -> 本次成功解析 {len(fresh)} 个节点")

    print("4. 合并新旧节点（同名覆盖刷新，新节点追加）...")
    merged = merge_proxies(existing, fresh)

    print("5. 写入 YAML...")
    write_proxies(OUTPUT_YAML, merged)
    print(f"6. 完成！{OUTPUT_YAML} 现共有 {len(merged)} 个节点")


if __name__ == "__main__":
    main()