#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Mục tiêu:
# - Hỗ trợ nhiều định dạng: ABP (||, @@, http...), hosts (0.0.0.0 domain), plain domain
# - Bỏ whitelist (@@), bỏ cosmetic (##...), regex ( /.../ )
# - Chuẩn hoá domain (lowercase, bỏ "*.", ".", ":port"), loại trùng, sort ổn định
# - Phân loại: domain_set (exact), domain_suffix_set (suffix kiểu ||example.com^)
# - Xuất YAML theo schema Egern: no_resolve, domain_set, domain_suffix_set

import os
import re
import sys
import time
from urllib.parse import urlparse

import requests
import yaml

TXT_URLS = [
    # ví dụ Hagezi + hostsVN — mày thêm/bớt thoải mái
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/filters/adservers-all.txt",
    # có thể thêm: "https://abpvn.com/filter/abpvn-4h23Hh.txt",
]

OUTPUT = "docs/blocklist.yml"

# ===== Helpers =====

def http_get(url: str, timeout=60, max_retry=3) -> str:
    """Tải nội dung text, retry cơ bản cho ổn định."""
    headers = {"User-Agent": "egern-converter/1.0"}
    for i in range(1, max_retry + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            r.raise_for_status()
            # chuẩn hoá line endings
            return r.text.replace("\r\n", "\n").replace("\r", "\n")
        except Exception as e:
            if i == max_retry:
                raise
            time.sleep(1.5 * i)

def is_ip_literal(host: str) -> bool:
    return bool(re.fullmatch(r"\d+(?:\.\d+){3}", host))

def clean_host(h: str) -> str:
    # chuẩn hoá domain
    h = h.strip().lower()
    if not h:
        return ""
    if h.startswith("."):
        h = h[1:]
    h = h.lstrip("*.")      # bỏ wildcard đầu
    h = h.split(":")[0]     # bỏ cổng
    return h

def take_until_sep(s: str) -> str:
    # lấy phần domain trước các ký tự phân tách ABP
    for i, ch in enumerate(s):
        if ch in "^/*?|":
            return s[:i]
    return s

# ===== Parsers =====

def parse_abp_line(line: str):
    """Phân loại 1 dòng ABP.
    Trả về tuple (kind, host)
    - kind: 'block_suffix' (||domain^), 'block_exact', 'allow' (whitelist), None (bỏ)
    """
    s = line.strip()
    if not s:
        return None, None

    # comment & cosmetic & regex
    if s.startswith(("!", "[Adblock")) or "##" in s or "#@#" in s or "#?$#" in s or s.startswith("/") and s.endswith("/") and len(s) > 2:
        return None, None

    is_whitelist = s.startswith("@@")
    if is_whitelist:
        s = s[2:]

    host = None
    kind = None

    if s.startswith("||"):
        # dạng suffix
        host = take_until_sep(s[2:])
        kind = "allow" if is_whitelist else "block_suffix"

    elif s.startswith("|http"):
        # |https?://host/...
        u = s.lstrip("|")
        try:
            host = urlparse(u).hostname
        except Exception:
            host = None
        kind = "allow" if is_whitelist else "block_exact"

    elif s.startswith(("http://", "https://")):
        try:
            host = urlparse(s).hostname
        except Exception:
            host = None
        kind = "allow" if is_whitelist else "block_exact"

    else:
        # hostname trần (ít gặp): coi như exact nếu không chứa ký tự lạ
        if re.fullmatch(r"[A-Za-z0-9*_.-]+", s):
            host = s
            kind = "allow" if is_whitelist else "block_exact"

    if not host:
        return None, None

    host = clean_host(host)
    if not host or is_ip_literal(host) or "." not in host or "/" in host:
        return None, None

    return kind, host

def parse_hosts_or_plain_line(line: str):
    """Nhận các biến thể: 'domain', '0.0.0.0 domain', '||domain^', 'https://...'
    Trả về host hoặc None.
    """
    s = line.strip()
    if not s or s.startswith(("#", ";", "//", "!")):
        return None

    parts = s.split()
    s = parts[-1].strip()

    if s.startswith("||"):
        s = take_until_sep(s[2:])
    if s.endswith("^"):
        s = s[:-1]

    if s.startswith(("http://", "https://")):
        try:
            host = urlparse(s).hostname or ""
        except Exception:
            host = ""
    else:
        host = s

    host = clean_host(host)
    if not host or is_ip_literal(host) or "/" in host or "." not in host:
        return None
    return host

def parse_text_auto(text: str):
    """Tự phát hiện ABP vs plain dựa trên đặc trưng, trả về sets:
       (block_exact, block_suffix, allow_exact)
    """
    block_exact, block_suffix, allow_exact = set(), set(), set()

    is_abp_like = "||" in text or "[Adblock" in text or "##" in text

    for raw in text.splitlines():
        if is_abp_like:
            kind, host = parse_abp_line(raw)
            if not host:
                continue
            if kind == "allow":
                allow_exact.add(host)
            elif kind == "block_suffix":
                block_suffix.add(host)
            elif kind == "block_exact":
                block_exact.add(host)
        else:
            host = parse_hosts_or_plain_line(raw)
            if host:
                block_exact.add(host)

    # whitelist thắng block
    block_exact -= allow_exact
    block_suffix -= allow_exact

    return block_exact, block_suffix, allow_exact

# ===== Main =====

def convert_to_egern_yaml(urls, out_path):
    domain_set = set()         # exact
    domain_suffix_set = set()  # suffix
    allow_exact = set()        # để trừ ưu tiên

    notes = []
    for url in urls:
        try:
            txt = http_get(url)
            b_exact, b_suffix, a_exact = parse_text_auto(txt)
            domain_set |= b_exact
            domain_suffix_set |= b_suffix
            allow_exact |= a_exact
            notes.append(f"# - {url} (+{len(b_exact)} exact, +{len(b_suffix)} suffix, -{len(a_exact)} allow)")
        except Exception as e:
            notes.append(f"# - {url} (error: {e})")

    # whitelist đã trừ ở trên; ở đây chỉ sắp xếp ổn định
    data = {
        "no_resolve": True,
        "domain_set": sorted(domain_set),
        "domain_suffix_set": sorted(domain_suffix_set),
    }

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Sources:\n")
        f.write("\n".join(notes) + "\n")
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)

    print(f"Wrote {out_path} -> exact={len(domain_set)}, suffix={len(domain_suffix_set)} (allow={len(allow_exact)})")

if __name__ == "__main__":
    convert_to_egern_yaml(TXT_URLS, OUTPUT)
