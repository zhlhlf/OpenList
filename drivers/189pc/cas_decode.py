#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
189pc CAS 迁移工具: v1 解密 -> v2 重加密

用途: 批量把旧版(v1, 固定密钥XOR)的 .bin 占位文件迁移到新版(v2, 随机nonce)格式。

交互模式(默认): 输入 v1 文件名回车 -> 打印解密内容 + 生成新的 v2 文件名(每次都不同)
迁移模式(-m):   只输出新 v2 文件名, 方便脚本批量 rename:
                   python cas_decode.py -m < old_names.txt > new_names.txt
                   输出两列: 旧文件名<TAB>新文件名

v1 解码: XOR("zhlhlf" 循环) -> JSON
v2 生成: 4字节随机nonce || 2字节校验和 || SHA256-CTR密钥流异或 -> base64url
         (无版本字节, 校验和覆盖 key+nonce+body, 兼作格式识别)
"""

import base64
import hashlib
import json
import os
import struct
import sys

CAS_KEY = b"zhlhlf"   # cas.go 中的 casKey
CAS_EXT = ".bin"      # cas.go 中的 casExt
NONCE_SIZE = 4
CHECK_SIZE = 2
HEADER_SIZE = NONCE_SIZE + CHECK_SIZE


def xor_cas(data: bytes) -> bytes:
    """v1: 固定密钥循环异或"""
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ CAS_KEY[i % len(CAS_KEY)]
    return bytes(out)


def xor_cas_v2(data: bytes, nonce: bytes) -> bytes:
    """v2: SHA-256 计数器模式密钥流异或, 对应 cas.go 的 xorCASv2"""
    out = bytearray(len(data))
    counter = 0
    off = 0
    while off < len(data):
        h = hashlib.sha256()
        h.update(CAS_KEY)
        h.update(nonce)
        h.update(struct.pack(">I", counter))
        ks = h.digest()
        for j in range(min(32, len(data) - off)):
            out[off + j] = data[off + j] ^ ks[j]
        off += 32
        counter += 1
    return bytes(out)


def cas_checksum(nonce: bytes, body: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(CAS_KEY)
    h.update(nonce)
    h.update(body)
    return h.digest()[:CHECK_SIZE]


def decode_v1(name: str) -> dict:
    """解密 v1 格式, 返回 payload dict; 失败抛 ValueError"""
    name = name.strip()
    if not name:
        raise ValueError("空输入")
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    if name.lower().endswith(CAS_EXT):
        name = name[: -len(CAS_EXT)]
    try:
        raw = base64.urlsafe_b64decode(name + "=" * (-len(name) % 4))
    except Exception as e:
        raise ValueError(f"base64 解码失败: {e}")
    try:
        text = xor_cas(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("不是 v1 CAS 文件(异或后非有效文本)")
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        raise ValueError(f"不是 v1 CAS 文件(内容非 JSON): {text!r}")
    if not obj.get("name") or obj.get("size") is None or not obj.get("md5"):
        raise ValueError("payload 缺少必要字段")
    if not obj.get("smd5"):
        obj["smd5"] = obj["md5"]
    return obj


def decode_v2(name: str) -> dict:
    """解密 v2 格式(校验和验证), 返回 payload dict; 失败抛 ValueError"""
    name = name.strip()
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    if name.lower().endswith(CAS_EXT):
        name = name[: -len(CAS_EXT)]
    raw = base64.urlsafe_b64decode(name + "=" * (-len(name) % 4))
    if len(raw) < HEADER_SIZE:
        raise ValueError("不是 v2 格式(长度不足)")
    nonce = raw[:NONCE_SIZE]
    checksum = raw[NONCE_SIZE:HEADER_SIZE]
    body = raw[HEADER_SIZE:]
    if checksum != cas_checksum(nonce, body):
        raise ValueError("v2 校验和不匹配")
    return json.loads(xor_cas_v2(body, nonce).decode("utf-8"))


def encode_v2(obj: dict) -> str:
    """payload dict 加密为 v2 文件名(每次调用随机, 结果都不同)"""
    payload = json.dumps(
        {"name": obj["name"], "size": obj["size"], "md5": obj["md5"], "smd5": obj.get("smd5", obj["md5"])},
        separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    nonce = os.urandom(NONCE_SIZE)
    body = xor_cas_v2(payload, nonce)
    data = nonce + cas_checksum(nonce, body) + body
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=") + CAS_EXT


def format_payload(obj: dict) -> str:
    size = obj["size"]
    human = f"{size / 1024 / 1024 / 1024:.2f} GB" if size >= 1024**3 else \
            f"{size / 1024 / 1024:.2f} MB" if size >= 1024**2 else \
            f"{size / 1024:.2f} KB" if size >= 1024 else f"{size} B"
    lines = [
        f"文件名  : {obj['name']}",
        f"大小    : {size} ({human})",
        f"MD5     : {obj['md5']}",
        f"分片MD5 : {obj['smd5']}",
    ]
    return "\n".join(lines)


def main():
    migrate = "-m" in sys.argv[1:]

    if migrate:
        # 批量迁移模式: stdin 每行一个旧文件名, stdout 输出 "旧名<TAB>新名"
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = decode_v1(line)
            except ValueError:
                print(f"{line}\tERROR", file=sys.stderr)
                continue
            print(f"{line}\t{encode_v2(obj)}")
        return

    print("189pc CAS 迁移工具: v1 解密 -> v2 重新加密")
    print("输入 v1 .bin 文件名回车, 输出解密内容和新 v2 文件名")
    print("批量模式: python cas_decode.py -m < 旧名.txt > 新名.txt")
    print("-" * 60)
    while True:
        try:
            line = input("cas> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n退出")
            sys.exit(0)
        if not line:
            continue
        try:
            obj = decode_v1(line)
        except ValueError as e:
            print(f"[v1 解密失败] {e}")
            print("-" * 60)
            continue
        print(format_payload(obj))
        print(f"新v2名  : {encode_v2(obj)}")
        print("-" * 60)


if __name__ == "__main__":
    main()
