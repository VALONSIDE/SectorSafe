#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 VALONSIDE
"""
SectorSafe  M1 卡密码管理器

版本    beta_v0.1
作者    VALONSIDE
项目    https://github.com/VALONSIDE/SectorSafe
协议    Apache License 2.0

依赖    pip install -r requirements.txt
运行    python sectorsafe.py
        python sectorsafe.py --sim card.bin [--sim-type 4K]
参数    --reader 读卡器名称关键字   --key 扇区密钥   --key-type A|B   --type 1K|4K

卡片布局，数据块按可用顺序编号，不含 0 号块和扇区尾块：
  属性区  8 块，128 字节
          公开属性 32：标识、版本、卡名、密码模式与长度、标签长度、槽位数、开卡时间、KDF 参数、标志
          密钥材料 96：盐 16，主密码包装的数据密钥 40，恢复码包装的数据密钥 40
  安全区  2 块，32 字节，可选
          胁迫校验值 16，锁卡阈值、错误计数、锁定标志，恢复码阈值、错误计数
  密码区  nonce 12 + AES-256-GCM 密文 + tag 16
          明文为配置 1 字节加全部槽位。槽位定长：
          标志 1，标签长度 1，标签 L，密码长度 1，密码 ceil(P/2)（HEX）或 P（ASCII）
  公开属性作为密码区 GCM 的附加认证数据。
"""

import argparse
import hashlib
import hmac
import os
import secrets
import string
import struct
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

import tkinter as tk
import tkinter.font as tkfont

APP_NAME = "SectorSafe"
APP_VERSION = "beta_v0.1"
APP_AUTHOR = "VALONSIDE"
APP_LICENSE = "Apache License 2.0"
APP_URL = "https://github.com/VALONSIDE/SectorSafe"

DEFAULT_KEY = "FFFFFFFFFFFF"


class CardError(Exception):
    pass


class CardWiped(Exception):
    """安全策略触发后卡片已清零。reason 为 "duress" 或 "recovery"。"""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# =====================================================================
#  卡片访问层
# =====================================================================

def is_trailer(block):
    return block % 4 == 3 if block < 128 else (block - 128) % 16 == 15


def data_blocks(card_type):
    """可用数据块列表 [(块号, 扇区首块号)]，不含 0 号块和扇区尾块。"""
    small = {"1K": 16, "4K": 32}.get(card_type)
    if small is None:
        raise CardError(f"不支持的卡型：{card_type}")
    blocks = []
    for s in range(small):
        first = s * 4
        blocks += [(b, first) for b in range(first, first + 3) if b != 0]
    if card_type == "4K":
        for s in range(32, 40):
            first = 128 + (s - 32) * 16
            blocks += [(b, first) for b in range(first, first + 15)]
    return blocks


def card_capacity_bytes(card_type):
    return len(data_blocks(card_type)) * 16


def detect_type(atr):
    """按 PC/SC Part 3 存储卡 ATR 判断卡型，无法识别时返回 None。"""
    if len(atr) >= 15 and atr[:4] == bytes.fromhex("3B8F8001") and atr[5:7] == b"\x4f\x0c":
        return {b"\x00\x01": "1K", b"\x00\x02": "4K"}.get(atr[13:15])
    return None


def pick_reader(readers, hint=None):
    """按名称关键字选择读卡器，未指定时优先 PICC 通道。"""
    if hint:
        cand = [r for r in readers if hint.lower() in str(r).lower()]
    else:
        cand = [r for r in readers if "picc" in str(r).lower()] or list(readers)
    return cand[0] if cand else None


class PresenceProbe:
    """用 SCardGetStatusChange 查询是否有卡，不建立卡片连接。
    返回 True / False，读卡器不可用时返回 None。"""

    def __init__(self, hint=None):
        self.hint = hint
        self.ctx = None

    def _reset(self):
        if self.ctx is not None:
            try:
                from smartcard import scard
                scard.SCardReleaseContext(self.ctx)
            except Exception:
                pass
        self.ctx = None

    def present(self):
        try:
            from smartcard import scard
        except ImportError:
            return None
        try:
            if self.ctx is None:
                rc, ctx = scard.SCardEstablishContext(scard.SCARD_SCOPE_USER)
                if rc != scard.SCARD_S_SUCCESS:
                    return None
                self.ctx = ctx
            rc, names = scard.SCardListReaders(self.ctx, [])
            if rc != scard.SCARD_S_SUCCESS or not names:
                if rc not in (scard.SCARD_S_SUCCESS, scard.SCARD_E_NO_READERS_AVAILABLE):
                    self._reset()
                return None
            name = pick_reader(names, self.hint)
            if name is None:
                return None
            rc, states = scard.SCardGetStatusChange(self.ctx, 0, [(name, scard.SCARD_STATE_UNAWARE)])
            if rc != scard.SCARD_S_SUCCESS:
                self._reset()
                return None
            return bool(states[0][1] & scard.SCARD_STATE_PRESENT)
        except Exception:
            self._reset()
            return None


class PcscM1:
    """基于 ACS 读卡器 PC/SC 伪 APDU 的 M1 卡读写。"""

    # 易失密钥位置：ACR1281U / ACR128 为 20h，ACR122U / ACR1252U 为 00h–01h。
    # 不使用非易失位置。
    KEY_SLOTS = (0x20, 0x00, 0x01)

    def __init__(self, reader_hint=None, key_hex=DEFAULT_KEY, key_type="A", card_type=None):
        try:
            from smartcard.System import readers
        except ImportError:
            raise CardError("缺少pyscard组件，请执行：pip install pyscard") from None
        try:
            all_readers = readers()
        except Exception as e:
            raise CardError(f"无法访问PC/SC服务：{e}") from None
        if not all_readers:
            raise CardError("未找到读卡器。\n请检查USB连接、驱动程序及Smart Card服务状态。")
        chosen = pick_reader(all_readers, reader_hint)
        if chosen is None:
            names = "\n  ".join(str(r) for r in all_readers)
            raise CardError(f"未找到名称包含“{reader_hint}”的读卡器。现有读卡器：\n  {names}")
        self.reader = str(chosen)
        self.conn = chosen.createConnection()
        try:
            self.conn.connect()
        except Exception:
            raise CardError(f"读卡器上未检测到卡片。\n{self.reader}") from None

        self.atr = bytes(self.conn.getATR())
        self.card_type = card_type or detect_type(self.atr)
        if self.card_type is None:
            self.close()
            raise CardError(f"无法识别卡片类型，ATR：{self.atr.hex(' ').upper()}\n"
                            "如确认为M1卡，请使用 --type 1K 参数启动。")
        key = bytes.fromhex(key_hex)
        if len(key) != 6:
            raise CardError("扇区密钥应为12位十六进制数字。")
        self.key_type = 0x60 if key_type.upper() == "A" else 0x61
        self._authed = None
        self.key_slot = self._load_key(key)

    def _load_key(self, key):
        tried = []
        for slot in self.KEY_SLOTS:
            _, sw1, sw2 = self._raw([0xFF, 0x82, 0x00, slot, 0x06] + list(key), "载入扇区密钥")
            if (sw1, sw2) == (0x90, 0x00):
                return slot
            tried.append(f"位置{slot:02X}h：状态字{sw1:02X}{sw2:02X}")
        raise CardError("读卡器拒绝载入扇区密钥：\n  " + "\n  ".join(tried)
                        + "\n请确认已安装ACS官方PC/SC驱动。")

    def _raw(self, cmd, what):
        try:
            return self.conn.transmit(cmd)
        except Exception as e:
            raise CardError(f"{what}时通信中断，请检查卡片是否移开。\n{e}") from None

    def _apdu(self, cmd, what):
        data, sw1, sw2 = self._raw(cmd, what)
        if (sw1, sw2) != (0x90, 0x00):
            raise CardError(f"{what}失败，状态字{sw1:02X}{sw2:02X}。")
        return bytes(data)

    def uid(self):
        return self._apdu([0xFF, 0xCA, 0x00, 0x00, 0x00], "读取 UID")

    def _auth(self, first):
        if self._authed == first:
            return
        try:
            self._apdu([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, first, self.key_type, self.key_slot],
                       f"认证扇区{first // 4 if first < 128 else 32 + (first - 128) // 16}")
        except CardError as e:
            raise CardError(f"{e}\n请检查扇区密钥，空白卡默认为FFFFFFFFFFFF。") from None
        self._authed = first

    def read_block(self, block, first):
        self._auth(first)
        return self._apdu([0xFF, 0xB0, 0x00, block, 0x10], f"读取数据块{block}")

    def write_block(self, block, first, data):
        if block == 0 or is_trailer(block):
            raise CardError(f"禁止写入保护块{block}。")
        self._auth(first)
        self._apdu([0xFF, 0xD6, 0x00, block, 0x10] + list(data), f"写入数据块{block}")

    def close(self):
        try:
            self.conn.disconnect()
        except Exception:
            pass


class SimCard:
    """以 1024 / 4096 字节文件模拟 M1 卡，接口同 PcscM1。"""
    SIZES = {"1K": 1024, "4K": 4096}

    def __init__(self, path, card_type="1K"):
        self.path = path
        if os.path.exists(path):
            with open(path, "rb") as f:
                self.mem = bytearray(f.read())
            self.card_type = {1024: "1K", 4096: "4K"}.get(len(self.mem))
            if self.card_type is None:
                raise CardError(f"模拟卡文件大小无效：{path}")
        else:
            self.card_type = card_type
            self.mem = bytearray(self.SIZES[card_type])
            self.mem[0:4] = os.urandom(4)
            self._flush()
        self.reader = f"模拟卡  {os.path.abspath(path)}"
        self.atr = b""

    def _flush(self):
        with open(self.path, "wb") as f:
            f.write(self.mem)

    def uid(self):
        return bytes(self.mem[0:4])

    def read_block(self, block, first):
        return bytes(self.mem[block * 16:block * 16 + 16])

    def write_block(self, block, first, data):
        if block == 0 or is_trailer(block):
            raise CardError(f"禁止写入保护块{block}。")
        self.mem[block * 16:block * 16 + 16] = data
        self._flush()

    def close(self):
        pass


def read_region(card, start, nbytes):
    blocks = data_blocks(card.card_type)[start:]
    n = -(-nbytes // 16)
    if n > len(blocks):
        raise CardError("读取范围超出卡片容量。")
    return b"".join(card.read_block(b, f) for b, f in blocks[:n])[:nbytes]


def write_region(card, start, data):
    blocks = data_blocks(card.card_type)[start:]
    n = -(-len(data) // 16)
    if n > len(blocks):
        raise CardError("写入内容超出卡片容量。")
    padded = data + bytes(n * 16 - len(data))
    for i, (b, f) in enumerate(blocks[:n]):
        card.write_block(b, f, padded[i * 16:(i + 1) * 16])
    if read_region(card, start, len(data)) != data:
        raise CardError("回读校验失败，写入可能不完整。\n请保持卡片位置不变后重试。")


def wipe_card(card):
    """数据块全部写零。从属性区开始写，密钥材料最先清除。"""
    write_region(card, 0, bytes(card_capacity_bytes(card.card_type)))


# =====================================================================
#  卡片格式与加密
# =====================================================================

# 卡片格式标识沿用早期名称，修改后已开卡片将无法识别
MAGIC = b"HXV2"
OLD_MAGICS = (b"HXVT",)
VERSION = 2
PUB = struct.Struct(">4sB15sBBBBBIBBB")           # 32 字节公开属性
SALT_LEN, WRAP_LEN = 16, 40
NONCE_LEN, TAG_LEN = 12, 16
ATTR_BLOCKS = 8
ATTR_BYTES = ATTR_BLOCKS * 16
assert PUB.size + SALT_LEN + 2 * WRAP_LEN == ATTR_BYTES
SEC = struct.Struct(">16sBBBBB11s")               # 32 字节安全区
SEC_BLOCKS = 2
SEC_BYTES = SEC_BLOCKS * 16
assert SEC.size == SEC_BYTES
FLAG_SEC = 0x01
VAULT_DURESS_ON = 0x01

MODE_HEX, MODE_ASCII = 0, 1
MODE_NAMES = {MODE_HEX: "HEX", MODE_ASCII: "ASCII"}
PW_LIMITS = {MODE_HEX: 128, MODE_ASCII: 64}
NAME_MAX = 15
LABEL_MAX_LIMIT = 32
SLOTS_LIMIT = 255
MASTER_MIN, MASTER_MAX = 8, 32
DURESS_MIN, DURESS_MAX = 4, 32
ATTEMPTS_LIMIT = 20
RECOVERY_DIGITS = 8
KDF_LOG2N = 15            # 主密码 scrypt N=2^15，约 32 MB
RECOVERY_LOG2N = 17       # 恢复码仅 32 位，N=2^17，约 128 MB
ASCII_RANDOM = string.ascii_letters + string.digits + "!#$%&*+-=?@^_"

HEX_CHARS = set("0123456789ABCDEF")


def is_ascii_text(s):
    return all(0x20 <= ord(c) <= 0x7E for c in s)


def clean_hex(s):
    return "".join(c for c in s.upper() if c not in " \t-")


def is_hex(s):
    return all(c in HEX_CHARS for c in s.upper())


def group_hex(s, n=4):
    return " ".join(s[i:i + n] for i in range(0, len(s), n))


@dataclass
class CardAttrs:
    name: str
    mode: int              # MODE_HEX / MODE_ASCII
    pw_max: int            # HEX 为位数，ASCII 为字符数
    fixed: bool
    label_max: int
    slots: int
    has_sec: bool
    created: int = 0
    log2n: int = KDF_LOG2N
    rlog2n: int = RECOVERY_LOG2N

    @property
    def is_hex(self):
        return self.mode == MODE_HEX

    @property
    def pw_limit(self):
        return PW_LIMITS.get(self.mode, 0)

    @property
    def unit(self):
        return "位" if self.is_hex else "个字符"

    @property
    def pw_bytes(self):
        return (self.pw_max + 1) // 2 if self.is_hex else self.pw_max

    @property
    def slot_size(self):
        return 3 + self.label_max + self.pw_bytes

    @property
    def sec_bytes(self):
        return SEC_BYTES if self.has_sec else 0

    @property
    def vault_start(self):
        return ATTR_BLOCKS + (SEC_BLOCKS if self.has_sec else 0)

    @property
    def vault_len(self):
        return NONCE_LEN + 1 + self.slots * self.slot_size + TAG_LEN

    def total_bytes(self):
        return ATTR_BYTES + self.sec_bytes + self.vault_len

    def problems(self):
        if not self.name:
            return "请输入卡片名称。"
        if len(self.name) > NAME_MAX:
            return f"卡片名称不得超过{NAME_MAX}个字符。"
        if not is_ascii_text(self.name):
            return "卡片名称仅可使用可打印ASCII字符。"
        if self.mode not in PW_LIMITS:
            return "密码模式无效。"
        if not 1 <= self.pw_max <= self.pw_limit:
            return f"{MODE_NAMES[self.mode]}模式下密码长度应为1–{self.pw_limit}。"
        if not 0 <= self.label_max <= LABEL_MAX_LIMIT:
            return f"标签长度应为0–{LABEL_MAX_LIMIT}。"
        if not 1 <= self.slots <= SLOTS_LIMIT:
            return f"条目数量应为1–{SLOTS_LIMIT}。"
        return None

    def pack(self):
        return PUB.pack(MAGIC, VERSION, self.name.encode("ascii").ljust(NAME_MAX, b"\0"),
                        self.mode, self.pw_max, int(self.fixed), self.label_max, self.slots,
                        self.created, self.log2n, self.rlog2n, FLAG_SEC if self.has_sec else 0)

    @classmethod
    def unpack(cls, raw):
        (magic, ver, name, mode, pw_max, fixed, label_max, slots,
         created, log2n, rlog2n, flags) = PUB.unpack(raw[:PUB.size])
        if magic in OLD_MAGICS:
            raise CardError("该卡片为旧版格式，请重新开卡。")
        if magic != MAGIC:
            return None
        if ver != VERSION:
            raise CardError(f"不支持的卡片格式版本：{ver}。")
        attrs = cls(name.rstrip(b"\0").decode("ascii", "replace"), mode, pw_max, bool(fixed),
                    label_max, slots, bool(flags & FLAG_SEC), created, log2n, rlog2n)
        if attrs.problems() or not (10 <= log2n <= 20 and 10 <= rlog2n <= 20):
            raise CardError("属性区数据无效，卡片可能已损坏。")
        return attrs


def max_slots_for(card_type, mode, pw_max, label_max, has_sec):
    probe = CardAttrs("x", mode, pw_max, False, label_max, 1, has_sec)
    free = card_capacity_bytes(card_type) - ATTR_BYTES - probe.sec_bytes - NONCE_LEN - 1 - TAG_LEN
    return max(0, free // probe.slot_size)


@dataclass
class SecState:
    verifier: bytes
    lock_max: int = 0        # 0 表示不启用
    wrong: int = 0
    locked: bool = False
    rec_max: int = 0         # 0 表示不启用
    rec_wrong: int = 0

    def pack(self):
        return SEC.pack(self.verifier, self.lock_max, self.wrong, int(self.locked),
                        self.rec_max, self.rec_wrong, bytes(11))

    @classmethod
    def unpack(cls, raw):
        v, lm, w, lk, rm, rw, _ = SEC.unpack(raw[:SEC.size])
        return cls(v, lm, w, bool(lk), rm, rw)


@dataclass
class Entry:
    label: str
    pw: str


def entry_problem(attrs, label, pw):
    if not is_ascii_text(label):
        return "标签仅可使用可打印ASCII字符。"
    if len(label) > attrs.label_max:
        return f"标签长度不得超过{attrs.label_max}个字符。"
    if attrs.label_max and not label:
        return "请输入标签。"
    if not pw:
        return "请输入密码。"
    if attrs.is_hex and not is_hex(pw):
        return "HEX模式下密码仅可包含0–9与A–F。"
    if not attrs.is_hex and not is_ascii_text(pw):
        return "ASCII模式下密码仅可使用可打印ASCII字符。"
    if attrs.fixed and len(pw) != attrs.pw_max:
        return f"本卡为定长卡，密码长度须为{attrs.pw_max}{attrs.unit}，当前为{len(pw)}。"
    if len(pw) > attrs.pw_max:
        return f"密码长度不得超过{attrs.pw_max}{attrs.unit}，当前为{len(pw)}。"
    return None


def master_problem(pw):
    if not MASTER_MIN <= len(pw) <= MASTER_MAX:
        return f"主密码长度应为{MASTER_MIN}–{MASTER_MAX}个字符。"
    return None


def duress_problem(pw):
    if not DURESS_MIN <= len(pw) <= DURESS_MAX:
        return f"胁迫密码长度应为{DURESS_MIN}–{DURESS_MAX}个字符。"
    return None


# ---------------------------------------------------------------- 密钥派生

def _kdf(secret, salt, log2n, dklen=32):
    return hashlib.scrypt(secret, salt=salt, n=1 << log2n, r=8, p=1,
                          maxmem=512 * 1024 * 1024, dklen=dklen)


def derive_master(pw, salt, log2n):
    """一次 scrypt 输出 64 字节：前 32 字节解包主密钥，后 32 字节用于胁迫校验。"""
    return _kdf(b"M:" + pw.encode("utf-8"), salt, log2n, 64)


def duress_tag(k64):
    return hashlib.sha256(b"HXV2-duress:" + k64[32:]).digest()[:16]


def recovery_bytes(code):
    code = clean_hex(code)
    if len(code) != RECOVERY_DIGITS or not is_hex(code):
        raise CardError(f"恢复码应为{RECOVERY_DIGITS}位十六进制数字。")
    return bytes.fromhex(code)


def derive_recovery(code, salt, rlog2n):
    return _kdf(b"R:" + recovery_bytes(code), salt, rlog2n)


def _wrap(kek, dk):
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap
    return aes_key_wrap(kek, dk)


def _unwrap(kek, wrapped):
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, InvalidUnwrap
    try:
        return aes_key_unwrap(kek, wrapped)
    except InvalidUnwrap:
        return None


def new_recovery_code():
    return secrets.token_hex(RECOVERY_DIGITS // 2).upper()


# ---------------------------------------------------------------- 卡头与密码区

@dataclass
class CardHeader:
    uid: bytes
    card_type: str
    reader: str
    attrs: CardAttrs
    pub_raw: bytes
    salt: bytes
    wrap_master: bytes
    wrap_recovery: bytes
    sec: Optional[SecState]


def read_header(card):
    """读取属性区与安全区，未开卡返回 None。"""
    raw = read_region(card, 0, ATTR_BYTES)
    attrs = CardAttrs.unpack(raw)
    if attrs is None:
        return None
    if attrs.total_bytes() > card_capacity_bytes(card.card_type):
        raise CardError("属性区记录的容量超出卡片容量，卡片可能已损坏。")
    o = PUB.size
    sec = SecState.unpack(read_region(card, ATTR_BLOCKS, SEC_BYTES)) if attrs.has_sec else None
    return CardHeader(card.uid(), card.card_type, card.reader, attrs, raw[:o],
                      raw[o:o + SALT_LEN],
                      raw[o + SALT_LEN:o + SALT_LEN + WRAP_LEN],
                      raw[o + SALT_LEN + WRAP_LEN:o + SALT_LEN + 2 * WRAP_LEN], sec)


def encode_vault(attrs, entries, duress_on, dk):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(entries) > attrs.slots:
        raise CardError("条目数量超出槽位数量。")
    plain = bytearray([VAULT_DURESS_ON if duress_on else 0])
    for i in range(attrs.slots):
        if i < len(entries):
            e = entries[i]
            err = entry_problem(attrs, e.label, e.pw)
            if err:
                raise CardError(f"第{i + 1}条：{err}")
            lab = e.label.encode("ascii")
            if attrs.is_hex:
                pwb = bytes.fromhex(e.pw.upper() + ("0" if len(e.pw) % 2 else ""))
            else:
                pwb = e.pw.encode("ascii")
            plain += (bytes([1, len(lab)]) + lab.ljust(attrs.label_max, b"\0")
                      + bytes([len(e.pw)]) + pwb.ljust(attrs.pw_bytes, b"\0"))
        else:
            plain += bytes(attrs.slot_size)
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(dk).encrypt(nonce, bytes(plain), attrs.pack())


def decode_vault(hdr, blob, dk):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    a = hdr.attrs
    try:
        plain = AESGCM(dk).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], hdr.pub_raw)
    except InvalidTag:
        raise CardError("密码区校验失败，数据可能已被篡改或损坏。") from None
    duress_on = bool(plain[0] & VAULT_DURESS_ON)
    body = plain[1:]
    entries = []
    for i in range(a.slots):
        s = body[i * a.slot_size:(i + 1) * a.slot_size]
        if not s[0] & 1:
            continue
        label = s[2:2 + s[1]].decode("ascii", "replace")
        p = 2 + a.label_max
        n = s[p]
        raw = s[p + 1:p + 1 + a.pw_bytes]
        pw = raw.hex().upper()[:n] if a.is_hex else raw[:n].decode("ascii", "replace")
        entries.append(Entry(label, pw))
    return entries, duress_on


def read_vault(card, hdr):
    return read_region(card, hdr.attrs.vault_start, hdr.attrs.vault_len)


def ensure_same_card(card, hdr):
    if card.uid() != hdr.uid:
        raise CardError("读卡器上的卡片与当前卡片UID不一致，操作已中止。")
    if read_region(card, 0, PUB.size) != hdr.pub_raw:
        raise CardError("卡片属性区已发生变化，操作已中止。")


def _refresh_sec(card, hdr):
    if hdr.attrs.has_sec:
        hdr.sec = SecState.unpack(read_region(card, ATTR_BLOCKS, SEC_BYTES))


def _write_sec(card, hdr, sec):
    write_region(card, ATTR_BLOCKS, sec.pack())
    hdr.sec = sec


# ---------------------------------------------------------------- 解锁与安全策略

def open_with_master(card, hdr, pw):
    """主密码解锁，返回 (dk, entries, duress_on)。
    密码错误抛 CardError，匹配胁迫密码时清卡并抛 CardWiped。"""
    ensure_same_card(card, hdr)
    _refresh_sec(card, hdr)                       # 以卡上计数为准
    sec = hdr.sec
    k = derive_master(pw, hdr.salt, hdr.attrs.log2n)

    if sec and hmac.compare_digest(duress_tag(k), sec.verifier):
        wipe_card(card)
        raise CardWiped("duress")
    if sec and sec.locked:
        raise CardError("卡片已锁定，请使用恢复码解锁。")

    counting = bool(sec and sec.lock_max)
    if counting:                                  # 先写入错误计数再校验
        sec = SecState(**{**sec.__dict__, "wrong": min(sec.wrong + 1, 255)})
        _write_sec(card, hdr, sec)
    dk = _unwrap(k[:32], hdr.wrap_master)
    if dk is None:
        if counting:
            left = sec.lock_max - sec.wrong
            if left <= 0:
                _write_sec(card, hdr, SecState(**{**sec.__dict__, "locked": True}))
                raise CardError("主密码错误次数已达上限，卡片已锁定。\n请使用恢复码解锁。")
            raise CardError(f"主密码错误，剩余{left}次尝试机会。")
        raise CardError("主密码错误。")
    if counting:
        _write_sec(card, hdr, SecState(**{**sec.__dict__, "wrong": 0}))
    entries, duress_on = decode_vault(hdr, read_vault(card, hdr), dk)
    return dk, entries, duress_on


def open_with_recovery(card, hdr, code):
    """恢复码解锁，成功后清除锁定与计数。错误次数达到上限时清卡并抛 CardWiped。"""
    ensure_same_card(card, hdr)
    recovery_bytes(code)                          # 格式错误不计入次数
    _refresh_sec(card, hdr)
    sec = hdr.sec
    counting = bool(sec and sec.rec_max)
    if counting:
        sec = SecState(**{**sec.__dict__, "rec_wrong": min(sec.rec_wrong + 1, 255)})
        _write_sec(card, hdr, sec)
    dk = _unwrap(derive_recovery(code, hdr.salt, hdr.attrs.rlog2n), hdr.wrap_recovery)
    if dk is None:
        if counting:
            left = sec.rec_max - sec.rec_wrong
            if left <= 0:
                wipe_card(card)
                raise CardWiped("recovery")
            raise CardError(f"恢复码错误，剩余{left}次尝试机会。")
        raise CardError("恢复码错误。")
    if sec:
        _write_sec(card, hdr, SecState(sec.verifier, sec.lock_max, 0, False, sec.rec_max, 0))
    entries, duress_on = decode_vault(hdr, read_vault(card, hdr), dk)
    return dk, entries, duress_on


# ---------------------------------------------------------------- 写卡操作

def format_card(card, attrs, master, recovery, duress=None, lock_max=0, rec_max=0):
    err = attrs.problems() or master_problem(master)
    if err:
        raise CardError(err)
    cap = card_capacity_bytes(card.card_type)
    if attrs.total_bytes() > cap:
        raise CardError(f"所需空间{attrs.total_bytes()}字节，超出卡片容量{cap}字节。")
    recovery_bytes(recovery)
    if not attrs.has_sec:
        duress, lock_max, rec_max = None, 0, 0
    if duress is not None:
        err = duress_problem(duress)
        if err:
            raise CardError(err)
        if duress == master:
            raise CardError("胁迫密码不得与主密码相同。")
    if not (0 <= lock_max <= ATTEMPTS_LIMIT and 0 <= rec_max <= ATTEMPTS_LIMIT):
        raise CardError(f"次数应为1–{ATTEMPTS_LIMIT}。")

    attrs.created = int(time.time())
    dk, salt = os.urandom(32), os.urandom(SALT_LEN)
    wm = _wrap(derive_master(master, salt, attrs.log2n)[:32], dk)
    wr = _wrap(derive_recovery(recovery, salt, attrs.rlog2n), dk)
    sec = b""
    if attrs.has_sec:
        verifier = duress_tag(derive_master(duress, salt, attrs.log2n)) if duress else os.urandom(16)
        sec = SecState(verifier, lock_max, 0, False, rec_max, 0).pack()
    body = attrs.pack() + salt + wm + wr + sec + encode_vault(attrs, [], duress is not None, dk)
    write_region(card, 0, body.ljust(cap, b"\0"))      # 整卡重写
    return read_header(card), dk


def save_entries(card, hdr, entries, duress_on, dk):
    ensure_same_card(card, hdr)
    write_region(card, hdr.attrs.vault_start, encode_vault(hdr.attrs, entries, duress_on, dk))


def _rewrite_keys(card, hdr, wm, wr):
    ensure_same_card(card, hdr)
    write_region(card, 0, hdr.pub_raw + hdr.salt + wm + wr)
    hdr.wrap_master, hdr.wrap_recovery = wm, wr


def change_master(card, hdr, dk, new_master):
    err = master_problem(new_master)
    if err:
        raise CardError(err)
    k = derive_master(new_master, hdr.salt, hdr.attrs.log2n)
    if hdr.sec and hmac.compare_digest(duress_tag(k), hdr.sec.verifier):
        raise CardError("主密码不得与胁迫密码相同。")
    _rewrite_keys(card, hdr, _wrap(k[:32], dk), hdr.wrap_recovery)


def change_recovery(card, hdr, dk, code):
    _rewrite_keys(card, hdr, hdr.wrap_master,
                  _wrap(derive_recovery(code, hdr.salt, hdr.attrs.rlog2n), dk))


def update_security(card, hdr, dk, entries, duress_on, duress_action, duress_pw, lock_max, rec_max):
    """更新安全区并重写密码区。duress_action 为 "keep"、"off" 或 "set"，返回新的 duress_on。"""
    if not hdr.sec:
        raise CardError("该卡片未启用安全区。")
    ensure_same_card(card, hdr)
    _refresh_sec(card, hdr)
    verifier = hdr.sec.verifier
    if duress_action == "set":
        err = duress_problem(duress_pw)
        if err:
            raise CardError(err)
        k = derive_master(duress_pw, hdr.salt, hdr.attrs.log2n)
        if _unwrap(k[:32], hdr.wrap_master) is not None:
            raise CardError("胁迫密码不得与主密码相同。")
        verifier, duress_on = duress_tag(k), True
    elif duress_action == "off":
        verifier, duress_on = os.urandom(16), False
    _write_sec(card, hdr, SecState(verifier, lock_max, 0, False, rec_max, 0))
    write_region(card, hdr.attrs.vault_start, encode_vault(hdr.attrs, entries, duress_on, dk))
    return duress_on


# =====================================================================
#  CDE 外观
# =====================================================================

C = {
    "bg": "#AEB2C3",        # CDE 默认窗口底色（灰蓝）
    "light": "#D3D6E0",
    "field": "#C6C9D6",     # 输入框 / 列表底色
    "panel": "#8D92A9",     # 侧栏
    "title": "#B24D7A",     # CDE 活动窗口标题色（紫红）
    "sel": "#B24D7A",
    "ok": "#1F5E2E",
    "err": "#8E1A1A",
    "dim": "#4E5267",
}
# 界面字体：Windows 用微软雅黑 UI，其他平台用 Helvetica。等宽字体仅用于密码内容。
UI_FAMILY = "Microsoft YaHei UI" if sys.platform == "win32" else "Helvetica"
UI_SIZE = 9 if sys.platform == "win32" else 10
FONT = (UI_FAMILY, UI_SIZE)
FONT_B = (UI_FAMILY, UI_SIZE, "bold")
FONT_T = (UI_FAMILY, UI_SIZE + 1, "bold")
MONO = ("Courier", 11, "bold")
MONO_BIG = ("Courier", 20, "bold")


def apply_cde(root):
    o = root.option_add
    o("*Background", C["bg"])
    o("*Foreground", "black")
    o("*Font", FONT)
    o("*activeBackground", C["light"])
    # 仅可交互控件保留焦点框，其余控件的焦点框在彩色背景上显示为白边
    o("*highlightBackground", C["bg"])
    o("*highlightColor", "black")
    o("*highlightThickness", 0)
    for cls in ("Entry", "Spinbox", "Listbox", "Button", "Checkbutton", "Radiobutton"):
        o(f"*{cls}.highlightThickness", 1)
    o("*selectBackground", C["sel"])
    o("*selectForeground", "white")
    o("*disabledForeground", "#70748A")
    o("*troughColor", C["panel"])
    o("*Button.relief", "raised")
    o("*Button.borderWidth", 2)
    o("*Button.padX", 10)
    o("*Button.padY", 2)
    o("*Entry.background", C["field"])
    o("*Entry.disabledBackground", C["bg"])
    o("*Entry.relief", "sunken")
    o("*Entry.borderWidth", 2)
    o("*Entry.insertWidth", 2)
    o("*Spinbox.background", C["field"])
    o("*Spinbox.disabledBackground", C["bg"])
    o("*Spinbox.buttonBackground", C["bg"])
    o("*Spinbox.relief", "sunken")
    o("*Listbox.background", C["field"])
    o("*Listbox.relief", "sunken")
    o("*Listbox.borderWidth", 2)
    o("*Checkbutton.selectColor", C["field"])
    o("*Radiobutton.selectColor", C["field"])
    o("*Scrollbar.relief", "raised")
    o("*Scrollbar.borderWidth", 2)
    o("*Menu.background", C["bg"])
    o("*Menu.activeBackground", C["sel"])
    o("*Menu.activeForeground", "white")
    o("*Menu.relief", "raised")
    o("*Menu.borderWidth", 2)
    root.configure(bg=C["bg"])


def title_band(parent, text):
    f = tk.Frame(parent, bg=C["title"], relief="raised", bd=2)
    f.label = tk.Label(f, text=text, bg=C["title"], fg="white", font=FONT_T, anchor="w")
    f.label.pack(side="left", padx=8, pady=3)
    return f


def separator(parent):
    return tk.Frame(parent, height=2, bd=1, relief="sunken")


def group(parent, text):
    return tk.LabelFrame(parent, text=f" {text} ", font=FONT_B, relief="groove", bd=2, padx=8, pady=6)


def set_text(widget, text):
    """文字变化时才更新。"""
    if widget.cget("text") != text:
        widget.config(text=text)


def enable(widget, on):
    state = "normal" if on else "disabled"
    if str(widget.cget("state")) != state:
        widget.config(state=state)


def int_of(var, default=0):
    try:
        return int(str(var.get()).strip())
    except (ValueError, tk.TclError):
        return default


def set_state(widgets, on):
    for w in widgets:
        try:
            w.config(state="normal" if on else "disabled")
        except tk.TclError:
            pass


class CdeButton(tk.Frame):
    """Motif 风格按钮。default 为 True 时加凹陷外框，表示默认按钮。"""

    def __init__(self, parent, text, command, default=False, width=10):
        super().__init__(parent, relief="sunken" if default else "flat", bd=1)
        self.btn = tk.Button(self, text=text, command=command, width=width)
        self.btn.pack(padx=2, pady=2)

    def enable(self, on=True):
        self.btn.config(state="normal" if on else "disabled")


class HoldButton(CdeButton):
    """按下时调用 on_press，松开或指针移出时调用 on_release。"""

    def __init__(self, parent, text, on_press, on_release, width=10):
        super().__init__(parent, text, None, width=width)
        self.on_press, self.on_release = on_press, on_release
        self._held = False
        self.btn.bind("<ButtonPress-1>", lambda e: self._press())
        self.btn.bind("<ButtonRelease-1>", lambda e: self._release())
        self.btn.bind("<Leave>", lambda e: self._release())

    def _press(self):
        if str(self.btn["state"]) == "disabled":
            return
        self._held = True
        self.on_press()

    def _release(self):
        if self._held:
            self._held = False
            self.on_release()


class StatusLight(tk.Frame):
    """面板指示灯。"""
    COLORS = {
        "noreader": ("#141414", "#3A3A3A", "未连接读卡器"),
        "none": ("#141414", "#3A3A3A", "无卡"),
        "ready": ("#E0A800", "#FFF0A0", "准备就绪"),
        "open": ("#1FAE3C", "#8CF0A0", "已读卡"),
        "busy": ("#D01818", "#FF9A9A", "读写中"),
    }

    def __init__(self, parent):
        super().__init__(parent)
        self.cv = tk.Canvas(self, width=26, height=26, highlightthickness=0, bg=C["bg"])
        self.cv.pack(side="left")
        self.cv.create_oval(1, 1, 25, 25, fill="#5F6377", outline="#E5E7EE")
        self.cv.create_oval(3, 3, 23, 23, fill="#8D92A9", outline="#4A4E62")
        self.bulb = self.cv.create_oval(6, 6, 20, 20, fill="#141414", outline="#000000")
        self.glint = self.cv.create_oval(9, 8, 13, 12, fill="#3A3A3A", outline="")
        self.text = tk.Label(self, text="", font=FONT_B, width=12, anchor="w")
        self.text.pack(side="left", padx=(6, 0))
        self.state = None
        self.set("none")

    def set(self, state):
        if state == self.state:
            return
        self.state = state
        fill, glint, text = self.COLORS[state]
        self.cv.itemconfig(self.bulb, fill=fill)
        self.cv.itemconfig(self.glint, fill=glint)
        self.text.config(text=text, fg=C["err"] if state == "busy" else "black")


class KVTable(tk.Frame):
    """两列键值表。"""

    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.bg = kw.get("bg", C["bg"])
        self.cells = []

    def set(self, rows):
        for w in self.cells:
            w.destroy()
        self.cells = []
        for r, row in enumerate(rows):
            k, v = row[0], row[1]
            color = row[2] if len(row) > 2 else "black"
            a = tk.Label(self, text=k, fg=C["dim"], bg=self.bg, anchor="w")
            b = tk.Label(self, text=v, font=FONT_B, fg=color, bg=self.bg, anchor="w", justify="left")
            a.grid(row=r, column=0, sticky="nw", padx=(0, 14), pady=1)
            b.grid(row=r, column=1, sticky="w", pady=1)
            self.cells += [a, b]


class AttemptsRow(tk.Frame):
    """启用开关加次数输入。value() 未启用返回 0，数值无效返回 None。"""

    def __init__(self, parent, before, after, default, on=True, on_change=None):
        super().__init__(parent)
        self.on_change = on_change
        self.on = tk.BooleanVar(value=on)
        self.n = tk.StringVar(value=str(default))
        tk.Checkbutton(self, text=before, variable=self.on, command=self._toggle).pack(side="left")
        self.spin = tk.Spinbox(self, from_=1, to=ATTEMPTS_LIMIT, textvariable=self.n, width=4)
        self.spin.pack(side="left", padx=4)
        tk.Label(self, text=after).pack(side="left")
        self.n.trace_add("write", lambda *_: self._changed())
        self._toggle()

    def _changed(self):
        if self.on_change:
            self.on_change()

    def _toggle(self):
        self.spin.config(state="normal" if self.on.get() else "disabled")
        self._changed()

    def value(self):
        if not self.on.get():
            return 0
        v = int_of(self.n, -1)
        return v if 1 <= v <= ATTEMPTS_LIMIT else None

    def set(self, v):
        self.on.set(v > 0)
        if v > 0:
            self.n.set(str(v))
        self._toggle()


def limit_vcmd(widget, maxlen, ascii_only=False):
    def check(new):
        return len(new) <= maxlen and (not ascii_only or is_ascii_text(new))
    return (widget.register(check), "%P")


# ---------------------------------------------------------------- 对话框

class CdeDialog(tk.Toplevel):
    def __init__(self, parent, title):
        super().__init__(parent)
        self.withdraw()
        self.title(title)
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.transient(parent)
        self.result = None
        self.body = tk.Frame(self, padx=18, pady=14)
        self.body.pack(fill="both", expand=True)
        separator(self).pack(fill="x")
        self.buttons = tk.Frame(self, pady=8)
        self.buttons.pack(fill="x")
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.bind("<Escape>", lambda e: self.cancel())

    def add_buttons(self, specs):
        made = []
        for text, cmd, default in specs:
            b = CdeButton(self.buttons, text, cmd, default)
            b.pack(side="left", expand=True)
            made.append(b)
            if default:
                self.bind("<Return>", lambda e, c=cmd: c())
        return made

    def show(self, focus=None):
        self.update_idletasks()
        p = self.master
        x = p.winfo_rootx() + (p.winfo_width() - self.winfo_reqwidth()) // 2
        y = p.winfo_rooty() + (p.winfo_height() - self.winfo_reqheight()) // 3
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        prev = self.grab_current()
        self.deiconify()
        self.lift()
        try:
            self.grab_set()
        except tk.TclError:
            pass
        (focus or self).focus_force()
        self.wait_window()
        if prev is not None and prev.winfo_exists():
            try:
                prev.grab_set()
            except tk.TclError:
                pass
        return self.result

    def cancel(self):
        self.result = None
        self.destroy()


class CdeMessage(CdeDialog):
    def __init__(self, parent, title, text, kind="info", ask=False, ok_text="确定"):
        super().__init__(parent, title)
        glyph = {"info": "i", "warn": "!", "error": "!", "ask": "?"}[kind]
        color = C["err"] if kind in ("warn", "error") else C["title"]
        tk.Label(self.body, text=glyph, font=("Times", 26, "bold italic"), width=2, fg=color,
                 bg=C["light"], relief="raised", bd=2).grid(row=0, column=0, sticky="n", padx=(0, 14))
        tk.Label(self.body, text=text, justify="left", wraplength=560).grid(row=0, column=1, sticky="w")
        specs = [(ok_text, self.ok, True)]
        if ask:
            specs.append(("取消", self.cancel, False))
        self.add_buttons(specs)

    def ok(self):
        self.result = True
        self.destroy()


def cde_info(parent, title, text, kind="info"):
    CdeMessage(parent, title, text, kind).show()


def cde_ask(parent, title, text, kind="ask", ok_text="确定"):
    return bool(CdeMessage(parent, title, text, kind, ask=True, ok_text=ok_text).show())


class TypeConfirmDialog(CdeDialog):
    """需输入指定字词确认的危险操作对话框。"""

    def __init__(self, parent, title, text, word, ok_text):
        super().__init__(parent, title)
        self.word = word
        tk.Label(self.body, text="!", font=("Times", 26, "bold italic"), width=2, fg=C["err"],
                 bg=C["light"], relief="raised", bd=2).grid(row=0, column=0, rowspan=3, sticky="n", padx=(0, 14))
        tk.Label(self.body, text=text, justify="left", wraplength=560).grid(row=0, column=1, sticky="w")
        tk.Label(self.body, text=f"请输入“{word}”以确认：", font=FONT_B).grid(row=1, column=1, sticky="w", pady=(10, 2))
        self.var = tk.StringVar()
        self.var.trace_add("write", lambda *_: self.okbtn.enable(self.var.get().strip() == word))
        self.entry = tk.Entry(self.body, textvariable=self.var, width=16)
        self.entry.grid(row=2, column=1, sticky="w")
        self.okbtn, _ = self.add_buttons([(ok_text, self.ok, False), ("取消", self.cancel, True)])
        self.okbtn.enable(False)

    def ok(self):
        if self.var.get().strip() == self.word:
            self.result = True
            self.destroy()

    def show(self, focus=None):
        return bool(super().show(self.entry))


class HexFormatter:
    """十六进制输入格式化：过滤非十六进制字符，转大写，每 4 位插入空格。
    在 after_idle 中处理，此时 Tk 已完成插入，光标位置可靠。active() 为 False 时不处理。"""

    def __init__(self, entry, var, digits, group=4, active=None):
        self.entry, self.var, self.digits, self.group = entry, var, digits, group
        self.active = active or (lambda: True)
        self._pending = False
        var.trace_add("write", self._schedule)

    def _schedule(self, *_):
        if self._pending or not self.active():
            return
        self._pending = True
        self.entry.after_idle(self._fmt)

    def _fmt(self):
        self._pending = False
        if not self.active():
            return
        try:
            v = self.var.get()
            cur = self.entry.index("insert")
            hexed = "".join(c for c in v.upper() if c in HEX_CHARS)[:self.digits]
            out = group_hex(hexed, self.group)
            if out == v:
                return
            n = min(len([c for c in v[:cur].upper() if c in HEX_CHARS]), len(hexed))
            self.var.set(out)
            self.entry.icursor(n + max(n - 1, 0) // self.group)
        except tk.TclError:
            pass


class UnlockDialog(CdeDialog):
    """attempt(mode, value) 成功返回结果，失败抛 CardError，触发安全策略抛 CardWiped。"""

    def __init__(self, parent, hdr, attempt):
        super().__init__(parent, "解锁卡片")
        self.attempt = attempt
        self.hdr = hdr
        sec = hdr.sec
        locked = bool(sec and sec.locked)
        self.mode = tk.StringVar(value="recovery" if locked else "master")
        info = KVTable(self.body)
        info.set([("卡片名称", hdr.attrs.name), ("卡片UID", hdr.uid.hex(" ").upper())])
        info.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        r = 1
        if locked:
            tk.Label(self.body, text="卡片已锁定，请使用恢复码解锁。", fg=C["err"],
                     font=FONT_B).grid(row=r, column=0, columnspan=2, sticky="w", pady=(0, 6))
            r += 1
        tk.Radiobutton(self.body, text="主密码", variable=self.mode, value="master",
                       command=self._mode).grid(row=r, column=0, sticky="w")
        tk.Radiobutton(self.body, text="恢复码", variable=self.mode,
                       value="recovery", command=self._mode).grid(row=r, column=1, sticky="w")
        r += 1
        self.var = tk.StringVar()
        self.entry = tk.Entry(self.body, textvariable=self.var, width=36, font=MONO, validate="key",
                              validatecommand=(self.register(self._valid), "%P"))
        self.entry.grid(row=r, column=0, columnspan=2, sticky="we", pady=8)
        HexFormatter(self.entry, self.var, RECOVERY_DIGITS, active=lambda: self.mode.get() == "recovery")
        r += 1
        self.policy = tk.Label(self.body, text="", fg=C["dim"], justify="left")
        self.policy.grid(row=r, column=0, columnspan=2, sticky="w")
        r += 1
        self.msg = tk.Label(self.body, text="", fg=C["err"], font=FONT_B, justify="left")
        self.msg.grid(row=r, column=0, columnspan=2, sticky="w", pady=(4, 0))
        self.add_buttons([("解锁", self.ok, True), ("取消", self.cancel, False)])
        self._mode()

    def _valid(self, new):
        if self.mode.get() == "master":
            return len(new) <= max(MASTER_MAX, DURESS_MAX)
        return True                                # 恢复码由 HexFormatter 处理

    def _policy_text(self):
        sec = self.hdr.sec
        if self.mode.get() == "recovery":
            text = f"请输入{RECOVERY_DIGITS}位十六进制恢复码。"
            if sec and sec.rec_max:
                text += f"\n恢复码错误{sec.rec_max}次将清除卡片，当前已错误{sec.rec_wrong}次。"
            return text
        if sec and sec.lock_max and not sec.locked:
            return f"主密码连续错误{sec.lock_max}次将锁定卡片，当前已错误{sec.wrong}次。"
        return ""

    def _mode(self):
        self.entry.config(show="*" if self.mode.get() == "master" else "")
        self.var.set("")
        self.msg.config(text="")
        self.policy.config(text=self._policy_text())
        self.entry.focus_set()

    def ok(self):
        value = self.var.get()
        if not value:
            self.msg.config(text="请输入密码。", fg=C["err"])
            return
        self.msg.config(text="正在校验……", fg=C["dim"])
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            res = self.attempt(self.mode.get(), value)
        except CardWiped as w:
            self.result = ("wiped", w.reason)
            self.destroy()
            return
        except CardError as e:
            self.config(cursor="")
            sec = self.hdr.sec
            if sec and sec.locked and self.mode.get() == "master":
                self.mode.set("recovery")          # 卡片刚被锁定，切换到恢复码
                self._mode()
            self.msg.config(text=str(e), fg=C["err"])
            self.policy.config(text=self._policy_text())
            self.var.set("")
            return
        self.result = (self.mode.get(), res)
        self.destroy()

    def show(self, focus=None):
        return super().show(self.entry)


class NewPasswordDialog(CdeDialog):
    def __init__(self, parent, title, intro):
        super().__init__(parent, title)
        tk.Label(self.body, text=intro, justify="left").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        self.p1, self.p2 = tk.StringVar(), tk.StringVar()
        tk.Label(self.body, text="新主密码：").grid(row=1, column=0, sticky="e")
        self.e1 = tk.Entry(self.body, textvariable=self.p1, show="*", width=30, validate="key",
                           validatecommand=limit_vcmd(self, MASTER_MAX))
        self.e1.grid(row=1, column=1, pady=3)
        tk.Label(self.body, text="确认主密码：").grid(row=2, column=0, sticky="e")
        tk.Entry(self.body, textvariable=self.p2, show="*", width=30, validate="key",
                 validatecommand=limit_vcmd(self, MASTER_MAX)).grid(row=2, column=1, pady=3)
        tk.Label(self.body, text=f"长度为{MASTER_MIN}–{MASTER_MAX}个字符。", fg=C["dim"]).grid(
            row=3, column=1, sticky="w")
        self.msg = tk.Label(self.body, text="", fg=C["err"])
        self.msg.grid(row=4, column=0, columnspan=2, sticky="w")
        self.add_buttons([("确定", self.ok, True), ("取消", self.cancel, False)])

    def ok(self):
        a, b = self.p1.get(), self.p2.get()
        err = master_problem(a)
        if err:
            self.msg.config(text=err)
        elif a != b:
            self.msg.config(text="两次输入的主密码不一致。")
        else:
            self.result = a
            self.destroy()

    def show(self, focus=None):
        return super().show(self.e1)


class EntryDialog(CdeDialog):
    def __init__(self, parent, attrs, entry=None):
        super().__init__(parent, "编辑条目" if entry else "新建条目")
        self.attrs = a = attrs
        rules = [("密码模式", MODE_NAMES[a.mode]),
                 ("密码长度", f"{'定长' if a.fixed else '最长'}{a.pw_max}{a.unit}")]
        if a.label_max:
            rules.append(("标签长度", f"最长{a.label_max}个字符"))
        info = KVTable(self.body)
        info.set(rules)
        info.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        self.label_var = tk.StringVar(value=entry.label if entry else "")
        self.pw_var = tk.StringVar(value=entry.pw if entry else "")
        row = 1
        self.label_entry = None
        if a.label_max:
            tk.Label(self.body, text="标签：").grid(row=row, column=0, sticky="e")
            self.label_entry = tk.Entry(self.body, textvariable=self.label_var, width=a.label_max + 2,
                                        validate="key", validatecommand=limit_vcmd(self, a.label_max, True))
            self.label_entry.grid(row=row, column=1, sticky="w", pady=3)
            row += 1

        tk.Label(self.body, text="密码：").grid(row=row, column=0, sticky="e")
        width = min(max(a.pw_max + (a.pw_max // 4 if a.is_hex else 0) + 2, 16), 56)
        self.pw_entry = tk.Entry(self.body, textvariable=self.pw_var, width=width, font=MONO, show="*",
                                 validate="key", validatecommand=(self.register(self._v_pw), "%P"))
        self.pw_entry.grid(row=row, column=1, sticky="w", pady=3)
        btns = tk.Frame(self.body)
        btns.grid(row=row, column=2, padx=(8, 0))
        HoldButton(btns, "按住显示", lambda: self.pw_entry.config(show=""),
                   lambda: self.pw_entry.config(show="*"), width=8).pack(side="left")
        CdeButton(btns, "随机生成", self._random, width=8).pack(side="left", padx=(4, 0))
        row += 1
        self.count = tk.Label(self.body, text="", font=FONT_B)
        self.count.grid(row=row, column=1, sticky="w")
        row += 1
        self.msg = tk.Label(self.body, text="", fg=C["err"], font=FONT_B, justify="left")
        self.msg.grid(row=row, column=0, columnspan=3, sticky="w", pady=(6, 0))

        self.pw_var.trace_add("write", self._on_pw)
        self._on_pw()
        self.add_buttons([("确定", self.ok, True), ("取消", self.cancel, False)])

    def _clean(self, s):
        return clean_hex(s) if self.attrs.is_hex else s

    def _v_pw(self, new):
        v = self._clean(new)
        ok = is_hex(v) if self.attrs.is_hex else is_ascii_text(v)
        return ok and len(v) <= self.attrs.pw_max

    def _on_pw(self, *_):
        v = self.pw_var.get()
        if self.attrs.is_hex and v != v.upper():
            self.pw_var.set(v.upper())
            return
        n, a = len(self._clean(v)), self.attrs
        good = n == a.pw_max if a.fixed else 0 < n <= a.pw_max
        self.count.config(text=f"已输入{n}{a.unit}，{'须为' if a.fixed else '最长'}{a.pw_max}{a.unit}",
                          fg=C["ok"] if good else C["err"])

    def _random(self):
        n = self.attrs.pw_max
        if self.attrs.is_hex:
            self.pw_var.set(secrets.token_hex((n + 1) // 2).upper()[:n])
        else:
            self.pw_var.set("".join(secrets.choice(ASCII_RANDOM) for _ in range(n)))

    def ok(self):
        label = self.label_var.get()
        pw = self._clean(self.pw_var.get())
        err = entry_problem(self.attrs, label, pw)
        if err:
            self.msg.config(text=err)
            return
        self.result = Entry(label, pw)
        self.destroy()

    def show(self, focus=None):
        return super().show(self.label_entry or self.pw_entry)


def export_recovery(parent, code, name, uid):
    """导出恢复码文本文件，返回路径，取消时返回 None。"""
    from tkinter import filedialog
    safe = "".join(c for c in name if c.isalnum() or c in "-_") or "CARD"
    path = filedialog.asksaveasfilename(
        parent=parent, title="导出恢复码", defaultextension=".txt",
        initialfile=f"SectorSafe恢复码_{safe}_{uid.hex().upper()}.txt",
        filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
    if not path:
        return None
    text = (
        "SectorSafe 卡片恢复码\n"
        "====================\n\n"
        f"卡片名称：{name}\n"
        f"卡片UID：{uid.hex(' ').upper()}\n"
        f"生成时间：{time.strftime('%Y-%m-%d %H:%M')}\n\n"
        f"恢复码：{group_hex(code)}\n\n"
        "说明：\n"
        "1. 恢复码用于忘记主密码或卡片锁定后解锁卡片。\n"
        "2. 使用恢复码解锁后，请立即设置新的主密码。\n"
        "3. 请妥善保管本文件，勿与卡片存放在一起。\n"
        "4. 更换恢复码后，本文件中的恢复码即失效。\n"
    )
    with open(path, "w", encoding="utf-8-sig", newline="\r\n" if sys.platform == "win32" else "\n") as f:
        f.write(text)
    return path


class RecoveryPanel(tk.Frame):
    """恢复码显示、导出与复核。context() 返回 (卡片名称, UID)。"""

    def __init__(self, parent, on_change, context):
        super().__init__(parent)
        self.on_change = on_change
        self.context = context
        tk.Label(self, justify="left", text=(
            "恢复码用于忘记主密码或卡片锁定后解锁卡片。\n"
            "卡片不保存恢复码明文，请妥善保管，勿与卡片存放在一起。")).pack(anchor="w")
        box = tk.Frame(self, relief="sunken", bd=2, bg=C["field"])
        box.pack(fill="x", pady=10)
        self.code_lbl = tk.Label(box, font=MONO_BIG, bg=C["field"], pady=10)
        self.code_lbl.pack()
        bar = tk.Frame(self)
        bar.pack(anchor="w")
        CdeButton(bar, "重新生成", self.regenerate).pack(side="left")
        CdeButton(bar, "导出…", self.export).pack(side="left", padx=(8, 0))
        self.export_msg = tk.Label(bar, text="", fg=C["ok"])
        self.export_msg.pack(side="left", padx=(10, 0))
        self.ack = tk.BooleanVar()
        tk.Checkbutton(self, text="已妥善保存恢复码", variable=self.ack,
                       command=self._changed).pack(anchor="w", pady=(10, 2))
        row = tk.Frame(self)
        row.pack(anchor="w")
        tk.Label(row, text="请再次输入恢复码：").pack(side="left")
        self.again = tk.StringVar()
        again_entry = tk.Entry(row, textvariable=self.again, font=MONO, width=12)
        again_entry.pack(side="left")
        HexFormatter(again_entry, self.again, RECOVERY_DIGITS)
        self.again.trace_add("write", lambda *_: self._changed())
        self.regenerate()

    def regenerate(self):
        self.code = new_recovery_code()
        self.code_lbl.config(text=group_hex(self.code))
        self.ack.set(False)
        self.again.set("")
        self.export_msg.config(text="")
        self._changed()

    def export(self):
        name, uid = self.context()
        try:
            path = export_recovery(self, self.code, name, uid)
        except OSError as e:
            cde_info(self, "导出失败", f"无法写入文件。\n{e}", kind="error")
            return
        if path:
            self.export_msg.config(text=f"已导出：{os.path.basename(path)}")

    def _changed(self):
        self.on_change()

    def confirmed(self):
        return self.ack.get() and clean_hex(self.again.get()) == self.code


class RecoveryDialog(CdeDialog):
    def __init__(self, parent, hdr):
        super().__init__(parent, "更换恢复码")
        self.okbtn = None
        self.panel = RecoveryPanel(self.body, self._update, lambda: (hdr.attrs.name, hdr.uid))
        self.panel.pack()
        tk.Label(self.body, text="新恢复码写入后，原恢复码即失效。", fg=C["dim"]).pack(anchor="w", pady=(8, 0))
        self.okbtn, _ = self.add_buttons([("写入", self.ok, True), ("取消", self.cancel, False)])
        self._update()

    def _update(self):
        if self.okbtn:
            self.okbtn.enable(self.panel.confirmed())

    def ok(self):
        if self.panel.confirmed():
            self.result = self.panel.code
            self.destroy()


def attempts_rows(parent, on_change=None):
    """输错锁卡与恢复码保护设置组。"""
    g2 = group(parent, "输错锁卡")
    g2.pack(fill="x", pady=(8, 0))
    lock = AttemptsRow(g2, "主密码连续错误", "次后锁定卡片", 5, on=True, on_change=on_change)
    lock.pack(anchor="w")
    tk.Label(g2, text="卡片锁定后，仅可使用恢复码解锁。", fg=C["dim"]).pack(anchor="w")
    g3 = group(parent, "恢复码保护")
    g3.pack(fill="x", pady=(8, 0))
    rec = AttemptsRow(g3, "恢复码错误", "次后清除卡片", 5, on=True, on_change=on_change)
    rec.pack(anchor="w")
    tk.Label(g3, text="清除后卡片恢复为空白状态，数据无法找回。", fg=C["dim"]).pack(anchor="w")
    return lock, rec


class SecurityDialog(CdeDialog):
    """安全设置对话框。"""

    def __init__(self, parent, hdr, duress_on):
        super().__init__(parent, "安全设置")
        sec = hdr.sec
        g1 = group(self.body, "胁迫密码")
        g1.pack(fill="x")
        tk.Label(g1, text=f"当前状态：{'已启用' if duress_on else '未启用'}", font=FONT_B).grid(
            row=0, column=0, columnspan=3, sticky="w")
        self.action = tk.StringVar(value="keep")
        for c, (val, txt) in enumerate([("keep", "保持不变"), ("off", "停用"), ("set", "重新设置")]):
            tk.Radiobutton(g1, text=txt, variable=self.action, value=val, command=self._toggle).grid(
                row=1, column=c, sticky="w", padx=(0, 10))
        self.d1, self.d2 = tk.StringVar(), tk.StringVar()
        tk.Label(g1, text="胁迫密码：").grid(row=2, column=0, sticky="e", pady=(6, 2))
        self.e1 = tk.Entry(g1, textvariable=self.d1, show="*", width=26, validate="key",
                           validatecommand=limit_vcmd(self, DURESS_MAX))
        self.e1.grid(row=2, column=1, columnspan=2, sticky="w", pady=(6, 2))
        tk.Label(g1, text="确认胁迫密码：").grid(row=3, column=0, sticky="e")
        self.e2 = tk.Entry(g1, textvariable=self.d2, show="*", width=26, validate="key",
                           validatecommand=limit_vcmd(self, DURESS_MAX))
        self.e2.grid(row=3, column=1, columnspan=2, sticky="w")
        tk.Label(g1, text=f"长度为{DURESS_MIN}–{DURESS_MAX}个字符，不得与主密码相同。", fg=C["dim"]).grid(
            row=4, column=1, columnspan=2, sticky="w")

        self.lock, self.rec = attempts_rows(self.body)
        self.lock.set(sec.lock_max)
        self.rec.set(sec.rec_max)

        tk.Label(self.body, text="保存时将同时写入当前全部条目，并清零错误计数。",
                 fg=C["dim"]).pack(anchor="w", pady=(8, 0))
        self.msg = tk.Label(self.body, text="", fg=C["err"], font=FONT_B)
        self.msg.pack(anchor="w")
        self.add_buttons([("写入卡片", self.ok, True), ("取消", self.cancel, False)])
        self._toggle()

    def _toggle(self):
        set_state([self.e1, self.e2], self.action.get() == "set")

    def ok(self):
        act = self.action.get()
        if act == "set":
            err = duress_problem(self.d1.get())
            if err:
                self.msg.config(text=err)
                return
            if self.d1.get() != self.d2.get():
                self.msg.config(text="两次输入的胁迫密码不一致。")
                return
        lock, rec = self.lock.value(), self.rec.value()
        if lock is None or rec is None:
            self.msg.config(text=f"次数应为1–{ATTEMPTS_LIMIT}。")
            return
        self.result = (act, self.d1.get() if act == "set" else None, lock, rec)
        self.destroy()

    def show(self, focus=None):
        return super().show()


# ---------------------------------------------------------------- 开卡向导

class OpenCardWizard(tk.Toplevel):
    STEPS = ["检测卡片", "卡片属性", "主密码", "安全区设置", "恢复码", "确认写卡"]

    def __init__(self, app, auto_detect=False):
        super().__init__(app.root)
        self.app = app
        self.title("开卡向导")
        self.configure(bg=C["bg"])
        self.transient(app.root)
        self.protocol("WM_DELETE_WINDOW", self.cancel)

        self.card_type = None
        self.uid = None
        self.need_confirm = False
        self.written = None          # (hdr, dk, duress_on)
        self.writing = False
        self._minw = self._minh = 0

        nav = tk.Frame(self, pady=8)
        nav.pack(fill="x", side="bottom")
        separator(self).pack(fill="x", side="bottom")
        self.b_cancel = CdeButton(nav, "取消", self.cancel)
        self.b_cancel.pack(side="right", padx=10)
        self.b_next = CdeButton(nav, "下一步 >", self.next, default=True)
        self.b_next.pack(side="right")
        self.b_back = CdeButton(nav, "< 上一步", self.back)
        self.b_back.pack(side="right", padx=6)

        main = tk.Frame(self)
        main.pack(fill="both", expand=True)
        side = tk.Frame(main, bg=C["panel"], relief="sunken", bd=2, padx=6, pady=10)
        side.pack(side="left", fill="y", padx=(8, 0), pady=8)
        self.step_lbls = []
        for _ in self.STEPS:
            lbl = tk.Label(side, text="", anchor="w", width=12, bg=C["panel"], font=FONT_B, padx=6, pady=4)
            lbl.pack(fill="x", pady=1)
            self.step_lbls.append(lbl)
        self.holder = tk.Frame(main, padx=18, pady=14)
        self.holder.pack(side="left", fill="both", expand=True)

        self.pages = [self._page_detect(), self._page_attrs(), self._page_master(),
                      self._page_security(), self._page_recovery(), self._page_confirm()]
        self.idx = 0
        self._show(0)

        self.update_idletasks()
        r = app.root
        x = r.winfo_rootx() + (r.winfo_width() - self.winfo_reqwidth()) // 2
        y = r.winfo_rooty() + (r.winfo_height() - self.winfo_reqheight()) // 4
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.grab_set()
        if auto_detect:
            self.after(50, self._detect)

    # ---- 通用
    def _page(self):
        return tk.Frame(self.holder)

    def _h(self, page, text):
        tk.Label(page, text=text, font=FONT_T, anchor="w").pack(anchor="w", pady=(0, 10))

    def _p(self, page, text, **kw):
        """说明文字。Tk 只在空白处自动折行，中文段落需手动换行。"""
        lbl = tk.Label(page, text=text, justify="left", anchor="w", **kw)
        lbl.pack(anchor="w", pady=(0, 8))
        return lbl

    def _fit(self):
        """窗口尺寸只增不减。"""
        self.update_idletasks()
        self._minw = max(self._minw, self.winfo_reqwidth())
        self._minh = max(self._minh, self.winfo_reqheight())
        self.minsize(self._minw, self._minh)

    def _show(self, i):
        for p in self.pages:
            p.pack_forget()
        self.idx = i
        self.pages[i].pack(fill="both", expand=True)
        for j, lbl in enumerate(self.step_lbls):
            on = j == i
            lbl.config(text=f"{j + 1}. {self.STEPS[j]}", bg=C["title"] if on else C["panel"],
                       fg="white" if on else ("black" if j < i else "#3A3E52"),
                       relief="raised" if on else "flat", bd=2 if on else 0)
        if i == 3:
            self._layout_security()
        if i == 5:
            self._fill_summary()
        self._refresh()

    def _can_next(self):
        if self.written:
            return True
        return [self._ok_detect, self._ok_attrs, self._ok_master, self._ok_security,
                self._ok_recovery, lambda: True][self.idx]()

    def _refresh(self, *_):
        if not hasattr(self, "pages"):
            return
        if self.idx == 1:
            self._update_capacity()
        if self.idx == 3:
            self._update_security_msg()
        last = self.idx == len(self.pages) - 1
        self.b_next.btn.config(text="完成" if self.written else ("开始写卡" if last else "下一步 >"))
        self.b_next.enable(self._can_next() and not self.writing)
        self.b_back.enable(self.idx > 0 and not self.written and not self.writing)
        self.b_cancel.enable(not self.writing and not self.written)
        self._fit()

    def next(self):
        if not self._can_next():
            return
        if self.written:
            hdr, dk, duress_on = self.written
            self.grab_release()
            self.destroy()
            self.app.load_unlocked(hdr, dk, [], duress_on, "开卡完成，卡片已读取。")
            return
        if self.idx == len(self.pages) - 1:
            self._write()
            return
        self._show(self.idx + 1)

    def back(self):
        if self.idx > 0 and not self.written:
            self._show(self.idx - 1)

    def cancel(self):
        if self.writing:
            return
        if self.written:
            self.next()
            return
        if cde_ask(self, "取消开卡", "确定取消开卡？\n卡片内容不会被修改。", kind="warn"):
            self.grab_release()
            self.destroy()

    # ---- 第 1 步：检测卡片
    def _page_detect(self):
        p = self._page()
        self._h(p, "检测卡片")
        self._p(p, "请将MIFARE Classic 1K或4K卡片放置于读卡器感应区，然后点击“检测卡片”。\n"
                   "开卡将重写卡片全部数据区，原有数据将被清除。")
        CdeButton(p, "检测卡片", self._detect, default=True).pack(anchor="w", pady=6)
        g = group(p, "检测结果")
        g.pack(fill="x", pady=6)
        self.det = KVTable(g)
        self.det.pack(anchor="w")
        self.det.set([("读卡器", "—"), ("卡片UID", "—"), ("卡片类型", "—"), ("可用容量", "—"), ("卡片状态", "—")])
        self.overwrite = tk.BooleanVar()
        self.overwrite_cb = tk.Checkbutton(p, text="确认清除该卡片上的全部数据", variable=self.overwrite,
                                           command=self._refresh, fg=C["err"], font=FONT_B)
        return p

    def _detect(self):
        self.card_type = None
        self.overwrite.set(False)
        self.overwrite_cb.pack_forget()
        try:
            with self.app.busy(), self.app.io(), self.app.source.open() as card:
                uid, ctype, reader = card.uid(), card.card_type, card.reader
                raw = read_region(card, 0, ATTR_BYTES)
                try:
                    hdr = read_header(card)
                except CardError as e:
                    hdr = str(e)
        except CardError as e:
            self.det.set([("读卡器", "—"), ("卡片UID", "—"), ("卡片类型", "—"), ("可用容量", "—"),
                          ("卡片状态", str(e), C["err"])])
            self._refresh()
            return
        self.card_type, self.uid = ctype, uid
        if isinstance(hdr, CardHeader):
            self.need_confirm = True
            state = (f"已开卡：{hdr.attrs.name}，{hdr.attrs.slots}个槽位", C["err"])
        elif isinstance(hdr, str):
            self.need_confirm = True
            state = (hdr, C["err"])
        elif any(raw):
            self.need_confirm = True
            state = ("存在无法识别的数据", C["err"])
        else:
            self.need_confirm = False
            state = ("空白卡", C["ok"])
        self.det.set([("读卡器", reader), ("卡片UID", uid.hex(" ").upper()), ("卡片类型", f"MIFARE Classic {ctype}"),
                      ("可用容量", f"{card_capacity_bytes(ctype)}字节，共{len(data_blocks(ctype))}个数据块"),
                      ("卡片状态", state[0], state[1])])
        if self.need_confirm:
            self.overwrite_cb.pack(anchor="w", pady=4)
        self._refresh()

    def _ok_detect(self):
        return self.card_type is not None and (not self.need_confirm or self.overwrite.get())

    # ---- 第 2 步：卡片属性与容量
    def _page_attrs(self):
        p = self._page()
        self._h(p, "卡片属性")
        f = tk.Frame(p)
        f.pack(anchor="w")
        self.name_var = tk.StringVar(value="MY-CARD")
        self.mode_var = tk.IntVar(value=MODE_HEX)
        self.pwmax_var = tk.StringVar(value="32")
        self.fixed_var = tk.BooleanVar(value=False)
        self.lblmax_var = tk.StringVar(value="12")
        self.slots_var = tk.StringVar(value="12")
        self.sec_var = tk.BooleanVar(value=True)

        def row(r, text, widget, unit=None):
            tk.Label(f, text=text).grid(row=r, column=0, sticky="e", pady=3)
            widget.grid(row=r, column=1, sticky="w")
            if unit is not None:
                unit.grid(row=r, column=2, sticky="w", padx=8)

        row(0, "卡片名称：", tk.Entry(f, textvariable=self.name_var, width=20, validate="key",
                                      validatecommand=limit_vcmd(self, NAME_MAX, True)),
            tk.Label(f, text=f"最长{NAME_MAX}个ASCII字符", fg=C["dim"]))
        mf = tk.Frame(f)
        for val, txt in ((MODE_HEX, "HEX"), (MODE_ASCII, "ASCII")):
            tk.Radiobutton(mf, text=txt, variable=self.mode_var, value=val,
                           command=self._mode_changed).pack(side="left", padx=(0, 14))
        self.mode_hint = tk.Label(f, text="", fg=C["dim"])
        row(1, "密码模式：", mf, self.mode_hint)
        self.pw_spin = tk.Spinbox(f, from_=1, to=PW_LIMITS[MODE_HEX], textvariable=self.pwmax_var, width=6)
        self.pw_unit = tk.Label(f, text="", fg=C["dim"])
        row(2, "密码长度：", self.pw_spin, self.pw_unit)
        tk.Checkbutton(f, text="固定长度", variable=self.fixed_var,
                       command=self._refresh).grid(row=3, column=1, sticky="w")
        tk.Label(f, text="启用后，每条密码长度须与设定值一致", fg=C["dim"]).grid(row=3, column=2, sticky="w", padx=8)
        row(4, "标签长度：", tk.Spinbox(f, from_=0, to=LABEL_MAX_LIMIT, textvariable=self.lblmax_var, width=6),
            tk.Label(f, text="个ASCII字符，设为0则不使用标签", fg=C["dim"]))
        sf = tk.Frame(f)
        tk.Spinbox(sf, from_=1, to=SLOTS_LIMIT, textvariable=self.slots_var, width=6).pack(side="left")
        CdeButton(sf, "最大值", self._fill_slots, width=6).pack(side="left", padx=8)
        row(5, "条目数量：", sf)
        tk.Checkbutton(f, text="启用安全区", variable=self.sec_var, command=self._refresh).grid(
            row=6, column=1, sticky="w", pady=(4, 0))
        tk.Label(f, text=f"占用{SEC_BYTES}字节，用于胁迫密码、输错锁卡及恢复码保护", fg=C["dim"]).grid(
            row=6, column=2, sticky="w", padx=8, pady=(4, 0))
        for v in (self.name_var, self.pwmax_var, self.lblmax_var, self.slots_var):
            v.trace_add("write", self._refresh)

        g = group(p, "容量计算")
        g.pack(fill="x", pady=(12, 0))
        tk.Label(g, text="按全部槽位写满、标签与密码均达到最大长度计算。", fg=C["dim"]).pack(anchor="w", pady=(0, 4))
        self.cap_text = KVTable(g)
        self.cap_text.pack(anchor="w")
        self.meter = tk.Canvas(g, width=460, height=14, bg=C["field"], relief="sunken", bd=2,
                               highlightthickness=0)
        self.meter.pack(anchor="w", pady=6)
        self.cap_msg = tk.Label(g, font=FONT_B, anchor="w", justify="left")
        self.cap_msg.pack(anchor="w")
        self._mode_changed()
        return p

    def _mode_changed(self):
        mode = self.mode_var.get()
        limit = PW_LIMITS[mode]
        self.pw_spin.config(to=limit)
        if int_of(self.pwmax_var) > limit:
            self.pwmax_var.set(str(limit))
        if mode == MODE_HEX:
            self.mode_hint.config(text="十六进制数字0–9、A–F")
            self.pw_unit.config(text=f"位，范围1–{limit}")
        else:
            self.mode_hint.config(text="可打印ASCII字符")
            self.pw_unit.config(text=f"个字符，范围1–{limit}")
        self._refresh()

    def _attrs(self):
        return CardAttrs(self.name_var.get(), self.mode_var.get(), int_of(self.pwmax_var),
                         self.fixed_var.get(), int_of(self.lblmax_var, -1), int_of(self.slots_var),
                         self.sec_var.get())

    def _fill_slots(self):
        a = self._attrs()
        if self.card_type and 1 <= a.pw_max <= a.pw_limit and 0 <= a.label_max <= LABEL_MAX_LIMIT:
            mx = max_slots_for(self.card_type, a.mode, a.pw_max, a.label_max, a.has_sec)
            self.slots_var.set(str(max(1, min(SLOTS_LIMIT, mx))))

    def _update_capacity(self):
        a = self._attrs()
        err = a.problems()
        cap = card_capacity_bytes(self.card_type) if self.card_type else 0
        self.meter.delete("all")
        if err:
            self.cap_text.set([])
            self.cap_msg.config(text=err, fg=C["err"])
            return
        need = a.total_bytes()
        mx = max_slots_for(self.card_type, a.mode, a.pw_max, a.label_max, a.has_sec) if self.card_type else 0
        self.cap_text.set([
            ("单个槽位", f"{a.slot_size}字节 = 3 + 标签{a.label_max} + 密码{a.pw_bytes}"),
            ("属性区", f"{ATTR_BYTES}字节"),
            ("安全区", f"{a.sec_bytes}字节" if a.has_sec else "未启用"),
            ("密码区", f"{a.vault_len}字节 = {NONCE_LEN + 1 + TAG_LEN} + {a.slots} × {a.slot_size}"),
            ("合计", f"{need}字节，卡片可用{cap}字节"),
            ("最大条目数", f"{min(mx, SLOTS_LIMIT)}"),
        ])
        w = 460
        frac = min(need / cap, 1.0) if cap else 1.0
        over = need > cap
        self.meter.create_rectangle(2, 2, 2 + int((w - 2) * frac), 14,
                                    fill=C["err"] if over else C["title"], width=0)
        if over:
            self.cap_msg.config(text=f"超出卡片容量{need - cap}字节，请减少条目数量或缩短长度。", fg=C["err"])
        else:
            self.cap_msg.config(text=f"容量充足，剩余{cap - need}字节。", fg=C["ok"])

    def _ok_attrs(self):
        a = self._attrs()
        return (self.card_type is not None and not a.problems()
                and a.total_bytes() <= card_capacity_bytes(self.card_type))

    # ---- 第 3 步：主密码
    def _page_master(self):
        p = self._page()
        self._h(p, "设置主密码")
        self._p(p, "主密码用于解锁本卡全部条目，不以任何形式存储于卡片中。\n"
                   f"长度为{MASTER_MIN}–{MASTER_MAX}个字符。")
        f = tk.Frame(p)
        f.pack(anchor="w", pady=6)
        self.m1, self.m2 = tk.StringVar(), tk.StringVar()
        tk.Label(f, text="主密码：").grid(row=0, column=0, sticky="e")
        tk.Entry(f, textvariable=self.m1, show="*", width=30, validate="key",
                 validatecommand=limit_vcmd(self, MASTER_MAX)).grid(row=0, column=1, pady=3)
        tk.Label(f, text="确认主密码：").grid(row=1, column=0, sticky="e")
        tk.Entry(f, textvariable=self.m2, show="*", width=30, validate="key",
                 validatecommand=limit_vcmd(self, MASTER_MAX)).grid(row=1, column=1, pady=3)
        self.m_msg = tk.Label(p, font=FONT_B, anchor="w")
        self.m_msg.pack(anchor="w")
        for v in (self.m1, self.m2):
            v.trace_add("write", self._master_changed)
        self._master_changed()
        return p

    def _master_changed(self, *_):
        a, b = self.m1.get(), self.m2.get()
        if not a:
            self.m_msg.config(text="")
        elif master_problem(a):
            self.m_msg.config(text=master_problem(a), fg=C["err"])
        elif a != b:
            self.m_msg.config(text="两次输入的主密码不一致。", fg=C["err"])
        else:
            self.m_msg.config(text="主密码有效。", fg=C["ok"])
        self._refresh()

    def _ok_master(self):
        return not master_problem(self.m1.get()) and self.m1.get() == self.m2.get()

    # ---- 第 4 步：安全区设置
    def _page_security(self):
        p = self._page()
        self._h(p, "安全区设置")
        self.sec_off = tk.Frame(p)
        self._p(self.sec_off, "本卡未启用安全区，不支持胁迫密码、输错锁卡及恢复码保护。\n"
                              "如需启用，请返回“卡片属性”修改设置。")

        self.sec_on = tk.Frame(p)
        g1 = group(self.sec_on, "胁迫密码")
        g1.pack(fill="x")
        self.duress_var = tk.BooleanVar(value=False)
        tk.Checkbutton(g1, text="启用胁迫密码", variable=self.duress_var,
                       command=self._duress_toggle).grid(row=0, column=0, columnspan=2, sticky="w")
        tk.Label(g1, text="解锁时输入胁迫密码，将立即清除卡片全部数据。", fg=C["dim"]).grid(
            row=1, column=0, columnspan=2, sticky="w")
        self.d1, self.d2 = tk.StringVar(), tk.StringVar()
        tk.Label(g1, text="胁迫密码：").grid(row=2, column=0, sticky="e", pady=(6, 2))
        self.de1 = tk.Entry(g1, textvariable=self.d1, show="*", width=26, validate="key",
                            validatecommand=limit_vcmd(self, DURESS_MAX))
        self.de1.grid(row=2, column=1, sticky="w", pady=(6, 2))
        tk.Label(g1, text="确认胁迫密码：").grid(row=3, column=0, sticky="e")
        self.de2 = tk.Entry(g1, textvariable=self.d2, show="*", width=26, validate="key",
                            validatecommand=limit_vcmd(self, DURESS_MAX))
        self.de2.grid(row=3, column=1, sticky="w")
        tk.Label(g1, text=f"长度为{DURESS_MIN}–{DURESS_MAX}个字符，不得与主密码相同。", fg=C["dim"]).grid(
            row=4, column=1, sticky="w")
        for v in (self.d1, self.d2):
            v.trace_add("write", self._refresh)

        self.lock_row, self.rec_row = attempts_rows(self.sec_on, self._refresh)
        self.sec_msg = tk.Label(self.sec_on, font=FONT_B, anchor="w")
        self.sec_msg.pack(anchor="w", pady=(6, 0))
        self._duress_toggle()
        return p

    def _layout_security(self):
        self.sec_off.pack_forget()
        self.sec_on.pack_forget()
        (self.sec_on if self.sec_var.get() else self.sec_off).pack(anchor="w", fill="x")

    def _duress_toggle(self):
        set_state([self.de1, self.de2], self.duress_var.get())
        self._refresh()

    def _security_problem(self):
        if not self.sec_var.get():
            return None
        if self.duress_var.get():
            err = duress_problem(self.d1.get())
            if err:
                return err
            if self.d1.get() != self.d2.get():
                return "两次输入的胁迫密码不一致。"
            if self.d1.get() == self.m1.get():
                return "胁迫密码不得与主密码相同。"
        if self.lock_row.value() is None or self.rec_row.value() is None:
            return f"次数应为1–{ATTEMPTS_LIMIT}。"
        return None

    def _update_security_msg(self):
        if not self.sec_var.get():
            return
        self.sec_msg.config(text=self._security_problem() or "", fg=C["err"])

    def _ok_security(self):
        return self._security_problem() is None

    # ---- 第 5 步：恢复码
    def _page_recovery(self):
        p = self._page()
        self._h(p, "恢复码")
        self.recovery = RecoveryPanel(p, self._refresh,
                                      lambda: (self.name_var.get() or "CARD", self.uid or b""))
        self.recovery.pack(anchor="w", fill="x")
        return p

    def _ok_recovery(self):
        return self.recovery.confirmed()

    # ---- 第 6 步：确认写卡
    def _page_confirm(self):
        p = self._page()
        self._h(p, "确认写卡")
        self._p(p, "请核对以下信息，确认无误后点击“开始写卡”。\n开卡完成后，卡片属性不可修改。")
        self.summary = KVTable(p, relief="sunken", bd=2, bg=C["field"], padx=12, pady=8)
        self.summary.pack(fill="x")
        self.write_msg = tk.Label(p, font=FONT_B, anchor="w", justify="left")
        self.write_msg.pack(anchor="w", pady=(10, 0))
        return p

    def _sec_choices(self):
        if not self.sec_var.get():
            return None, 0, 0
        return (self.d1.get() if self.duress_var.get() else None,
                self.lock_row.value() or 0, self.rec_row.value() or 0)

    def _fill_summary(self):
        a = self._attrs()
        duress, lock, rec = self._sec_choices()
        rows = [
            ("卡片名称", a.name),
            ("卡片UID", self.uid.hex(" ").upper() if self.uid else "—"),
            ("卡片类型", f"MIFARE Classic {self.card_type}"),
            ("密码模式", MODE_NAMES[a.mode]),
            ("密码长度", f"{'定长' if a.fixed else '最长'}{a.pw_max}{a.unit}"),
            ("标签长度", f"最长{a.label_max}个字符" if a.label_max else "不使用"),
            ("条目数量", f"{a.slots}"),
            ("占用空间", f"{a.total_bytes()}字节，卡片可用{card_capacity_bytes(self.card_type)}字节"),
        ]
        if a.has_sec:
            rows += [("胁迫密码", "启用" if duress else "不启用"),
                     ("输错锁卡", f"连续错误{lock}次锁定" if lock else "不启用"),
                     ("恢复码保护", f"错误{rec}次清除卡片" if rec else "不启用")]
        else:
            rows.append(("安全区", "未启用"))
        self.summary.set(rows)
        if not self.written:
            self.write_msg.config(text="写卡期间请勿移开卡片。", fg=C["dim"])

    def _write(self):
        if self.written or self.writing:
            return
        self.writing = True
        self.write_msg.config(text="正在写卡……", fg=C["dim"])
        self._refresh()
        self.update_idletasks()
        duress, lock, rec = self._sec_choices()
        try:
            with self.app.busy(), self.app.io(), self.app.source.open() as card:
                if card.uid() != self.uid:
                    raise CardError("当前卡片与检测时的卡片不一致，写卡已中止。")
                hdr, dk = format_card(card, self._attrs(), self.m1.get(), self.recovery.code,
                                      duress, lock, rec)
        except CardError as e:
            self.writing = False
            self.write_msg.config(text=f"写卡失败：{e}", fg=C["err"])
            self._refresh()
            return
        self.writing = False
        self.written = (hdr, dk, duress is not None)
        for v in (self.m1, self.m2, self.d1, self.d2):
            v.set("")
        self.write_msg.config(text="开卡完成。点击“完成”进入管理界面。", fg=C["ok"])
        self._refresh()


# ---------------------------------------------------------------- 主窗口

class CardSource:
    def __init__(self, args):
        self.args = args
        self.probe = None if args.sim else PresenceProbe(args.reader)
        self.sim_present = True          # 模拟模式：点击指示灯切换有卡 / 无卡

    def present(self):
        if self.args.sim:
            return self.sim_present
        return self.probe.present()

    @contextmanager
    def open(self):
        a = self.args
        if a.sim and not self.sim_present:
            raise CardError("读卡器上未检测到卡片。")
        card = SimCard(a.sim, a.sim_type) if a.sim else PcscM1(a.reader, a.key, a.key_type, a.type)
        try:
            yield card
        finally:
            card.close()


def draw_card_logo(cv, x, y):
    """卡片图标：斜边卡面与非接触感应符号。"""
    w, h = 150, 96
    cv.create_rectangle(x + 4, y + 4, x + w + 4, y + h + 4, fill="#7A7F96", outline="")
    cv.create_rectangle(x, y, x + w, y + h, fill="#C9CDDA", outline="")
    cv.create_line(x, y + h, x, y, x + w, y, fill="#EEF0F5", width=2)
    cv.create_line(x, y + h, x + w, y + h, x + w, y, fill="#5F6377", width=2)
    cx, cy = x + 52, y + h // 2
    cv.create_oval(cx - 5, cy - 5, cx + 5, cy + 5, fill=C["title"], outline="")
    for i, r in enumerate((16, 28, 40)):
        cv.create_arc(cx - r, cy - r, cx + r, cy + r, start=-50, extent=100, style="arc",
                      outline=C["title"], width=4 if i == 0 else 3)


class AboutDialog(CdeDialog):
    def __init__(self, parent):
        super().__init__(parent, f"关于{APP_NAME}")
        top = tk.Frame(self.body)
        top.pack(anchor="w", fill="x")
        cv = tk.Canvas(top, width=170, height=110, bg=C["bg"], highlightthickness=0)
        cv.pack(side="left")
        draw_card_logo(cv, 6, 4)
        head = tk.Frame(top)
        head.pack(side="left", padx=(16, 0))
        tk.Label(head, text=APP_NAME, font=(UI_FAMILY, UI_SIZE + 10, "bold")).pack(anchor="w")
        tk.Label(head, text="M1卡密码管理器", fg=C["dim"]).pack(anchor="w")

        info = KVTable(self.body)
        info.pack(anchor="w", pady=(14, 0))
        info.set([("版本", APP_VERSION), ("作者", APP_AUTHOR), ("开源协议", APP_LICENSE)])
        link = tk.Label(self.body, text=APP_URL, fg=C["title"], cursor="hand2", font=FONT_B)
        link.pack(anchor="w", pady=(2, 0))
        link.bind("<Button-1>", lambda e: self._open_url())

        g = group(self.body, "硬件支持")
        g.pack(fill="x", pady=(12, 0))
        hw = KVTable(g)
        hw.pack(anchor="w")
        hw.set([("已验证读卡器", "ACS ACR1281U-C1"),
                ("兼容读卡器", "ACS ACR122U、ACR1252U，未经实测"),
                ("支持卡片", "MIFARE Classic 1K、MIFARE Classic 4K")])

        g2 = group(self.body, "第三方组件")
        g2.pack(fill="x", pady=(8, 0))
        lib = KVTable(g2)
        lib.pack(anchor="w")
        lib.set([("pyscard", "LGPL-2.1-or-later"),
                 ("cryptography", "Apache-2.0 / BSD-3-Clause"),
                 ("Python / Tkinter", "PSF License")])

        tk.Label(self.body, text="错误计数与锁卡策略仅在本程序中生效，无法防范使用其他工具对卡片的直接读写。",
                 fg=C["dim"]).pack(anchor="w", pady=(10, 0))
        self.add_buttons([("确定", self.cancel, True)])

    def _open_url(self):
        import webbrowser
        webbrowser.open(APP_URL)


class App:
    CLIP_SECONDS = 30
    POLL_MS = 500

    def __init__(self, root, source):
        self.root = root
        self.source = source
        self.hdr = None
        self.dk = None
        self.entries = []
        self.duress_on = False
        self.dirty = False
        self.reveal_idx = None
        self._clip_job = None
        self._clip_value = ""
        self._io = 0
        self.card_in = False          # 读卡器上是否有卡
        self.reader_ok = True
        self.epoch = 0                # 会话编号，清理会话时递增，被中断的流程据此放弃后续操作
        self.view = None

        root.title(f"{APP_NAME} {APP_VERSION}")
        root.minsize(940, 580)
        root.protocol("WM_DELETE_WINDOW", self.quit)
        self._build_menu()
        self.status = tk.Label(root, anchor="w", relief="sunken", bd=2, padx=6)
        self.status.pack(side="bottom", fill="x", padx=2, pady=2)
        self.band = title_band(root, "SectorSafe")
        self.band.pack(fill="x")
        self._build_body()
        self._bind_keys()
        if source.args.sim:
            self.light.cv.bind("<Button-1>", lambda e: self._toggle_sim())
            self.light.text.bind("<Button-1>", lambda e: self._toggle_sim())
        self.refresh()
        self.say("模拟模式：点击指示灯可模拟插入或移除卡片。" if source.args.sim else "就绪。")
        self._poll()

    # ---- 构建界面
    def _build_menu(self):
        bar = tk.Frame(self.root, relief="raised", bd=2)
        bar.pack(fill="x")
        self.menus = {}

        def make(title, items, side="left"):
            mb = tk.Menubutton(bar, text=title, padx=10, pady=2, activebackground=C["sel"],
                               activeforeground="white")
            m = tk.Menu(mb, tearoff=True)
            for it in items:
                if it is None:
                    m.add_separator()
                else:
                    label, cmd, acc = it
                    m.add_command(label=label, command=cmd, accelerator=acc)
            mb["menu"] = m
            mb.pack(side=side)
            self.menus[title] = m

        make("卡片", [("读取卡片", self.read_card, "Ctrl+O"), ("写入卡片", self.save_card, "Ctrl+S"),
                    ("退卡", self.eject, "Ctrl+E"), None,
                    ("开卡向导…", self.wizard, "Ctrl+N"), ("销毁卡片…", self.destroy_card, ""), None,
                    ("退出", self.quit, "Ctrl+Q")])
        make("条目", [("新建条目", self.new_entry, "Insert"), ("编辑条目", self.edit_entry, "Enter"),
                    ("删除条目", self.delete_entry, "Delete"), None,
                    ("复制到剪贴板", self.copy_entry, "Ctrl+C")])
        make("安全", [("安全设置…", self.security_settings, ""), ("修改主密码…", self.change_master, ""),
                    ("更换恢复码…", self.change_recovery, "")])
        make("帮助", [("关于SectorSafe", self.about, "")], side="right")   # 帮助菜单靠右

    def _build_body(self):
        # 操作栏：读取卡片 / 退卡、指示灯、写入卡片
        act = tk.Frame(self.root, pady=8)
        act.pack(fill="x", side="bottom")
        separator(self.root).pack(fill="x", side="bottom")
        self.b = {}
        self.b["main"] = CdeButton(act, "读取卡片", self._main_action, width=12)
        self.b["main"].btn.config(font=FONT_T, pady=6)
        self.b["main"].pack(side="left", padx=(16, 14))
        self.light = StatusLight(act)
        self.light.pack(side="left")
        self.b["save"] = CdeButton(act, "写入卡片", self.save_card, default=True)
        self.b["save"].pack(side="right", padx=16)
        self.dirty_lbl = tk.Label(act, text="", fg=C["err"], font=FONT_B)
        self.dirty_lbl.pack(side="right")

        self.content = tk.Frame(self.root)
        self.content.pack(fill="both", expand=True)

        # 无卡占位页
        self.placeholder = tk.Frame(self.content)
        inner = tk.Frame(self.placeholder)
        inner.place(relx=0.5, rely=0.45, anchor="center")
        cv = tk.Canvas(inner, width=170, height=116, bg=C["bg"], highlightthickness=0)
        cv.pack()
        draw_card_logo(cv, 8, 6)
        self.ph_title = tk.Label(inner, text="", font=(UI_FAMILY, UI_SIZE + 4, "bold"))
        self.ph_title.pack(pady=(14, 4))
        self.ph_text = tk.Label(inner, text="", fg=C["dim"], justify="center")
        self.ph_text.pack()

        # 卡片清除告示页
        self.alertview = tk.Frame(self.content, bd=8, relief="ridge")
        a_inner = tk.Frame(self.alertview)
        a_inner.place(relx=0.5, rely=0.45, anchor="center")
        self.alert_big = tk.Label(a_inner, text="", font=(UI_FAMILY, 30, "bold"))
        self.alert_big.pack(pady=(0, 14))
        self.alert_msg = tk.Label(a_inner, text="", font=(UI_FAMILY, 14, "bold"), justify="center")
        self.alert_msg.pack()
        self.alert_btnbar = tk.Frame(a_inner, pady=24)
        self.alert_btnbar.pack()
        CdeButton(self.alert_btnbar, "确定", self.dismiss_alert, default=True).pack()
        self.alert_parts = (self.alertview, a_inner, self.alert_btnbar, self.alert_big, self.alert_msg)
        self.alert_on = False
        self._alert_job = None
        self._alert_phase = False

        # 主界面
        self.mainview = tk.Frame(self.content, padx=10, pady=8)
        g = group(self.mainview, "卡片属性")
        g.pack(side="left", fill="y", padx=(0, 8))
        self.attr_vals = {}
        rows = [("name", "卡片名称"), ("uid", "卡片UID"), ("type", "卡片类型"), ("mode", "密码模式"),
                ("pw", "密码长度"), ("label", "标签长度"), ("slots", "条目数量"), ("bytes", "占用空间"),
                ("created", "开卡时间"), ("sec", "安全区"), ("duress", "胁迫密码"),
                ("lock", "输错锁卡"), ("rec", "恢复码保护")]
        for r, (k, t) in enumerate(rows):
            tk.Label(g, text=t + "：", anchor="e").grid(row=r, column=0, sticky="e", pady=2)
            v = tk.Label(g, text="—", font=FONT_B, anchor="w", width=20)
            v.grid(row=r, column=1, sticky="w")
            self.attr_vals[k] = v
        tk.Label(g, text="条目使用：", anchor="e").grid(row=len(rows), column=0, sticky="e", pady=(10, 0))
        self.meter = tk.Canvas(g, width=170, height=12, bg=C["field"], relief="sunken", bd=2,
                               highlightthickness=0)
        self.meter.grid(row=len(rows), column=1, sticky="w", pady=(10, 0))

        g2 = group(self.mainview, "密码条目")
        g2.pack(side="left", fill="both", expand=True)
        self.list_head = tk.Frame(g2, height=22)
        self.list_head.grid(row=0, column=0, columnspan=2, sticky="we")
        self.head_cols = [tk.Label(self.list_head, text=t, fg=C["dim"], font=FONT_B)
                          for t in ("#", "标签", "密码")]
        self.listbox = tk.Listbox(g2, font=MONO, width=52, height=18, activestyle="none",
                                  exportselection=False, selectmode="browse")
        sb = tk.Scrollbar(g2, orient="vertical", command=self.listbox.yview)
        self.listbox.config(yscrollcommand=sb.set)
        self.listbox.grid(row=1, column=0, sticky="nsew")
        sb.grid(row=1, column=1, sticky="ns")
        g2.grid_rowconfigure(1, weight=1)
        g2.grid_columnconfigure(0, weight=1)
        self.listbox.bind("<<ListboxSelect>>", lambda e: self.refresh_buttons())
        self.listbox.bind("<Double-Button-1>", lambda e: self.edit_entry())
        self.list_hint = tk.Label(g2, text="", fg=C["dim"])
        self.list_hint.grid(row=2, column=0, sticky="w", pady=(4, 0))

        side = tk.Frame(g2, padx=8)
        side.grid(row=1, column=2, sticky="n")
        for key, text, cmd in [("new", "新建", self.new_entry), ("edit", "编辑", self.edit_entry),
                               ("del", "删除", self.delete_entry)]:
            btn = CdeButton(side, text, cmd, width=9)
            btn.pack(pady=2)
            self.b[key] = btn
        self.b["show"] = HoldButton(side, "按住显示", self.reveal_start, self.reveal_end, width=9)
        self.b["show"].pack(pady=(10, 2))
        self.b["copy"] = CdeButton(side, "复制", self.copy_entry, width=9)
        self.b["copy"].pack(pady=2)
        tk.Label(side, text="选中条目后\n按住空格键\n亦可查看密码", fg=C["dim"], justify="center").pack(pady=(10, 0))

    def _bind_keys(self):
        r = self.root
        r.bind_all("<Control-o>", lambda e: self.read_card())
        r.bind_all("<Control-e>", lambda e: self.eject())
        r.bind_all("<Control-n>", lambda e: self.wizard())
        r.bind_all("<Control-s>", lambda e: self.save_card())
        r.bind_all("<Control-q>", lambda e: self.quit())
        lb = self.listbox
        lb.bind("<Insert>", lambda e: self.new_entry())
        lb.bind("<Delete>", lambda e: self.delete_entry())
        lb.bind("<Return>", lambda e: self.edit_entry())
        lb.bind("<KeyPress-space>", lambda e: self.reveal_start() or "break")
        lb.bind("<KeyRelease-space>", lambda e: self.reveal_end() or "break")
        lb.bind("<FocusOut>", lambda e: self.reveal_end())
        lb.bind("<Control-c>", lambda e: self.copy_entry())

    # ---- 卡片状态
    def _state(self):
        if self._io:
            return "busy"
        if not self.reader_ok:
            return "noreader"
        if not self.card_in:
            return "none"
        return "open" if self.hdr else "ready"

    def _sig(self):
        return (self._state(), self.card_in, self.reader_ok, self.hdr is not None, self.alert_on)

    def _show_view(self, name):
        if self.view == name:
            return
        for v in (self.placeholder, self.mainview, self.alertview):
            v.pack_forget()
        {"empty": self.placeholder, "main": self.mainview, "alert": self.alertview}[name].pack(
            fill="both", expand=True)
        self.view = name

    def _apply_state(self):
        st = self._state()
        self._last_sig = self._sig()
        self.light.set(st)
        if self.alert_on:
            self._show_view("alert")
        elif st != "busy":
            self._show_view("main" if st in ("ready", "open") else "empty")
            if st == "noreader":
                set_text(self.ph_title, "未连接读卡器")
                set_text(self.ph_text, "请连接读卡器，并确认驱动程序与Smart Card服务正常运行")
            elif st == "none":
                set_text(self.ph_title, "请放置卡片")
                set_text(self.ph_text, "将卡片放置于读卡器感应区后，即可读取卡片或开卡")
        if self.hdr:
            title = f"SectorSafe    {self.hdr.attrs.name}    UID {self.hdr.uid.hex(' ').upper()}"
        elif st in ("ready", "busy") and self.card_in:
            title = "SectorSafe    已检测到卡片"
        else:
            title = "SectorSafe"
        set_text(self.band.label, title)
        self.refresh_buttons()

    def _poll(self):
        try:
            self._tick()
        finally:
            self.root.after(self.POLL_MS, self._poll)

    def _tick(self):
        if self._io:
            return
        p = self.source.present()
        self.reader_ok = p is not None
        if p is True and not self.card_in:
            self.card_in = True
            self.say("已检测到卡片，请点击“读取卡片”。")
        elif p is not True and self.card_in:
            self.card_in = False
            self._on_removed()
            return
        if self._sig() != getattr(self, "_last_sig", None):     # 状态未变化时不刷新界面
            self._apply_state()

    def _toggle_sim(self):
        if not self._io:
            self.source.sim_present = not self.source.sim_present
            self._tick()

    def _other_windows(self):
        return [w for w in self.root.winfo_children() if isinstance(w, tk.Toplevel)]

    def _reset_session(self):
        """关闭其他窗口，清除已读取的内容和密钥。"""
        self.epoch += 1
        for w in self._other_windows():
            try:
                w.grab_release()
                w.destroy()
            except tk.TclError:
                pass
        self.hdr, self.dk, self.entries, self.duress_on = None, None, [], False
        self.reveal_idx = None
        self.set_dirty(False)
        self.refresh()

    def _on_removed(self, force_alert=False):
        working = force_alert or self.hdr is not None or bool(self._other_windows())
        dirty = self.dirty
        self._reset_session()
        self._apply_state()
        self.say("卡片已移除。")
        if working:
            cde_info(self.root, "提示", "卡片异常移除" + ("\n未写入卡片的修改已丢弃" if dirty else ""), kind="warn")

    def fail(self, e, title="操作失败"):
        """卡片操作失败：卡片已移除时按异常移除处理，否则显示错误。"""
        if self.source.present() is not True:
            self.card_in = False
            self._on_removed(force_alert=True)
        else:
            self.error(e, title)

    @contextmanager
    def io(self):
        """读写期间指示灯为红色。"""
        self._io += 1
        self.light.set("busy")
        self.root.update_idletasks()
        try:
            yield
        finally:
            self._io -= 1
            self._apply_state()

    # ---- 工具
    @contextmanager
    def busy(self):
        self.root.config(cursor="watch")
        self.root.update_idletasks()
        try:
            yield
        finally:
            self.root.config(cursor="")

    def say(self, text):
        self.status.config(text=text)

    def error(self, e, title="错误"):
        cde_info(self.root, title, str(e), kind="error")

    def selected(self):
        sel = self.listbox.curselection()
        return sel[0] if sel else None

    def set_dirty(self, on=True):
        self.dirty = on
        self.dirty_lbl.config(text="有未写入的修改" if on else "")

    def confirm_discard(self):
        return not self.dirty or cde_ask(self.root, "放弃修改", "当前修改尚未写入卡片，确定放弃？", kind="warn")

    # ---- 刷新
    def _line(self, i):
        a, e = self.hdr.attrs, self.entries[i]
        lw = max(a.label_max, 4)
        pw = e.pw if i == self.reveal_idx else "*" * len(e.pw)
        if a.is_hex:
            pw = group_hex(pw)
        return f"{i + 1:>3}  {e.label.ljust(lw)}  {pw}"

    def _render_row(self, i):
        if self.hdr is None or i is None or not 0 <= i < len(self.entries):
            return
        sel = self.selected() == i
        self.listbox.delete(i)
        self.listbox.insert(i, self._line(i))
        if sel:
            self.listbox.selection_set(i)
            self.listbox.activate(i)

    def refresh(self):
        h = self.hdr
        v = self.attr_vals
        self.reveal_idx = None
        if h:
            a = h.attrs
            cap = card_capacity_bytes(h.card_type)
            sec = h.sec
            v["name"].config(text=a.name)
            v["uid"].config(text=h.uid.hex(" ").upper())
            v["type"].config(text=f"MIFARE Classic {h.card_type}")
            v["mode"].config(text=MODE_NAMES[a.mode])
            v["pw"].config(text=f"{'定长' if a.fixed else '最长'}{a.pw_max}{a.unit}")
            v["label"].config(text=f"最长{a.label_max}个字符" if a.label_max else "不使用")
            v["slots"].config(text=f"{len(self.entries)}/{a.slots}")
            v["bytes"].config(text=f"{a.total_bytes()}/{cap}字节")
            v["created"].config(text=time.strftime("%Y-%m-%d %H:%M", time.localtime(a.created)))
            v["sec"].config(text="已启用" if a.has_sec else "未启用")
            if sec:
                v["duress"].config(text="已启用" if self.duress_on else "未启用")
                v["lock"].config(text=f"连续错误{sec.lock_max}次锁定" if sec.lock_max else "未启用")
                v["rec"].config(text=f"错误{sec.rec_max}次清除" if sec.rec_max else "未启用")
            else:
                for k in ("duress", "lock", "rec"):
                    v[k].config(text="—")
        else:
            for lbl in v.values():
                lbl.config(text="—")
        self.meter.delete("all")
        if h:
            frac = len(self.entries) / h.attrs.slots
            self.meter.create_rectangle(2, 2, 2 + int(168 * frac), 12, fill=C["title"], width=0)

        self.listbox.delete(0, "end")
        for i in range(len(self.entries)):
            self.listbox.insert("end", self._line(i))
        self.list_hint.config(text="" if h else "卡片内容需读取后显示。")
        cw = tkfont.Font(font=MONO).measure("0")
        lw = max(h.attrs.label_max, 4) if h else 4
        for lbl, col in zip(self.head_cols, (2, 5, 5 + lw + 2)):
            if h:
                lbl.place(x=4 + col * cw, rely=0.5, anchor="w")
            else:
                lbl.place_forget()
        self.refresh_buttons()

    def refresh_buttons(self):
        busy = self._io > 0
        has, sel = self.hdr is not None, self.selected() is not None
        card = self.card_in and self.reader_ok
        full = has and len(self.entries) >= self.hdr.attrs.slots
        has_sec = has and self.hdr.attrs.has_sec

        main = self.b["main"]
        set_text(main.btn, "退卡" if has else "读取卡片")
        enable(main.btn, card and not busy and not self.alert_on)
        packed = main.winfo_manager() == "pack"
        if card and not packed:
            main.pack(side="left", padx=(16, 14), before=self.light)
        elif not card and packed:
            main.pack_forget()
        enable(self.b["new"].btn, has and not full)
        for k in ("edit", "del", "show", "copy"):
            enable(self.b[k].btn, has and sel)
        enable(self.b["save"].btn, has and self.dirty)
        packed = self.b["save"].winfo_manager() == "pack"
        if has and not packed:
            self.b["save"].pack(side="right", padx=16)
        elif not has and packed:
            self.b["save"].pack_forget()

        # 菜单项状态有变化时才更新，避免已展开的菜单重绘闪烁
        want = {
            ("卡片", "读取卡片"): card and not has, ("卡片", "写入卡片"): has and self.dirty,
            ("卡片", "退卡"): has, ("卡片", "开卡向导…"): card and not has, ("卡片", "销毁卡片…"): card,
            ("条目", "新建条目"): has and not full, ("条目", "编辑条目"): has and sel,
            ("条目", "删除条目"): has and sel, ("条目", "复制到剪贴板"): has and sel,
            ("安全", "安全设置…"): has_sec, ("安全", "修改主密码…"): has, ("安全", "更换恢复码…"): has,
        }
        cache = self.__dict__.setdefault("_menu_cache", {})
        for (menu, label), on in want.items():
            if cache.get((menu, label)) != on:
                self.menus[menu].entryconfig(label, state="normal" if on else "disabled")
                cache[(menu, label)] = on

    # ---- 按住显示
    def reveal_start(self):
        i = self.selected()
        if i is None or self.reveal_idx == i:
            return
        self.reveal_end()
        self.reveal_idx = i
        self._render_row(i)

    def reveal_end(self):
        i, self.reveal_idx = self.reveal_idx, None
        if i is not None:
            self._render_row(i)

    # ---- 卡片操作
    def _main_action(self):
        if self.hdr:
            self.eject()
        else:
            self.read_card()

    def read_card(self):
        if self.hdr or not self.card_in or self._io:
            return
        if self.alert_on:
            self.dismiss_alert()
        ep = self.epoch
        try:
            with self.busy(), self.io(), self.source.open() as card:
                hdr = read_header(card)
        except CardError as e:
            self.fail(e, "读取失败")
            return
        if hdr is None:
            self.say("该卡片尚未开卡，已打开开卡向导。")
            OpenCardWizard(self, auto_detect=True)
            return

        def attempt(mode, value):
            with self.busy(), self.io(), self.source.open() as card:
                if mode == "master":
                    return open_with_master(card, hdr, value)
                return open_with_recovery(card, hdr, value)

        res = UnlockDialog(self.root, hdr, attempt).show()
        if ep != self.epoch:
            return
        if not res:
            self.say("已取消读取。")
            return
        mode, payload = res
        if mode == "wiped":
            self.after_wipe(payload)
            return
        dk, entries, duress_on = payload
        self.load_unlocked(hdr, dk, entries, duress_on, f"已读取卡片{hdr.attrs.name}，共{len(entries)}个条目。")
        if mode == "recovery":
            new = NewPasswordDialog(self.root, "设置新主密码",
                                    "已使用恢复码解锁，锁定状态与错误计数已清除。\n"
                                    "请设置新的主密码。").show()
            if new and ep == self.epoch:
                self._card_op(lambda card: change_master(card, self.hdr, self.dk, new), "新主密码已写入卡片。")

    def eject(self):
        if not self.hdr or self._io:
            return
        if not self.confirm_discard():
            return
        self._reset_session()
        self._apply_state()
        self.say("已退卡。")

    def after_wipe(self, reason):
        self._reset_session()            # 关闭其他窗口并清除内容
        sub = "恢复码错误次数已达上限" if reason == "recovery" else "安全策略已触发"
        self.alert_big.config(text="卡片已清除")
        self.alert_msg.config(text=f"{sub}\n卡片数据已全部清除")
        self.alert_on = True
        self._apply_state()
        self.root.bell()
        self._alert_tick()
        self.say("卡片数据已清除。")

    def _alert_tick(self):
        self._alert_phase = not self._alert_phase
        fg, bg = ("white", "#C0161B") if self._alert_phase else ("#8E0E12", "#FFD83D")
        for w in self.alert_parts:
            w.config(bg=bg)
        for w in (self.alert_big, self.alert_msg):
            w.config(fg=fg)
        self._alert_job = self.root.after(420, self._alert_tick)

    def dismiss_alert(self):
        if self._alert_job:
            self.root.after_cancel(self._alert_job)
            self._alert_job = None
        self.alert_on = False
        self._apply_state()

    def load_unlocked(self, hdr, dk, entries, duress_on, msg):
        self.hdr, self.dk, self.entries, self.duress_on = hdr, dk, list(entries), duress_on
        self.set_dirty(False)
        self.refresh()
        self._apply_state()
        self.say(msg)

    def _card_op(self, fn, ok_msg):
        """执行写卡操作，返回 fn 的结果，失败返回 None。"""
        try:
            with self.busy(), self.io(), self.source.open() as card:
                result = fn(card)
        except CardError as e:
            self.fail(e)
            return None
        self.say(ok_msg)
        return result if result is not None else True

    def save_card(self):
        if not (self.hdr and self.dirty) or self._io:
            return
        if self._card_op(lambda card: save_entries(card, self.hdr, self.entries, self.duress_on, self.dk),
                         f"已写入卡片并完成校验，共{len(self.entries)}个条目。"):
            self.set_dirty(False)
            self.refresh_buttons()

    def wizard(self):
        if self.hdr or not self.card_in or self._io:
            return
        if self.alert_on:
            self.dismiss_alert()
        OpenCardWizard(self, auto_detect=True)

    def destroy_card(self):
        if not self.card_in or self._io:
            return
        ep = self.epoch
        try:
            with self.busy(), self.io(), self.source.open() as card:
                uid = card.uid()
                try:
                    hdr = read_header(card)
                    name = hdr.attrs.name if hdr else "未开卡"
                except CardError:
                    name = "无法识别"
        except CardError as e:
            self.fail(e, "读取失败")
            return
        ok = TypeConfirmDialog(self.root, "销毁卡片",
                               f"卡片名称：{name}\n卡片UID：{uid.hex(' ').upper()}\n\n"
                               "销毁将清除卡片全部数据，包括条目、密钥与安全设置。\n"
                               "此操作无法撤销，恢复码亦无法找回数据。", "销毁", "销毁卡片").show()
        if not ok or ep != self.epoch:
            return

        def op(card):
            if card.uid() != uid:
                raise CardError("读卡器上的卡片已更换，操作已中止。")
            wipe_card(card)

        if self._card_op(op, "卡片已销毁。"):
            if self.hdr and self.hdr.uid == uid:
                self._reset_session()
                self._apply_state()
            cde_info(self.root, "销毁完成", "卡片数据已全部清除，已恢复为空白卡。")

    def change_master(self):
        if not self.hdr:
            return
        ep = self.epoch
        new = NewPasswordDialog(self.root, "修改主密码", "新主密码将立即写入卡片，条目内容不受影响。").show()
        if new and ep == self.epoch:
            self._card_op(lambda card: change_master(card, self.hdr, self.dk, new), "主密码已修改。")

    def change_recovery(self):
        if not self.hdr:
            return
        ep = self.epoch
        code = RecoveryDialog(self.root, self.hdr).show()
        if code and ep == self.epoch:
            self._card_op(lambda card: change_recovery(card, self.hdr, self.dk, code),
                          "新恢复码已写入，原恢复码已失效。")

    def security_settings(self):
        if not (self.hdr and self.hdr.attrs.has_sec):
            return
        ep = self.epoch
        res = SecurityDialog(self.root, self.hdr, self.duress_on).show()
        if not res or ep != self.epoch:
            return
        act, pw, lock, rec = res
        new = self._card_op(lambda card: update_security(card, self.hdr, self.dk, self.entries, self.duress_on,
                                                         act, pw, lock, rec), "安全设置已写入卡片。")
        if new is not None and ep == self.epoch:
            self.duress_on = bool(new)
            self.set_dirty(False)
            self.refresh()

    # ---- 条目操作
    def new_entry(self):
        if not self.hdr:
            return
        if len(self.entries) >= self.hdr.attrs.slots:
            self.error(f"本卡{self.hdr.attrs.slots}个槽位已全部使用。", "槽位已满")
            return
        ep = self.epoch
        e = EntryDialog(self.root, self.hdr.attrs).show()
        if e and ep == self.epoch:
            self.entries.append(e)
            self.set_dirty()
            self.refresh()
            self.listbox.selection_set("end")
            self.refresh_buttons()

    def edit_entry(self):
        i = self.selected()
        if i is None or not self.hdr:
            return
        ep = self.epoch
        e = EntryDialog(self.root, self.hdr.attrs, self.entries[i]).show()
        if e and ep == self.epoch and e != self.entries[i]:
            self.entries[i] = e
            self.set_dirty()
            self.refresh()
            self.listbox.selection_set(i)
            self.refresh_buttons()

    def delete_entry(self):
        i = self.selected()
        if i is None or not self.hdr:
            return
        ep = self.epoch
        if cde_ask(self.root, "删除条目", f"确定删除第{i + 1}条“{self.entries[i].label}”？\n"
                                         "写入卡片后生效。", kind="warn", ok_text="删除") and ep == self.epoch:
            del self.entries[i]
            self.set_dirty()
            self.refresh()

    def copy_entry(self):
        i = self.selected()
        if i is None or not self.hdr:
            return
        value = self.entries[i].pw
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        if self._clip_job:
            self.root.after_cancel(self._clip_job)
        self._clip_value = value
        self._clip_job = self.root.after(self.CLIP_SECONDS * 1000, lambda: self._clear_clip(value))
        self.say(f"已复制第{i + 1}条，剪贴板将于{self.CLIP_SECONDS}秒后清空。")

    def _clear_clip(self, value):
        self._clip_job = None
        try:
            if self.root.clipboard_get() == value:
                self.root.clipboard_clear()
                self.root.clipboard_append("")
                self.say("剪贴板已清空。")
        except tk.TclError:
            pass

    def about(self):
        AboutDialog(self.root).show()

    def quit(self):
        if not self.confirm_discard():
            return
        if self._clip_job:
            self.root.after_cancel(self._clip_job)
            self._clear_clip(self._clip_value)
        self.root.destroy()


# =====================================================================

def main():
    ap = argparse.ArgumentParser(description=f"{APP_NAME} M1卡密码管理器")
    ap.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    ap.add_argument("--sim", metavar="FILE", help="使用模拟卡文件，文件不存在时自动创建空白卡")
    ap.add_argument("--sim-type", choices=["1K", "4K"], default="1K", help="新建模拟卡的类型")
    ap.add_argument("--reader", help="读卡器名称关键字")
    ap.add_argument("--key", default=DEFAULT_KEY, help="扇区密钥，12位十六进制数字")
    ap.add_argument("--key-type", default="A", choices=["A", "B", "a", "b"])
    ap.add_argument("--type", choices=["1K", "4K"], help="ATR 识别不出卡型时手动指定")
    args = ap.parse_args()

    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("缺少 cryptography，请先执行：pip install cryptography", file=sys.stderr)
        sys.exit(1)

    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    root = tk.Tk()
    apply_cde(root)

    def on_error(exc, val, tb):
        import traceback
        traceback.print_exception(exc, val, tb)
        cde_info(root, "出错了", f"{exc.__name__}: {val}", kind="error")
    root.report_callback_exception = on_error

    App(root, CardSource(args))
    root.mainloop()


if __name__ == "__main__":
    main()
