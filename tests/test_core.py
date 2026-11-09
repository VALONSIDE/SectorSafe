# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 VALONSIDE
"""卡片格式、加密与安全策略测试。全部使用模拟卡，不需要读卡器。

运行：pytest tests
"""

import os
import sys
import types

import pytest

pytest.importorskip("tkinter")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sectorsafe as ss  # noqa: E402

MASTER = "master123"


# ---------------------------------------------------------------- 工具

@pytest.fixture
def new_card(tmp_path):
    def make(card_type="1K", name="card"):
        return ss.SimCard(str(tmp_path / f"{name}.bin"), card_type)
    return make


def reopen(card):
    return ss.SimCard(card.path)


def is_blank(card):
    return not any(any(card.mem[b * 16:(b + 1) * 16]) for b, _ in ss.data_blocks(card.card_type))


def trailers_untouched(card):
    n = 64 if card.card_type == "1K" else 256
    return all(card.mem[b * 16:(b + 1) * 16] == bytes(16) for b in range(n) if ss.is_trailer(b))


def attrs(mode=ss.MODE_HEX, pw_max=32, fixed=False, label_max=12, slots=8, sec=True):
    return ss.CardAttrs("TEST", mode, pw_max, fixed, label_max, slots, sec)


def opened(card, a=None, duress=None, lock=0, rec=0):
    code = ss.new_recovery_code()
    hdr, dk = ss.format_card(card, a or attrs(), MASTER, code, duress, lock, rec)
    return hdr, dk, code


# ---------------------------------------------------------------- 卡片布局

def test_data_blocks_skip_manufacturer_and_trailers():
    b1 = ss.data_blocks("1K")
    assert len(b1) == 47 and ss.card_capacity_bytes("1K") == 752
    assert 0 not in [b for b, _ in b1]
    assert not any(ss.is_trailer(b) for b, _ in b1)
    b4 = ss.data_blocks("4K")
    assert len(b4) == 215 and ss.card_capacity_bytes("4K") == 3440
    assert not any(ss.is_trailer(b) for b, _ in b4)


def test_detect_type_from_atr():
    atr = bytes.fromhex("3B8F8001804F0CA000000306030001000000006A")
    assert ss.detect_type(atr) == "1K"
    assert ss.detect_type(atr[:13] + b"\x00\x02" + atr[15:]) == "4K"
    assert ss.detect_type(bytes.fromhex("3B6B000020900000FFFFFFF3E0A214")) is None


@pytest.mark.parametrize("card_type, mode, pw_max, label_max, sec, expected", [
    ("1K", ss.MODE_HEX, 32, 12, False, 19),
    ("1K", ss.MODE_HEX, 32, 12, True, 18),
    ("1K", ss.MODE_ASCII, 64, 12, True, 7),
    ("4K", ss.MODE_HEX, 32, 12, True, 104),
])
def test_capacity_worst_case(card_type, mode, pw_max, label_max, sec, expected):
    n = ss.max_slots_for(card_type, mode, pw_max, label_max, sec)
    assert n == expected
    a = ss.CardAttrs("X", mode, pw_max, False, label_max, n, sec)
    assert a.total_bytes() <= ss.card_capacity_bytes(card_type)
    a.slots += 1
    assert a.total_bytes() > ss.card_capacity_bytes(card_type)


def test_format_refuses_overflow(new_card):
    with pytest.raises(ss.CardError, match="超出卡片容量"):
        opened(new_card(), ss.CardAttrs("X", ss.MODE_ASCII, 64, True, 32, 50, True))


# ---------------------------------------------------------------- 条目读写

@pytest.mark.parametrize("mode, pw", [(ss.MODE_HEX, "DEADBEEF1"), (ss.MODE_ASCII, "Pa ss!~{}")])
def test_entries_roundtrip(new_card, mode, pw):
    card = new_card()
    hdr, dk, _ = opened(card, attrs(mode=mode, pw_max=16))
    entries = [ss.Entry(f"k{i}", pw) for i in range(hdr.attrs.slots)]
    ss.save_entries(card, hdr, entries, False, dk)
    hdr2 = ss.read_header(reopen(card))
    got_dk, got, duress = ss.open_with_master(reopen(card), hdr2, MASTER)
    assert got_dk == dk and got == entries and duress is False


def test_entry_rules():
    a = attrs(mode=ss.MODE_HEX, pw_max=8, fixed=True, label_max=4)
    assert ss.entry_problem(a, "door", "DEADBEEF") is None
    assert "定长" in ss.entry_problem(a, "door", "ABCD")
    assert ss.entry_problem(a, "door", "XYZ12345")
    assert ss.entry_problem(a, "toolong", "DEADBEEF")
    assert ss.entry_problem(a, "门", "DEADBEEF")
    b = attrs(mode=ss.MODE_ASCII, pw_max=4)
    assert ss.entry_problem(b, "k", "中文") and ss.entry_problem(b, "k", "abcde")


def test_tampered_attributes_fail_decryption(new_card):
    card = new_card()
    hdr, dk, _ = opened(card)
    raw = bytearray(card.read_block(2, 0))
    raw[22 - 16] ^= 1                     # 公开属性中的定长标志
    card.write_block(2, 0, bytes(raw))
    hdr2 = ss.read_header(card)
    with pytest.raises(ss.CardError, match="篡改"):
        ss.decode_vault(hdr2, ss.read_vault(card, hdr2), dk)


def test_old_format_rejected(new_card):
    card = new_card()
    card.write_block(1, 0, b"HXVT" + bytes(12))
    with pytest.raises(ss.CardError, match="旧版"):
        ss.read_header(card)


def test_write_refuses_other_card(new_card):
    a, b = new_card(name="a"), new_card(name="b")
    hdr, dk, _ = opened(a)
    with pytest.raises(ss.CardError, match="UID"):
        ss.save_entries(b, hdr, [], False, dk)


# ---------------------------------------------------------------- 安全策略

def test_wrong_master_locks_card(new_card):
    card = new_card()
    hdr, dk, code = opened(card, lock=3)
    for left in (2, 1):
        with pytest.raises(ss.CardError, match=f"剩余{left}次"):
            ss.open_with_master(card, hdr, "wrongpass")
    with pytest.raises(ss.CardError, match="已锁定"):
        ss.open_with_master(card, hdr, "wrongpass")
    assert hdr.sec.locked
    with pytest.raises(ss.CardError, match="已锁定"):
        ss.open_with_master(card, hdr, MASTER)
    ss.open_with_recovery(card, hdr, code.lower())
    assert not hdr.sec.locked and hdr.sec.wrong == 0
    assert ss.open_with_master(card, hdr, MASTER)[0] == dk


def test_counter_persists_across_sessions(new_card):
    card = new_card()
    hdr, _, _ = opened(card, lock=5)
    with pytest.raises(ss.CardError):
        ss.open_with_master(card, hdr, "wrongpass")
    assert ss.read_header(reopen(card)).sec.wrong == 1


def test_duress_wipes_even_when_locked(new_card):
    card = new_card()
    hdr, _, _ = opened(card, duress="help", lock=1)
    with pytest.raises(ss.CardError):
        ss.open_with_master(card, hdr, "wrongpass")
    assert hdr.sec.locked
    with pytest.raises(ss.CardWiped) as e:
        ss.open_with_master(card, hdr, "help")
    assert e.value.reason == "duress"
    assert is_blank(reopen(card)) and trailers_untouched(reopen(card))


def test_recovery_limit_wipes(new_card):
    card = new_card()
    hdr, _, code = opened(card, rec=2)
    bad = "00000000" if code != "00000000" else "11111111"
    with pytest.raises(ss.CardError, match="剩余1次"):
        ss.open_with_recovery(card, hdr, bad)
    with pytest.raises(ss.CardError, match="8位"):
        ss.open_with_recovery(card, hdr, "12")
    assert hdr.sec.rec_wrong == 1
    with pytest.raises(ss.CardWiped) as e:
        ss.open_with_recovery(card, hdr, bad)
    assert e.value.reason == "recovery" and is_blank(reopen(card))


def test_no_security_area_has_no_limits(new_card):
    card = new_card()
    hdr, _, _ = opened(card, attrs(sec=False), duress="help", lock=1, rec=1)
    assert hdr.sec is None and hdr.attrs.vault_start == ss.ATTR_BLOCKS
    for _ in range(5):
        with pytest.raises(ss.CardError):
            ss.open_with_master(card, hdr, "wrongpass")
    ss.open_with_master(card, hdr, MASTER)


def test_duress_flag_is_hidden(new_card):
    a, b = new_card(name="a"), new_card(name="b")
    ha, _, _ = opened(a, duress="help")
    hb, _, _ = opened(b)
    assert len(ha.sec.verifier) == len(hb.sec.verifier) == 16
    assert ha.sec.pack()[16:] == hb.sec.pack()[16:]


def test_security_settings_update(new_card):
    card = new_card()
    hdr, dk, _ = opened(card)
    entries = [ss.Entry("door", "DEADBEEF")]
    with pytest.raises(ss.CardError, match="不得与主密码相同"):
        ss.update_security(card, hdr, dk, entries, False, "set", MASTER, 5, 5)
    assert ss.update_security(card, hdr, dk, entries, False, "set", "sos!", 4, 0) is True
    hdr2 = ss.read_header(reopen(card))
    _, got, duress = ss.open_with_master(card, hdr2, MASTER)
    assert got == entries and duress and hdr2.sec.lock_max == 4 and hdr2.sec.rec_max == 0
    with pytest.raises(ss.CardWiped):
        ss.open_with_master(card, hdr2, "sos!")


def test_change_master_and_recovery(new_card):
    card = new_card()
    hdr, dk, old_code = opened(card, duress="duresspw9")
    with pytest.raises(ss.CardError, match="不得与胁迫密码相同"):
        ss.change_master(card, hdr, dk, "duresspw9")
    ss.change_master(card, hdr, dk, "newmaster1")
    new_code = ss.new_recovery_code()
    ss.change_recovery(card, hdr, dk, new_code)
    hdr2 = ss.read_header(reopen(card))
    assert ss.open_with_master(card, hdr2, "newmaster1")[0] == dk
    assert ss.open_with_recovery(card, hdr2, new_code)[0] == dk
    if old_code != new_code:
        with pytest.raises(ss.CardError):
            ss.open_with_recovery(card, hdr2, old_code)


def test_wipe_restores_blank_card(new_card):
    card = new_card("4K")
    a = ss.CardAttrs("FULL", ss.MODE_HEX, 64, True, 32, ss.max_slots_for("4K", ss.MODE_HEX, 64, 32, True), True)
    hdr, dk, _ = opened(card, a, duress="dur3ss", lock=3, rec=3)
    ss.save_entries(card, hdr, [ss.Entry("L" * 32, "F" * 64)] * a.slots, True, dk)
    ss.wipe_card(card)
    assert is_blank(card) and ss.read_header(card) is None
    assert trailers_untouched(card) and card.mem[:4] != bytes(4)


# ---------------------------------------------------------------- 读卡器

def test_pick_reader_prefers_picc():
    names = ["ACS ACR1281 1S Dual Reader ICC 0", "ACS ACR1281 1S Dual Reader PICC 0",
             "ACS ACR1281 1S Dual Reader SAM 0"]
    assert ss.pick_reader(names).endswith("PICC 0")
    assert ss.pick_reader(names, "sam").endswith("SAM 0")
    assert ss.pick_reader(names, "nothing") is None


def test_presence_probe(monkeypatch):
    sc = types.ModuleType("smartcard.scard")
    state = {"present": True, "readers": ["X ICC 0", "X PICC 0"], "asked": None}
    sc.SCARD_SCOPE_USER, sc.SCARD_S_SUCCESS, sc.SCARD_E_NO_READERS_AVAILABLE = 0, 0, 0x8010002E
    sc.SCARD_STATE_UNAWARE, sc.SCARD_STATE_PRESENT = 0, 0x20
    sc.SCardEstablishContext = lambda scope: (0, 1)
    sc.SCardReleaseContext = lambda ctx: 0
    sc.SCardListReaders = lambda ctx, g: ((0, state["readers"]) if state["readers"]
                                          else (sc.SCARD_E_NO_READERS_AVAILABLE, []))

    def status(ctx, timeout, rs):
        state["asked"] = rs[0][0]
        return 0, [(rs[0][0], 0x20 if state["present"] else 0x10, [])]
    sc.SCardGetStatusChange = status
    pkg = types.ModuleType("smartcard")
    pkg.scard = sc
    monkeypatch.setitem(sys.modules, "smartcard", pkg)
    monkeypatch.setitem(sys.modules, "smartcard.scard", sc)

    probe = ss.PresenceProbe()
    assert probe.present() is True and state["asked"] == "X PICC 0"
    state["present"] = False
    assert probe.present() is False
    state["readers"] = []
    assert probe.present() is None


def test_pcsc_session_key_slot(monkeypatch):
    """ACR1281U 只接受 20h 会话密钥位置，认证须使用同一位置。"""
    sent = []

    class Conn:
        slot = None

        def connect(self):
            pass

        def disconnect(self):
            pass

        def getATR(self):
            return list(bytes.fromhex("3B8F8001804F0CA000000306030001000000006A"))

        def transmit(self, c):
            sent.append(bytes(c[:5]).hex(" ").upper())
            if c[:2] == [0xFF, 0x82]:
                if c[3] == 0x20:
                    Conn.slot = 0x20
                    return [], 0x90, 0
                return [], 0x63, 0
            if c[:2] == [0xFF, 0x86]:
                return ([], 0x90, 0) if c[9] == Conn.slot else ([], 0x63, 0)
            if c[:2] == [0xFF, 0xCA]:
                return [1, 2, 3, 4], 0x90, 0
            if c[:2] == [0xFF, 0xB0]:
                return [0] * 16, 0x90, 0
            return [], 0x6A, 0x81

    class Reader:
        def __str__(self):
            return "ACS ACR1281 1S Dual Reader PICC 0"

        def createConnection(self):
            return Conn()

    system = types.ModuleType("smartcard.System")
    system.readers = lambda: [Reader()]
    monkeypatch.setitem(sys.modules, "smartcard", types.ModuleType("smartcard"))
    monkeypatch.setitem(sys.modules, "smartcard.System", system)

    card = ss.PcscM1()
    assert card.key_slot == 0x20 and card.card_type == "1K"
    assert ss.read_header(card) is None
    assert any(s.startswith("FF 86") for s in sent)
