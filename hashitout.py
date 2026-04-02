#!/usr/bin/env python3

import argparse
import base64
import collections
import copy
import csv
import datetime
import hashlib
import io
import json
import math
import os
import quopri
import random
import re
import string
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

VERSION               = '4.2.0'
MAX_URL_BYTES         = 10 * 1024 * 1024
URL_TIMEOUT           = 20
MAX_REPORT_STRING_LEN = 1240
DISPLAY_DELAY         = 2.0

_KEY_HINT_METHOD       = 'Key Length Hints'
_KEY_PARAM_METHOD      = 'Parameter Hints'
_CIPHER_PROFILE_METHOD = 'Cipher Profile'
_ARTIFACT_TREE_METHOD  = 'Artifact Tree'
_ARTIFACT_TRIAGE_METHOD = 'Artifact Triage'

_FULL_NASTY_PROFILE = {
    'beam_width':     42,
    'beam_depth':     8,
    'beam_min_score': 8,
    'max_key_period': 32,
    'max_trans_width': 24,
    'max_rails':      14,
}

TETRAGRAMS = {
    'TION': 6.9, 'THER': 6.7, 'THAT': 6.5, 'OFTH': 6.2, 'FTHE': 6.1,
    'WITH': 5.9, 'INTH': 5.8, 'ATIO': 5.8, 'HERE': 5.7, 'OULD': 5.6,
    'IGHT': 5.5, 'HAVE': 5.4, 'ETHE': 5.2, 'MENT': 5.1, 'IONS': 5.0,
    'THIS': 4.9, 'TING': 4.8, 'FROM': 4.7, 'EVER': 4.6, 'THEM': 4.5,
    'OUGH': 4.3, 'ERES': 4.2, 'ENCE': 4.2,
}

SUB_TETRAGRAMS = {
    'TION': 3.0, 'THER': 2.9, 'HERE': 2.8, 'THAT': 2.8, 'MENT': 2.6,
    'IONS': 2.4, 'WITH': 2.5, 'THIS': 2.6, 'ATIO': 2.5, 'EVER': 2.3,
    'FROM': 2.4, 'OUGH': 2.3, 'IGHT': 2.3, 'HAVE': 2.3, 'TING': 2.3,
    'ANDT': 2.1, 'EDTH': 1.9, 'THES': 1.8, 'INGT': 2.0,
}

EN_FREQ = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

_ENGLISH_TOP = (
    'the','and','that','have','for','not','with','you','this','but','his','from','they',
    'say','her','she','will','one','all','would','there','their','what','about','which',
    'when','make','like','time','just','know','take','into','year','good','some','could',
    'them','other','than','then','look','only','come','over','think','also','back','after',
    'work','first','well','even','want','because','these','give','most',
)

COMMON_VIGENERE_KEYS = [
    'key','secret','password','abc','flag','cipher','hack','leet',
    'admin','root','code','virus','ctf','crypto','hidden','stego',
    'pass','test','hio','hashitout','pwn','exploit','hacker',
    'hello','world','python','linux','windows','security','reverse',
    'decode','encode','base','shift','alpha','beta','gamma','delta',
]

_ENGLISH_FREQ = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074,
}

def _self_install():
    import shutil, stat as _st
    src = os.path.abspath(__file__)
    for d in [os.path.expanduser("~/.local/bin"), "/usr/local/bin"]:
        os.makedirs(d, exist_ok=True)
        dst = os.path.join(d, "hashitout")
        try:
            shutil.copy2(src, dst)
            os.chmod(dst, os.stat(dst).st_mode | _st.S_IEXEC | _st.S_IXGRP | _st.S_IXOTH)
            open(dst + ".installed", "w").write("ok")
            print("  installed: " + dst)
            return
        except PermissionError:
            continue
    print("  install failed")

@dataclass
class Finding:
    method:       str
    result_text:  Optional[str]            = None
    result_bytes: Optional[bytes]          = None
    filetype:     Optional[Tuple[str,str]] = None
    confidence:   str                      = 'LOW'
    note:         str                      = ''
    score:        float                    = 0.0
    entropy:      float                    = 0.0
    chain:        List[str]                = field(default_factory=list)
    rrsw_signal:  str                      = 'RRSW-NOISE'
    source_label: str                      = ''
    why:          str                      = ''
    key_hints:    List[Dict]               = field(default_factory=list)
    parent_artifact: str                   = ''
    child_count:  int                      = 0
    analyst_interpretation: str            = ''
    analyst_hypothesis:     str            = ''
    analyst_next_steps:     str            = ''
    artifact_profile:       List[str]      = field(default_factory=list)
    timestamp:    Any = field(default_factory=datetime.datetime.now)

    def display_result(self) -> str:
        if self.result_text:
            return self.result_text
        if self.result_bytes:
            return bytes_to_hex_display(self.result_bytes)
        return '[no output]'

def rot_n(text: str, n: int) -> str:
    result = []
    for ch in text:
        if ch.isascii() and ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + n) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def rot47(text: str) -> str:
    return ''.join(
        chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
        for c in text
    )

def rot5(text: str) -> str:
    return ''.join(
        chr((ord(c) - ord('0') + 5) % 10 + ord('0')) if c.isdigit() else c
        for c in text
    )

def rot18(text: str) -> str:
    return rot5(rot_n(text, 13))

def decode_base2(data: str) -> Optional[bytes]:
    try:
        clean = data.strip().replace(' ', '').replace('\n', '')
        if not all(c in '01' for c in clean) or len(clean) % 8 != 0:
            return None
        return bytes(int(clean[i:i+8], 2) for i in range(0, len(clean), 8))
    except Exception:
        return None

def decode_base8(data: str) -> Optional[bytes]:
    try:
        parts = data.strip().split()
        if not parts:
            return None
        result = bytearray()
        for p in parts:
            val = int(p, 8)
            if val > 255:
                return None
            result.append(val)
        return bytes(result)
    except Exception:
        return None

def decode_base10(data: str) -> Optional[bytes]:
    try:
        parts = data.strip().split()
        if len(parts) < 2:
            return None
        result = bytearray()
        for p in parts:
            val = int(p)
            if val > 255:
                return None
            result.append(val)
        return bytes(result)
    except Exception:
        return None

def decode_base16(data: str) -> Optional[bytes]:
    try:
        return base64.b16decode(data.strip().upper())
    except Exception:
        return None

def decode_base32(data: str) -> Optional[bytes]:
    try:
        padded = data.strip().upper()
        missing = len(padded) % 8
        if missing:
            padded += '=' * (8 - missing)
        return base64.b32decode(padded)
    except Exception:
        return None

def decode_base32hex(data: str) -> Optional[bytes]:
    std    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    exthex = '0123456789ABCDEFGHIJKLMNOPQRSTUV'
    try:
        translated = data.strip().upper().translate(str.maketrans(exthex, std))
        missing = len(translated) % 8
        if missing:
            translated += '=' * (8 - missing)
        return base64.b32decode(translated)
    except Exception:
        return None

def decode_base32_crockford(data: str) -> Optional[bytes]:
    CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
    STD_B32   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    try:
        text = data.strip().upper().replace('I','1').replace('L','1').replace('O','0')
        translated = ''.join(STD_B32[CROCKFORD.index(c)] for c in text if c in CROCKFORD)
        missing = len(translated) % 8
        if missing:
            translated += '=' * (8 - missing)
        return base64.b32decode(translated)
    except Exception:
        return None

def decode_base36(data: str) -> Optional[bytes]:
    try:
        num = int(data.strip(), 36)
        result = []
        while num > 0:
            result.append(num & 0xFF)
            num >>= 8
        return bytes(reversed(result)) if result else None
    except Exception:
        return None

def decode_base45(data: str) -> Optional[bytes]:
    ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
    try:
        text = data.strip()
        res = []
        for i in range(0, len(text), 3):
            chunk = text[i:i+3]
            if len(chunk) == 3:
                c, d, e = [ALPHABET.index(x) for x in chunk]
                n = c + d * 45 + e * 2025
                res.extend(divmod(n, 256))
            elif len(chunk) == 2:
                c, d = [ALPHABET.index(x) for x in chunk]
                res.append(c + d * 45)
        return bytes(res)
    except Exception:
        return None

def decode_base58(data: str) -> Optional[bytes]:
    ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    try:
        num = 0
        for ch in data.strip():
            if ch not in ALPHA:
                return None
            num = num * 58 + ALPHA.index(ch)
        result = []
        while num > 0:
            result.append(num % 256)
            num //= 256
        for ch in data.strip():
            if ch == ALPHA[0]:
                result.append(0)
            else:
                break
        return bytes(reversed(result))
    except Exception:
        return None

def decode_base58_flickr(data: str) -> Optional[bytes]:
    ALPHA = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
    try:
        num = 0
        for ch in data.strip():
            if ch not in ALPHA:
                return None
            num = num * 58 + ALPHA.index(ch)
        result = []
        while num > 0:
            result.append(num % 256)
            num //= 256
        return bytes(reversed(result)) if result else None
    except Exception:
        return None

def decode_base62(data: str) -> Optional[bytes]:
    ALPHA = string.digits + string.ascii_uppercase + string.ascii_lowercase
    try:
        num = 0
        for ch in data.strip():
            if ch not in ALPHA:
                return None
            num = num * 62 + ALPHA.index(ch)
        result = []
        while num > 0:
            result.append(num % 256)
            num //= 256
        return bytes(reversed(result)) if result else None
    except Exception:
        return None

def decode_base64(data: str) -> Optional[bytes]:
    try:
        padded = data.strip()
        missing = len(padded) % 4
        if missing:
            padded += '=' * (4 - missing)
        return base64.b64decode(padded)
    except Exception:
        return None

def decode_base64_url(data: str) -> Optional[bytes]:
    try:
        padded = data.strip().replace('-', '+').replace('_', '/')
        missing = len(padded) % 4
        if missing:
            padded += '=' * (4 - missing)
        return base64.b64decode(padded)
    except Exception:
        return None

def decode_base64_mime(data: str) -> Optional[bytes]:
    try:
        clean = ''.join(data.split())
        missing = len(clean) % 4
        if missing:
            clean += '=' * (4 - missing)
        return base64.b64decode(clean)
    except Exception:
        return None

def decode_base85(data: str) -> Optional[bytes]:
    try:
        return base64.b85decode(data.strip())
    except Exception:
        return None

def decode_ascii85(data: str) -> Optional[bytes]:
    try:
        s = data.strip()
        if s.startswith('<~') and s.endswith('~>'):
            s = s[2:-2]
        return base64.a85decode(s)
    except Exception:
        return None

def decode_z85(data: str) -> Optional[bytes]:
    Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
    try:
        text = data.strip()
        if len(text) % 5 != 0:
            return None
        result = bytearray()
        for i in range(0, len(text), 5):
            val = 0
            for c in text[i:i+5]:
                if c not in Z85:
                    return None
                val = val * 85 + Z85.index(c)
            result.extend(struct.pack('>I', val))
        return bytes(result)
    except Exception:
        return None

def decode_base91(data: str) -> Optional[bytes]:
    TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
    try:
        decode_table = {c: i for i, c in enumerate(TABLE)}
        v = -1
        b = 0
        n = 0
        result = bytearray()
        for c in data.strip():
            if c not in decode_table:
                continue
            p = decode_table[c]
            if v < 0:
                v = p
            else:
                v += p * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                v = -1
                while n > 7:
                    result.append(b & 255)
                    b >>= 8
                    n -= 8
        if v > -1:
            result.append((b | v << n) & 255)
        return bytes(result) if result else None
    except Exception:
        return None

def decode_base92(data: str) -> Optional[bytes]:
    try:
        text = data.strip()
        if not text:
            return None
        num = 0
        for ch in text:
            code = ord(ch)
            if code < 35 or code > 126:
                return None
            num = num * 91 + (code - 35)
        result = []
        while num > 0:
            result.append(num & 0xFF)
            num >>= 8
        return bytes(reversed(result)) if result else None
    except Exception:
        return None

def decode_hex(data: str) -> Optional[bytes]:
    try:
        clean = data.strip().replace(' ','').replace('\n','')
        clean = clean.replace('0x','').replace('\\x','').replace(':','')
        if len(clean) % 2 != 0:
            clean = '0' + clean
        return bytes.fromhex(clean)
    except Exception:
        return None

def decode_hex_escaped(data: str) -> Optional[bytes]:
    try:
        if '\\x' not in data and '%' not in data:
            return None
        clean = data.strip().replace('\\x','').replace('%','').replace(' ','')
        return bytes.fromhex(clean)
    except Exception:
        return None

def decode_url(data: str) -> Optional[str]:
    try:
        decoded = urllib.parse.unquote(data.strip())
        return decoded if decoded != data.strip() else None
    except Exception:
        return None

def decode_url_double(data: str) -> Optional[str]:
    try:
        first = urllib.parse.unquote(data.strip())
        second = urllib.parse.unquote(first)
        return second if second != data.strip() else None
    except Exception:
        return None

def decode_html_entities(data: str) -> Optional[str]:
    try:
        from html import unescape
        decoded = unescape(data.strip())
        return decoded if decoded != data.strip() else None
    except Exception:
        return None

MORSE_TABLE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
    '--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
    '--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
    '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
    '-.--':'Y','--..':'Z',
    '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4',
    '.....':'5','-....':'6','--...':'7','---..':'8','----.':'9',
    '.-.-.-':'.','--..--':',','..--..':'?','-..-.':'/','-....-':'-',
    '.--.-.':'@','---...':':','-.-.-.':';','-.--.-':')','-.--.':'(',
}

def decode_morse(data: str) -> Optional[str]:
    try:
        text = data.strip()
        if not all(c in '.- /|\n\t' for c in text):
            return None
        words = text.replace('|','/').replace('\n','/').split('/')
        result = []
        for word in words:
            chars = []
            for code in word.strip().split():
                if code in MORSE_TABLE:
                    chars.append(MORSE_TABLE[code])
                else:
                    return None
            if chars:
                result.append(''.join(chars))
        decoded = ' '.join(result)
        return decoded if decoded.strip() else None
    except Exception:
        return None

def decode_atbash(text: str) -> str:
    result = []
    for ch in text:
        if ch.isascii() and ch.isalpha():
            if ch.isupper():
                result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
            else:
                result.append(chr(ord('z') - (ord(ch) - ord('a'))))
        else:
            result.append(ch)
    return ''.join(result)


def decode_vigenere(text: str, key: str) -> str:
    key = key.lower()
    result = []
    ki = 0
    for ch in text:
        if ch.isascii() and ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('a')
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

AFFINE_KEYS = [(3,7),(5,8),(7,3),(9,2),(11,5),(25,1),(7,11),(3,0),(5,0)]

def decode_affine(text: str, a: int, b: int) -> str:
    def mod_inv(a, m):
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None
    try:
        a_inv = mod_inv(a, 26)
        if a_inv is None:
            return text
        result = []
        for ch in text:
            if ch.isascii() and ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((a_inv * (ord(ch) - base - b)) % 26 + base))
            else:
                result.append(ch)
        return ''.join(result)
    except Exception:
        return text

def decode_bacon(text: str) -> Optional[str]:
    try:
        clean = text.upper().replace(' ','').replace('/','')
        if all(c in 'AB' for c in clean) and len(clean) % 5 == 0:
            chars = []
            for i in range(0, len(clean), 5):
                val = int(clean[i:i+5].replace('A','0').replace('B','1'), 2)
                if 0 <= val <= 25:
                    chars.append(chr(val + ord('A')))
            return ''.join(chars) if chars else None
        if all(c in '01' for c in clean) and len(clean) % 5 == 0:
            chars = []
            for i in range(0, len(clean), 5):
                val = int(clean[i:i+5], 2)
                if 0 <= val <= 25:
                    chars.append(chr(val + ord('A')))
            return ''.join(chars) if chars else None
        return None
    except Exception:
        return None

def decode_rail_fence(text: str, rails: int) -> str:
    try:
        n = len(text)
        pattern = []
        rail = 0
        direction = 1
        for _ in range(n):
            pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        indices = sorted(range(n), key=lambda i: pattern[i])
        result = [''] * n
        for i, idx in enumerate(indices):
            result[idx] = text[i]
        return ''.join(result)
    except Exception:
        return text

from collections import Counter as _Ctr
import re as _re3

def _binaryish(text):
    s=[c for c in text if not c.isspace()]
    if len(s)<10: return False
    t=_Ctr(s).most_common(2)
    return len(t)>=2 and (t[0][1]+t[1][1])/len(s)>=0.80

def _bin_streams(text):
    out=[]
    seen=set()
    s=[c for c in text if not c.isspace()]
    if len(s)<10: return out
    top=[c for c,_ in _Ctr(s).most_common(8)]
    for i in range(len(top)):
        for j in range(i+1,len(top)):
            a,b=top[i],top[j]
            f=[c for c in text if c==a or c==b]
            if len(f)<10: continue
            ab=''.join('A' if c==a else 'B' for c in f)
            if ab not in seen: seen.add(ab); out.append(('ch',ab))
    ab_=[c.upper() for c in text if c.upper() in {'A','B'}]
    if len(ab_)>=10:
        ab=''.join(ab_)
        if ab not in seen: seen.add(ab); out.append(('AB',ab))
    bi=[c for c in text if c in {'0','1'}]
    if len(bi)>=10:
        for lbl,fn in[('01',''.join('A' if c=='0' else 'B' for c in bi)),
                      ('10',''.join('A' if c=='1' else 'B' for c in bi))]:
            if fn not in seen: seen.add(fn); out.append((lbl,fn))
    lt=[c for c in text if c.isalpha()]
    if len(lt)>=10:
        if any(c.islower() for c in lt) and any(c.isupper() for c in lt):
            for lbl,fn in[('lA',''.join('A' if c.islower() else 'B' for c in lt)),
                          ('uA',''.join('A' if c.isupper() else 'B' for c in lt))]:
                if fn not in seen: seen.add(fn); out.append((lbl,fn))
        vw=set('AEIOUYaeiouy')
        fn=''.join('A' if c in vw else 'B' for c in lt)
        if fn not in seen: seen.add(fn); out.append(('vow',fn))
    dg=_re3.findall('..',  ''.join(s))
    if len(dg)>=10:
        td=[d for d,_ in _Ctr(dg).most_common(6)]
        for i in range(len(td)):
            for j in range(i+1,len(td)):
                d1,d2=td[i],td[j]
                f=[d for d in dg if d==d1 or d==d2]
                if len(f)<10: continue
                fn=''.join('A' if d==d1 else 'B' for d in f)
                if fn not in seen: seen.add(fn); out.append(('dg',fn))
    return out

_B26={}
_B24={}
for _i,_c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    _k=format(_i,'05b').replace('0','A').replace('1','B')
    _B26[_k]=_c
for _i,_c in enumerate(['A','B','C','D','E','F','G','H','I','K','L','M','N','O','P','Q','R','S','T','U','W','X','Y','Z']):
    _k=format(_i,'05b').replace('0','A').replace('1','B')
    _B24[_k]=_c

def _dbst(ab,tbl):
    return ''.join(tbl.get(ab[i:i+5],'?') for i in range(0,len(ab)-4,5))

def decode_bacon_robust(text, wordlist=None):
    res=[]
    for sdesc,ab in _bin_streams(text):
        for off in range(5):
            tr=ab[off:]
            ul=(len(tr)//5)*5
            if ul<10: continue
            u=tr[:ul]
            sw=u.translate(str.maketrans('AB','BA'))
            cr=''.join(u[i:i+5][::-1] for i in range(0,ul,5))
            scr=''.join(sw[i:i+5][::-1] for i in range(0,ul,5))
            for vn,vs in[('n',u),('s',sw),('cr',cr),('scr',scr)]:
                for tn,tbl in[('b26',_B26),('b24',_B24)]:
                    d=_dbst(vs,tbl)
                    if d.count('?')>len(d)*0.3: continue
                    if not any(c.isalpha() for c in d): continue
                    sc=0.0
                    dl=d.lower()
                    if wordlist:
                        sc+=sum(3 for w in wordlist if len(w)>3 and w in dl)
                    sc+=sum(1 for c in d if c.isalpha())*0.5
                    sc-=d.count('?')*3
                    if ul%5==0: sc+=1.5
                    if _binaryish(text): sc+=2.5
                    if '?' not in d: sc+=2.0
                    if sc>0:
                        res.append((sc,'Bacon(%s o=%d %s %s)'%(tn,off,vn,sdesc),d))
    res.sort(reverse=True)
    seen=set(); out=[]
    for s,desc,t in res:
        if t not in seen: seen.add(t); out.append((s,desc,t))
    return out[:8]

def decode_railfence_then_bacon(text, wordlist=None):
    res=[]
    for rails in range(2,11):
        rf=decode_rail_fence(text,rails)
        for bs,bd,bt in decode_bacon_robust(rf,wordlist):
            for sh in range(26):
                sh2=rot_n(bt,sh)
                sc=bs+(sum(3 for w in (wordlist or []) if len(w)>3 and w in sh2.lower()) if wordlist else 0)
                if sc>bs+3:
                    res.append((sc,'rf(%d)->%s->rot%d'%(rails,bd,sh),sh2))
            res.append((bs,'rf(%d)->%s'%(rails,bd),bt))
    res.sort(reverse=True)
    seen=set(); out=[]
    for s,c,t in res:
        if t not in seen: seen.add(t); out.append((s,c,t))
    return out[:10]

def decode_polybius(data: str) -> Optional[str]:
    try:
        text = data.strip()
        if not all(c in '12345 ' for c in text):
            return None
        GRID = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        parts = text.replace(' ','')
        if len(parts) % 2 != 0:
            return None
        result = []
        for i in range(0, len(parts), 2):
            row = int(parts[i]) - 1
            col = int(parts[i+1]) - 1
            idx = row * 5 + col
            if 0 <= idx < len(GRID):
                result.append(GRID[idx])
            else:
                return None
        return ''.join(result)
    except Exception:
        return None

def decode_tap_code(data: str) -> Optional[str]:
    try:
        parts = data.strip().split()
        if len(parts) % 2 != 0:
            return None
        GRID = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        result = []
        for i in range(0, len(parts), 2):
            row = int(parts[i]) - 1
            col = int(parts[i+1]) - 1
            idx = row * 5 + col
            if 0 <= idx < len(GRID):
                result.append(GRID[idx])
            else:
                return None
        return ''.join(result)
    except Exception:
        return None

def decode_nato(data: str) -> Optional[str]:
    NATO = {
        'ALPHA':'A','BRAVO':'B','CHARLIE':'C','DELTA':'D','ECHO':'E',
        'FOXTROT':'F','GOLF':'G','HOTEL':'H','INDIA':'I','JULIET':'J',
        'KILO':'K','LIMA':'L','MIKE':'M','NOVEMBER':'N','OSCAR':'O',
        'PAPA':'P','QUEBEC':'Q','ROMEO':'R','SIERRA':'S','TANGO':'T',
        'UNIFORM':'U','VICTOR':'V','WHISKEY':'W','XRAY':'X','YANKEE':'Y',
        'ZULU':'Z',
    }
    try:
        words = data.strip().upper().split()
        if not words or not all(w in NATO for w in words):
            return None
        return ''.join(NATO[w] for w in words)
    except Exception:
        return None

def decode_leetspeak(data: str) -> str:
    LEET = {'0':'o','1':'i','3':'e','4':'a','5':'s','6':'g','7':'t','@':'a','$':'s','!':'i'}
    return ''.join(LEET.get(c, c) for c in data)

def decode_quoted_printable(data: str) -> Optional[bytes]:
    try:
        result = quopri.decodestring(data.encode())
        return result if result != data.encode() else None
    except Exception:
        return None

def decode_uuencode(data: str) -> Optional[bytes]:
    try:
        lines = data.strip().split('\n')
        if not lines[0].startswith('begin'):
            return None
        out = bytearray()
        for line in lines[1:]:
            line = line.rstrip()
            if not line or line == 'end':
                break
            n = (ord(line[0]) - 32) & 63
            if n == 0:
                break
            enc = line[1:]
            while len(enc) % 4:
                enc += '`'
            for i in range(0, len(enc), 4):
                c = [((ord(enc[i+j]) - 32) & 63) for j in range(4)]
                out += bytes([(c[0]<<2)|(c[1]>>4), ((c[1]&0xf)<<4)|(c[2]>>2), ((c[2]&3)<<6)|c[3]])
            out = out[:-(len(out) - (len(out) // n * n)) or len(out)]
        return bytes(out) if out else None
    except Exception:
        return None

def is_mostly_printable(text: str, threshold: float = 0.85) -> bool:
    if not text:
        return False
    return sum(1 for c in text if c in string.printable) / len(text) >= threshold

def is_mostly_words(text: str, wordlist: set, threshold: float = 0.35) -> bool:
    if not text or not wordlist:
        return False
    tokens = text.lower().split()
    if not tokens:
        return False
    matches = sum(1 for t in tokens if t.strip(string.punctuation) in wordlist)
    return (matches / len(tokens)) >= threshold

def safe_decode_bytes(data: bytes) -> str:
    for enc in ('utf-8', 'latin-1', 'ascii', 'cp1252'):
        try:
            return data.decode(enc)
        except Exception:
            pass
    return data.decode('latin-1', errors='replace')

def bytes_to_hex_display(data: bytes, max_bytes: int = 64) -> str:
    snippet = data[:max_bytes]
    hex_str = ' '.join(f'{b:02X}' for b in snippet)
    if len(data) > max_bytes:
        hex_str += f' ... ({len(data)} bytes total)'
    return hex_str

def _trifid_ic(text):
    text = ''.join(c.lower() for c in text if c.isalpha())
    n = len(text)
    if n < 2: return 0.0
    freq = {}
    for c in text: freq[c] = freq.get(c,0) + 1
    return sum(f*(f-1) for f in freq.values()) / (n*(n-1))

def detect_trifid(text):
    alpha = ''.join(c for c in text.upper() if c.isalpha())
    if len(alpha) < 10: return None
    ic = _trifid_ic(alpha)
    if not (0.038 <= ic <= 0.058): return None
    if alpha.count("J") / len(alpha) > 0.02: return None
    periods = [p for p in range(2,11) if len(alpha) % p == 0] or list(range(2,9))
    return f"possible Trifid cipher  ic={ic:.4f}  candidate periods={periods}  key required"

def _hill_decrypt_2x2(alpha, mat):
    a,b,c,d = mat
    det = (a*d - b*c) % 26
    det_inv = next((i for i in range(1,26) if (det*i)%26==1), None)
    if det_inv is None: return None
    ia,ib,ic_,id_ = (det_inv*d)%26,(det_inv*(-b))%26,(det_inv*(-c))%26,(det_inv*a)%26
    if len(alpha) % 2: alpha += "X"
    res = []
    for i in range(0,len(alpha),2):
        x,y = ord(alpha[i])-65, ord(alpha[i+1])-65
        res += [chr((ia*x+ib*y)%26+65), chr((ic_*x+id_*y)%26+65)]
    return "".join(res)

def brute_hill_2x2(text, wordlist):
    alpha = "".join(ch for ch in text.upper() if ch.isalpha())
    if not (4 <= len(alpha) <= 200): return []
    best = []
    for a in range(26):
        for b in range(26):
            for c in range(26):
                for d in range(26):
                    det = (a*d-b*c)%26
                    if det==0 or det%2==0 or det%13==0: continue
                    plain = _hill_decrypt_2x2(alpha,(a,b,c,d))
                    if not plain: continue
                    score = sum(1 for w in wordlist if w in plain.lower() and len(w)>3)
                    if score > 0: best.append((score,f"[[{a},{b}],[{c},{d}]]",plain))
    best.sort(reverse=True)
    return best[:5]

_PORTA_HALF = [
    "nopqrstuvwxyzabcdefghijklm",
    "noqprstuvwxyzabcdefghijklm",
    "norpqstuvwxyzabcdefghijklm",
    "norsqptuvwxyzabcdefghijklm",
    "norstpquvwxyzabcdefghijklm",
    "norstupqvwxyzabcdefghijklm",
    "norstuvpqwxyzabcdefghijklm",
    "norstuvwpqxyzabcdefghijklm",
    "norstuvwxpqyzabcdefghijklm",
    "norstuvwxyqpzabcdefghijklm",
    "norstuvwxyzpqabcdefghijklm",
    "norstuvwxyzaqpbcdefghijklm",
    "norstuvwxyzabqpcdefghijklm",
]

def _porta_decrypt(ct, key):
    res = []
    ki = 0
    for ch in ct.lower():
        if ch.isalpha():
            row = min((ord(key[ki%len(key)])-97)//2, 12)
            t = _PORTA_HALF[row]
            res.append("abcdefghijklmnopqrstuvwxyz"[t.index(ch)] if ch in t else ch)
            ki += 1
        else:
            res.append(ch)
    return "".join(res)

def brute_porta(text, wordlist):
    if not any(c.isalpha() for c in text): return []
    results = []
    for k in "abcdefghijklm":
        plain = _porta_decrypt(text, k)
        score = sum(1 for w in wordlist if w in plain and len(w)>3)
        if score > 0: results.append((score, f"key={k.upper()}", plain))
    for key in list(wordlist)[:500]:
        if 3 <= len(key) <= 10:
            plain = _porta_decrypt(text, key)
            score = sum(1 for w in wordlist if w in plain and len(w)>3)
            if score > 1: results.append((score, f"key={key}", plain))
    results.sort(reverse=True)
    return results[:5]

def _nihilist_square(kw):
    kw = kw.lower().replace("j","i")
    seen = []
    for c in kw:
        if c.isalpha() and c not in seen: seen.append(c)
    for c in "abcdefghiklmnopqrstuvwxyz":
        if c not in seen: seen.append(c)
    return {c: (i//5+1)*10+(i%5+1) for i,c in enumerate(seen)}

def decode_nihilist(ct, keyword):
    tokens = ct.strip().split()
    if not tokens: return None
    try: nums = [int(x) for x in tokens]
    except: return None
    sq = _nihilist_square(keyword)
    inv = {v:k for k,v in sq.items()}
    key_nums = [sq[c] for c in keyword.lower() if c.isalpha() and c != "j"]
    if not key_nums: return None
    res = []
    for i,n in enumerate(nums):
        res.append(inv.get(n - key_nums[i%len(key_nums)], "?"))
    return "".join(res)

def brute_nihilist(ct, wordlist):
    tokens = ct.strip().split()
    if len(tokens) < 3: return []
    try:
        if not all(re.match(r"^\d{2,4}$", t) for t in tokens): return []
    except: return []
    results = []
    for kw in list(wordlist)[:2000]:
        if 3 <= len(kw) <= 12:
            plain = decode_nihilist(ct, kw)
            if plain and "?" not in plain:
                score = sum(1 for w in wordlist if w in plain and len(w)>3)
                if score > 0: results.append((score, f"keyword={kw}", plain))
    results.sort(reverse=True)
    return results[:5]

def decode_adfgx(ct, polybius_key, trans_key, variant="ADFGVX"):
    chars = "ADFGVX" if variant=="ADFGVX" else "ADFGX"
    size = len(chars)
    ct = ct.upper().replace(" ","")
    if not all(c in chars for c in ct) or len(ct)%2: return None
    key = trans_key.upper()
    ncols = len(key)
    nrows = len(ct)//ncols
    if nrows*ncols != len(ct): return None
    order = sorted(range(ncols), key=lambda i: key[i])
    cols = [""]*ncols
    pos = 0
    for col_idx in order:
        cols[col_idx] = ct[pos:pos+nrows]; pos += nrows
    frac = "".join(cols[col][row] for row in range(nrows) for col in range(ncols))
    pk = polybius_key.upper()
    if len(pk) < size*size: return None
    res = []
    for i in range(0,len(frac),2):
        r,c = chars.index(frac[i]), chars.index(frac[i+1])
        idx = r*size+c
        res.append(pk[idx].lower() if idx < len(pk) else "?")
    return "".join(res)

def brute_adfgvx(ct, wordlist):
    chars = "ADFGVX"
    c2 = ct.upper().replace(" ","")
    if not all(c in chars for c in c2) or len(c2)<6: return []
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    results = []
    for tk in list(wordlist)[:1000]:
        if 3 <= len(tk) <= 10 and len(c2)%len(tk)==0:
            plain = decode_adfgx(c2, std, tk, "ADFGVX")
            if plain and "?" not in plain:
                score = sum(1 for w in wordlist if w in plain and len(w)>3)
                if score > 0: results.append((score, f"trans_key={tk}", plain))
    results.sort(reverse=True)
    return results[:5]

_ENIGMA_ROTORS = {
    "I":   ("EKMFLGDQVZNTOWYHXUSPAIBRCJ","Q"),
    "II":  ("AJDKSIRUXBLHWTMCQGZNPYFVOE","E"),
    "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO","V"),
    "IV":  ("ESOVPZJAYQUIRHXLNFTGKDCMWB","J"),
    "V":   ("VZBRGITYUPSDNHLXAWMJQOFECK","Z"),
    "VI":  ("JPGVOUMFYQBENHZRDKASXLICTW","ZM"),
    "VII": ("NZJHGRCXMYSWBOUFAIVLPEKQDT","ZM"),
    "VIII":("FKQHTLXOCBJSPDZRAMEWNIUYGV","ZM"),
}
_ENIGMA_REFLECTORS = {
    "A":"EJMZALYXVBWFCRQUONTSPIKHGD",
    "B":"YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C":"FVPJIAOYEDRZXWGCTKUQSBNMHL",
}

def decode_enigma(text, rotors, reflector, positions, rings, plugboard_str=""):
    pb = {}
    for pair in plugboard_str.upper().split():
        if len(pair)==2: pb[pair[0]]=pair[1]; pb[pair[1]]=pair[0]
    pos = list(positions)
    r_data = [_ENIGMA_ROTORS[rid] for rid in rotors]
    result = []
    for ch in text.upper():
        if not ch.isalpha():
            result.append(ch); continue
        notches = [r_data[i][1] for i in range(len(rotors))]
        if len(pos)>=3 and chr(pos[1]+65) in notches[1]:
            pos[0]=(pos[0]+1)%26; pos[1]=(pos[1]+1)%26
        elif len(pos)>=3 and chr(pos[2]+65) in notches[2]:
            pos[1]=(pos[1]+1)%26
        pos[-1]=(pos[-1]+1)%26
        c = pb.get(ch, ch)
        idx = ord(c)-65
        for i in range(len(rotors)-1,-1,-1):
            w = r_data[i][0]; off=(pos[i]-rings[i])%26
            idx = (ord(w[(idx+off)%26])-65-off)%26
        ref = _ENIGMA_REFLECTORS.get(reflector,"B" if reflector not in _ENIGMA_REFLECTORS else reflector)
        ref_w = _ENIGMA_REFLECTORS.get(ref, _ENIGMA_REFLECTORS["B"]) if len(ref)==1 else _ENIGMA_REFLECTORS["B"]
        idx = ord(ref_w[idx])-65
        for i in range(len(rotors)):
            w = r_data[i][0]; off=(pos[i]-rings[i])%26
            idx = (w.index(chr((idx+off)%26+65))-off)%26
        c = chr(idx+65)
        result.append(pb.get(c,c))
    return "".join(result)

def brute_enigma_positions(text, rotor_ids, reflector, rings, plugboard_str, wordlist,
                            verbose=True):
    from itertools import product as ip
    import sys, time
    alpha = "".join(c for c in text.upper() if c.isalpha())
    if len(alpha) < 6: return []
    total = 26 ** len(rotor_ids)
    results = []
    t0 = time.time()
    for n, pos in enumerate(ip(range(26), repeat=len(rotor_ids))):
        plain = decode_enigma(alpha, rotor_ids, reflector, list(pos), rings, plugboard_str)
        score = sum(1 for w in wordlist if w in plain.lower() and len(w)>3)
        if score > 1:
            results.append((score, "rotors=%s ref=%s pos=%s" % (rotor_ids, reflector, "".join(chr(p+65) for p in pos)), plain))
        if verbose and n % 500 == 0:
            elapsed = time.time() - t0
            rate = (n+1) / elapsed if elapsed > 0 else 1
            remaining = (total - n) / rate
            pos_str = "".join(chr(p+65) for p in pos)
            bar_done = int(30 * n / total)
            bar = "#" * bar_done + "-" * (30 - bar_done)
            sys.stderr.write(
                "\r  [%s] %d/%d  pos=%-3s  hits=%-3d  ~%ds remaining    " % (
                bar, n, total, pos_str, len(results), int(remaining))
            )
            sys.stderr.flush()
    if verbose:
        sys.stderr.write("\r  [" + "#"*30 + "] %d/%d  done                              \n" % (total,total))
        sys.stderr.flush()
    results.sort(reverse=True)
    return results[:5]

def brute_enigma_rotors(text, wordlist, reflectors=None):
    from itertools import permutations, product as ip
    alpha = "".join(c for c in text.upper() if c.isalpha())
    if not (8 <= len(alpha) <= 100): return []
    if reflectors is None: reflectors = ["B"]
    results = []
    for ref in reflectors:
        for rcombo in permutations(["I","II","III","IV","V"],3):
            for pos in ip(range(26),repeat=3):
                plain = decode_enigma(alpha,list(rcombo),ref,list(pos),[0,0,0],"")
                score = sum(1 for w in wordlist if w in plain.lower() and len(w)>3)
                if score > 2:
                    results.append((score,f"rotors={list(rcombo)} ref={ref} pos={''.join(chr(p+65) for p in pos)}",plain))
                    if len(results)>20: results.sort(reverse=True); results=results[:10]
    results.sort(reverse=True)
    return results[:5]

def decode_a1z26(text):
    tokens = re.split(r"[\s,.\-]+", text.strip())
    if not tokens: return None
    result = []
    for t in tokens:
        if not t: continue
        try:
            n = int(t)
            if not (1 <= n <= 26): return None
            result.append(chr(n + 64))
        except ValueError: return None
    return "".join(result) if result else None

def _build_polybius_sq(keyword):
    keyword = keyword.upper().replace("J","I")
    seen = []
    for c in keyword:
        if c.isalpha() and c not in seen: seen.append(c)
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in seen: seen.append(c)
    return [seen[i*5:(i+1)*5] for i in range(5)]

def _polybius_coords(square):
    coords = {}
    for r,row in enumerate(square):
        for c,ch in enumerate(row): coords[ch] = (r,c)
    return coords

def decode_bifid(text, keyword, period=0):
    ct = "".join(c.upper() for c in text if c.isalpha()).replace("J","I")
    if not ct: return None
    sq = _build_polybius_sq(keyword)
    coords = _polybius_coords(sq)
    inv = {v:k for k,v in coords.items()}
    def decode_block(block):
        rows = [coords[c][0] for c in block]
        cols = [coords[c][1] for c in block]
        combined = rows + cols
        pairs = [(combined[i], combined[len(block)+i]) for i in range(len(block))]
        return "".join(inv.get(p,"?") for p in pairs)
    if period == 0: return decode_block(ct)
    result = ""
    for i in range(0, len(ct), period): result += decode_block(ct[i:i+period])
    return result

def brute_bifid(text, wordlist):
    ct = "".join(c.upper() for c in text if c.isalpha())
    if len(ct) < 6: return []
    results = []
    for kw in list(wordlist)[:1000]:
        if 3 <= len(kw) <= 15:
            for period in [0, 5, 6, 7, 8, 10]:
                plain = decode_bifid(ct, kw, period)
                if plain and "?" not in plain:
                    score = sum(1 for w in wordlist if w in plain.lower() and len(w)>3)
                    if score > 0: results.append((score, "key=%s period=%d" % (kw,period), plain))
    results.sort(reverse=True)
    return results[:5]

_BAUDOT_LTRS = [None,"E","\n","A"," ","S","I","U","\r","D","R","J","N","F","C","K","T","Z","L","W","H","Y","P","Q","O","B","G","F-SHIFT","M","X","V","LTRS"]
_BAUDOT_FIGS = [None,"3","\n","-"," ","'","8","7","\r","ENQ","4","\a",",","!",":",  "(", "+","\"",")","2","#","6","0","1","9","?","&","E-SHIFT",".","/"," ","FIGS"]

def decode_baudot(data):
    data = data.strip()
    tokens = data.split()
    codes = []
    try:
        if all(re.match(r"^[01]{5}$", t) for t in tokens):
            codes = [int(t,2) for t in tokens]
        elif all(re.match(r"^\d+$", t) for t in tokens):
            codes = [int(t) for t in tokens]
        else: return None
    except: return None
    if not codes: return None
    result = []
    fig_mode = False
    for code in codes:
        if code == 31: fig_mode = False; continue
        if code == 27: fig_mode = True; continue
        table = _BAUDOT_FIGS if fig_mode else _BAUDOT_LTRS
        if code < len(table) and table[code]:
            c = table[code]
            if c not in ("LTRS","FIGS","E-SHIFT","F-SHIFT"): result.append(c)
    text = "".join(result)
    return text if len(text) > 1 else None

def decode_punycode(data):
    try:
        data = data.strip()
        if "xn--" in data.lower():
            parts = data.lower().split(".")
            decoded = []
            for part in parts:
                if part.startswith("xn--"): decoded.append(part[4:].encode("ascii").decode("punycode"))
                else: decoded.append(part)
            result = ".".join(decoded)
            return result if result != data else None
        result = data.encode("ascii").decode("punycode")
        if result != data and any(ord(c) > 127 for c in result): return result
        return None
    except: return None

_HASH_SIGS = [
    (32,"hex","MD5 / NTLM"),
    (40,"hex","SHA-1"),
    (56,"hex","SHA-224"),
    (64,"hex","SHA-256 / Keccak-256"),
    (96,"hex","SHA-384"),
    (128,"hex","SHA-512"),
    (8,"hex","CRC-32 / Adler-32"),
    (16,"hex","CRC-64"),
    (32,"b64","MD5 (base64)"),
    (44,"b64","SHA-256 (base64)"),
]
_BCRYPT = ("$2a$","$2b$","$2y$")
_UNIX_HASH = {"$1$":"MD5-crypt","$5$":"SHA-256-crypt","$6$":"SHA-512-crypt"}

def identify_hash(data):
    data = data.strip()
    if not data: return None
    if any(data.startswith(p) for p in _BCRYPT) and len(data)==60:
        return "bcrypt hash"
    for prefix,name in _UNIX_HASH.items():
        if data.startswith(prefix): return name + " hash"
    is_hex = bool(re.match(r"^[0-9a-fA-F]+$", data))
    is_b64 = bool(re.match(r"^[A-Za-z0-9+/]+=*$", data))
    for length,enc,name in _HASH_SIGS:
        if enc=="hex" and is_hex and len(data)==length:
            return "possible %s hash (%d hex chars)" % (name, length)
        if enc=="b64" and is_b64 and len(data)==length:
            return "possible %s (%d base64 chars)" % (name, length)
    lines = [l.strip() for l in data.splitlines() if l.strip()]
    if len(lines) > 1:
        types = set()
        for line in lines[:5]:
            t = identify_hash(line)
            if t: types.add(t)
        if types:
            joined = ", ".join(types)
            return "hash list detected: " + joined
    return None

def decode_rc4(data, key):
    if isinstance(key, str): key = key.encode()
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = []
    for byte in data:
        i = (i+1) % 256
        j = (j+S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i]+S[j])%256])
    return bytes(result)

def brute_rc4(data, wordlist):
    if isinstance(data, str): data = data.encode()
    if len(data) < 4: return []
    results = []
    for key in list(wordlist)[:5000]:
        if 3 <= len(key) <= 16:
            try:
                plain = decode_rc4(data, key.encode())
                text = plain.decode("utf-8", errors="ignore")
                score = sum(1 for w in wordlist if w in text.lower() and len(w)>3)
                if score > 1: results.append((score, "key=%s" % key, text[:200]))
            except: pass
    results.sort(reverse=True)
    return results[:5]

def detect_enigma(text):
    alpha = "".join(c.upper() for c in text if c.isalpha())
    if len(alpha) < 20: return None

    freq = {}
    for c in alpha: freq[c] = freq.get(c,0) + 1
    n = len(alpha)
    ic = sum(f*(f-1) for f in freq.values()) / (n*(n-1)) if n > 1 else 0
    if not (0.035 <= ic <= 0.050): return None

    max_freq = max(freq.values()) / n
    if max_freq > 0.12: return None

    if n < 20: return None

    return ("possible Enigma ciphertext  ic=%.4f  "
            "no letter encodes to itself  "
            "use --enigma to brute-force positions or provide settings" % ic)

def classify_encryption(data):
    import re, math
    if isinstance(data, str):
        raw = data.strip()
        raw_b = raw.encode("latin-1", errors="ignore")
    else:
        raw = data.decode("latin-1", errors="ignore").strip()
        raw_b = data
    if "-----BEGIN PGP" in raw:
        if "PRIVATE KEY" in raw: return "PGP private key block"
        if "PUBLIC KEY"  in raw: return "PGP public key block"
        if "MESSAGE"     in raw: return "PGP encrypted message"
        if "SIGNATURE"   in raw: return "PGP signature block"
        return "PGP/GPG block"
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in raw: return "OpenSSH private key"
    if "-----BEGIN RSA PRIVATE KEY-----" in raw: return "RSA private key (PEM)"
    if "-----BEGIN EC PRIVATE KEY-----" in raw: return "EC private key (PEM)"
    if "-----BEGIN CERTIFICATE-----" in raw: return "X.509 certificate (PEM)"
    if raw.startswith("ssh-rsa ") or raw.startswith("ssh-ed25519 "): return "SSH public key"
    jwt_parts = raw.split(".")
    if len(jwt_parts) == 3:
        b64url = re.compile(r"^[A-Za-z0-9_\-]+=*$")
        if all(b64url.match(p) for p in jwt_parts) and len(jwt_parts[0]) > 10:
            try:
                import base64 as _b64
                hdr = _b64.urlsafe_b64decode(jwt_parts[0] + "==").decode("utf-8", errors="ignore")
                hdr_c = hdr.replace(chr(10)," ")
                if "alg" in hdr or "typ" in hdr:
                    return "JWT token - header: %s" % hdr_c[:80]
            except Exception: pass
            return "possible JWT token (3-part base64url)"
    if raw_b[:8] == b"Salted__":
        return "OpenSSL salted encrypted data (AES-CBC likely) - salt: %s" % raw_b[8:16].hex()
    if raw.startswith("pbkdf2_sha"):    return "Django PBKDF2 password hash"
    if raw.startswith("argon2"):        return "Argon2 password hash"
    if raw.startswith("$S$"):           return "Drupal SHA-512 password hash"
    if raw.startswith("$P$") or raw.startswith("$H$"): return "WordPress/phpBB MD5 password hash"
    if raw.startswith("$apr1$"):        return "Apache MD5 password hash"
    if raw.startswith("sha1$"):         return "Django SHA1 password hash (legacy)"
    if re.match(r"^\*[0-9A-F]{40}$", raw.upper()): return "MySQL password hash"
    n = len(raw_b)
    if n < 8: return None
    freq = [0] * 256
    for b in raw_b: freq[b] += 1
    entropy = -sum((f/n) * math.log2(f/n) for f in freq if f > 0)
    if n < 16:   _eth = 3.5
    elif n < 32: _eth = 4.5
    elif n < 64: _eth = 5.2
    elif n < 128: _eth = 5.8
    elif n < 256: _eth = 6.5
    elif n < 512: _eth = 7.0
    else:         _eth = 7.4
    _high = entropy >= _eth

    if n in (128, 256, 384, 512) and _high:
        return "RSA-%d ciphertext possible - %d bytes entropy=%.2f" % (n*8, n, entropy)

    if n >= 32 and n % 16 == 0:
        blocks = [raw_b[i:i+16] for i in range(0, n, 16)]
        if len(blocks) != len(set(blocks)):
            return "AES-ECB ciphertext likely - %d bytes, repeating block detected (ECB mode)" % n
        if _high:
            return "AES-CBC/ECB ciphertext likely - %d bytes (%d blocks) entropy=%.2f" % (n, len(blocks), entropy)

    if n >= 8 and n % 8 == 0 and n % 16 != 0 and _high:
        return "DES/3DES ciphertext possible - %d bytes entropy=%.2f" % (n, entropy)

    if _high and n > 16 and n % 16 != 0 and n % 8 != 0:
        return "stream cipher possible (ChaCha20/RC4/Salsa20) - %d bytes entropy=%.2f" % (n, entropy)

    if _high and n >= 16:
        return "high entropy data - %d bytes entropy=%.2f - possibly encrypted or compressed" % (n, entropy)
    return None

def _atbash(text):
    out = []
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr(base+25-(ord(c)-base)))
        else:
            out.append(c)
    return "".join(out)

def _rev(text):
    return text[::-1]

def brute_chained_ciphers(text, wordlist, min_score=2):
    results = []
    seen = set()

    def _add(score, chain, plain):
        if score >= min_score and plain not in seen:
            seen.add(plain)
            results.append((score, chain, plain))

    rev = _rev(text)

    for n in range(26):
        p = _rot(rev, n)
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "reverse -> ROT%d" % n, p)

    p = _atbash(rev)
    s = _score_text(p, wordlist)
    if s >= min_score:
        _add(s, "reverse -> Atbash", p)

    p_ab = _atbash(rev)
    for n in range(26):
        p = _rot(p_ab, n)
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "reverse -> Atbash -> ROT%d" % n, p)

    p = _rev(_atbash(text))
    s = _score_text(p, wordlist)
    if s >= min_score:
        _add(s, "Atbash -> reverse", p)

    p_ab = _atbash(text)
    for n in range(26):
        p = _rot(p_ab, n)
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "Atbash -> ROT%d" % n, p)

    for n in range(26):
        p = _rev(_rot(_atbash(text), n))
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "Atbash -> ROT%d -> reverse" % n, p)

    for n in range(26):
        p = _atbash(_rot(text, n))
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "ROT%d -> Atbash" % n, p)

    for n in range(26):
        p = _rev(_atbash(_rot(text, n)))
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "ROT%d -> Atbash -> reverse" % n, p)

    for n in range(26):
        r = _rev(_rot(text, n))
        for m in range(26):
            p = _rot(r, m)
            s = _score_text(p, wordlist)
            if s >= min_score:
                _add(s, "ROT%d -> reverse -> ROT%d" % (n,m), p)

    results.sort(reverse=True)
    return results[:8]

_CW = {
    "the","be","to","of","and","a","in","that","have","it","for","not","on",
    "with","he","as","do","at","this","but","his","by","from","they","we",
    "say","her","she","or","an","will","one","all","would","there","their",
    "what","so","up","out","if","about","who","get","which","go","when",
    "make","can","like","time","no","just","him","know","take","people",
    "into","year","good","some","could","them","see","other","than","then",
    "now","look","only","come","its","over","think","also","you","your",
    "are","was","were","has","had","been","did","does","is","we","us",
}

_TG = {
    "TION":-1.0,"THER":-1.1,"WITH":-1.2,"HERE":-1.3,"IGHT":-1.4,
    "THAT":-1.5,"MENT":-1.6,"IONS":-1.8,"ATIO":-1.9,"OULD":-2.0,
    "FROM":-2.1,"THEM":-2.2,"THIS":-2.3,"TING":-2.4,"HAVE":-2.5,
    "EVER":-2.6,"NTER":-2.8,"ENCE":-2.9,"OUGH":-3.0,"WERE":-3.1,
    "EACH":-3.2,"WHEN":-3.3,"YOUR":-3.4,"COME":-3.5,"BEEN":-3.9,
    "INTO":-4.1,"TIME":-4.2,"SOME":-4.3,"THAN":-4.4,"ONLY":-4.5,
}
_TGF = -8.5

_EF = {
    "a":8.2,"b":1.5,"c":2.8,"d":4.3,"e":12.7,"f":2.2,"g":2.0,"h":6.1,
    "i":7.0,"j":0.15,"k":0.77,"l":4.0,"m":2.4,"n":6.7,"o":7.5,"p":1.9,
    "q":0.1,"r":6.0,"s":6.3,"t":9.1,"u":2.8,"v":0.98,"w":2.4,"x":0.15,
    "y":2.0,"z":0.07,
}

def _tetragram_score(text):
    letters = re.sub(r'[^A-Za-z]', '', text.upper())
    if len(letters) < 4: return 0.0
    total = sum(_TG.get(letters[i:i+4], _TGF) for i in range(len(letters)-3))
    return total / max(len(letters)-3, 1)

def _repeat_token_signal(tl):
    from collections import Counter
    tokens = re.findall(r"[a-z']+", tl)
    if len(tokens) < 6: return 0.0
    counts = collections.Counter(tokens)
    score = 0.0
    single = [t for t in tokens if len(t)==1]
    if 1 <= len(set(single)) <= 2 and single: score += 4.0
    score += min(sum(3.0 for t,c in counts.items() if len(t)<=3 and c>=3), 12.0)
    return score

_FAST_TRANSFORMS = (
    ['reverse', 'atbash'] +
    [f'rot{n}' for n in range(1,26)] +
    ['base64', 'base64url', 'base32', 'hex', 'url', 'html', 'binary', 'a1z26', 'morse',
     'bacon_ab', 'bacon_01', 'polybius', 'railfence2', 'railfence3', 'railfence4',
     'scytale2', 'scytale3', 'leet_speak_decode', 'decimal_bytes']
)

_BEAM_RISKY_TRANSFORMS = {'reverse', 'atbash'}
_BEAM_DECODE_TRANSFORMS = {'base64','base64url','base32','hex','url','html','binary','a1z26','morse',
                           'bacon_ab','bacon_01','polybius','railfence2','railfence3','railfence4',
                           'scytale2','scytale3','leet_speak_decode','decimal_bytes'}

FILE_SIGNATURES = [
    (b'\xFF\xD8\xFF',           0,  'jpg',    'JPEG Image'),
    (b'\x89PNG\r\n\x1a\n',     0,  'png',    'PNG Image'),
    (b'GIF87a',                 0,  'gif',    'GIF Image (87a)'),
    (b'GIF89a',                 0,  'gif',    'GIF Image (89a)'),
    (b'BM',                     0,  'bmp',    'BMP Image'),
    (b'II*\x00',                0,  'tif',    'TIFF (little-endian)'),
    (b'MM\x00*',                0,  'tif',    'TIFF (big-endian)'),
    (b'RIFF',                   0,  'riff',   'RIFF Container'),
    (b'\x00\x00\x01\x00',      0,  'ico',    'ICO Icon'),
    (b'8BPS',                   0,  'psd',    'Photoshop PSD'),
    (b'JFIF',                   6,  'jpg',    'JPEG (JFIF)'),
    (b'Exif',                   6,  'jpg',    'JPEG (EXIF)'),
    (b'IHDR',                   12, 'png',    'PNG (IHDR chunk)'),
    (b'P1\n',                   0,  'pbm',    'PBM Bitmap'),
    (b'P2\n',                   0,  'pgm',    'PGM Greymap'),
    (b'P3\n',                   0,  'ppm',    'PPM Pixmap'),
    (b'P4\n',                   0,  'pbm',    'PBM Binary'),
    (b'P5\n',                   0,  'pgm',    'PGM Binary'),
    (b'P6\n',                   0,  'ppm',    'PPM Binary'),
    (b'%PDF-',                  0,  'pdf',    'PDF Document'),
    (b'\xD0\xCF\x11\xE0',      0,  'doc',    'MS Office Legacy'),
    (b'%!PS-Adobe',             0,  'ps',     'PostScript'),
    (b'{\rtf',                  0,  'rtf',    'Rich Text Format'),
    (b'PK\x03\x04',             0,  'zip',    'ZIP Archive'),
    (b'PK\x05\x06',             0,  'zip',    'ZIP (empty)'),
    (b'Rar!\x1a\x07\x00',      0,  'rar',    'RAR v4'),
    (b'Rar!\x1a\x07\x01\x00',  0,  'rar',    'RAR v5'),
    (b'\x1f\x8b',               0,  'gz',     'Gzip'),
    (b'BZh',                    0,  'bz2',    'Bzip2'),
    (b'\xfd7zXZ\x00',           0,  'xz',     'XZ Archive'),
    (b'7z\xbc\xaf\x27\x1c',    0,  '7z',     '7-Zip'),
    (b'MSCF',                   0,  'cab',    'MS Cabinet'),
    (b'LZIP',                   0,  'lz',     'LZIP'),
    (b'\x1f\xa0',               0,  'z',      'Unix Compress'),
    (b'\x7fELF',                0,  'elf',    'ELF Executable'),
    (b'MZ',                     0,  'exe',    'PE Executable'),
    (b'\xCA\xFE\xBA\xBE',      0,  'class',  'Java Class'),
    (b'\xCE\xFA\xED\xFE',      0,  'macho',  'Mach-O 32-bit'),
    (b'\xCF\xFA\xED\xFE',      0,  'macho',  'Mach-O 64-bit'),
    (b'#!',                     0,  'sh',     'Shell Script'),
    (b'dex\n',                  0,  'dex',    'Android DEX'),
    (b'OggS',                   0,  'ogg',    'OGG'),
    (b'fLaC',                   0,  'flac',   'FLAC Audio'),
    (b'ID3',                    0,  'mp3',    'MP3 (ID3)'),
    (b'\xFF\xFB',               0,  'mp3',    'MP3'),
    (b'ftyp',                   4,  'mp4',    'MPEG-4'),
    (b'WAVEfmt',                8,  'wav',    'WAV Audio'),
    (b'\x30\x26\xB2\x75',      0,  'wmv',    'Windows Media'),
    (b'FWS',                    0,  'swf',    'Flash SWF'),
    (b'CWS',                    0,  'swf',    'Flash SWF (compressed)'),
    (b'\xD4\xC3\xB2\xA1',      0,  'pcap',   'PCAP (LE)'),
    (b'\xA1\xB2\xC3\xD4',      0,  'pcap',   'PCAP (BE)'),
    (b'\x0a\x0d\x0d\x0a',      0,  'pcapng', 'PCAPng'),
    (b'<?xml',                  0,  'xml',    'XML'),
    (b'<?php',                  0,  'php',    'PHP'),
    (b'<!DOCTYPE',              0,  'html',   'HTML'),
    (b'<html',                  0,  'html',   'HTML'),
    (b'{"',                     0,  'json',   'JSON'),
    (b'[{',                     0,  'json',   'JSON Array'),
    (b'-----BEGIN',             0,  'pem',    'PEM Key/Cert'),
    (b'ssh-rsa',                0,  'pub',    'SSH RSA Key'),
    (b'ssh-ed25519',            0,  'pub',    'SSH Ed25519 Key'),
    (b'OpenSSH',                0,  'key',    'OpenSSH Private Key'),
    (b'PuTTY',                  0,  'ppk',    'PuTTY Key'),
    (b'II\x2a\x00',             0,  'tif',    'TIFF/FAX (LE)'),
    (b'MM\x00\x2a',             0,  'tif',    'TIFF/FAX (BE)'),
    (b'SQLite format 3',        0,  'db',     'SQLite DB'),
    (b'StegHide',               0,  'steg',   'Steghide marker'),
    (b'SIMPLE  =',              0,  'fits',   'FITS Astronomical Data'),
    (b'wOFF',                   0,  'woff',   'Web Font WOFF'),
    (b'\x00\x01\x00\x00',      0,  'ttf',    'TrueType Font'),
    (b'OTTO',                   0,  'otf',    'OpenType Font'),
]

def detect_filetype(data: bytes) -> Optional[Tuple[str, str]]:
    for magic, offset, ext, desc in FILE_SIGNATURES:
        end = offset + len(magic)
        if len(data) >= end and data[offset:end] == magic:
            if magic == b'RIFF' and len(data) >= 12:
                sub = data[8:12]
                if sub == b'WEBP': return ('webp', 'WebP Image')
                if sub == b'WAVE': return ('wav',  'WAV Audio')
                if sub == b'AVI ': return ('avi',  'AVI Video')
            return (ext, desc)
    return None

def lsb_extract_text(data: bytes, max_chars: int = 4000) -> Optional[str]:
    try:
        bits = [byte & 1 for byte in data]
        chars = []
        for i in range(0, min(len(bits) - 7, max_chars * 8), 8):
            byte_val = sum(bits[i + j] << (7 - j) for j in range(8))
            if byte_val == 0:
                break
            if 32 <= byte_val <= 126 or byte_val in (9, 10, 13):
                chars.append(chr(byte_val))
            else:
                break
        result = ''.join(chars)
        return result if len(result) >= 4 else None
    except Exception:
        return None

def lsb_extract_all_planes(data: bytes) -> List[Tuple[str, str]]:
    results = []
    sample = data[:25600]
    for plane in range(8):
        try:
            bits = [(byte >> plane) & 1 for byte in sample]
            chars = []
            for i in range(0, min(len(bits) - 7, 3200), 8):
                byte_val = sum(bits[i + j] << (7 - j) for j in range(8))
                if byte_val == 0:
                    break
                if 32 <= byte_val <= 126 or byte_val in (9, 10, 13):
                    chars.append(chr(byte_val))
                else:
                    break
            result = ''.join(chars)
            if len(result) >= 4:
                results.append((f'LSB bit-plane {plane}', result))
        except Exception:
            pass
    return results

def scan_for_embedded_strings(data: bytes, min_len: int = 5) -> List[str]:
    results = []
    current = []
    for byte in data:
        if 32 <= byte <= 126 or byte in (9, 10, 13):
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append(''.join(current))
            current = []
    if len(current) >= min_len:
        results.append(''.join(current))
    return results

def extract_png_chunks(data: bytes) -> List[Tuple[str, bytes]]:
    chunks = []
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        return chunks
    pos = 8
    while pos + 12 <= len(data):
        try:
            length = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8].decode('ascii', errors='replace')
            chunk_data = data[pos+8:pos+8+length]
            chunks.append((chunk_type, chunk_data))
            pos += 12 + length
        except Exception:
            break
    return chunks

def extract_jpeg_comments(data: bytes) -> List[str]:
    comments = []
    pos = 0
    while pos < len(data) - 1:
        if data[pos] == 0xFF and data[pos+1] == 0xFE:
            if pos + 4 <= len(data):
                length = struct.unpack('>H', data[pos+2:pos+4])[0]
                comment = data[pos+4:pos+2+length]
                comments.append(comment.decode('utf-8', errors='replace'))
                pos += 2 + length
            else:
                break
        else:
            pos += 1
    return comments

def extract_zip_comment(data: bytes) -> Optional[str]:
    try:
        eocd = data.rfind(b'PK\x05\x06')
        if eocd == -1:
            return None
        comment_len = struct.unpack('<H', data[eocd+20:eocd+22])[0]
        if comment_len > 0:
            return data[eocd+22:eocd+22+comment_len].decode('utf-8', errors='replace')
        return None
    except Exception:
        return None

def check_polyglot(data: bytes) -> List[str]:
    hits = []
    types_found = set()
    for magic, offset, ext, desc in FILE_SIGNATURES:
        end = offset + len(magic)
        if len(data) >= end and data[offset:end] == magic:
            types_found.add(ext)
    if len(data) > 22:
        tail = data[-65536:]
        for magic, offset, ext, desc in FILE_SIGNATURES:
            pos = tail.find(magic)
            if pos != -1 and ext not in types_found:
                types_found.add(ext)
                hits.append(f'Appended {desc} detected at tail (offset -{len(tail)-pos})')
    if len(types_found) > 1:
        hits.insert(0, f'POLYGLOT: valid signatures for: {", ".join(sorted(types_found))}')
    return hits

def try_zlib_decompress(data: bytes) -> Optional[bytes]:
    for skip in range(0, min(16, len(data))):
        try:
            result = zlib.decompress(data[skip:])
            if result:
                return result
        except Exception:
            pass
    for wbits in (15, -15, 47):
        try:
            result = zlib.decompress(data, wbits)
            if result:
                return result
        except Exception:
            pass
    return None

def scan_whitespace_stego(text: str) -> Optional[str]:
    try:
        lines = text.split('\n')
        bits = []
        for line in lines:
            stripped = line.rstrip()
            trail = line[len(stripped):]
            for ch in trail:
                if ch == ' ':
                    bits.append('0')
                elif ch == '\t':
                    bits.append('1')
        if len(bits) < 8:
            return None
        result = []
        for i in range(0, len(bits) - 7, 8):
            byte_val = int(''.join(bits[i:i+8]), 2)
            if byte_val == 0:
                break
            if 32 <= byte_val <= 126:
                result.append(chr(byte_val))
        decoded = ''.join(result)
        return decoded if len(decoded) >= 3 else None
    except Exception:
        return None

def scan_unicode_stego(text: str) -> Optional[str]:
    ZWCHARS = {
        '\u200b': '0', '\u200c': '1', '\u200d': '1',
        '\u2060': '0', '\ufeff': '0',
    }
    try:
        bits = [ZWCHARS[ch] for ch in text if ch in ZWCHARS]
        if len(bits) < 8:
            return None
        result = []
        for i in range(0, len(bits) - 7, 8):
            byte_val = int(''.join(bits[i:i+8]), 2)
            if byte_val == 0:
                break
            if 32 <= byte_val <= 126:
                result.append(chr(byte_val))
        decoded = ''.join(result)
        return decoded if len(decoded) >= 2 else None
    except Exception:
        return None

from dataclasses import dataclass, field

MAGIC = [
    (b'\x89PNG\r\n\x1a\n',  'png',   'PNG Image',           67),
    (b'\xff\xd8\xff',        'jpg',   'JPEG Image',          100),
    (b'GIF87a',              'gif',   'GIF87 Image',         35),
    (b'GIF89a',              'gif',   'GIF89 Image',         35),
    (b'BM',                  'bmp',   'BMP Image',           54),
    (b'II*\x00',             'tiff',  'TIFF Image (LE)',     8),
    (b'MM\x00*',             'tiff',  'TIFF Image (BE)',     8),
    (b'II\x2b\x00',          'tiff',  'BigTIFF (LE)',        8),
    (b'MM\x00\x2b',          'tiff',  'BigTIFF (BE)',        8),
    (b'PK\x03\x04',          'zip',   'ZIP Archive',         30),
    (b'PK\x05\x06',          'zip',   'ZIP Empty',           22),
    (b'Rar!\x1a\x07\x00',   'rar',   'RAR Archive',         20),
    (b'Rar!\x1a\x07\x01',   'rar',   'RAR5 Archive',        20),
    (b'\x1f\x8b',            'gz',    'Gzip',                18),
    (b'BZh',                 'bz2',   'BZIP2',               10),
    (b'7z\xbc\xaf\x27\x1c', '7z',    '7-Zip Archive',       32),
    (b'%PDF',                'pdf',   'PDF Document',        100),
    (b'\x7fELF',             'elf',   'ELF Binary',          52),
    (b'MZ',                  'exe',   'PE Executable',       64),
    (b'\xca\xfe\xba\xbe',   'class', 'Java Class',          10),
    (b'RIFF',                'riff',  'RIFF Container',      12),
    (b'OggS',                'ogg',   'OGG Stream',          27),
    (b'fLaC',                'flac',  'FLAC Audio',          42),
    (b'ID3',                 'mp3',   'MP3 Audio (ID3)',     10),
    (b'\xff\xfb',            'mp3',   'MP3 Frame',           4),
    (b'\xff\xf3',            'mp3',   'MP3 Frame',           4),
    (b'\xff\xf2',            'mp3',   'MP3 Frame',           4),
    (b'\x89HDF\r\n\x1a\n',  'h5',    'HDF5 Data',           8),
    (b'SQLite format 3',     'db',    'SQLite DB',           100),
    (b'\x00\x01\x00\x00SF', 'ttf',   'TrueType Font',       12),
    (b'OTTO',                'otf',   'OpenType Font',       12),
    (b'<!DOCTYPE',           'html',  'HTML Document',       20),
    (b'<html',               'html',  'HTML Document',       20),
    (b'<?xml',               'xml',   'XML Document',        10),
    (b'-----BEGIN ',         'pem',   'PEM Certificate',     30),
    (b'\x1f\xa0',            'z',     'Unix Compress',       4),
    (b'\x1f\x9d',            'z',     'Unix Compress (LZW)', 4),
    (b'\x00\x00\x01\x00',   'ico',   'ICO Icon',            6),
    (b'#!',                  'sh',    'Shell Script',        4),
    (b'{"',                  'json',  'JSON Object',         2),
    (b'[{',                  'json',  'JSON Array',          2),
]
MAGIC.sort(key=lambda x: len(x[0]), reverse=True)

@dataclass
class CarveHit:
    offset:   int
    end:      int
    ext:      str
    label:    str
    data:     bytes
    source:   str
    depth:    int
    bounded:  bool
    note:     str = ''
    entropy:  float = 0.0
    children: list = field(default_factory=list)

def calc_entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = [0] * 256
    for b in data: counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return round(e, 3)

def _end_png(data, start):
    i = start + 8
    while i + 12 <= len(data):
        if i + 4 > len(data): break
        chunk_len = struct.unpack('>I', data[i:i+4])[0]
        if chunk_len > 0x10000000: break
        chunk_type = data[i+4:i+8]
        i += 12 + chunk_len
        if chunk_type == b'IEND':
            return i
    return None

def _end_jpeg(data, start):
    i = start + 2
    while i + 2 <= len(data):
        if data[i] != 0xFF:
            i += 1; continue
        marker = data[i+1]
        if marker == 0xD9:
            return i + 2
        if marker in (0x01,) or (0xD0 <= marker <= 0xD8):
            i += 2; continue
        if i + 4 > len(data): break
        seg_len = struct.unpack('>H', data[i+2:i+4])[0]
        i += 2 + seg_len
    return None

def _end_gif(data, start):
    pos = data.find(b'\x3b', start + 6)
    return pos + 1 if pos != -1 else None

def _end_bmp(data, start):
    if start + 6 > len(data): return None
    size = struct.unpack('<I', data[start+2:start+6])[0]
    if size < 54 or size > 0x10000000: return None
    end = start + size
    return end if end <= len(data) else None

def _end_zip(data, start):
    pos = data.rfind(b'PK\x05\x06', start)
    if pos == -1: return None
    if pos + 22 > len(data): return None
    comment_len = struct.unpack('<H', data[pos+20:pos+22])[0]
    return pos + 22 + comment_len

def _end_pdf(data, start):
    pos = data.find(b'%%EOF', start)
    return pos + 5 if pos != -1 else None

def _end_riff(data, start):
    if start + 8 > len(data): return None
    size = struct.unpack('<I', data[start+4:start+8])[0]
    end = start + 8 + size
    return end if end <= len(data) else None

def _end_pe(data, start):
    if start + 64 > len(data): return None
    if data[start:start+2] != b'MZ': return None
    pe_off = struct.unpack('<I', data[start+0x3c:start+0x40])[0]
    if pe_off > len(data) - 4: return None
    if data[start+pe_off:start+pe_off+4] != b'PE\x00\x00': return None
    opt_off = start + pe_off + 24
    if opt_off + 4 > len(data): return None
    num_sec  = struct.unpack('<H', data[start+pe_off+6:start+pe_off+8])[0]
    opt_size = struct.unpack('<H', data[start+pe_off+20:start+pe_off+22])[0]
    sec_table = start + pe_off + 24 + opt_size
    last_end = 0
    for i in range(num_sec):
        sec_off = sec_table + i * 40
        if sec_off + 40 > len(data): break
        raw_offset = struct.unpack('<I', data[sec_off+20:sec_off+24])[0]
        raw_size   = struct.unpack('<I', data[sec_off+16:sec_off+20])[0]
        sec_end = raw_offset + raw_size
        if sec_end > last_end:
            last_end = sec_end
    if last_end > 0 and start + last_end <= len(data):
        return start + last_end
    return None

def _end_elf(data, start):
    if start + 64 > len(data): return None
    ei_class = data[start+4]
    if ei_class == 1:
        e_shoff     = struct.unpack('<I', data[start+32:start+36])[0]
        e_shentsize = struct.unpack('<H', data[start+46:start+48])[0]
        e_shnum     = struct.unpack('<H', data[start+48:start+50])[0]
    elif ei_class == 2:
        e_shoff     = struct.unpack('<Q', data[start+40:start+48])[0]
        e_shentsize = struct.unpack('<H', data[start+58:start+60])[0]
        e_shnum     = struct.unpack('<H', data[start+60:start+62])[0]
    else: return None
    if e_shoff == 0 or e_shnum == 0: return None
    end = start + e_shoff + (e_shnum * e_shentsize)
    return end if end <= len(data) else None

def _end_tiff(data, start):
    be = data[start:start+2] == b'MM'
    U32, U16 = ('>I','>H') if be else ('<I','<H')
    if start + 8 > len(data): return None
    ifd_offset = struct.unpack(U32, data[start+4:start+8])[0]
    max_end = start + 8
    visited = set()
    type_sizes = {1:1,2:1,3:2,4:4,5:8,6:1,7:1,8:2,9:4,10:8,11:4,12:8}
    while ifd_offset and ifd_offset not in visited:
        visited.add(ifd_offset)
        abs_off = start + ifd_offset
        if abs_off + 2 > len(data): break
        count = struct.unpack(U16, data[abs_off:abs_off+2])[0]
        if count > 500: break
        for i in range(count):
            ep = abs_off + 2 + i * 12
            if ep + 12 > len(data): break
            typ = struct.unpack(U16, data[ep+2:ep+4])[0]
            cnt = struct.unpack(U32, data[ep+4:ep+8])[0]
            tsz = type_sizes.get(typ, 1)
            data_size = cnt * tsz
            if data_size > 4:
                val_off = struct.unpack(U32, data[ep+8:ep+12])[0]
                end_of_data = start + val_off + data_size
                if end_of_data > max_end and end_of_data <= len(data):
                    max_end = end_of_data
        next_pos = abs_off + 2 + count * 12
        if next_pos + 4 > len(data): break
        ifd_offset = struct.unpack(U32, data[next_pos:next_pos+4])[0]
    return max_end if max_end > start + 8 else None

def _end_gz(data, start):
    d = zlib.decompressobj(-zlib.MAX_WBITS)
    for end in range(start + 18, min(start + 2000000, len(data))):
        try:
            d.decompress(bytes([data[end-1]]))
            if d.eof:
                return end + 8
        except Exception:
            break
    return None

def _end_mp3(data, start):
    BITRATES = [0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0]
    i = start
    if data[i:i+3] == b'ID3' and i+10 <= len(data):
        id3_size = ((data[i+6]&0x7f)<<21|(data[i+7]&0x7f)<<14|
                    (data[i+8]&0x7f)<<7 |(data[i+9]&0x7f))
        i += 10 + id3_size
    good = 0
    last_good = i
    while i + 4 <= len(data):
        if data[i] != 0xFF or (data[i+1] & 0xE0) != 0xE0:
            if good > 10: return last_good
            i += 1; continue
        b2 = data[i+2]
        br_idx = (b2 >> 4) & 0x0F
        sr_idx = (b2 >> 2) & 0x03
        pad    = (b2 >> 1) & 0x01
        if br_idx in (0,15) or sr_idx == 3:
            if good > 10: return last_good
            i += 1; continue
        br = BITRATES[br_idx] * 1000
        sr = [44100,48000,32000][sr_idx]
        fsz = (144 * br // sr) + pad
        if fsz < 24 or fsz > 2880:
            if good > 10: return last_good
            i += 1; continue
        good += 1
        last_good = i + fsz
        i += fsz
    return last_good if good > 5 else None

def _end_json(data, start):
    try:
        text = data[start:start+500000].decode('utf-8', errors='replace')
        open_char = text[0]
        close_char = '}' if open_char == '{' else ']'
        depth = 0; in_str = False; esc = False
        for i, c in enumerate(text):
            if esc: esc = False; continue
            if c == '\\' and in_str: esc = True; continue
            if c == '"': in_str = not in_str; continue
            if in_str: continue
            if c in ('{','['): depth += 1
            elif c in ('}',']'):
                depth -= 1
                if depth == 0: return start + i + 1
    except Exception:
        pass
    return None

_END_FINDERS = {
    'png': _end_png, 'jpg': _end_jpeg, 'gif': _end_gif,
    'bmp': _end_bmp, 'zip': _end_zip,  'pdf': _end_pdf,
    'riff':_end_riff,'exe': _end_pe,   'elf': _end_elf,
    'tiff':_end_tiff,'gz':  _end_gz,   'mp3': _end_mp3,
    'json':_end_json,
}

class FileCarver:

    def __init__(self, max_depth=3, min_size=32,
                 output_dir=None, save_carved=False):
        self.max_depth  = max_depth
        self.min_size   = min_size
        self.output_dir = output_dir
        self.save_carved= save_carved
        self._seen      = set()

    def carve(self, data: bytes, source_label: str, depth: int = 0) -> List[CarveHit]:
        if depth > self.max_depth or len(data) < self.min_size:
            return []
        if len(data) > 65536:
            data = data[:32768] + data[-32768:]
        h = hashlib.md5(data[:4096]).hexdigest()
        if h in self._seen: return []
        self._seen.add(h)

        hits = []
        offset = min(len(data), 8) if depth == 0 else 0

        while offset < len(data) - 4:
            matched = False
            for sig, ext, label, min_sz in MAGIC:
                slen = len(sig)
                if data[offset:offset+slen] != sig: continue
                if len(data) - offset < max(slen, min_sz, self.min_size): break

                finder  = _END_FINDERS.get(ext)
                end     = None
                bounded = False
                if finder:
                    try:
                        end = finder(data, offset)
                        if end and end > offset + self.min_size:
                            bounded = True
                    except Exception:
                        end = None

                if not bounded:
                    end = len(data)

                embedded = data[offset:end]
                if len(embedded) < self.min_size: break

                ent = calc_entropy(embedded[:65536])
                bound_note = 'bounded' if bounded else 'extent unknown - sliced to eof'
                note = f'offset 0x{offset:x}  size {len(embedded):,} bytes ({bound_note})  entropy {ent:.2f}'

                hit = CarveHit(
                    offset=offset, end=end, ext=ext, label=label,
                    data=embedded, source=source_label, depth=depth,
                    bounded=bounded, note=note, entropy=ent,
                )

                if depth + 1 <= self.max_depth and bounded:
                    hit.children = self.carve(embedded, f'{label}@0x{offset:x}', depth+1)
                    inner = self._decompress(embedded, ext)
                    if inner:
                        ih = hashlib.md5(inner).hexdigest()
                        if ih not in self._seen:
                            hit.children.extend(
                                self.carve(inner, f'{label}@0x{offset:x}(unpacked)', depth+1))

                if self.save_carved and self.output_dir:
                    self._save(embedded, ext, source_label, offset)

                hits.append(hit)
                offset = end if bounded else offset + 1
                matched = True
                break

            if not matched:
                offset += 1

        return hits

    def _decompress(self, data, ext):
        try:
            if ext == 'gz':
                import gzip; return gzip.decompress(data)
            if ext == 'bz2':
                import bz2; return bz2.decompress(data)
            if ext == 'zip':
                import zipfile
                parts = []
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for n in zf.namelist():
                        try: parts.append(zf.read(n))
                        except: pass
                return b'\n'.join(parts) if parts else None
        except: pass
        return None

    def _save(self, data, ext, source, offset):
        import re, datetime
        os.makedirs(self.output_dir, exist_ok=True)
        safe = re.sub(r'[^\w]', '_', source)[:20]
        ts   = datetime.datetime.now().strftime('%H%M%S')
        path = os.path.join(self.output_dir, f'{safe}_{ext}_{offset:x}_{ts}.{ext}')
        open(path, 'wb').write(data)
        return path

def format_carve_tree(hits: List[CarveHit], indent: int = 0) -> str:
    lines = []
    prefix = '  ' * indent
    for i, hit in enumerate(hits):
        conn = 'L-' if i == len(hits)-1 else '+-'
        mark = '' if hit.bounded else ' [extent unknown]'
        lines.append(f'{prefix}{conn} [{hit.label}] @ 0x{hit.offset:x}  ({len(hit.data):,} bytes){mark}')
        if hit.entropy > 7.2:
            lines.append(f'{prefix}   high entropy {hit.entropy:.2f} - possibly encrypted or compressed')
        if hit.children:
            lines.append(format_carve_tree(hit.children, indent+1))
    return '\n'.join(lines)

def analyze_image_deep(data: bytes, source_label: str = '') -> List[Finding]:
    findings = []

    if data[:3] == b'\xff\xd8\xff':
        findings.extend(_analyze_jpeg(data, source_label))

    elif data[:8] == b'\x89PNG\r\n\x1a\n':
        findings.extend(_analyze_png(data, source_label))

    elif data[:2] == b'BM':
        findings.extend(_analyze_bmp(data, source_label))

    return findings

def _analyze_jpeg(data: bytes, source_label: str) -> list:
    """
    JPEG triage: trailing data, comment segments, APPn segment map,
    EXIF field extraction, thumbnail detection.
    """
    import struct
    findings = []

    # ── Trailing data (after EOI 0xFFD9) ──────────────────────────────────
    eoi = data.rfind(b'\xff\xd9')
    if eoi != -1 and eoi + 2 < len(data):
        appended = data[eoi + 2:]
        printable = sum(1 for b in appended if 32 <= b <= 126 or b in (9, 10, 13))
        if appended and printable / len(appended) > 0.5:
            findings.append(Finding(
                method='JPEG appended data (after EOI)',
                confidence='HIGH',
                note=f'{len(appended)} bytes after JPEG end marker',
                result_text=appended.decode('latin-1', errors='replace'),
                source_label=source_label,
            ))
        elif appended:
            findings.append(Finding(
                method='JPEG appended binary (after EOI)',
                confidence='MEDIUM',
                result_bytes=appended,
                note=f'{len(appended)} binary bytes after JPEG EOI marker',
                source_label=source_label,
            ))

    # ── Segment map + APPn extraction ─────────────────────────────────────
    pos = 2
    seg_map = []
    exif_data = b''
    xmp_data  = b''
    comments  = []
    thumbnails = []

    while pos + 3 < len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9, 0xDA):
            break
        if marker in (0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7):
            pos += 2; continue
        if pos + 4 > len(data):
            break
        try:
            length = struct.unpack('>H', data[pos+2:pos+4])[0]
        except Exception:
            break
        seg_end  = pos + 2 + length
        seg_data = data[pos+4:seg_end]
        marker_name = 'FF%02X' % marker
        seg_map.append((pos, marker_name, length, seg_data[:16].hex()))

        # Comment FFFE
        if marker == 0xFE:
            try:
                c = seg_data.decode('utf-8', errors='replace').strip()
                if c:
                    comments.append(c)
            except Exception:
                pass

        # APP0 JFIF thumbnail
        if marker == 0xE0 and seg_data[:4] == b'JFIF':
            if len(seg_data) > 10:
                tw = seg_data[8] if len(seg_data) > 8 else 0
                th = seg_data[9] if len(seg_data) > 9 else 0
                if tw and th:
                    thumbnails.append(('JFIF', tw, th, seg_data[10:]))

        # APP1 EXIF
        if marker == 0xE1 and seg_data[:4] == b'Exif':
            exif_data = seg_data[6:]

        # APP1 XMP
        if marker == 0xE1 and b'xap/1.0/' in seg_data[:40]:
            xmp_data = seg_data

        pos = seg_end

    # Segment map
    if seg_map:
        seg_summary = '  '.join('%s@0x%x' % (m, o) for o, m, _, _ in seg_map[:20])
        findings.append(Finding(
            method='JPEG segment map',
            result_text=seg_summary,
            confidence='LOW',
            note='%d segments found' % len(seg_map),
            source_label=source_label,
        ))

    # Comments
    for comment in comments:
        findings.append(Finding(
            method='JPEG comment segment (FFFE)',
            result_text=comment,
            confidence='HIGH' if len(comment) > 10 else 'MEDIUM',
            note='Embedded comment: %d chars' % len(comment),
            source_label=source_label,
        ))

    # EXIF
    if exif_data:
        exif_fields = _parse_exif_basic(exif_data)
        if exif_fields:
            field_text = '\n'.join('%s: %s' % (k, v) for k, v in exif_fields.items())
            findings.append(Finding(
                method='EXIF metadata',
                result_text=field_text,
                confidence='MEDIUM',
                note='%d EXIF fields extracted' % len(exif_fields),
                source_label=source_label,
            ))

    # XMP
    if xmp_data:
        try:
            xmp_text = xmp_data.decode('utf-8', errors='replace').strip()
            if xmp_text:
                findings.append(Finding(
                    method='XMP metadata',
                    result_text=xmp_text[:1000],
                    confidence='MEDIUM',
                    note='%d bytes XMP/RDF metadata' % len(xmp_data),
                    source_label=source_label,
                ))
        except Exception:
            pass

    # Thumbnails
    for label, w, h, tb in thumbnails:
        if len(tb) > 100:
            findings.append(Finding(
                method='JPEG embedded thumbnail (%s)' % label,
                result_bytes=tb,
                confidence='MEDIUM',
                note='%dx%d px thumbnail, %d bytes' % (w, h, len(tb)),
                source_label=source_label,
            ))

    return findings


def _parse_exif_basic(data: bytes) -> dict:
    """Pure-Python minimal EXIF IFD parser. No external dependencies."""
    import struct
    if not data or len(data) < 8:
        return {}
    if data[:2] == b'II':
        bo = '<'
    elif data[:2] == b'MM':
        bo = '>'
    else:
        return {}
    try:
        ifd_offset = struct.unpack_from(bo + 'I', data, 4)[0]
        if ifd_offset + 2 > len(data):
            return {}
        count = struct.unpack_from(bo + 'H', data, ifd_offset)[0]
    except Exception:
        return {}

    TAGS = {
        0x010F:'Make', 0x0110:'Model', 0x0131:'Software',
        0x0132:'DateTime', 0x013B:'Artist', 0x8298:'Copyright',
        0x9003:'DateTimeOriginal', 0x9004:'DateTimeDigitized',
        0xA420:'ImageUniqueID', 0x9C9B:'XPTitle', 0x9C9C:'XPComment',
        0x9C9D:'XPAuthor', 0x9C9E:'XPKeywords', 0x9C9F:'XPSubject',
        0xA002:'PixelXDimension', 0xA003:'PixelYDimension',
        0x0100:'ImageWidth', 0x0101:'ImageLength',
        0x0112:'Orientation', 0x0128:'ResolutionUnit',
    }
    fields = {}
    entry_start = ifd_offset + 2
    for i in range(min(count, 60)):
        offset = entry_start + i * 12
        if offset + 12 > len(data):
            break
        try:
            tag, dtype, ncomp = struct.unpack_from(bo + 'HHI', data, offset)
            name = TAGS.get(tag)
            if not name:
                continue
            voff = offset + 8
            if dtype == 2:  # ASCII
                if ncomp > 4:
                    raw_off = struct.unpack_from(bo + 'I', data, voff)[0]
                    str_bytes = data[raw_off:raw_off + ncomp]
                else:
                    str_bytes = data[voff:voff + ncomp]
                val = str_bytes.rstrip(b'\x00').decode('utf-8', errors='replace').strip()
                if val:
                    fields[name] = val
            elif dtype in (3, 4):  # SHORT / LONG
                fmt = 'H' if dtype == 3 else 'I'
                val = struct.unpack_from(bo + fmt, data, voff)[0]
                fields[name] = str(val)
        except Exception:
            continue
    return fields


def _analyze_png(data, source_label):
    findings = []
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert('RGBA')
        pixels = list(img.getdata())

        bits = []
        for px in pixels:
            bits.append(px[0] & 1)

        out = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            out.append(byte)

        printable = sum(1 for b in out[:256] if 32 <= b <= 126 or b in (9, 10, 13))
        if len(out) > 0 and printable / min(len(out), 256) > 0.7:
            findings.append(Finding(
                method='PNG LSB R channel (row scan)',
                confidence='MEDIUM',
                note=f'{len(out)} bytes extracted from R channel LSB',
                result_text=out.decode('latin-1'),
                source_label=source_label,
            ))
    except Exception:
        pass
    return findings

def _analyze_bmp(data, source_label):
    findings = []
    if len(data) < 54:
        return findings
    pixel_offset = struct.unpack('<I', data[10:14])[0]
    pixel_data = data[pixel_offset:]
    if not pixel_data:
        return findings

    bits = [b & 1 for b in pixel_data]
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)

    printable = sum(1 for b in out[:256] if 32 <= b <= 126 or b in (9, 10, 13))
    if len(out) > 0 and printable / min(len(out), 256) > 0.7:
        findings.append(Finding(
            method='BMP LSB pixel data',
            confidence='MEDIUM',
            note=f'{len(out)} bytes extracted from BMP LSBs',
            result_text=out.decode('latin-1'),
            source_label=source_label,
        ))
    return findings

import io, os
RESET = '\033[0m'

def _ansi_fg(r,g,b): return f'\033[38;2;{r};{g};{b}m'
def _ansi_bg(r,g,b): return f'\033[48;2;{r};{g};{b}m'

def supports_truecolor():
    c = os.environ.get('COLORTERM','').lower()
    if c in ('truecolor','24bit'): return True
    return '256' in os.environ.get('TERM','') or 'xterm' in os.environ.get('TERM','')

def render_image_to_ansi(data,max_width=72,max_height=40,label=''):
    try: from PIL import Image
    except: return None
    try: img = Image.open(io.BytesIO(data)).convert('RGB')
    except: return None
    ow,oh = img.size
    s = min(max_width/ow,(max_height*2)/oh,1.0)
    nw = max(1,int(ow*s))
    nh = max(2,int(oh*s)); nh = nh if nh%2==0 else nh+1
    img = img.resize((nw, nh),Image.LANCZOS)
    px = list(img.getdata())
    lines = []
    if label:
        lines.append(f'\033[38;5;82m┌{"─"*(nw+2)}┐{RESET}')
        lines.append(f'\033[38;5;82m│ \033[1m{label[:nw-2]}\033[0m\033[38;5;82m{" "*(max(0,nw-len(label)-2))} │{RESET}')
        lines.append(f'\033[38;5;82m├{"─"*(nw+2)}┘{RESET}')
    for r in range(0,nh,2):
        line = '\033[38;5;82m│\033[0m'
        for c in range(nw):
            tr,tg,tb = px[r*nw+c]
            br,bg,bb = px[((r+1)*nw+c) if r+1<nh else r*nw+c]
            line += _ansi_fg(tr,tg,tb)+_ansi_bg(br,bg,bb)+'▀'+RESET
        line += '\033[38;5;82m│\033[0m'
        lines.append(line)
    lines.append(f'\033[38;5;82m└{"─"*(nw+2)}┘{RESET}')
    return '\n'.join(lines)

def render_image_greyscale(data,max_width=60,max_height=30,label=''):
    try: from PIL import Image
    except: return None
    CHARS = ' .:-=+*#%@'
    try: img = Image.open(io.BytesIO(data)).convert('L')
    except: return None
    s = min(max_width/img.width,(max_height*2)/img.height,1.0)
    nw = max(1,int(img.width*s)); nh = max(1,int(img.height*s))
    img = img.resize((nw, nh))
    px = list(img.getdata())
    lines = []
    if label: lines.append(f'[ {label} ]')
    lines.append('+'+'-'*nw+'+')
    for r in range(nh):
        row = ''.join(CHARS[min(int(px[r*nw+c]/256*len(CHARS)),len(CHARS)-1)] for c in range(nw))
        lines.append('|'+row+'|')
    lines.append('+'+'-'*nw+'+')
    return '\n'.join(lines)

def render_to_terminal(data,label='',max_width=72,max_height=36):
    if supports_truecolor():
        r = render_image_to_ansi(data,max_width,max_height,label)
        if r: return r
    return render_image_greyscale(data,max_width//2,max_height,label) or ''

def is_renderable_image(data):
    for m in [b'\xff\xd8\xff',b'\x89PNG\r\n\x1a\n',b'GIF8',b'BM',b'II*\x00',b'MM\x00*',b'RIFF']:
        if data[:len(m)]==m: return True
    return False

def render_found_file(data,label,ext,nocolor=False):
    if is_renderable_image(data) and not nocolor:
        r = render_to_terminal(data,label)
        if r: return r
    try:
        t = data.decode('utf-8')
        if sum(1 for c in t if c.isprintable() or c in '\n\t')/len(t)>.08:
            return t[:500]+(f'\n  [...{len(t)} chars]' if len(t)>500 else '')
    except: pass
    lines = [f'  binary - {len(data):,} bytes']
    for i in range(0,min(len(data),256),16):
        c = data[i:i+16]
        lines.append(f'  {i:04x}:  {" ".join(hex(b)[2:].zfill(2) for b in c):<47}  {"".join(chr(b) if 32<=b<=166 else"." for b in c)}')
    if len(data)>256: lines.append(f'  ... [{len(data)-256:,} more bytes]')
    return '\n'.join(lines)

"""
core/reporter.py  -  Hash It Out v4.1
handles all terminal output and file report generation.
clean filenames, per-run output subfolders, proper v4 branding.
"""


class C:
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RED     = '\033[38;5;196m'
    ORANGE  = '\033[38;5;208m'
    YELLOW  = '\033[38;5;226m'
    GREEN   = '\033[38;5;82m'
    CYAN    = '\033[38;5;51m'
    WHITE   = '\033[97m'
    GREY    = '\033[38;5;245m'
    TOXGRN  = '\033[38;5;82m'
    HIGH    = '\033[38;5;196m'
    MEDIUM  = '\033[38;5;226m'
    LOW     = '\033[38;5;245m'

_W = 72

def _line(char='-', color=None):
    s = char * _W
    if color: return f"{color}{s}{C.RESET}"
    return s

def _bar(char, n, color=None):
    s = char * n
    if color: return f"{color}{s}{C.RESET}"
    return s

def nocolor():
    for attr in [a for a in dir(C) if not a.startswith('_')]:
        setattr(C, attr, '')

BANNER = r"""
 _   _    _    ____  _   _   ___ _____    ___  _   _ _____
| | | |  / \  / ___|| | | | |_ _|_   _|  / _ \| | | |_   _|
| |_| | / _ \ \___ \| |_| |  | |  | |   | | | | | | | | |
|  _  |/ ___ \ ___) |  _  |  | |  | |   | |_| | |_| | | |
|_| |_/_/   \_\____/|_| |_| |___| |_|    \___/ \___/  |_|"""

def print_banner(version=None):
    print(f"{C.TOXGRN}{C.BOLD}{BANNER}{C.RESET}")
    print(f"{C.TOXGRN}  decoder  |  reverser  |  file carver  |  stego scanner  |  crypto detector{C.RESET}")
    print(f"{C.GREY}  github.com/RRSWSEC/Hash-It-Out  |  RRSW Corp{C.RESET}")
    print(f"{C.GREY}  {'+'+'='*54+'+'}{C.RESET}")
    print(f"{C.GREY}  |  for educational and authorized research use only   |{C.RESET}")
    print(f"{C.GREY}  {'+'+'='*54+'+'}{C.RESET}")
    print()
    _warn_special_chars()

def print_input_header(source, size, filetype=None, entropy=None,
                        wordlist_size=0, depth=None, enc_type=None):
    print()
    print(f"{C.CYAN}  {_line('=', C.CYAN)}{C.RESET}")

    label = os.path.basename(source) if os.path.sep in source else source
    if len(label) > 50: label = label[:47] + '...'
    print(f"{C.CYAN}  {C.BOLD}[*]{C.RESET}{C.WHITE} {label}{C.RESET}")

    meta = []
    if filetype:
        meta.append(f"{C.WHITE}{filetype}{C.RESET}")
    if size:
        s = f"{size:,} bytes" if isinstance(size, int) else str(size)
        meta.append(f"{C.GREY}{s}{C.RESET}")
    if entropy is not None:
        if entropy > 7.5:   ecol = C.RED
        elif entropy > 6.0: ecol = C.YELLOW
        else:               ecol = C.GREY
        meta.append(f"{ecol}entropy {entropy:.2f}{C.RESET}")
    if False:  # depth removed from display
        meta.append(f"{C.GREY}depth {depth}{C.RESET}")
    if wordlist_size:
        meta.append(f"{C.GREY}{wordlist_size:,} words{C.RESET}")
    if meta:
        print(f"      {'  |  '.join(meta)}")

    if enc_type:
        print(f"      {C.YELLOW}[enc] {enc_type}{C.RESET}")

    print(f"{C.CYAN}  {_line('=', C.CYAN)}{C.RESET}")
    print()

_CONF_ICON = {
    'HIGH':   f"{C.HIGH}{C.BOLD}  [!]{C.RESET}",
    'MEDIUM': f"{C.MEDIUM}  [~]{C.RESET}",
    'LOW':    f"{C.LOW}  [.]{C.RESET}",
}
_CONF_COLOR = {
    'HIGH':   C.HIGH,
    'MEDIUM': C.MEDIUM,
    'LOW':    C.LOW,
}

def _format_output(text, maxlen=500):
    if not text: return ''
    text = text.strip().replace('\n', ' ').replace('\r', '')
    if len(text) > maxlen:
        return text[:maxlen-3] + '...'
    return text

def _method_label(method, maxlen=50):
    m = method
    for prefix in ('Extracted: ', 'Carved: ', 'Carved (nested): ', '[REVERSED] '):
        if m.startswith(prefix):
            m = m[len(prefix):]
            break
    if len(m) > maxlen:
        m = m[:maxlen-2] + '..'
    return m


# ── Pass timing registry ──────────────────────────────────────────────────
_PASS_TIMING: List[Dict] = []

def _pass_record(name: str, status: str = 'ok', duration: float = 0.0,
                 candidates: int = 0, error: str = '') -> None:
    _PASS_TIMING.append({
        'pass': name, 'status': status,
        'duration_ms': round(duration * 1000, 1),
        'candidates': candidates, 'error': error,
    })

def _print_pass_timing() -> None:
    if not _PASS_TIMING:
        return
    print(f"\n  {C.GREY}pass timing:{C.RESET}")
    total_ms = sum(p['duration_ms'] for p in _PASS_TIMING)
    for p in sorted(_PASS_TIMING, key=lambda x: -x['duration_ms'])[:20]:
        bar_len = max(1, int(p['duration_ms'] / max(total_ms, 1) * 30))
        bar = '█' * bar_len
        status_col = C.GREEN if p['status'] == 'ok' else (C.YELLOW if p['status'] == 'skip' else C.RED)
        print(f"  {status_col}{p['status']:4}{C.RESET}  {p['pass']:<36}  "
              f"{C.GREY}{p['duration_ms']:6.0f}ms  {bar}  {p['candidates']} candidates{C.RESET}")
        if p['error']:
            print(f"         {C.RED}error: {p['error'][:80]}{C.RESET}")
    print(f"  {C.GREY}total: {total_ms:.0f}ms across {len(_PASS_TIMING)} passes{C.RESET}\n")



# ── Evidence-grade confidence labels for analyst mode ─────────────────────
_ANALYST_CONF = {
    'CONFIRMED': 'CONFIRMED',
    'HIGH':      'PROBABLE',
    'MEDIUM':    'POSSIBLE',
    'LOW':       'INSUFFICIENT',
}
_ANALYST_CONF_COLOR = {
    'CONFIRMED':    C.TOXGRN,
    'PROBABLE':     C.HIGH,
    'POSSIBLE':     C.MEDIUM,
    'INSUFFICIENT': C.LOW,
}


def _analyst_ioc_summary(findings) -> str:
    """Aggregate IOCs across all findings, dedupe, group by type."""
    from collections import defaultdict
    groups = defaultdict(set)
    for f in findings:
        for ioc in (getattr(f, 'iocs', []) or []):
            t = ioc.get('type', 'unknown')
            v = ioc.get('value', '')
            if v:
                groups[t].add(v)
    if not groups:
        return ''
    out = []
    TYPE_ORDER = ('url','ipv4','ipv6','domain','email','jwt','pem_block',
                  'sha256','sha1','md5','command')
    for t in TYPE_ORDER:
        if t in groups:
            vals = sorted(groups[t])[:6]
            out.append(f"  {C.CYAN}{t:<14}{C.RESET} {('  ').join(vals[:3])}")
            if len(vals) > 3:
                out.append(f"  {'':14} {('  ').join(vals[3:6])}")
    for t in sorted(groups):
        if t not in TYPE_ORDER:
            out.append(f"  {C.CYAN}{t:<14}{C.RESET} {', '.join(sorted(groups[t])[:4])}")
    return '\n'.join(out)


def _analyst_timeline(findings) -> str:
    """Pull timestamps from findings and return a sorted timeline."""
    import re as _re
    entries = []
    seen = set()
    PATS = [
        _re.compile(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'),
        _re.compile(r'\b(\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2})'),
        _re.compile(r'\b(\d{4}-\d{2}-\d{2})\b'),
    ]
    for f in findings:
        txt = f.result_text or ''
        if not txt:
            continue
        method = f.method or ''
        for pat in PATS:
            for m in pat.finditer(txt):
                raw = m.group(1)
                norm = raw.replace(':','-',2) if re.match(r'\d{4}:\d{2}:\d{2}', raw) else raw
                key = (norm, method[:40])
                if key not in seen:
                    seen.add(key)
                    entries.append((norm, method[:50]))
    if not entries:
        return ''
    entries.sort(key=lambda x: x[0])
    prev_date, out = '', []
    for ts, src_method in entries[:20]:
        date = ts[:10]
        if date != prev_date:
            out.append(f"  {C.GREY}{date}{C.RESET}")
            prev_date = date
        out.append(f"    {ts}  {C.GREY}{src_method}{C.RESET}")
    return '\n'.join(out)


def print_results_analyst(findings, source_label, input_size, saved_files=None):
    """
    Analyst-mode output — IOC-first, evidence-grade, defensible.

    Read order (top → cursor):
      ══ case header (farthest from cursor)
      ── IOC summary
      ── timeline (if present)
      ── suppressed count
      ── other signal hits with analyst narrative
      ── BEST MATCH box right at cursor
    """
    if not findings:
        print(f"  {C.GREY}no findings{C.RESET}")
        return

    import datetime as _dt

    conf_rank = {'CONFIRMED': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
    sorted_f = sorted(findings,
                      key=lambda f: (conf_rank.get(f.confidence, 0), f.score),
                      reverse=True)

    # Deduplicate by content
    def _norm(t):
        return re.sub(r'[^a-z0-9]', '', (t or '').lower())[:300]

    seen_norm, aliases = {}, {}
    for f in sorted_f:
        norm = _norm(f.result_text or '')
        if not norm or len(norm) < 6:
            seen_norm[(f.method or '') + str(id(f))] = f
            continue
        if norm not in seen_norm:
            seen_norm[norm] = f
            aliases[id(f)] = []
        else:
            aliases.setdefault(id(seen_norm[norm]), []).append(f.method or '')

    deduped = sorted(seen_norm.values(),
                     key=lambda f: (conf_rank.get(f.confidence, 0), f.score),
                     reverse=True)

    # Signal = CONFIRMED or HIGH only
    signal = [f for f in deduped if f.confidence in ('CONFIRMED', 'HIGH')]
    suppressed = [f for f in deduped if f.confidence not in ('CONFIRMED', 'HIGH')]
    _W2 = _W

    # ── Case header ──────────────────────────────────────────────────────────
    ts_now = _dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    counts = {c: sum(1 for f in deduped if f.confidence == c)
              for c in ('CONFIRMED','HIGH','MEDIUM','LOW')}
    count_parts = []
    for c in ('CONFIRMED','HIGH','MEDIUM','LOW'):
        if counts.get(c):
            aconf = _ANALYST_CONF.get(c, c)
            col   = _ANALYST_CONF_COLOR.get(aconf, C.GREY)
            count_parts.append(f"{col}{counts[c]} {aconf}{C.RESET}")

    print()
    print(f"  {C.GREY}{'═'*_W2}{C.RESET}")
    print(f"  {C.WHITE}ANALYST REPORT  ·  {source_label}  ·  {ts_now}{C.RESET}")
    print(f"  {'  '.join(count_parts)}")
    print(f"  {C.GREY}{'─'*_W2}{C.RESET}")
    print()

    # ── IOC summary ──────────────────────────────────────────────────────────
    ioc_txt = _analyst_ioc_summary(deduped)
    if ioc_txt:
        print(f"  {C.CYAN}EXTRACTED INDICATORS{C.RESET}")
        print(ioc_txt)
        print()

    # ── Timeline ─────────────────────────────────────────────────────────────
    tl_txt = _analyst_timeline(deduped)
    if tl_txt:
        print(f"  {C.CYAN}TIMELINE{C.RESET}")
        print(tl_txt)
        print()

    # ── Suppressed count ─────────────────────────────────────────────────────
    if suppressed:
        print(f"  {C.GREY}  {len(suppressed)} POSSIBLE/INSUFFICIENT findings not shown"
              f"  (--verbose to show all){C.RESET}")
        print()

    # ── Other signal hits with narrative ─────────────────────────────────────
    rest = signal[1:] if signal else []
    if rest:
        print(f"  {C.GREY}other signal hits  {'─'*max(1,_W2-20)}{C.RESET}")
        for f in rest[:8]:
            aconf  = _ANALYST_CONF.get(f.confidence, f.confidence)
            col    = _ANALYST_CONF_COLOR.get(aconf, C.GREY)
            label  = (f.method or '')[:44]
            out    = (f.result_text or '')[:160].replace('\n',' ')
            sc     = int(f.score)
            stype  = getattr(f, 'structured_type', '') or ''
            iocs   = getattr(f, 'iocs', []) or []
            badge  = ''
            if stype:
                badge += f" {C.CYAN}{stype}{C.RESET}"
            if iocs:
                kinds = list({i['type'] for i in iocs})[:3]
                badge += f" {C.GREY}IOC:{','.join(kinds)}{C.RESET}"
            print(f"  {col}[{aconf[:4]}]{C.RESET}"
                  f" {C.WHITE}{label:<44}{C.RESET}"
                  f" {C.GREY}[{sc}]{C.RESET}{badge}")
            print(f"       {C.GREY}{out[:160]}{C.RESET}")
            # Analyst narrative
            bundle = _analyst_bundle(f)
            if bundle.get('interpretation'):
                print(f"       {C.GREY}consistent with: {bundle['interpretation'][:120]}{C.RESET}")
            if bundle.get('next_steps'):
                print(f"       {C.GREY}suggest:         {bundle['next_steps'][:120]}{C.RESET}")
        print()

    # ── BEST MATCH — right at cursor ─────────────────────────────────────────
    best = signal[0] if signal else (deduped[0] if deduped else None)
    if best:
        aconf      = _ANALYST_CONF.get(best.confidence, best.confidence)
        col        = _ANALYST_CONF_COLOR.get(aconf, C.GREY)
        method_str = (best.method or '')[:60]
        score_str  = str(int(best.score))
        bundle     = _analyst_bundle(best)
        stype      = getattr(best, 'structured_type', '') or ''
        iocs       = getattr(best, 'iocs', []) or []
        chain_str  = ' → '.join(getattr(best, 'chain', []) or [best.method or ''])
        fid        = getattr(best, 'finding_id', '') or ''
        sup        = getattr(best, 'support_count', 1)

        print()
        print(f"  {col}{C.BOLD}{'━'*_W2}{C.RESET}")
        print(f"  {col}{C.BOLD}  {aconf}  ·  {method_str}  ·  score {score_str}{C.RESET}")
        if fid:
            print(f"  {C.GREY}  finding #{fid}  ·  {chain_str[:60]}{C.RESET}")
        print(f"  {col}{C.BOLD}{'━'*_W2}{C.RESET}")
        # Result content
        preview = (best.result_text or '')[:600].replace('\n', ' ')
        print(f"  {C.WHITE}{preview}{C.RESET}")
        print()
        # Structured type + IOCs
        if stype or iocs:
            stype_str = f"{C.CYAN}type: {stype}  {C.RESET}" if stype else ''
            if iocs:
                kinds    = list({i['type'] for i in iocs})[:5]
                ioc_vals = [i['value'] for i in iocs[:4]]
                ioc_str  = (f"{C.GREY}indicators [{','.join(kinds)}]: "
                            f"{', '.join(ioc_vals)}"
                            f"{'…' if len(iocs)>4 else ''}{C.RESET}")
            else:
                ioc_str = ''
            print(f"  {stype_str}{ioc_str}")
        if sup > 1:
            print(f"  {C.TOXGRN}  corroborated by {sup} independent passes{C.RESET}")
        # Analyst narrative — conservative language
        if bundle.get('interpretation'):
            print(f"  {C.GREY}  consistent with: {bundle['interpretation'][:180]}{C.RESET}")
        if bundle.get('hypothesis'):
            print(f"  {C.GREY}  suggests:        {bundle['hypothesis'][:180]}{C.RESET}")
        if bundle.get('next_steps'):
            print(f"  {C.GREY}  worth verifying: {bundle['next_steps'][:180]}{C.RESET}")
        print(f"  {col}{C.BOLD}{'━'*_W2}{C.RESET}")
        print()


def print_results(findings, source_label, input_size, saved_files=None, verbose=True, nocolor=False):
    if not findings:
        print(f"{C.GREY}  no findings{C.RESET}")
        return

    def _norm(txt):
        return re.sub(r'[^a-z0-9]', '', (txt or '').lower())[:300]

    conf_rank = {'CONFIRMED': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
    sorted_in = sorted(findings,
                       key=lambda f: (conf_rank.get(f.confidence, 0), f.score),
                       reverse=True)

    seen_norm = {}
    aliases   = {}
    for f in sorted_in:
        txt  = f.result_text or ''
        norm = _norm(txt)
        if not norm or len(norm) < 6:
            seen_norm[(f.method or '') + str(id(f))] = f
            continue
        existing = seen_norm.get(norm)
        if existing is None:
            seen_norm[norm] = f
            aliases[id(f)] = []
        else:
            aliases.setdefault(id(existing), []).append(f.method or '')

    deduped = list(seen_norm.values())
    deduped.sort(key=lambda f: (conf_rank.get(f.confidence, 0), f.score), reverse=True)

    saved = saved_files or []

    _STRUCTURAL_KEYWORDS = (
        'Parameter Hints', 'Cipher Profile', 'Substitution Helper',
        'Embedded ASCII', 'Artifact Triage', 'Artifact Tree',
        'Key Hints', 'Cipher family', 'JPEG JSteg capacity',
    )
    def _is_structural(f):
        m = f.method or ''
        return any(kw.lower() in m.lower() for kw in _STRUCTURAL_KEYWORDS)

    signal_findings     = [f for f in deduped if not _is_structural(f)]
    structural_findings = [f for f in deduped if _is_structural(f)]

    TOP_N = None if verbose else 5
    if TOP_N is None:
        top5       = signal_findings
        suppressed = structural_findings
    else:
        top5       = signal_findings[:TOP_N]
        suppressed = signal_findings[TOP_N:] + structural_findings

    best = top5[0] if top5 else (deduped[0] if deduped else None)
    rest = top5[1:] if best else top5

    # ── Totals line first (top of results, farthest from cursor) ────────────
    total     = len(deduped)
    extracted = len([sv for sv in saved if sv])
    confirmed = len([f for f in deduped if f.confidence == 'CONFIRMED'])
    high_c    = len([f for f in deduped if f.confidence == 'HIGH'])
    medium_c  = len([f for f in deduped if f.confidence == 'MEDIUM'])
    low_c     = len([f for f in deduped if f.confidence == 'LOW'])

    tparts = []
    if confirmed: tparts.append("\033[38;5;82m\033[1m%d CONFIRMED\033[0m" % confirmed)
    if high_c:    tparts.append(f"{C.HIGH}{high_c} HIGH{C.RESET}")
    if medium_c:  tparts.append(f"{C.MEDIUM}{medium_c} MEDIUM{C.RESET}")
    if low_c:     tparts.append(f"{C.LOW}{low_c} LOW{C.RESET}")
    if extracted: tparts.append(f"{C.GREEN}{extracted} file{'s' if extracted!=1 else ''} extracted{C.RESET}")

    print(f"  {C.GREY}{_line('=')}{C.RESET}")
    print(f"  {('  |  ').join(tparts)}")
    print()

    # ── Suppressed count (above runners-up) ──────────────────────────────────
    n_sup = len(suppressed)
    if n_sup:
        conf_breakdown = {}
        for f in suppressed:
            c = f.confidence
            conf_breakdown[c] = conf_breakdown.get(c, 0) + 1
        parts_sup = []
        for c in ('CONFIRMED', 'HIGH', 'MEDIUM', 'LOW'):
            if conf_breakdown.get(c):
                col = _CONF_COLOR.get(c, C.GREY)
                parts_sup.append(f"{col}{conf_breakdown[c]} {c}{C.RESET}")
        breakdown = '  |  '.join(parts_sup)
        print(f"  {C.GREY}  {n_sup} additional findings not shown  ({breakdown}{C.GREY}){C.RESET}")
        print(f"  {C.GREY}  --verbose for full list  |  --report saves everything{C.RESET}")
        print()

    # ── Runners-up (above best match) ────────────────────────────────────────
    if rest:
        print(f"  {C.GREY}other hits  {_line('·', C.GREY)}{C.RESET}")
        for f in rest:
            icon       = _CONF_ICON.get(f.confidence, '  [?]')
            color      = _CONF_COLOR.get(f.confidence, C.WHITE)
            label      = _method_label(f.method)
            out        = _format_output(f.result_text or f.note or '', maxlen=180)
            alias_list = aliases.get(id(f), [])
            alias_str  = ''
            if alias_list:
                short     = [_method_label(a) for a in alias_list[:2]]
                alias_str = (f"  {C.GREY}also: " + ", ".join(short) + ("\u2026" if len(alias_list)>2 else "") + f"{C.RESET}")
            sc = f'{C.GREY}[{f.score}]{C.RESET}' if f.score else ''
            print(f"  {icon} {color}{label:<44}{C.RESET} {sc}  {C.WHITE}{out}{C.RESET}{alias_str}")
            # Structured type + IOC summary inline
            stype = getattr(f, 'structured_type', '') or ''
            iocs  = getattr(f, 'iocs', []) or []
            sup   = getattr(f, 'support_count', 1)
            extras2 = []
            if stype:
                extras2.append(f'{C.CYAN}{stype}{C.RESET}')
            if iocs:
                kinds = list({i['type'] for i in iocs})[:3]
                extras2.append(f"{C.GREY}IOC: {', '.join(kinds)} ({len(iocs)}){C.RESET}")
            if sup > 1:
                extras2.append(f'{C.TOXGRN}corroborated x{sup}{C.RESET}')
            if extras2:
                print(f"         {'  '.join(extras2)}")
        print()

    # ── BEST MATCH — printed last, right at cursor ────────────────────────────
    if best and best.result_text:
        alias_list = aliases.get(id(best), [])
        also       = ''
        if alias_list:
            short = [_method_label(a) for a in alias_list[:3]]
            also  = '  also: ' + ', '.join(short) + (f' +{len(alias_list)-3} more' if len(alias_list)>3 else '')
        method_str = _method_label(best.method)
        score_str  = f'score {best.score}' if best.score else ''
        print()
        print(f"  {C.TOXGRN}{C.BOLD}" + chr(9473)*_W + f"{C.RESET}")
        print(f"  {C.TOXGRN}{C.BOLD}  {method_str}  ·  {best.confidence}  ·  {score_str}{C.RESET}")
        print(f"  {C.TOXGRN}{C.BOLD}" + chr(9473)*_W + f"{C.RESET}")
        preview = (best.result_text or '')[:600].replace('\n', ' ')
        print(f"  {C.WHITE}{preview}{C.RESET}")
        # Structured type + IOC summary in best match box
        _bstype = getattr(best, 'structured_type', '') or ''
        _biocs  = getattr(best, 'iocs', []) or []
        _bsup   = getattr(best, 'support_count', 1)
        _bextras = []
        if _bstype:
            _bextras.append(f'{C.CYAN}type: {_bstype}{C.RESET}')
        if _biocs:
            _kinds = list({i['type'] for i in _biocs})[:4]
            _bextras.append(f"{C.GREY}IOC: {', '.join(_kinds)} ({len(_biocs)} found){C.RESET}")
        if _bsup > 1:
            _bextras.append(f'{C.TOXGRN}corroborated by {_bsup} passes{C.RESET}')
        if also:
            print(f"  {C.GREY}{also.strip()}{C.RESET}")
        if _bextras:
            print(f"  {'  '.join(_bextras)}")
        print(f"  {C.TOXGRN}{C.BOLD}" + chr(9473)*_W + f"{C.RESET}")
        print()




class FetchResult:
    __slots__ = ('url', 'raw_bytes', 'text', 'content_type', 'headers', 'status', 'error', 'is_binary', 'detected_type', 'final_url')
    def __init__(self):
        self.url = ''; self.raw_bytes = b''; self.text = ''
        self.content_type = ''; self.headers = {}; self.status = 0
        self.error = ''; self.is_binary = False
        self.detected_type = None; self.final_url = ''

def fetch_url(url: str):
    result = FetchResult()
    result.url = url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url; result.url = url
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0','Accept-Encoding':'identity'})
        with urllib.request.urlopen(req, timeout=URL_TIMEOUT) as resp:
            result.status = resp.getcode()
            result.content_type = resp.headers.get('Content-Type', '')
            result.headers = dict(resp.headers)
            result.final_url = resp.geturl()
            result.raw_bytes = resp.read(MAX_URL_BYTES)
    except urllib.error.HTTPError as e:
        result.error = f'HTTP {e.code}'; result.status = e.code; return result
    except Exception as e:
        result.error = str(e); return result
    result.detected_type = detect_filetype(result.raw_bytes)
    ct = result.content_type.lower()
    is_text = any(x in ct for x in ('text/','json','xml','html','plain'))
    if is_text:
        result.is_binary = False
        result.text = result.raw_bytes.decode('utf-8', errors='replace')
    else:
        result.is_binary = True
        result.text = result.raw_bytes.decode('latin-1')
    return result

class AnalysisEngine:
    def __init__(self, wordlist: set = None, output_dir: str = './output', max_depth: int = 3, stegopw_wordlist: str = None,
                 verbose: bool = True, flags: dict = None):
        self.wordlist = wordlist or set()
        self.output_dir = output_dir
        self.verbose = verbose
        self.flags = flags or {}
        os.makedirs(output_dir, exist_ok=True)

    def _do(self, *keys) -> bool:
        if self.flags.get('all'):
            return True
        decode_flags = ['rot','base','hex','binary','url','morse',
                        'cipher','xor','misc','stego','reverse','deep']
        if not any(self.flags.get(f) for f in decode_flags):
            return True
        return any(self.flags.get(k) for k in keys)

    def analyze(self, data: str, source_label: str = 'INPUT') -> List[Finding]:
        findings = []

        findings += self._try_structural(data)
        if self._do('rot'):
            findings += self._try_rots(data)
        if self._do('base'):
            findings += self._try_bases(data)
        if self._do('hex'):
            findings += self._try_hex(data)
        if self._do('binary'):
            findings += self._try_binary(data)
        if self._do('url'):
            findings += self._try_url(data)
        if self._do('morse'):
            findings += self._try_morse(data)
        if self._do('cipher'):
            findings += self._try_ciphers(data)
        if self._do('xor'):
            findings += self._try_xor(data)
        if self._do('misc'):
            findings += self._try_misc(data)
        if self._do('stego', 'deep'):
            findings += self._try_text_stego(data)
        if self._do('reverse'):
            for f in self._run_text_passes(data[::-1]):
                f.method = '[REVERSED] ' + f.method
                findings.append(f)

        raw = self._try_get_bytes(data)
        if raw and self._do('stego', 'deep'):
            findings += self._try_binary_stego(raw)

        for f in findings:
            if f.result_bytes and not f.filetype:
                ft = detect_filetype(f.result_bytes)
                if ft:
                    f.filetype = ft
                    f.confidence = 'HIGH'

        return findings

    def analyze_string(self, data: str, source_label: str = 'INPUT'):
        return self.analyze(data, source_label)

    def analyze_url(self, url: str) -> List[Finding]:
        fetch = fetch_url(url)
        if fetch.error:
            return [Finding(method="URL Fetch Error",
                result_text=fetch.error, confidence="LOW",
                note=fetch.error)]
        if fetch.is_binary:
            return self.analyze_file(fetch.raw_bytes, url)
        text = fetch.text or fetch.raw_bytes.decode("utf-8", errors="ignore")
        return self.analyze_string(text, url)

    def _ascii_filter(self, findings):
        out = []
        for f in findings:
            if f.result_text:
                printable = sum(1 for c in f.result_text if 32 <= ord(c) < 127)
                if printable / max(len(f.result_text), 1) > 0.90:
                    out.append(f)
            elif f.result_bytes:
                try:
                    t = f.result_bytes.decode('ascii')
                    printable = sum(1 for c in t if 32 <= ord(c) < 127)
                    if printable / max(len(t), 1) > 0.90:
                        f.result_text = t
                        out.append(f)
                except Exception:
                    pass
        return out

    def _try_file_carve(self, data: bytes, filename: str):
        carver = FileCarver(max_depth=self.max_depth, min_size=32,
                            output_dir=self.output_dir, save_carved=self.flags.get('savefile', False))
        hits = carver.carve(data, filename, depth=0)
        findings = []
        for hit in hits:
            note = hit.note
            f = Finding(
                method=f'Carved: {hit.label} @ 0x{hit.offset:x}',
                confidence='HIGH' if hit.bounded else 'MEDIUM',
                note=note,
                result_bytes=hit.data if hit.bounded else None,
                filetype=(hit.ext, hit.label),
            )
            findings.append(f)
            for child in hit.children:
                cf = Finding(
                    method=f'Carved (nested): {child.label} @ 0x{child.offset:x}',
                    confidence='HIGH' if child.bounded else 'MEDIUM',
                    note=child.note,
                    result_bytes=child.data if child.bounded else None,
                    filetype=(child.ext, child.label),
                    )
                findings.append(cf)
        return findings

    def analyze_file(self, data: bytes, filename: str) -> List[Finding]:
        findings = []

        ft = detect_filetype(data)
        if ft:
            findings.append(Finding(
                method='File Magic Bytes (direct)',
                result_bytes=data, filetype=ft, confidence='HIGH',
                note=f'Input is {ft[1]}'))

        poly = check_polyglot(data)
        if poly:
            findings.append(Finding(
                method='Polyglot Detection',
                result_text='\n'.join(poly),
                confidence='HIGH',
                note='File valid in multiple formats simultaneously'))

        embedded = find_embedded_files(data)
        if embedded:
            summary = '\n'.join(
                f'  0x{pos:08X} : {desc} (.{ext})' for pos, ext, desc in embedded)
            findings.append(Finding(
                method='Embedded File Scan (all offsets)',
                result_text=summary,
                confidence='HIGH',
                note=f'{len(embedded)} embedded file type(s) detected'))
            for pos, ext, desc in embedded:
                findings.append(Finding(
                    method=f'Extracted: {desc} at offset 0x{pos:x}',
                    result_bytes=data[pos:],
                    filetype=(ext, desc),
                    confidence='MEDIUM',
                    note='Sliced from detected signature to EOF'))

        if data[:8] == b'\x89PNG\r\n\x1a\n':
            findings += self._analyze_png(data)
        if data[:3] == b'\xFF\xD8\xFF':
            findings += self._analyze_jpeg(data)
        if data[:4] == b'PK\x03\x04':
            findings += self._analyze_zip(data)

        for label, result in lsb_extract_all_planes(data):
            conf, note = self._text_quality(result)
            findings.append(Finding(
                method=f'LSB Steganography ({label})',
                result_text=result, confidence=conf, note=note))

        decompressed = try_zlib_decompress(data)
        if decompressed:
            ft2 = detect_filetype(decompressed)
            if ft2:
                findings.append(Finding(
                    method='Zlib Decompress → File',
                    result_bytes=decompressed, filetype=ft2,
                    confidence='HIGH',
                    note=f'Decompressed to {ft2[1]}'))
            else:
                text = safe_decode_bytes(decompressed)
                if is_mostly_printable(text):
                    conf, note = self._text_quality(text)
                    findings.append(Finding(
                        method='Zlib Decompress → Text',
                        result_text=text, confidence=conf, note=note))

        strings = scan_for_embedded_strings(data, min_len=6)
        interesting = [s for s in strings if self._has_word_content(s)]
        if interesting:
            findings.append(Finding(
                method='Embedded ASCII Strings',
                result_text='\n'.join(interesting[:60]),
                confidence='LOW',
                note=f'{len(interesting)} readable strings found in binary'))

        text_repr = data.decode('utf-8', errors='ignore')
        if text_repr.strip():
            for f in self._run_text_passes(text_repr):
                findings.append(f)

        ws = scan_whitespace_stego(text_repr)
        if ws:
            conf, note = self._text_quality(ws)
            findings.append(Finding(
                method='Whitespace Steganography (SNOW-style)',
                result_text=ws, confidence=conf,
                note='Found in trailing whitespace of text lines'))
        uc = scan_unicode_stego(text_repr)
        if uc:
            conf, note = self._text_quality(uc)
            findings.append(Finding(
                method='Unicode Zero-Width Steganography',
                result_text=uc, confidence=conf,
                note='Decoded from zero-width characters in text'))

        try:
            findings += self._try_file_carve(data, filename)
        except Exception as e:
            findings.append(Finding(method='File Carver', confidence='LOW',
                note=f'carver error: {e}'))
        return findings

    def _analyze_png(self, data: bytes) -> List[Finding]:
        findings = []
        chunks = extract_png_chunks(data)
        interesting_types = {'tEXt', 'zTXt', 'iTXt', 'cHRM', 'hIST', 'oFFs'}
        for chunk_type, chunk_data in chunks:
            if chunk_type in interesting_types:
                try:
                    text = chunk_data.decode('utf-8', errors='replace')
                    conf, note = self._text_quality(text)
                    findings.append(Finding(
                        method=f'PNG Chunk ({chunk_type})',
                        result_text=text, confidence=conf,
                        note=f'Data in PNG {chunk_type} chunk'))
                except Exception:
                    pass
            if chunk_type == 'zTXt':
                try:
                    import zlib
                    null_pos = chunk_data.index(0)
                    compressed = chunk_data[null_pos+2:]
                    decompressed = zlib.decompress(compressed)
                    text = decompressed.decode('utf-8', errors='replace')
                    conf, note = self._text_quality(text)
                    findings.append(Finding(
                        method='PNG zTXt Chunk (decompressed)',
                        result_text=text, confidence=conf,
                        note='Decompressed hidden text from PNG zTXt chunk'))
                except Exception:
                    pass
        return findings

    def _analyze_jpeg(self, data: bytes) -> List[Finding]:
        findings = []
        for comment in extract_jpeg_comments(data):
            conf, note = self._text_quality(comment)
            findings.append(Finding(
                method='JPEG Comment (COM segment)',
                result_text=comment, confidence=conf,
                note='Text in JPEG comment marker'))
        return findings

    def _analyze_zip(self, data: bytes) -> List[Finding]:
        findings = []
        comment = extract_zip_comment(data)
        if comment:
            conf, note = self._text_quality(comment)
            findings.append(Finding(
                method='ZIP Archive Comment',
                result_text=comment, confidence=conf,
                note='Text in ZIP end-of-central-directory comment'))
        return findings

    def _try_structural(self, data: str):
        import re as _rs
        findings = []
        seen = set()

        def _add(method, text, conf, note):
            key = method + text[:40]
            if key not in seen:
                seen.add(key)
                findings.append(Finding(method=method, result_text=text,
                                        confidence=conf, note=note))

        HASH_SIGS = [
            (8,  'CRC32 / Adler32'),
            (16, 'CRC64 or truncated hash'),
            (32, 'MD5 / NTLM'),
            (40, 'SHA1'),
            (56, 'SHA224'),
            (64, 'SHA256 / Keccak-256'),
            (96, 'SHA384'),
            (128,'SHA512'),
        ]
        for m in re.finditer(r'[0-9a-fA-F]{8,128}', data):
            h = m.group(0)
            for length, name in HASH_SIGS:
                if len(h) == length:
                    _add('Hash Detected: ' + name, h, 'HIGH',
                         '%d hex chars = %s  |  position %d in input' % (length, name, m.start()))

        for m in re.finditer(r'[A-Za-z0-9+/]{20,}={0,2}', data):
            blob = m.group(0)
            try:
                decoded = base64.b64decode(blob + '==').decode('utf-8', errors='strict')
                if all(32 <= ord(c) <= 126 for c in decoded):
                    conf = 'CONFIRMED' if re.search(r'[a-z0-9_]{2,}_[a-z0-9_]{2,}|\{[^}]{3,}\}', decoded, re.I) else 'HIGH'
                    _add('Base64 Component', decoded, conf,
                         'base64 blob at position %d decoded to printable text' % m.start())
            except Exception:
                pass

        parts = re.split(r'(?<=[=])|(?=[0-9a-fA-F]{32,})', data.strip())
        parts = [p for p in parts if p.strip()]
        if len(parts) >= 2:
            summary = []
            for i, part in enumerate(parts):
                part = part.strip()
                if re.match(r'^[0-9a-fA-F]{32}$', part):
                    summary.append('part %d: MD5 hash (%s)' % (i+1, part))
                elif re.match(r'^[0-9a-fA-F]{40}$', part):
                    summary.append('part %d: SHA1 hash (%s)' % (i+1, part))
                elif re.match(r'^[0-9a-fA-F]{64}$', part):
                    summary.append('part %d: SHA256 hash (%s)' % (i+1, part))
                elif re.match(r'^[A-Za-z0-9+/]{10,}={0,2}$', part):
                    try:
                        d = base64.b64decode(part + '==').decode('utf-8', errors='strict')
                        if all(32 <= ord(c) <= 126 for c in d):
                            summary.append('part %d: base64 blob → "%s"' % (i+1, d[:60]))
                    except Exception:
                        summary.append('part %d: encoded blob (%s...)' % (i+1, part[:20]))
            if len(summary) >= 2:
                _add('Compound Artifact Analysis',
                     '\n'.join(summary),
                     'CONFIRMED',
                     'Input contains multiple distinct components — decoded above. This is a multi-part artifact. Collect all fragments to reconstruct.')

        frag = re.search(r'fragment[_\-]([a-z0-9]+)', data, re.I)
        if frag:
            _add('Fragment Series Marker',
                 'fragment_%s detected' % frag.group(1),
                 'CONFIRMED',
                 'Part of a multi-fragment challenge. Look for other fragments (a, b, c... or 1, 2, 3...). Collect all to reconstruct the full artifact.')

        flag = re.search(r'([A-Za-z0-9_]{2,}\{[^}]{3,}\})', data)
        if flag:
            _add('CTF Flag Pattern', flag.group(1), 'CONFIRMED',
                 'Standard CTF flag format detected: wrapper{content}')

        for m in re.finditer(r'\b([0-9a-fA-F]{10,31}|[0-9a-fA-F]{33,39}|[0-9a-fA-F]{41,})\b', data):
            h = m.group(1)
            if len(h) % 2 == 0:
                try:
                    decoded = bytes.fromhex(h).decode('utf-8', errors='strict')
                    if all(32 <= ord(c) <= 126 for c in decoded):
                        _add('Hex String Decoded', decoded, 'HIGH',
                             '%d hex chars decoded to ASCII at position %d' % (len(h), m.start()))
                except Exception:
                    pass

        return findings

    def _try_rots(self, data: str) -> List[Finding]:
        findings = []
        for n in range(1, 26):
            decoded = rot_n(data, n)
            conf, note = self._text_quality(decoded)
            if conf == 'HIGH':
                findings.append(Finding(
                    method=f'ROT{n}', result_text=decoded,
                    confidence=conf, note=note))
        for label, fn in [('ROT47', rot47), ('ROT18 (ROT13+ROT5)', rot18)]:
            decoded = fn(data)
            if decoded != data:
                conf, note = self._text_quality(decoded)
                if conf == 'HIGH':
                    findings.append(Finding(method=label, result_text=decoded,
                                            confidence=conf, note=note))
        return findings

    def _try_bases(self, data: str) -> List[Finding]:
        findings = []
        bases = [
            ('Base64', decode_base64),
            ('Base64 (URL-safe)', decode_base64_url),
            ('Base64 (MIME)', decode_base64_mime),
            ('Base32', decode_base32),
            ('Base32 (Extended Hex)', decode_base32hex),
            ('Base32 (Crockford)', decode_base32_crockford),
            ('Base16 (Hex)', decode_base16),
            ('Base85 (Python)', decode_base85),
            ('Base85 (ASCII85/Adobe)', decode_ascii85),
            ('Base85 (Z85/ZeroMQ)', decode_z85),
            ('Base58 (Bitcoin)', decode_base58),
            ('Base58 (Flickr)', decode_base58_flickr),
            ('Base62', decode_base62),
            ('Base45', decode_base45),
            ('Base91', decode_base91),
            ('Base92', decode_base92),
            ('Base36', decode_base36),
            ('Base10 (Decimal bytes)', decode_base10),
            ('Base8 (Octal)', decode_base8),
            ('Base2 (Binary)', decode_base2),
        ]
        for name, fn in bases:
            result = fn(data)
            if not result:
                continue
            ft = detect_filetype(result)
            if ft:
                findings.append(Finding(method=name, result_bytes=result, filetype=ft,
                                        confidence='HIGH', note=f'decoded binary -> {ft[1]}'))
                continue
            text = safe_decode_bytes(result)
            conf, note = self._text_quality(text)
            if conf in ('CONFIRMED', 'HIGH', 'MEDIUM'):
                findings.append(Finding(method=name, result_text=text,
                                        confidence=conf, note=note))
        return findings

    def _try_hex(self, data: str) -> List[Finding]:
        findings = []
        for label, fn in [('Hexadecimal', decode_hex), ('Hex (escaped \\x/% format)', decode_hex_escaped)]:
            result = fn(data)
            if not result:
                continue
            ft = detect_filetype(result)
            if ft:
                findings.append(Finding(method=f'{label} -> Binary', result_bytes=result,
                                        filetype=ft, confidence='HIGH',
                                        note=f'hex decoded to {ft[1]}'))
                continue
            text = safe_decode_bytes(result)
            conf, note = self._text_quality(text)
            if conf in ('CONFIRMED', 'HIGH', 'MEDIUM'):
                findings.append(Finding(method=f'{label} -> ASCII', result_text=text,
                                        confidence=conf, note=note))
        return findings

    def _try_binary(self, data: str) -> List[Finding]:
        findings = []
        for label, fn in [('Binary (01 string)', decode_base2), ('Octal', decode_base8), ('Decimal bytes', decode_base10)]:
            result = fn(data)
            if not result:
                continue
            ft = detect_filetype(result)
            if ft:
                findings.append(Finding(method=label, result_bytes=result, filetype=ft,
                                        confidence='HIGH', note=f'decoded binary -> {ft[1]}'))
                continue
            text = safe_decode_bytes(result)
            conf, note = self._text_quality(text)
            if conf in ('CONFIRMED', 'HIGH', 'MEDIUM'):
                findings.append(Finding(method=label, result_text=text,
                                        confidence=conf, note=note))
        return findings

    def _try_url(self, data: str) -> List[Finding]:
        findings = []
        for label, fn in [('URL Encoding (%XX)', decode_url),
                           ('Double URL Encoding', decode_url_double),
                           ('HTML Entities', decode_html_entities)]:
            result = fn(data)
            if result:
                conf, note = self._text_quality(result)
                findings.append(Finding(method=label, result_text=result,
                                        confidence=conf, note=note))
        return findings

    def _try_morse(self, data: str) -> List[Finding]:
        result = decode_morse(data)
        if result:
            conf, note = self._text_quality(result)
            return [Finding(method='Morse Code', result_text=result,
                            confidence=conf, note=note)]
        return []

    def _try_ciphers(self, data: str) -> List[Finding]:
        findings = []
        atbash = decode_atbash(data)
        if atbash != data:
            conf, note = self._text_quality(atbash)
            if conf == 'HIGH':
                findings.append(Finding(method='Atbash Cipher', result_text=atbash,
                                        confidence=conf, note=note))
        for key in COMMON_VIGENERE_KEYS:
            vig = decode_vigenere(data, key)
            if vig != data:
                conf, note = self._text_quality(vig)
                if conf == 'HIGH':
                    findings.append(Finding(
                        method=f'Vigenère (key="{key}")',
                        result_text=vig, confidence=conf, note=note))
        for a, b in AFFINE_KEYS:
            aff = decode_affine(data, a, b)
            if aff != data:
                conf, note = self._text_quality(aff)
                if conf == 'HIGH':
                    findings.append(Finding(
                        method=f'Affine Cipher (a={a}, b={b})',
                        result_text=aff, confidence=conf, note=note))
        bacon = decode_bacon(data)
        if bacon:
            conf, note = self._text_quality(bacon)
            findings.append(Finding(method="Bacon's Cipher",
                                    result_text=bacon, confidence=conf, note=note))
        for rails in range(2, 6):
            rf = decode_rail_fence(data, rails)
            if rf != data:
                conf, note = self._text_quality(rf)
                if conf == 'HIGH':
                    findings.append(Finding(
                        method=f'Rail Fence ({rails} rails)',
                        result_text=rf, confidence=conf, note=note))
        pb = decode_polybius(data)
        if pb:
            conf, note = self._text_quality(pb)
            findings.append(Finding(method='Polybius Square',
                                    result_text=pb, confidence=conf, note=note))
        tap = decode_tap_code(data)
        if tap:
            conf, note = self._text_quality(tap)
            findings.append(Finding(method='Tap Code',
                                    result_text=tap, confidence=conf, note=note))
        nato = decode_nato(data)
        if nato:
            conf, note = self._text_quality(nato)
            findings.append(Finding(method='NATO Phonetic Alphabet',
                                    result_text=nato, confidence=conf, note=note))
        leet = decode_leetspeak(data)
        if leet != data:
            conf, note = self._text_quality(leet)
            if conf == 'HIGH':
                findings.append(Finding(method='Leet Speak (1337)',
                                        result_text=leet, confidence=conf, note=note))

        for _bs,_bd,_bt in decode_bacon_robust(data, self.wordlist):
            _bc="CONFIRMED" if _bs>=15 else "HIGH" if _bs>=6 else "MEDIUM"
            if _bt not in {f.result_text for f in findings if f.result_text}:
                findings.append(Finding(method=_bd,result_text=_bt,confidence=_bc,note="bacon %.1f"%_bs))
        for _rs,_rc,_rt in decode_railfence_then_bacon(data, self.wordlist):
            _rcc="CONFIRMED" if _rs>=20 else "HIGH" if _rs>=10 else "MEDIUM"
            if _rt not in {f.result_text for f in findings if f.result_text}:
                findings.append(Finding(method=_rc,result_text=_rt,confidence=_rcc,note="rf+bacon %.1f"%_rs))
        a1 = decode_a1z26(data)
        if a1 and len(a1) > 1:
            findings.append(Finding(method="A1Z26", result_text=a1,
                confidence="HIGH" if sum(1 for w in self.wordlist if w in a1.lower() and len(w)>3)>2 else "MEDIUM",
                note="decoded A=1 B=2 ... Z=26"))

        ht = identify_hash(data.strip())
        if ht:
            findings.append(Finding(method="Hash Identification",
                result_text=ht, confidence="HIGH",
                note=ht))

        enc_type = classify_encryption(data)
        if enc_type:
            findings.append(Finding(method="Encryption Classifier",
                result_text=enc_type, confidence="MEDIUM", note=enc_type))

        enc_type = classify_encryption(data)
        if enc_type:
            findings.append(Finding(method="Encryption Classifier",
                result_text=enc_type, confidence="MEDIUM", note=enc_type))

        tri = detect_trifid(data)
        if tri:
            findings.append(Finding(method="Trifid Cipher (detected)",
                result_text=tri, confidence="MEDIUM", note=tri))

        baud = decode_baudot(data)
        if baud:
            findings.append(Finding(method="Baudot/ITA2",
                result_text=baud,
                confidence="HIGH" if sum(1 for w in self.wordlist if w in baud.lower() and len(w)>3)>2 else "MEDIUM",
                note="decoded Baudot ITA2"))

        pun = decode_punycode(data)
        if pun:
            findings.append(Finding(method="Punycode",
                result_text=pun, confidence="HIGH",
                note="decoded punycode/IDN"))

        _enigma_det = detect_enigma(data)
        if _enigma_det:
            findings.append(Finding(method="Enigma (detected)",
                result_text=_enigma_det, confidence="MEDIUM", note=_enigma_det))

        _run_bf = self.flags.get("cipher") or self.flags.get("deep")
        _bfalpha = "".join(c for c in data if c.isalpha())
        if _run_bf:
            if len(_bfalpha) >= 10 and len(_bfalpha) == len(data.strip()):
                for score, key, plain in brute_bifid(data, self.wordlist):
                    findings.append(Finding(method="Bifid cipher",
                        result_text=plain, confidence="HIGH" if score>2 else "MEDIUM",
                        note="bifid %s" % key))
                for score, key, plain in brute_porta(data, self.wordlist):
                    findings.append(Finding(method="Porta cipher",
                        result_text=plain, confidence="HIGH" if score>2 else "MEDIUM",
                        note="porta %s" % key))
            if any(c.isdigit() for c in data) and " " in data:
                for score, key, plain in brute_nihilist(data, self.wordlist):
                    findings.append(Finding(method="Nihilist cipher",
                        result_text=plain, confidence="HIGH" if score>2 else "MEDIUM",
                        note="nihilist %s" % key))
            _adfg_in = data.upper().replace(" ","")
            if len(_adfg_in) >= 6 and all(c in "ADFGVX" for c in _adfg_in):
                for score, key, plain in brute_adfgvx(data, self.wordlist):
                    findings.append(Finding(method="ADFGVX cipher",
                        result_text=plain, confidence="HIGH" if score>2 else "MEDIUM",
                        note="adfgvx %s" % key))
            _hill_in = "".join(c for c in data.upper() if c.isalpha())
            if (4 <= len(_hill_in) <= 30 and " " not in data.strip()
                    and len(_hill_in) % 2 == 0 and len(_hill_in) == len(data.strip())
                    and not any(c.isdigit() for c in data)):
                for score, key, plain in brute_hill_2x2(data, self.wordlist):
                    findings.append(Finding(method="Hill 2x2 cipher",
                        result_text=plain, confidence="HIGH" if score>2 else "MEDIUM",
                        note="hill key=%s" % key))
        if len(data) >= 4:
            for score, chain, plain in beam_chain_decode(
                    data, self.wordlist, max_depth=6, beam_width=18, min_score=10,
                    show_progress=self.verbose):
                findings.append(Finding(
                    method="Decoded chain: %s" % chain,
                    result_text=plain,
                    confidence="HIGH" if score > 8 else "MEDIUM",
                    note="chain depth %d  score %d" % (chain.count('->')+1, score)
                ))

        return findings
        profile = _classify_cipher_profile(data, b'')
        profile_finding = _cipher_profile_finding(data, b'')
        if profile_finding:
            findings.append(profile_finding)
        hints = _parameter_hint_finding(data, b'')
        if hints:
            findings.append(hints)
        alpha = ''.join(c for c in data if c.isalpha())
        if len(alpha) >= 10:
            periods = estimate_vigenere_key_lengths(data, top_n=6)
            for score, key, plain, period in _recover_vigenere_candidates(data, periods=periods, top_n=8):
                conf, note = self._text_quality(plain)
                total = score + (_ngram_score(plain) * 8.0) + (_word_density(plain, self.wordlist) * 40.0)
                if conf in ('HIGH', 'MEDIUM') or total > 10:
                    findings.append(Finding(
                        method=f'Vigenère full recovery (key="{key}", period={period})',
                        result_text=plain,
                        confidence='HIGH' if total > 28 else conf,
                        note=(note + f'; recovered key candidate {key}; period {period}')[:260]
                    ))
            if 0.055 <= profile['ic'] <= 0.085 and len(alpha) >= 12:
                aff_best = []
                for a in [1,3,5,7,9,11,15,17,19,21,23,25]:
                    for b in range(26):
                        plain = decode_affine(data, a, b)
                        if not plain:
                            continue
                        score = (_ngram_score(plain) * 5.0) + (_word_density(plain, self.wordlist) * 35.0) - min(_chi_squared_english(plain), 200.0) / 30.0
                        aff_best.append((score, a, b, plain))
                aff_best.sort(reverse=True)
                for score, a, b, plain in aff_best[:4]:
                    conf, note = self._text_quality(plain)
                    if conf in ('HIGH', 'MEDIUM') or score > 8:
                        findings.append(Finding(method=f'Affine candidate (a={a}, b={b})', result_text=plain, confidence=conf, note=(note + '; affine parameters ranked by tetragrams / words')[:240]))
            for width in estimate_transposition_widths(data, top_n=4):
                plain = _columnar_untranspose(data, width)
                if plain:
                    conf, note = self._text_quality(plain)
                    score = (_ngram_score(plain) * 6.0) + (_word_density(plain, self.wordlist) * 24.0)
                    if conf in ('HIGH','MEDIUM') or score > 4:
                        findings.append(Finding(method=f'Columnar/width candidate ({width})', result_text=plain, confidence=conf, note=(note + '; width chosen by IC / ngram ranking')[:240]))
            if profile['family'].startswith('monoalphabetic') or profile['family'].startswith('transposition'):
                freq = collections.Counter(c.lower() for c in data if c.isalpha())
                common = ''.join(ch for ch, _ in freq.most_common(8))
                findings.append(Finding(method='Substitution Helper', result_text='top ciphertext letters: ' + common + '\ncommon english targets: etaoinsh', confidence='LOW', note='partial progress helper for hard monoalphabetic cases'))
        return findings

    def _try_xor(self, data: str) -> List[Finding]:
        findings = []
        candidates = []
        seen = set()
        def add_blob(blob):
            if blob and blob not in seen:
                seen.add(blob)
                candidates.append(blob)
        try:
            add_blob(data.encode('latin-1'))
        except Exception:
            pass
        for fn in (decode_hex, decode_base64, decode_base64_url, decode_base32):
            try:
                b = fn(data)
                if b:
                    add_blob(b)
            except Exception:
                pass
        short_input = len(data.strip()) < 12
        for raw in candidates:
            for key, text in try_xor_keys(raw):
                conf, note = self._text_quality(text)
                if conf in ('HIGH', 'MEDIUM'):
                    score = _xor_rank_text(text, f'0x{key:02X}')
                    if short_input and score < 35:
                        continue
                    findings.append(Finding(
                        method=f'XOR single-byte (key=0x{key:02X})',
                        result_text=text, confidence=conf, note=note))
            for key, text in try_xor_multibyte(raw):
                conf, note = self._text_quality(text)
                if conf in ('HIGH', 'MEDIUM'):
                    score = _xor_rank_text(text, key.hex())
                    if short_input and score < 45:
                        continue
                    findings.append(Finding(
                        method=f'XOR multi-byte (key=0x{key.hex().upper()})',
                        result_text=text, confidence=conf, note=note))
            for score, key, text, ksize in break_repeating_key_xor(raw, top_n=6):
                conf, note = self._text_quality(text)
                if conf in ('HIGH', 'MEDIUM') or score > 40:
                    findings.append(Finding(
                        method=f'XOR repeating-key (keysize={ksize}, key=0x{key.hex().upper()})',
                        result_text=text,
                        confidence=('HIGH' if score > 70 else conf),
                        note=f'{note}; repeating-key xor keysize candidate {ksize}'))
        return findings

    def _try_misc(self, data: str) -> List[Finding]:
        findings = []
        qp = decode_quoted_printable(data)
        if qp:
            try:
                text = qp.decode('utf-8')
                conf, note = self._text_quality(text)
                findings.append(Finding(method='Quoted-Printable',
                                        result_text=text, confidence=conf, note=note))
            except Exception:
                pass
        uu = decode_uuencode(data)
        if uu:
            ft = detect_filetype(uu)
            if ft:
                findings.append(Finding(method='UUEncoding', result_bytes=uu,
                                        filetype=ft, confidence='HIGH'))
            else:
                text = safe_decode_bytes(uu)
                if is_mostly_printable(text):
                    conf, note = self._text_quality(text)
                    findings.append(Finding(method='UUEncoding',
                                            result_text=text, confidence=conf, note=note))
        pny = decode_punycode(data)
        if pny:
            findings.append(Finding(method='Punycode', result_text=pny,
                                    confidence='MEDIUM', note='IDN/punycode decoded'))
        return findings

    def _try_text_stego(self, data: str) -> List[Finding]:
        findings = []
        ws = scan_whitespace_stego(data)
        if ws:
            conf, note = self._text_quality(ws)
            findings.append(Finding(
                method='Whitespace Steganography (SNOW)',
                result_text=ws, confidence=conf,
                note='Hidden in trailing spaces/tabs'))
        uc = scan_unicode_stego(data)
        if uc:
            conf, note = self._text_quality(uc)
            findings.append(Finding(
                method='Unicode Zero-Width Steganography',
                result_text=uc, confidence=conf,
                note='Hidden in zero-width Unicode characters'))
        return findings

    def _try_binary_stego(self, raw: bytes) -> List[Finding]:
        findings = []
        lsb = lsb_extract_text(raw)
        if lsb and is_mostly_printable(lsb):
            conf, note = self._text_quality(lsb)
            findings.append(Finding(
                method='LSB Steganography (bit-plane 0)',
                result_text=lsb, confidence=conf,
                note='Extracted from LSBs of input bytes'))
        ft = detect_filetype(raw)
        if ft:
            findings.append(Finding(
                method='File Signature (forward)',
                result_bytes=raw, filetype=ft, confidence='HIGH'))
        ft_rev = detect_filetype(raw[::-1])
        if ft_rev:
            findings.append(Finding(
                method='File Signature (reversed bytes)',
                result_bytes=raw[::-1], filetype=ft_rev, confidence='MEDIUM',
                note='Reversed byte order produced valid file signature'))
        return findings

    def _run_text_passes(self, data: str) -> List[Finding]:
        cache_key = ('text_passes', hashlib.sha1(data.encode('utf-8', errors='ignore')).hexdigest(), tuple(sorted(k for k,v in self.flags.items() if v)))
        hit = _cache_get(cache_key)
        if hit is not None:
            return _clone_findings(hit)
        findings = []
        findings += self._try_structural(data)
        findings += self._try_rots(data)
        findings += self._try_bases(data)
        findings += self._try_hex(data)
        findings += self._try_binary(data)
        findings += self._try_url(data)
        findings += self._try_morse(data)
        findings += self._try_ciphers(data)
        findings += self._try_xor(data)
        findings += self._try_misc(data)
        findings = _finalize_findings(findings, 'TEXT_PASS', self.wordlist)
        _cache_put(cache_key, _clone_findings(findings))
        return findings

    def _try_get_bytes(self, data: str) -> Optional[bytes]:
        for fn in (decode_hex, decode_base64):
            b = fn(data)
            if b and detect_filetype(b):
                return b
        return None

    def _text_quality(self, text: str) -> tuple:
        if not text or not text.strip():
            return ('LOW', 'empty result')
        ratio = _hio_printable_ratio(text)
        alpha = _hio_alpha_ratio(text)
        score = _score_candidate(text=text, wordlist=self.wordlist, confidence='LOW')
        if re.search(r'(flag|ctf|rrsw|htb|picoctf|thm)\{[^}]{3,}\}', text.lower()):
            return ('CONFIRMED', f'scored {score} and matches flag pattern')
        if score >= 62 or (ratio > 0.96 and alpha > 0.55 and (is_mostly_words(text, self.wordlist, 0.20) if self.wordlist else False)):
            return ('HIGH', f'scored {score} with strong plaintext indicators')
        if score >= 38 or (ratio > 0.92 and alpha > 0.40):
            return ('MEDIUM', f'scored {score} and is mostly readable')
        if ratio > 0.78:
            return ('LOW', f'scored {score} with partial plaintext indicators')
        return ('LOW', f'scored {score} with weak plaintext indicators')

    def _has_word_content(self, text: str) -> bool:
        if not self.wordlist:
            return len(text) > 8
        tokens = text.lower().split()
        return any(t.strip(string.punctuation) in self.wordlist for t in tokens)

_HIO_ANALYSIS_CACHE = {}
_HIO_CACHE_LIMIT = 96

def _cache_get(key):
    return _HIO_ANALYSIS_CACHE.get(key)

def _cache_put(key, value):
    if len(_HIO_ANALYSIS_CACHE) >= _HIO_CACHE_LIMIT:
        try:
            _HIO_ANALYSIS_CACHE.pop(next(iter(_HIO_ANALYSIS_CACHE)))
        except Exception:
            _HIO_ANALYSIS_CACHE.clear()
    _HIO_ANALYSIS_CACHE[key] = value

def _clone_finding(f):
    nf = Finding(method=getattr(f, 'method', ''),
                 result_text=getattr(f, 'result_text', None),
                 result_bytes=getattr(f, 'result_bytes', None),
                 filetype=getattr(f, 'filetype', None),
                 confidence=getattr(f, 'confidence', 'LOW'),
                 note=getattr(f, 'note', ''))
    for attr in ('entropy', 'score', 'chain', 'rrsw_signal', 'source_label'):
        if hasattr(f, attr):
            setattr(nf, attr, getattr(f, attr))
    return nf

def _clone_findings(items):
    return [_clone_finding(f) for f in (items or [])]

def _hio_entropy(data) -> float:
    if data is None:
        return 0.0
    if isinstance(data, str):
        data = data.encode('utf-8', errors='ignore')
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    out = 0.0
    for c in counts:
        if c:
            p = c / n
            out -= p * math.log2(p)
    return round(out, 3)

def _normalize_chain(f: Finding) -> List[str]:
    if getattr(f, 'chain', None):
        return [str(x).strip() for x in f.chain if str(x).strip()]
    method = (f.method or '').strip()
    chain = []
    if method.startswith('[REVERSED] '):
        chain.append('reverse')
        method = method[len('[REVERSED] '):]
    if '->' in method:
        chain.extend([p.strip() for p in method.split('->') if p.strip()])
    elif method:
        chain.append(method)
    return chain or ['analysis']

def _hio_printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c in string.printable) / max(len(text), 1)

def _hio_alpha_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c.isalpha()) / max(len(text), 1)

def _hio_norm_text(text: str) -> str:
    t = (text or '').lower()
    t = re.sub(r'\s+', ' ', t)
    t = re.sub(r'[^a-z0-9{}:_ -]+', '', t)
    return t.strip()

def _hio_fast_token_score(text: str) -> int:
    tl = _hio_norm_text(text)
    if not tl:
        return 0
    score = 0
    fast_words = {
        'the','and','that','this','with','from','into','hidden','password','secret',
        'flag','ctf','rrsw','http','https','admin','login','token','cookie','user',
        'message','image','file','data','decoded','binary','text','key','cipher',
        'hello','world'
    }
    tokens = re.findall(r"[a-z0-9_']+", tl)
    hits = sum(1 for t in tokens if t in fast_words)
    score += min(hits * 4, 32)
    if re.search(r'(flag|ctf|rrsw|htb|picoctf|thm)\{[^}]{3,}\}', tl):
        score += 80
    if re.search(r'\b[a-z]{3,}_[a-z0-9_]{3,}\b', tl):
        score += 8
    if re.search(r'\b(?:http|https|ftp)://', tl):
        score += 10
    return score

def _ic(text):
    from collections import Counter
    letters = [c.lower() for c in text if c.isalpha()]
    N = len(letters)
    if N < 20: return 0.0
    counts = collections.Counter(letters)
    return sum(n*(n-1) for n in counts.values()) / (N*(N-1))

def _chi_sq(text):
    from collections import Counter
    letters = [c.lower() for c in text if c.isalpha()]
    N = len(letters)
    if N < 20: return 9999.0
    counts = collections.Counter(letters)
    return sum((counts.get(ch,0) - N*exp/100)**2 / (N*exp/100)
               for ch,exp in _EF.items())

def _ic_signal(text):
    ic = _ic(text)
    chi = _chi_sq(text)
    if ic > 0.060:   return ic, chi, 'monoalpha'
    elif ic > 0.055: return ic, chi, 'likely_sub'
    elif ic > 0.048: return ic, chi, 'possible_poly'
    return ic, chi, 'none'

def _chain_score(text, wordlist):
    if not text or len(text) < 2: return 0
    score = 0.0
    tl = text.lower()

    n = max(len(text), 1)
    pr = sum(1 for c in text if 32 <= ord(c) <= 126) / n
    ar = sum(c.isalpha() for c in text) / n
    sr = text.count(' ') / n
    score += pr * 20.0
    score += min(ar, 0.9) * 10.0

    if 0.08 <= sr <= 0.30:   score += 10.0
    elif sr > 0.40:           score -= 5.0

    freq = {}
    for c in text: freq[c] = freq.get(c,0)+1
    ent = -sum((v/n)*math.log2(v/n) for v in freq.values()) if n>1 else 0
    if 3.2 <= ent <= 5.5:    score += 8.0
    elif ent > 6.2:           score -= 8.0

    for pat in ('ctf{','htb{','flag{','thm{','picoctf{','ictf{','root{',
                'hackthebox','tryhackme','rrsw{'):
        if pat in tl: score += 100.0

    words = re.findall(r"[a-z']+", tl)
    common_hits = sum(1 for w in words if w in _CW)
    score += min(common_hits * 3.0, 35.0)

    if wordlist:
        for w in wordlist:
            if len(w) > 5 and w in tl: score += 3
            elif len(w) > 3 and w in tl: score += 1

    if any(c in text for c in ',.;:!?'):   score += 3.0
    if re.search(r'\b(the|and|that|this|with|from|into|have|there)\b', tl): score += 12.0

    score += _tetragram_score(text) * 5.0

    ic = _ic(tl)
    chi = _chi_sq(tl)
    if ic > 0.060:
        score += 12.0 if common_hits == 0 else 6.0
    elif ic > 0.055: score += 6.0
    elif ic > 0.048: score += 2.0
    if ic > 0.055 and chi > 200: score += 5.0

    score += _repeat_token_signal(tl)

    ctrl = sum(1 for c in text if ord(c)<32 and c not in '\t\n\r')
    score -= ctrl * 10.0
    import re as _re2
    score -= len(_re2.findall(r'[^A-Za-z0-9\s]{4,}', text)) * 4.0

    return max(0, int(score))

def _score_candidate(text: str = '', raw: bytes = b'', wordlist=None, confidence='LOW') -> int:
    score = 0
    if raw and not text:
        try:
            text = raw.decode('utf-8', errors='ignore')
        except Exception:
            text = ''
    tl = text or ''
    if tl:
        printable_ratio = _hio_printable_ratio(tl)
        alpha_ratio = _hio_alpha_ratio(tl)
        space_ratio = tl.count(' ') / max(len(tl), 1)
        entropy = _hio_entropy(tl)
        ic, chi, sig_type = _ic_signal(tl)
        score += int(printable_ratio * 24)
        score += int(alpha_ratio * 16)
        if 0.08 <= space_ratio <= 0.34:
            score += 8
        elif 0.04 <= space_ratio <= 0.45:
            score += 3
        score += _hio_fast_token_score(tl)
        if wordlist:
            word_hits = sum(1 for w in wordlist if len(w) > 3 and w in tl.lower())
            score += min(word_hits * 2, 34)
        if 2.8 <= entropy <= 5.6:
            score += 10
        elif entropy > 6.4:
            score -= 8
        if sig_type in ('monoalpha', 'likely_sub') and printable_ratio > 0.85:
            score += 6
        if re.search(r'\b(?:[A-Za-z]{4,}\s+){2,}[A-Za-z]{4,}\b', tl):
            score += 8
        if re.search(r'\b(?:md5|sha1|sha256|aes|xor|base64|hex|png|zip|jpg)\b', tl.lower()):
            score += 5
        if '\n' in tl:
            score += 3
    elif raw:
        ent = _hio_entropy(raw)
        if 2.0 <= ent <= 6.9:
            score += 10
        ft = detect_filetype(raw)
        if ft:
            score += 28
            if ft[0] in ('png','jpg','gif','zip','pdf','pcap','pcapng','db','wav'):
                score += 8
    conf_bonus = {'CONFIRMED': 50, 'HIGH': 24, 'MEDIUM': 10, 'LOW': 0}
    score += conf_bonus.get(confidence, 0)
    return max(0, int(score))

def _rrsw_signal(score: int, entropy: float, confidence: str) -> str:
    if confidence == 'CONFIRMED' or score >= 88:
        return 'RRSW-SIGMA'
    if score >= 58:
        return 'RRSW-TRACK'
    if score >= 30:
        return 'RRSW-TRACE'
    return 'RRSW-NOISE'

def _ngram_score(text: str) -> float:
    s = ''.join(c for c in (text or '').upper() if c.isalpha())
    if len(s) < 4:
        return 0.0
    score = 0.0
    for i in range(len(s) - 3):
        score += TETRAGRAMS.get(s[i:i+4], -0.15)
    return score / max(1, len(s) - 3)

def _word_density(text: str, wordlist=None) -> float:
    words = re.findall(r"\b[a-zA-Z]{3,}\b", text or '')
    if not words:
        return 0.0
    if wordlist:
        hits = sum(1 for w in words if w.lower() in wordlist)
    else:
        hits = sum(1 for w in words if w.lower() in _ENGLISH_TOP)
    return hits / max(1, len(words))

def _looks_binaryish(raw: bytes) -> bool:
    if not raw:
        return False
    nul = raw.count(0)
    high = sum(1 for b in raw if b > 0xF0)
    ctrl = sum(1 for b in raw if b < 9 or 13 < b < 32)
    return (nul / len(raw)) > 0.08 or (ctrl / len(raw)) > 0.18 or (high / len(raw)) > 0.12

def _xor_rank_text(text: str, key_label: str = '') -> int:
    base = _score_candidate(text=text, confidence='LOW')
    tl = (text or '').lower()
    if not tl:
        return 0
    if any(p in tl for p in ('flag{','ctf{','rrsw{','password','secret','http://','https://')):
        base += 60
    if re.search(r'\b(?:the|and|this|that|with|from|user|admin|cookie|token)\b', tl):
        base += 14
    if len(re.findall(r'[A-Za-z]{3,}', tl)) >= 3:
        base += 8
    if key_label and key_label in ('0x00', '0x20', '0xFF'):
        base -= 12
    return base

def _score_text(text, wordlist):
    if not text: return 0
    t = text.lower()
    return sum(1 for w in wordlist if len(w) > 3 and w in t)

def _rot(text, n):
    out = []
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c)-base+n)%26+base))
        else:
            out.append(c)
    return "".join(out)

def _chi_squared_english(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 4:
        return 1e9
    counts = collections.Counter(letters)
    chi = 0.0
    for ch, freq in _ENGLISH_FREQ.items():
        observed = counts.get(ch, 0)
        expected = max(freq * n, 1e-9)
        chi += ((observed - expected) ** 2) / expected
    return chi

def _period_factor_candidates(text: str, min_len: int = 3, max_len: int = 5, top_n: int = 8):
    letters = ''.join(c.lower() for c in text if c.isalpha())
    if len(letters) < 24:
        return []
    spacings = []
    for ngram_len in range(min_len, max_len + 1):
        seen = {}
        for i in range(0, len(letters) - ngram_len + 1):
            gram = letters[i:i+ngram_len]
            if gram in seen:
                spacings.append(i - seen[gram])
            seen[gram] = i
    factors = collections.Counter()
    for dist in spacings:
        for f in range(2, min(20, dist) + 1):
            if dist % f == 0:
                factors[f] += 1
    return [k for k, _ in factors.most_common(top_n)]

def _kasiski_factors(text: str, n_values=(3,4,5), top_n=8):
    s = ''.join(c for c in (text or '').upper() if c.isalpha())
    if len(s) < 18:
        return []
    factors = collections.Counter()
    for n in n_values:
        seen = {}
        for i in range(len(s) - n + 1):
            gram = s[i:i+n]
            if gram in seen:
                dist = i - seen[gram]
                for f in range(2, min(32, dist) + 1):
                    if dist % f == 0:
                        factors[f] += 1
            else:
                seen[gram] = i
    return [k for k, _ in factors.most_common(top_n)]

def _ioc_profile(text: str, max_period=24):
    letters = ''.join(c for c in (text or '').upper() if c.isalpha())
    out = []
    if len(letters) < 20:
        return out
    for p in range(1, min(max_period, len(letters)//2) + 1):
        cols = ['' for _ in range(p)]
        for i, ch in enumerate(letters):
            cols[i % p] += ch
        usable = [c for c in cols if len(c) > 4]
        if not usable:
            continue
        avg_ic = sum(_ic(c) for c in usable) / len(usable)
        out.append((p, avg_ic))
    return out

def _classify_cipher_profile(text: str = '', raw: bytes = b''):
    s = text or ''
    alpha = ''.join(c for c in s if c.isalpha())
    alnum = ''.join(c for c in s if c.isalnum())
    ic = _ic(alpha) if len(alpha) >= 8 else 0.0
    chi = _chi_squared_english(alpha) if len(alpha) >= 10 else 999.0
    pf = _period_factor_candidates(s) if s else []
    kas = _kasiski_factors(s)
    vig = estimate_vigenere_key_lengths(s, top_n=4) if s else []
    trans = estimate_transposition_widths(s, top_n=4) if s else []
    rails = estimate_rail_fence_candidates(s, top_n=4) if s else []
    xork = estimate_repeating_xor_keysizes(raw, top_n=4) if raw else []
    clues = []
    family = 'unknown'
    confidence = 'LOW'
    layers = 1
    if raw and _looks_binaryish(raw) and xork:
        family = 'repeating-key xor or binary-obfuscated payload'
        confidence = 'MEDIUM'
        clues.append('binary distribution and keysize peaks suggest repeating-key xor')
    if alpha and len(alpha) >= 18:
        if 0.060 <= ic <= 0.080 and _word_density(s) < 0.12:
            family = 'monoalphabetic substitution or transposition'
            confidence = 'MEDIUM'
            clues.append('IC is close to English while word density is low')
        elif 0.040 <= ic < 0.060 and (vig or kas or pf):
            family = 'polyalphabetic / Vigenère-like cipher'
            confidence = 'MEDIUM'
            clues.append('periodicity and lower IC suggest polyalphabetic structure')
        elif trans or rails:
            family = 'transposition-style cipher'
            confidence = 'LOW' if confidence == 'LOW' else confidence
            clues.append('column / rail candidates scored above baseline')
    if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', s):
        layers = max(layers, 2)
        clues.append('base-encoding characteristics suggest an outer encoding layer')
    if re.search(r'0x[0-9a-fA-F]{6,}|\\x[0-9a-fA-F]{2}', s):
        layers = max(layers, 2)
        clues.append('hex-style escapes suggest mixed representation layers')
    if xork and family == 'unknown':
        family = 'xor-obfuscated text or payload'
        confidence = 'LOW'
    return {
        'family': family,
        'confidence': confidence,
        'ic': ic,
        'chi': chi,
        'kasiski': kas,
        'period_peaks': vig,
        'trans_widths': trans,
        'rails': rails,
        'xor_keysizes': xork,
        'layers': layers,
        'clues': clues,
    }

def estimate_vigenere_key_lengths(text: str, max_period: int = 20, top_n: int = 5):
    flags = _HIO_ACTIVE_FLAGS
    if flags.get('full_nasty'):
        max_period = max(max_period, _FULL_NASTY_PROFILE['max_key_period'])
        top_n = max(top_n, 8)
    letters = ''.join(c for c in (text or '').upper() if c.isalpha())
    if len(letters) < 18:
        return []
    kas = _kasiski_factors(letters, top_n=top_n * 2)
    profile = _ioc_profile(letters, max_period=max_period)
    scored = []
    for p, avg_ic in profile:
        closeness = 1.0 / (abs(0.066 - avg_ic) + 0.001)
        factor_bonus = 3.5 if p in kas[:3] else (2.0 if p in kas else 0.0)
        repeat_bonus = 1.0 if p in _period_factor_candidates(letters)[:6] else 0.0
        scored.append((closeness + factor_bonus + repeat_bonus, p))
    scored.sort(reverse=True)
    out, seen = [], set()
    for _, p in scored:
        if p not in seen:
            seen.add(p)
            out.append(p)
        if len(out) >= top_n:
            break
    return out

def estimate_transposition_widths(text: str, max_w: int = 16, top_n: int = 5):
    flags = _HIO_ACTIVE_FLAGS
    if flags.get('full_nasty'):
        max_w = max(max_w, _FULL_NASTY_PROFILE['max_trans_width'])
        top_n = max(top_n, 8)
    letters = ''.join(c for c in (text or '') if c.isalpha())
    if len(letters) < 12:
        return []
    scored = []
    for w in range(2, min(max_w, len(letters) - 1) + 1):
        cols = ['' for _ in range(w)]
        for i, ch in enumerate(letters):
            cols[i % w] += ch
        usable = [c for c in cols if len(c) > 4]
        if not usable:
            continue
        avg_ic = sum(_ic(c) for c in usable) / len(usable)
        concat = ' '.join(usable[:min(6, len(usable))])
        ngram = _ngram_score(concat)
        shape = 0.02 if len(letters) % w == 0 else 0.0
        score = (1.0 / (abs(0.066 - avg_ic) + 0.001)) + ngram + shape
        scored.append((score, w))
    scored.sort(reverse=True)
    return [w for _, w in scored[:top_n]]

def estimate_rail_fence_candidates(text: str, max_rails: int = 10, top_n: int = 5):
    flags = _HIO_ACTIVE_FLAGS
    if flags.get('full_nasty'):
        max_rails = max(max_rails, _FULL_NASTY_PROFILE['max_rails'])
        top_n = max(top_n, 8)
    letters = ''.join(c for c in (text or '') if c.isalpha())
    if len(letters) < 12:
        return []
    scored = []
    for rails in range(2, min(max_rails, len(text) - 1) + 1):
        plain = decode_rail_fence(text, rails)
        score = (_ngram_score(plain) * 2.0) + (_word_density(plain) * 8.0) - min(_chi_squared_english(plain), 200.0) / 40.0
        scored.append((score, rails))
    scored.sort(reverse=True)
    return [r for _, r in scored[:top_n]]


def _best_caesar_shift_for_column(column: str):
    best = None
    for shift in range(26):
        plain = rot_n(column, -shift)
        chi = _chi_squared_english(plain)
        if best is None or chi < best[0]:
            best = (chi, shift, plain)
    return best

def _recover_vigenere_candidates(text: str, periods=None, top_n=8):
    flags = globals().get('_HIO_ACTIVE_FLAGS', {}) or {}
    if flags.get('full_nasty'):
        top_n = max(top_n, 10)
    periods = periods or estimate_vigenere_key_lengths(text, top_n=6)
    seen = set()
    results = []
    for period in periods:
        if period < 2:
            continue
        key_chars = []
        alt_key_chars = []
        col_quality = 0.0
        stripped_positions = [i for i, c in enumerate(text) if c.isalpha()]
        letters = ''.join(c.upper() for c in text if c.isalpha())
        if len(letters) < period * 2:
            continue
        for i in range(period):
            col = letters[i::period]
            scored = []
            for shift in range(26):
                dec = ''.join(chr((ord(ch) - 65 - shift) % 26 + 65) for ch in col)
                chi = _chi_squared_english(dec)
                score = -chi + (_ngram_score(dec) * 3.0)
                scored.append((score, shift, dec))
            scored.sort(reverse=True)
            best = scored[0]
            key_chars.append(chr(ord('A') + best[1]))
            alt_key_chars.append(chr(ord('A') + scored[1][1]) if len(scored) > 1 else chr(ord('A') + best[1]))
            col_quality += best[0]
        for key_variant in (''.join(key_chars), ''.join(alt_key_chars)):
            plain = decode_vigenere(text, key_variant.lower())
            marker = (period, key_variant, plain[:160])
            if marker in seen:
                continue
            seen.add(marker)
            score = col_quality + (_ngram_score(plain) * 6.0) + (_word_density(plain) * 30.0)
            results.append((score, key_variant.lower(), plain, period))
    results.sort(reverse=True, key=lambda x: x[0])
    return results[:top_n]

def recover_vigenere_candidates(text: str, periods=None, top_n: int = 5):
    letters = ''.join(c for c in text if c.isalpha())
    if len(letters) < 12:
        return []
    periods = periods or estimate_vigenere_key_lengths(text, top_n=4)
    results = []
    seen = set()
    for period in periods:
        cols = ['' for _ in range(period)]
        idxs = [[] for _ in range(period)]
        j = 0
        for i, ch in enumerate(text):
            if ch.isalpha():
                cols[j % period] += ch
                idxs[j % period].append(i)
                j += 1
        key_chars = []
        col_quality = 0.0
        for col in cols:
            best = _best_caesar_shift_for_column(col)
            if not best:
                key_chars.append('a')
                continue
            chi, shift, _ = best
            key_chars.append(chr(ord('a') + shift))
            col_quality += max(0.0, 20.0 - min(chi, 20.0))
        key = ''.join(key_chars)
        plain = decode_vigenere(text, key)
        marker = (period, plain[:160])
        if marker in seen:
            continue
        seen.add(marker)
        results.append((col_quality, key, plain, period))
    results.sort(reverse=True, key=lambda x: x[0])
    return results[:top_n]

def _columnar_untranspose(text: str, cols: int) -> str:
    t = ''.join(ch for ch in text if ch.isprintable())
    n = len(t)
    if cols < 2 or n < cols:
        return ''
    rows = (n + cols - 1) // cols
    short_cols = cols * rows - n
    lengths = [rows - 1 if i >= cols - short_cols and short_cols else rows for i in range(cols)]
    chunks, pos = [], 0
    for ln in lengths:
        chunks.append(list(t[pos:pos+ln]))
        pos += ln
    out = []
    for r in range(rows):
        for c in range(cols):
            if r < len(chunks[c]):
                out.append(chunks[c][r])
    return ''.join(out)

def _hamming_distance(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))

def _normalized_hamming_for_keysize(data: bytes, keysize: int) -> float:
    blocks = [data[i:i+keysize] for i in range(0, min(len(data), keysize * 8), keysize)]
    blocks = [b for b in blocks if len(b) == keysize]
    if len(blocks) < 4:
        return 999.0
    pairs = list(zip(blocks, blocks[1:]))[:6]
    ds = [_hamming_distance(x, y) / keysize for x, y in pairs]
    return sum(ds) / len(ds) if ds else 999.0

def estimate_repeating_xor_keysizes(data: bytes, min_k: int = 2, max_k: int = 40, top_n: int = 5):
    if not data or len(data) < min_k * 4:
        return []
    scores = []
    max_k = min(max_k, max(2, len(data) // 4))
    for k in range(min_k, max_k + 1):
        score = _normalized_hamming_for_keysize(data, k)
        if score < 999:
            scores.append((score, k))
    scores.sort()
    return [k for _, k in scores[:top_n]]

def _best_single_byte_xor(block: bytes):
    best = None
    for key in range(256):
        dec = bytes(b ^ key for b in block)
        text = dec.decode('latin-1', errors='ignore')
        score = _xor_rank_text(text, f'0x{key:02X}')
        if best is None or score > best[0]:
            best = (score, key, dec)
    return best

def break_repeating_key_xor(data: bytes, max_keysize: int = 40, top_n: int = 5):
    results = []
    seen = set()
    for ksize in estimate_repeating_xor_keysizes(data, 2, max_keysize, top_n=top_n):
        key = bytearray()
        for i in range(ksize):
            block = bytes(data[j] for j in range(i, len(data), ksize))
            best = _best_single_byte_xor(block)
            key.append(best[1] if best else 0)
        decoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        text = decoded.decode('latin-1', errors='ignore')
        score = _xor_rank_text(text, key.hex())
        marker = (bytes(key), text[:160])
        if marker in seen:
            continue
        seen.add(marker)
        results.append((score, bytes(key), text, ksize))
    results.sort(reverse=True, key=lambda x: x[0])
    return results[:top_n]

def try_xor_keys(data: bytes):
    results = []
    seen = set()
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        try:
            text = decoded.decode('utf-8', errors='ignore')
        except Exception:
            continue
        if not text or _hio_printable_ratio(text) < 0.84:
            continue
        score = _xor_rank_text(text, f'0x{key:02X}')
        norm = _hio_norm_text(text)[:260]
        if score < 30 or norm in seen:
            continue
        seen.add(norm)
        results.append((score, key, text))
    results.sort(reverse=True)
    return [(key, text) for score, key, text in results[:24]]

def try_xor_multibyte(data: bytes):
    common_keys = [
        b'\xde\xad', b'\xbe\xef', b'\xca\xfe', b'\xba\xbe',
        b'\xff\xfe', b'\xaa\x55', b'\x55\xaa', b'\xde\xad\xbe\xef',
        b'\xca\xfe\xba\xbe', b'\x13\x37', b'\x41\x41', b'\x00\xff',
        b'key', b'flag', b'ctf', b'rrsw', b'xor', b'admin', b'root'
    ]
    results = []
    seen = set()
    for key in common_keys:
        decoded = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        try:
            text = decoded.decode('utf-8', errors='ignore')
        except Exception:
            continue
        if not text or _hio_printable_ratio(text) < 0.84:
            continue
        score = _xor_rank_text(text, '0x' + key.hex().upper())
        norm = _hio_norm_text(text)[:260]
        if score < 28 or norm in seen:
            continue
        seen.add(norm)
        results.append((score, key, text))
    results.sort(reverse=True)
    return [(key, text) for score, key, text in results[:16]]

def _parameter_hint_finding(text: str = '', raw: bytes = b''):
    hints = []
    note_bits = []
    profile = _classify_cipher_profile(text, raw)
    if profile['family'] != 'unknown':
        hints.append(f'probable family: {profile["family"]} ({profile["confidence"].lower()})')
    if text:
        vig = estimate_vigenere_key_lengths(text, top_n=6)
        trans = estimate_transposition_widths(text, top_n=6)
        rails = estimate_rail_fence_candidates(text, top_n=6)
        if vig:
            hints.append('key length candidates: ' + ', '.join(map(str, vig)))
            note_bits.append('vigenere / polyalpha periodicity detected')
        if trans:
            hints.append('column / width candidates: ' + ', '.join(map(str, trans)))
            note_bits.append('transposition width peaks present')
        if rails:
            hints.append('rail fence candidates: ' + ', '.join(map(str, rails)))
            note_bits.append('zig-zag transposition candidates present')
        if profile['kasiski']:
            hints.append('repeat-spacing factors: ' + ', '.join(map(str, profile['kasiski'][:6])))
    if raw:
        xor_sizes = estimate_repeating_xor_keysizes(raw, top_n=6)
        if xor_sizes:
            hints.append('repeating-key xor sizes: ' + ', '.join(map(str, xor_sizes)))
            note_bits.append('normalized Hamming distance favored repeating-key xor')
    if not hints:
        return None
    return Finding(method=_KEY_PARAM_METHOD, result_text='\n'.join(hints), confidence='MEDIUM', note='; '.join(note_bits)[:260])

def _cipher_profile_finding(text: str = '', raw: bytes = b''):
    profile = _classify_cipher_profile(text, raw)
    if profile['family'] == 'unknown' and not profile['clues']:
        return None
    lines = [
        f'family: {profile["family"]}',
        f'confidence: {profile["confidence"]}',
        f'estimated layers: {profile["layers"]}',
    ]
    if profile['period_peaks']:
        lines.append('period peaks: ' + ', '.join(map(str, profile['period_peaks'][:6])))
    if profile['trans_widths']:
        lines.append('transposition widths: ' + ', '.join(map(str, profile['trans_widths'][:6])))
    if profile['rails']:
        lines.append('rail candidates: ' + ', '.join(map(str, profile['rails'][:6])))
    if profile['xor_keysizes']:
        lines.append('xor keysizes: ' + ', '.join(map(str, profile['xor_keysizes'][:6])))
    if profile['clues']:
        lines.append('why: ' + '; '.join(profile['clues'][:4]))
    return Finding(method=_CIPHER_PROFILE_METHOD, result_text='\n'.join(lines), confidence=profile['confidence'], note='cipher-family classification and parameter estimation')

def _make_key_hint_finding(text: str = '', raw: bytes = b''):
    base = _parameter_hint_finding(text, raw)
    if not base:
        return None
    lines = [base.result_text]
    full = _HIO_ACTIVE_FLAGS
    if full.get('full_nasty') and text:
        rec = _recover_vigenere_candidates(text, periods=estimate_vigenere_key_lengths(text, top_n=4), top_n=3)
        if rec:
            lines.append('recovered vigenere key candidates: ' + ', '.join(f'{k}/{p}' for _, k, _, p in rec[:3]))
    base.result_text = '\n'.join(lines)
    return base

def _substitution_score(text: str) -> float:
    s = ''.join(c for c in text.upper() if 'A' <= c <= 'Z')
    if len(s) < 20:
        return -1e9
    score = 0.0
    for i in range(len(s)-3):
        score += SUB_TETRAGRAMS.get(s[i:i+4], -4.5)
    common = (' THE ',' AND ','ING ','ION ','ED ',' TO ',' OF ','ER ')
    up = ' ' + text.upper() + ' '
    score += sum(up.count(token) * 3.0 for token in common)
    printable = sum(1 for c in text if c.isprintable()) / max(1, len(text))
    score += printable * 8.0
    return score

def _initial_sub_key(ciphertext: str):
    counts = collections.Counter(c for c in ciphertext.upper() if 'A' <= c <= 'Z')
    ordered = [c for c,_ in counts.most_common()]
    remaining = [c for c in EN_FREQ if c not in ordered]
    plain_order = ordered + remaining
    key = {cipher: plain for cipher, plain in zip(plain_order, EN_FREQ)}
    for c in string.ascii_uppercase:
        key.setdefault(c, c)
    return key

def _decrypt_substitution(ciphertext: str, key_map: dict) -> str:
    out = []
    for ch in ciphertext:
        up = ch.upper()
        if 'A' <= up <= 'Z':
            dec = key_map.get(up, up)
            out.append(dec if ch.isupper() else dec.lower())
        else:
            out.append(ch)
    return ''.join(out)

def _swap_key(key_map: dict):
    a, b = random.sample(list(string.ascii_uppercase), 2)
    inv = dict(key_map)
    inv[a], inv[b] = inv[b], inv[a]
    return inv

def _hill_climb_substitution(ciphertext: str, restarts=12, iterations=2500):
    best = None
    best_score = -1e18
    seed_key = _initial_sub_key(ciphertext)
    for r in range(max(4, restarts)):
        key = dict(seed_key)
        if r:
            for _ in range(25 + r * 2):
                key = _swap_key(key)
        plain = _decrypt_substitution(ciphertext, key)
        score = _substitution_score(plain)
        temp_best_key, temp_best_plain, temp_best_score = dict(key), plain, score
        no_improve = 0
        for _ in range(iterations):
            cand_key = _swap_key(key)
            cand_plain = _decrypt_substitution(ciphertext, cand_key)
            cand_score = _substitution_score(cand_plain)
            if cand_score > score or random.random() < 0.002:
                key, plain, score = cand_key, cand_plain, cand_score
                if cand_score > temp_best_score:
                    temp_best_key, temp_best_plain, temp_best_score = dict(cand_key), cand_plain, cand_score
                    no_improve = 0
                else:
                    no_improve += 1
            else:
                no_improve += 1
            if no_improve > 900:
                break
        if temp_best_score > best_score:
            best = (temp_best_key, temp_best_plain, temp_best_score)
            best_score = temp_best_score
    return best

def _likely_substitution_cipher(text: str) -> bool:
    s = ''.join(c for c in text.upper() if 'A' <= c <= 'Z')
    if len(s) < 60:
        return False
    unique = len(set(s))
    ic = _ic(s)
    words = _word_density(text) if '_word_density' in globals() else 0.0
    return unique >= 12 and 0.055 <= ic <= 0.078 and words < 0.18

def _monoalphabetic_findings(text: str, wordlist=None, full_nasty=False):
    findings = []
    if not _likely_substitution_cipher(text):
        return findings
    restarts = 20 if full_nasty else 8
    iterations = 4500 if full_nasty else 1800
    best = _hill_climb_substitution(text, restarts=restarts, iterations=iterations)
    if not best:
        return findings
    key_map, plain, raw_score = best
    density = _word_density(plain, wordlist) if '_word_density' in globals() else 0.0
    ngram = _ngram_score(plain) if '_ngram_score' in globals() else 0.0
    total = max(10.0, raw_score/6.0 + density*60.0 + ngram*8.0)
    f = Finding(
        method='Monoalphabetic substitution hill-climb',
        result_text=plain,
        confidence='MEDIUM' if density < 0.18 else 'HIGH',
        note='Heuristic hill-climbing solve for probable monoalphabetic substitution cipher.'
    )
    f.chain = ['substitution_hillclimb']
    f.score = total
    f.signal = 'RRSW-TRACK' if density > 0.16 else 'RRSW-TRACE'
    f.why = 'Cipher profile looked monoalphabetic. Hill-climbing improved tetragram and word-density scores.'
    f.key_hints = [{'kind':'substitution_key_preview','value':' '.join(f'{k}->{v}' for k,v in list(key_map.items())[:12])}]
    findings.append(f)
    return findings

_FAST_TRANSFORMS = (
    ['reverse', 'atbash'] +
    [f'rot{n}' for n in range(1,26)] +
    ['base64', 'base64url', 'base32', 'hex', 'url', 'html', 'binary', 'a1z26', 'morse',
     'bacon_ab', 'bacon_01', 'polybius', 'railfence2', 'railfence3', 'railfence4',
     'scytale2', 'scytale3', 'leet_speak_decode', 'decimal_bytes']
)

def _apply_transform(text, name):
    """Route a named transform. Returns str or None."""
    import base64 as _b64, urllib.parse, html as _html

    def _pr(s):
        return sum(1 for c in s if 32<=ord(c)<=126)/max(len(s),1)

    def _b32(t):
        try:
            r = _b64.b32decode(t.upper()+'='*((8-len(t)%8)%8)).decode('utf-8',errors='ignore')
            return r if len(r)>2 else None
        except Exception: return None

    def _hexd(t):
        try:
            c = t.replace(' ','').replace('0x','').replace('\\x','')
            if all(x in '0123456789abcdefABCDEF' for x in c) and len(c)%2==0:
                return bytes.fromhex(c).decode('utf-8',errors='ignore')
        except Exception: pass
        return None

    def _bacon(t, mode):
        try:
            s = t.upper().replace(' ','')
            if mode=='01': s=s.replace('0','A').replace('1','B')
            elif mode=='io': s=s.replace('I','A').replace('O','B')
            bm={'AAAAA':'A','AAAAB':'B','AAABA':'C','AAABB':'D','AABAA':'E',
                'AABAB':'F','AABBA':'G','AABBB':'H','ABAAA':'I','ABAAB':'J',
                'ABABA':'K','ABABB':'L','ABBAA':'M','ABBAB':'N','ABBBA':'O',
                'ABBBB':'P','BAAAA':'Q','BAAAB':'R','BAABA':'S','BAABB':'T',
                'BABAA':'U','BABAB':'V','BABBA':'W','BABBB':'X','BBAAA':'Y','BBAAB':'Z'}
            cl = re.sub(r'[^AB]','',s)
            if len(cl)<5: return None
            r=''.join(bm.get(cl[i:i+5],'?') for i in range(0,len(cl)-4,5))
            return r.lower() if '?' not in r and r else None
        except Exception: return None

    def _rail(t, rails):
        t2 = t.replace(' ','') if len(t.replace(' ',''))>4 else t
        n = len(t2)
        if n<rails: return None
        fence=[[] for _ in range(rails)]; rail,d=0,1
        for i in range(n):
            fence[rail].append(i)
            if rail==0: d=1
            elif rail==rails-1: d=-1
            rail+=d
        order=[i for r in fence for i in r]; res=['']*n
        for i,pos in enumerate(order): res[pos]=t2[i]
        return ''.join(res)

    def _scytale(t, cols):
        t2=t.replace(' ',''); n=len(t2)
        if n<cols: return None
        rows=(n+cols-1)//cols; pad=t2.ljust(rows*cols)
        return ''.join(pad[c*rows+r] for r in range(rows) for c in range(cols)).strip()

    def _vigenere_key(t, key):
        result,ki='',0
        for c in t:
            if c.isalpha():
                base=ord('A') if c.isupper() else ord('a')
                shift=ord(key[ki%len(key)].upper())-ord('A')
                result+=chr((ord(c.upper())-ord('A')-shift)%26+base); ki+=1
            else: result+=c
        return result

    # Static dispatch
    _S = {
        'reverse':      lambda t: t[::-1],
        'atbash':       lambda t: ''.join(chr(65+25-(ord(c)-65)) if c.isupper() else
                                          chr(97+25-(ord(c)-97)) if c.islower() else c for c in t),
        'base64':       lambda t: (lambda r: r if len(r)>2 else None)(
                            _b64.b64decode(t+'==').decode('utf-8',errors='ignore')),
        'base64url':    lambda t: (lambda r: r if len(r)>2 else None)(
                            _b64.urlsafe_b64decode(t+'==').decode('utf-8',errors='ignore')),
        'base32':       _b32,
        'hex':          _hexd,
        'url':          lambda t: urllib.parse.unquote(t) if urllib.parse.unquote(t)!=t else None,
        'html':         lambda t: _html.unescape(t) if _html.unescape(t)!=t else None,
        'morse':        decode_morse,
        'binary':       lambda t: (''.join(chr(int(tk,2)) for tk in t.strip().split())
                                   if all(all(c in '01' for c in tk) and len(tk)==8
                                          for tk in t.strip().split()) else None),
        'a1z26':        lambda t: (''.join(chr(n+64) for n in
                                   [int(x) for x in re.split(r'[\s,.\-]+',t.strip()) if x])
                                   if all(1<=int(x)<=26 for x in re.split(r'[\s,.\-]+',t.strip()) if x) else None),
        'a1z26_reverse':lambda t: (''.join(chr(ord('z')-n+1)
                                   for n in [int(x) for x in re.split(r'[\s,\-]+',t.strip()) if x.isdigit()]
                                   if 1<=n<=26) or None),
        'caesar_brute': lambda t: None,
        'polybius':     lambda t: (''.join('ABCDEFGHIKLMNOPQRSTUVWXYZ'[(int(p[0])-1)*5+(int(p[1])-1)]
                                   for p in re.findall(r'[1-5][1-5]',t.replace(' ',''))
                                   if (int(p[0])-1)*5+(int(p[1])-1)<25).lower() or None),
        'tap_code':     lambda t: (''.join('ABDEFGHIKLMNOPQRSTUVWXYZ'[(int(a)-1)*5+(int(b)-1)]
                                   for a,b in re.findall(r'(\d)\s+(\d)',t)
                                   if 0<=(int(a)-1)*5+(int(b)-1)<24).lower() or None),
        'bacon_ab':     lambda t: _bacon(t,'ab'),
        'bacon_01':     lambda t: _bacon(t,'01'),
        'bacon_io':     lambda t: _bacon(t,'io'),
        'phone_keypad': lambda t: (''.join({'2':'a','22':'b','222':'c','3':'d','33':'e','333':'f',
                                    '4':'g','44':'h','444':'i','5':'j','55':'k','555':'l',
                                    '6':'m','66':'n','666':'o','7':'p','77':'q','777':'r',
                                    '7777':'s','8':'t','88':'u','888':'v','9':'w','99':'x',
                                    '999':'y','9999':'z'}.get(tk,'?')
                                    for tk in t.strip().split()) or None),
        'nibble_swap':  lambda t: (lambda r: r if _pr(r)>0.8 else None)(
                            ''.join(chr(((ord(c)&0x0F)<<4)|((ord(c)&0xF0)>>4)) for c in t)),
        'bits_reverse': lambda t: (lambda r: r if _pr(r)>0.8 else None)(
                            ''.join(chr(int(f'{ord(c):08b}'[::-1],2)) for c in t)),
        'mirror_alphabet':lambda t: ''.join(
                            chr((ord('A') if c.isupper() else ord('a'))+25-
                                (ord(c)-(ord('A') if c.isupper() else ord('a'))))
                            if c.isalpha() else c for c in t),
        'dvorak_to_qwerty':lambda t: ''.join(
                            'qwertyuiopasdfghjklzxcvbnm'['pyfgcrlaoeuidhtnsqjkxbmwvz'.index(c)]
                            if c in 'pyfgcrlaoeuidhtnsqjkxbmwvz' else c for c in t.lower()),
        'keyboard_shift':lambda t: ''.join(
                            'pyfgcrlaoeuidhtnsqjkxbmwvz'['qwertyuiopasdfghjklzxcvbnm'.index(c)]
                            if c in 'qwertyuiopasdfghjklzxcvbnm' else c for c in t.lower()),
        'leet_speak_decode':lambda t: ''.join(
                            {'0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','@':'a','!':'i'}.get(c,c)
                            for c in t.lower()),
        'decimal_bytes':lambda t: (lambda nums: ''.join(chr(n) for n in nums)
                                   if len(nums)>=2 and all(32<=n<=126 for n in nums) else None)(
                            [int(x) for x in re.split(r'[\s,]+',t.strip()) if x.isdigit()]),
    }

    try:
        if name in _S: return _S[name](text)
        if name.startswith('rot') and name[3:].isdigit():
            n=int(name[3:])
            return ''.join(chr((ord(c)-65+n)%26+65) if c.isupper() else
                           chr((ord(c)-97+n)%26+97) if c.islower() else c for c in text)
        if name.startswith('railfence') and name[9:].isdigit():
            return _rail(text, int(name[9:]))
        if name.startswith('scytale') and name[7:].isdigit():
            return _scytale(text, int(name[7:]))
        if name.startswith('vigenere_'):
            key={'key':'key','secret':'secret','password':'password',
                 'crypto':'crypto','flag':'flag'}.get(name[9:])
            return _vigenere_key(text, key) if key else None
        if name.startswith('xor_0x'):
            key=int(name[4:],16)
            r=''.join(chr(ord(c)^key) for c in text)
            return r if _pr(r)>0.8 else None
    except Exception: pass
    return None


def _beam_normsig(text):
    tl = (text or '').strip().lower()
    compact = re.sub(r'\s+', ' ', tl)
    alnum = re.sub(r'[^a-z0-9{}]', '', compact)
    return compact[:220], alnum[:220]

def _beam_change_ratio(a, b):
    if not a and not b:
        return 0.0
    m = min(len(a), len(b))
    if m == 0:
        return 1.0
    diff = sum(1 for i in range(m) if a[i] != b[i])
    diff += abs(len(a) - len(b))
    return diff / max(len(a), len(b), 1)

def _beam_plainish(text):
    if not text:
        return False
    n = max(len(text), 1)
    printable = sum(1 for c in text if 32 <= ord(c) <= 126 or c in '\n\t\r') / n
    alpha = sum(1 for c in text if c.isalpha()) / n
    return printable >= 0.92 and alpha >= 0.35

def _beam_chain_penalty(chain):
    penalty = 0
    if len(chain) >= 2 and chain[-1] == chain[-2]:
        penalty += 14
    if len(chain) >= 2 and chain[-2:] == ['reverse', 'reverse']:
        penalty += 20
    if len(chain) >= 2 and chain[-2:] == ['atbash', 'atbash']:
        penalty += 20
    if len(chain) >= 2 and chain[-1].startswith('rot') and chain[-2].startswith('rot'):
        penalty += 10
    if len(chain) >= 3:
        tail = tuple(chain[-3:])
        if tail in {('reverse','atbash','reverse'), ('atbash','reverse','atbash')}:
            penalty += 20
    penalty += max(len(chain) - 1, 0) * 4
    return penalty

def _beam_should_skip(current, result, chain, transform):
    if not result or len(result) < 2:
        return True
    if result == current:
        return True
    if _beam_change_ratio(current, result) < 0.03:
        return True
    if len(chain) >= 1:
        prev = chain[-1]
        if transform == prev and transform in _BEAM_RISKY_TRANSFORMS:
            return True
        if prev == 'reverse' and transform == 'reverse':
            return True
        if prev == 'atbash' and transform == 'atbash':
            return True
        if prev.startswith('rot') and transform.startswith('rot'):
            return True
    if len(result) > 4000:
        return True
    printable = sum(1 for c in result if 32 <= ord(c) <= 126 or c in '\n\t\r') / max(len(result), 1)
    if printable < 0.55 and transform in _BEAM_DECODE_TRANSFORMS:
        return True
    if len(result) <= 6 and '{' not in result and '}' not in result:
        return True
    return False

def _looks_plaintext(text: str) -> bool:
    if not text or len(text) < 8:
        return False
    pr = _hio_printable_ratio(text)
    ar = _hio_alpha_ratio(text)
    ent = _hio_entropy(text)
    words = len(re.findall(r"\b[a-zA-Z]{3,}\b", text))
    return pr > 0.93 and ar > 0.45 and 2.6 <= ent <= 5.6 and words >= 2

def _normalize_visible(text: str) -> str:
    t = (text or '').lower()
    t = re.sub(r'\s+', ' ', t)
    t = re.sub(r'[^a-z0-9{}:_./ -]+', '', t)
    return t.strip()



def _family_for_transform(name: str) -> str:
    if name in ('reverse', 'atbash'):
        return name
    if name.startswith('rot'):
        return 'rot'
    if name.startswith('base64'):
        return 'base64'
    if name == 'base32':
        return 'base32'
    if name == 'hex':
        return 'hex'
    if name == 'url':
        return 'url'
    if name == 'html':
        return 'html'
    if name == 'binary':
        return 'binary'
    if name == 'a1z26':
        return 'a1z26'
    if name == 'morse':
        return 'morse'
    return name

def _candidate_transforms(text: str, chain_steps):
    s = (text or '').strip()
    transforms = ['reverse', 'atbash']
    if not _looks_plaintext(s):
        transforms.extend([f'rot{n}' for n in range(1, 26)])
    compact = ''.join(s.split())
    if compact and re.fullmatch(r'[A-Za-z0-9+/=_-]+', compact):
        transforms.extend(['base64', 'base64url'])
    if compact and re.fullmatch(r'[A-Z2-7=]+', compact.upper()):
        transforms.append('base32')
    hx = re.sub(r'(?:0x|\\x|\s|:|,)', '', s, flags=re.I)
    if len(hx) >= 8 and len(hx) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', hx):
        transforms.append('hex')
    if '%' in s:
        transforms.append('url')
    if '&' in s and ';' in s:
        transforms.append('html')
    if re.fullmatch(r'[01\s]+', s) and len(compact) >= 16:
        transforms.append('binary')
    if re.fullmatch(r'[0-9\s,.-]+', s) and len(s.split()) >= 2:
        transforms.append('a1z26')
    if all(c in '.- /|\n\t' for c in s) and len(compact) >= 6:
        transforms.append('morse')
    seen_fams = {_family_for_transform(x) for x in chain_steps[-2:]}
    uniq = []
    used = set()
    for t in transforms:
        fam = _family_for_transform(t)
        if fam in seen_fams and fam not in ('reverse', 'atbash'):
            continue
        if t not in used:
            used.add(t)
            uniq.append(t)
    return uniq

def _beam_chain_decode_impl(text, wordlist, max_depth=6, beam_width=24, min_score=16, show_progress=True):
    import sys, time, random
    _MATRIX_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*<>?/"
    _GRN = "\033[38;5;82m"; _DIM = "\033[2m"; _RST = "\033[0m"; _CLR = "\033[2K\r"
    t_start = time.time()
    total_ops = max_depth * max(beam_width, 1) * 18
    op_count = 0

    def _progress(current_transform, chain_steps, hits):
        nonlocal op_count
        op_count += 1
        if not show_progress or op_count % 40 != 0:
            return
        elapsed = time.time() - t_start
        rate = op_count / elapsed if elapsed > 0 else 1
        eta = max(0, (total_ops - op_count) / rate)
        noise = ''.join(random.choice(_MATRIX_CHARS) for _ in range(28))
        chain_str = (' -> '.join(chain_steps) + ' -> ' + current_transform)[-28:]
        sys.stderr.write(f"{_CLR}  {_GRN}{noise}{_RST}  {_DIM}depth {len(chain_steps)+1}  chain: {chain_str:<30}  hits: {hits}  ~{eta:.0f}s{_RST}")
        sys.stderr.flush()

    candidates = [(0, [], text)]
    found = []
    seen_texts = {_normalize_visible(text)[:800]}
    family_cap = {'rot': 4, 'base64': 4, 'base32': 2, 'hex': 2, 'reverse': 4, 'atbash': 4, 'url': 2, 'html': 2, 'binary': 2, 'a1z26': 2, 'morse': 2}

    for depth in range(1, max_depth + 1):
        next_candidates = []
        fam_counts = {}
        for _, chain, current in candidates:
            if _looks_plaintext(current) and _chain_score(current, wordlist) >= max(min_score + 18, 28):
                continue
            for transform in _candidate_transforms(current, chain):
                fam = _family_for_transform(transform)
                if fam_counts.get(fam, 0) >= family_cap.get(fam, 3) * max(1, beam_width // 8):
                    continue
                _progress(transform, chain, len(found))
                result = _apply_transform(current, transform)
                if not result or len(result) < 2:
                    continue
                if result == current:
                    continue
                norm = _normalize_visible(result)[:800]
                if norm in seen_texts:
                    continue
                if sum(1 for c in result if ord(c) < 32 and c not in '\t\n\r') > 6:
                    continue
                if _hio_printable_ratio(result) < 0.62 and not re.search(r'flag\{|ctf\{|rrsw\{', result.lower()):
                    continue
                seen_texts.add(norm)
                score = _chain_score(result, wordlist)
                if _looks_plaintext(result):
                    score += 10
                if len(chain) and _family_for_transform(chain[-1]) == fam:
                    score -= 8
                new_chain = chain + [transform]
                if score >= min_score:
                    found.append((score, ' -> '.join(new_chain), result))
                fam_counts[fam] = fam_counts.get(fam, 0) + 1
                next_candidates.append((score, new_chain, result))
        if not next_candidates:
            break
        next_candidates.sort(key=lambda x: (x[0], -len(x[1]), _hio_printable_ratio(x[2])), reverse=True)
        diverse = []
        fam_seen = {}
        for item in next_candidates:
            fam = _family_for_transform(item[1][-1]) if item[1] else 'root'
            if fam_seen.get(fam, 0) >= max(2, beam_width // 5):
                continue
            fam_seen[fam] = fam_seen.get(fam, 0) + 1
            diverse.append(item)
            if len(diverse) >= beam_width * 2:
                break
        candidates = diverse or next_candidates[:beam_width]

    if show_progress:
        elapsed = time.time() - t_start
        sys.stderr.write(f"{_CLR}  {_GRN}chain analysis complete{_RST}  {_DIM}{elapsed:.2f}s  {len(found)} candidates{_RST}\n")
        sys.stderr.flush()

    results = []
    seen_out = set()
    for score, chain, result in sorted(found, reverse=True):
        norm = _normalize_visible(result)[:600]
        if norm in seen_out:
            continue
        seen_out.add(norm)
        results.append((score, chain, result))
        if len(results) >= 12:
            break
    return results

def beam_chain_decode(text, wordlist, max_depth=6, beam_width=28, min_score=14, show_progress=True):
    flags = _HIO_ACTIVE_FLAGS
    if flags.get('full_nasty'):
        max_depth  = max(max_depth,  _FULL_NASTY_PROFILE['beam_depth'])
        beam_width = max(beam_width, _FULL_NASTY_PROFILE['beam_width'])
        min_score  = min(min_score,  _FULL_NASTY_PROFILE['beam_min_score'])
    return _beam_chain_decode_impl(
        text, wordlist,
        max_depth=max_depth, beam_width=beam_width,
        min_score=min_score, show_progress=show_progress,
    )

def _artifact_triage_text(text: str = '', raw: bytes = b'') -> str:
    bits = []
    if text:
        if re.search(r'\b(?:from:|to:|subject:|received:|message-id:|dkim|spf)\b', text, re.I):
            bits.append('email / header-like material present')
        if re.search(r'\b(?:onion|bitcoin|wallet|monero|tor)\b', text, re.I):
            bits.append('ioc-like domain or darkweb indicator present')
        if re.search(r'\b(?:cmd\.exe|powershell|bash_history|wget|curl|ssh|scp)\b', text, re.I):
            bits.append('shell history or command-line residue present')
        if re.search(r'\b(?:api[_-]?key|token|secret|bearer|authorization)\b', text, re.I):
            bits.append('credential / token language present')
        if re.search(r'\b(?:user-agent|cookie:|host:|referer:|content-type:)\b', text, re.I):
            bits.append('http headers or web traffic material present')
    if raw and _looks_binaryish(raw):
        bits.append('binary distribution suggests container, image, or compressed payload rather than plain text')
    return '; '.join(dict.fromkeys(bits)) if bits else ''

def _artifact_tree_summary(findings):
    children = []
    for f in findings:
        if getattr(f, 'result_bytes', None) and getattr(f, 'filetype', None):
            children.append(f'{getattr(f, "method", "artifact")} -> {f.filetype[1]}')
    if not children:
        return None
    return Finding(method=_ARTIFACT_TREE_METHOD, result_text='\n'.join(children[:30]), confidence='LOW', note='summary of binary child artifacts currently in result set')

def _zip_member_findings(data: bytes, engine=None, source_label='ZIP'):
    """
    Deep ZIP triage: member listing, per-entry metadata, timestamps,
    encrypted member detection, archive comment, nested archive flagging.
    """
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            # Archive-level comment
            comment = zf.comment
            if comment:
                try:
                    c_text = comment.decode('utf-8', errors='replace').strip()
                    if c_text:
                        findings.append(Finding(
                            method='ZIP archive comment',
                            result_text=c_text,
                            confidence='HIGH',
                            note='Embedded archive comment: %d bytes' % len(comment),
                            source_label=source_label,
                        ))
                except Exception:
                    pass

            import hashlib as _hl
            import datetime as _dt

            infos             = zf.infolist()
            encrypted_members = []
            nested_archives   = []
            member_lines      = []

            for info in infos:
                if info.is_dir():
                    member_lines.append('[DIR]  %s' % info.filename)
                    continue

                is_enc = bool(info.flag_bits & 0x1)
                if is_enc:
                    encrypted_members.append(info.filename)

                try:
                    ts_tuple = info.date_time
                    ts = _dt.datetime(*ts_tuple).isoformat() if ts_tuple[0] > 1980 else ''
                except Exception:
                    ts = ''

                lower_fn = info.filename.lower()
                is_nested = any(lower_fn.endswith(x) for x in (
                    '.zip','.jar','.war','.ear','.docx','.xlsx','.pptx','.gz','.7z'))
                if is_nested:
                    nested_archives.append(info.filename)

                enc_label = '[ENC] ' if is_enc else ''
                nested_label = '  [nested]' if is_nested else ''
                member_lines.append('%s%s  %s  size=%d%s' % (
                    enc_label, info.filename, ts, info.file_size, nested_label))

                if is_enc:
                    continue

                try:
                    payload = zf.read(info.filename)
                except Exception:
                    continue

                ft     = detect_filetype(payload)
                sha256 = _hl.sha256(payload).hexdigest()
                note   = 'ZIP member %s (%d bytes, sha256=%s...)' % (
                    info.filename, len(payload), sha256[:16])

                member = Finding(
                    method='ZIP member: %s' % info.filename,
                    result_bytes=payload,
                    filetype=ft,
                    confidence='HIGH' if ft else 'MEDIUM',
                    note=note,
                    source_label=source_label,
                )
                member.child_count = 0
                member.input_sha256 = sha256
                if ts:
                    member.why = 'member timestamp: %s' % ts
                findings.append(member)

                try:
                    text = payload.decode('utf-8', errors='ignore')
                    if text.strip():
                        did_engine = False
                        if engine:
                            try:
                                sub = engine.analyze_string(text[:4096], info.filename)
                                findings.extend(sub)
                                did_engine = True
                            except Exception:
                                pass
                        if not did_engine:
                            findings.append(Finding(
                                method='ZIP member text: %s' % info.filename,
                                result_text=text[:2000],
                                confidence='MEDIUM',
                                note='Text content of ZIP member %s' % info.filename,
                                source_label=source_label,
                            ))
                except Exception:
                    pass

            # Inventory
            if member_lines:
                inv_text = '\n'.join(member_lines[:100])
                findings.append(Finding(
                    method='ZIP member inventory',
                    result_text=inv_text,
                    confidence='LOW',
                    note='%d members, %d encrypted, %d nested archives' % (
                        len(member_lines), len(encrypted_members), len(nested_archives)),
                    source_label=source_label,
                ))

            if encrypted_members:
                enc_text = '\n'.join(encrypted_members[:20])
                findings.append(Finding(
                    method='ZIP encrypted members detected',
                    result_text=enc_text,
                    confidence='HIGH',
                    note='%d encrypted members -- password required' % len(encrypted_members),
                    source_label=source_label,
                ))

            if nested_archives:
                nest_text = '\n'.join(nested_archives[:10])
                findings.append(Finding(
                    method='ZIP nested archives detected',
                    result_text=nest_text,
                    confidence='MEDIUM',
                    note='%d nested archive(s) within container' % len(nested_archives),
                    source_label=source_label,
                ))

    except zipfile.BadZipFile as err:
        findings.append(Finding(
            method='ZIP parse error',
            result_text=str(err),
            confidence='LOW',
            note='File has ZIP magic but could not be parsed: %s' % err,
            source_label=source_label,
        ))
    except Exception:
        pass
    return findings



def _smart_boundary(data: bytes, offset: int, ext: str):
    max_sizes = {
        'png': 20_000_000, 'jpg': 20_000_000, 'gif': 10_000_000, 'bmp': 50_000_000,
        'pdf': 50_000_000, 'zip': 100_000_000, 'gz': 50_000_000, '7z': 100_000_000,
        'rar': 100_000_000, 'pcap': 200_000_000, 'sqlite': 100_000_000, 'db': 100_000_000,
    }
    nxt = None
    for sig, _, _, _ in MAGIC:
        pos = data.find(sig, offset + 1)
        if pos != -1 and (nxt is None or pos < nxt):
            nxt = pos
    cap = offset + max_sizes.get(ext, 8_000_000)
    if nxt is None:
        return min(len(data), cap)
    return min(nxt, len(data), cap)


def find_embedded_files(data: bytes) -> List[Tuple[int, str, str]]:
    found = []
    limit = min(len(data), 100_000_000)
    seen = set()
    for magic, offset_hint, ext, desc in FILE_SIGNATURES:
        start = 0
        while True:
            pos = data.find(magic, start, limit)
            if pos == -1:
                break
            key = (pos, ext)
            if key not in seen:
                seen.add(key)
                found.append((pos, ext, desc))
            start = pos + 1
    return sorted(found)

def _extract_bit_stream(bits):
    if len(bits) < 8:
        return b''
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | (b & 1)
        out.append(byte)
    return bytes(out)

def _score_stego_text(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for c in text if c.isprintable()) / max(1, len(text))
    words = _word_density(text) if '_word_density' in globals() else 0.0
    ngram = _ngram_score(text) if '_ngram_score' in globals() else 0.0
    return printable * 8.0 + words * 40.0 + ngram * 6.0

def _looks_like_meaningful_text(text: str, wordlist: set = None) -> bool:
    if not text or len(text.strip()) < 6:
        return False
    score = _score_stego_text(text, wordlist)
    if score >= 18.0:
        return True
    if wordlist:
        words = re.findall(r"[A-Za-z]{3,}", text.lower())
        if words and sum(1 for w in words if w in wordlist) >= 2:
            return True
    return False

def _iter_visual_lsb_candidates(img, full_nasty: bool = False):
    rgba = img.convert('RGBA')
    pixels = list(rgba.getdata())
    bit_range = range(0, 3) if full_nasty else range(0, 1)
    channel_sets = {
        'R': lambda p, bit: [px[0] >> bit & 1 for px in p],
        'G': lambda p, bit: [px[1] >> bit & 1 for px in p],
        'B': lambda p, bit: [px[2] >> bit & 1 for px in p],
        'A': lambda p, bit: [px[3] >> bit & 1 for px in p],
        'RGB': lambda p, bit: [b for px in p for b in ((px[0] >> bit) & 1, (px[1] >> bit) & 1, (px[2] >> bit) & 1)],
        'BGR': lambda p, bit: [b for px in p for b in ((px[2] >> bit) & 1, (px[1] >> bit) & 1, (px[0] >> bit) & 1)],
        'RGBA': lambda p, bit: [b for px in p for b in ((px[0] >> bit) & 1, (px[1] >> bit) & 1, (px[2] >> bit) & 1, (px[3] >> bit) & 1)],
    }
    for bit in bit_range:
        for label, fn in channel_sets.items():
            yield f'{label} bit{bit}', _extract_bit_stream(fn(pixels, bit), max_bytes=(262144 if full_nasty else 65536))

def _img_mode_color(pixels, sample=2000):
    from collections import Counter
    buckets = Counter()
    step = max(1, len(pixels) // sample)
    for px in pixels[::step]:
        if isinstance(px, (list, tuple)) and len(px) >= 3:
            buckets[(px[0]//8*8, px[1]//8*8, px[2]//8*8)] += 1
    if not buckets:
        return (248, 248, 248)
    dominant = buckets.most_common(1)[0][0]
    return dominant

def _visual_background_text(img, wordlist=None, full_nasty=False):
    results = []
    try:
        rgba = img.convert('RGBA')
        w, h = rgba.size
        pixels = list(rgba.getdata())

        bg = _img_mode_color(pixels)

        def _dev(px):
            return abs(int(px[0]) - bg[0]) + abs(int(px[1]) - bg[1]) + abs(int(px[2]) - bg[2])

        LOW, HIGH = 3, 80
        candidate_map = []
        for px in pixels:
            d = _dev(px)
            candidate_map.append(d if LOW <= d <= HIGH else 0)

        for ch_idx, ch_name in enumerate(['R', 'G', 'B']):
            text = ''
            for i, d in enumerate(candidate_map):
                if d > 0:
                    v = pixels[i][ch_idx]
                    text += chr(v) if 32 <= v <= 126 else '.'
            import re as _re2
            runs = _re2.findall(r'[!-~]{4,}', text)
            if runs:
                combined = ' '.join(runs[:60])
                if _looks_like_meaningful_text(combined, wordlist) or any(
                    len(r) >= 8 for r in runs
                ):
                    results.append((
                        f'Background text ({ch_name} channel, bg≈{bg})',
                        combined[:500]
                    ))

        dev_text = ''.join(
            chr(d) if 32 <= d <= 126 else '.'
            for d in candidate_map if d > 0
        )
        if _looks_like_meaningful_text(dev_text[:2000], wordlist):
            results.append(('Background text (deviation-magnitude encoding)', dev_text[:500]))

    except Exception:
        pass
    return results

def _visual_alpha_direct(img, wordlist=None):
    results = []
    try:
        rgba = img.convert('RGBA')
        pixels = list(rgba.getdata())

        semi = [px for px in pixels if 0 < px[3] < 255]
        if not semi:
            return results

        direct = ''.join(chr(px[3]) if 32 <= px[3] <= 126 else '.' for px in semi)
        if _looks_like_meaningful_text(direct[:2000], wordlist):
            results.append(('Alpha direct value encoding', direct[:500]))

        for ch_idx, name in [(0,'R'), (1,'G'), (2,'B')]:
            ch_text = ''.join(chr(px[ch_idx]) if 32 <= px[ch_idx] <= 126 else '.' for px in semi[:2000])
            if _looks_like_meaningful_text(ch_text, wordlist):
                results.append((f'Semi-transparent pixel {name} value encoding', ch_text[:500]))

    except Exception:
        pass
    return results

def _visual_strided_scan(img, wordlist=None, full_nasty=False):
    results = []
    try:
        rgba = img.convert('RGBA')
        pixels = list(rgba.getdata())
        max_stride = 33 if full_nasty else 17

        for stride in range(1, max_stride):
            sampled = pixels[::stride]
            for ch_idx, name in [(0,'R'), (1,'G'), (2,'B')]:
                text = ''.join(
                    chr(px[ch_idx]) if 32 <= px[ch_idx] <= 126 else '.'
                    for px in sampled[:1000]
                )
                if _looks_like_meaningful_text(text, wordlist):
                    results.append((
                        f'Strided pixel {name} (stride={stride})',
                        text[:500]
                    ))

    except Exception:
        pass
    return results

def _parse_jpeg_huffman_tables(data: bytes) -> tuple:
    """
    Parse JPEG markers to extract Huffman tables, quantization tables,
    frame info, and the raw SOS compressed bitstream.
    Returns (raw_stream_bytes, huffman_tables, comp_tables, frame_info) or (None,...).
    """
    import struct
    from io import BytesIO
    buf = BytesIO(data)
    def read_u16():
        b = buf.read(2)
        return struct.unpack('>H', b)[0] if len(b) == 2 else 0
    def next_marker():
        while True:
            b = buf.read(1)
            if not b:
                return None
            if b == b'\xff':
                m = buf.read(1)
                if m and m != b'\xff' and m != b'\x00':
                    return m[0]
    soi = buf.read(2)
    if soi != b'\xff\xd8':
        return None, {}, {}, {}
    huffman_tables = {}
    frame_info = {}
    while True:
        marker = next_marker()
        if marker is None:
            break
        if marker == 0xD9:
            break
        if marker in (0xC0, 0xC1, 0xC2):
            length = read_u16() - 2
            seg = buf.read(length)
            if len(seg) < 6:
                continue
            height = struct.unpack('>' + 'H', seg[1:3])[0]
            width  = struct.unpack('>' + 'H', seg[3:5])[0]
            ncomp  = seg[5]
            comps = []
            for i in range(ncomp):
                if 6 + i*3 + 2 >= len(seg):
                    break
                comps.append({'id': seg[6+i*3], 'qt': seg[6+i*3+2]})
            frame_info = {'w': width, 'h': height, 'comp': comps}
            continue
        if marker == 0xDB:
            length = read_u16() - 2
            seg = buf.read(length)
            continue
        if marker == 0xC4:
            length = read_u16() - 2
            seg = buf.read(length)
            pos = 0
            while pos < length:
                if pos >= len(seg):
                    break
                tc_tid = seg[pos]; pos += 1
                tc  = (tc_tid >> 4) & 0xF
                tid = tc_tid & 0xF
                if pos + 16 > len(seg):
                    break
                counts = list(seg[pos:pos+16]); pos += 16
                total_syms = sum(counts)
                if pos + total_syms > len(seg):
                    break
                values = list(seg[pos:pos+total_syms]); pos += total_syms
                codes = {}
                code = 0
                val_idx = 0
                for ln, count in enumerate(counts):
                    for _ in range(count):
                        if val_idx < len(values):
                            codes[(ln + 1, code)] = values[val_idx]
                            val_idx += 1
                        code += 1
                    code <<= 1
                huffman_tables[(tc, tid)] = codes
            continue
        if marker == 0xDA:
            sos_len = read_u16() - 2
            sos_hdr = buf.read(sos_len)
            if not sos_hdr:
                break
            ncomp_s = sos_hdr[0]
            comp_tables = {}
            for i in range(ncomp_s):
                if 1 + i*2 + 1 >= len(sos_hdr):
                    break
                cid = sos_hdr[1 + i*2]
                tb  = sos_hdr[1 + i*2 + 1]
                comp_tables[cid] = ((tb >> 4) & 0xF, tb & 0xF)
            raw = bytearray()
            while True:
                b = buf.read(1)
                if not b:
                    break
                if b == b'\xff':
                    nb = buf.read(1)
                    if nb == b'\x00':
                        raw.append(0xFF)
                    else:
                        break
                else:
                    raw.append(b[0])
            return bytes(raw), huffman_tables, comp_tables, frame_info
        else:
            length = read_u16() - 2
            buf.read(length)
    return None, {}, {}, {}


def _jsteg_extract(data: bytes) -> tuple:
    """
    Extract JSteg-style payload from JPEG DCT coefficients.
    JSteg embeds secret bits in the LSBs of non-zero AC DCT coefficients.
    Returns (payload_bytes, n_nonzero_coeffs, capacity_bytes) or (None, 0, 0).
    """
    raw, huffman_tables, comp_tables, frame_info = _parse_jpeg_huffman_tables(data)
    if not raw or not huffman_tables or not frame_info:
        return None, 0, 0

    bits_raw = len(raw) * 8

    def get_bit(pos):
        if pos >= bits_raw:
            return 0
        return (raw[pos >> 3] >> (7 - (pos & 7))) & 1

    def huff_decode(tc, tid, pos):
        table = huffman_tables.get((tc, tid), {})
        code = 0
        for ln in range(1, 17):
            if pos >= bits_raw:
                return None, pos
            code = (code << 1) | get_bit(pos)
            pos += 1
            sym = table.get((ln, code))
            if sym is not None:
                return sym, pos
        return None, pos

    def coeff_decode(nbits, pos):
        if nbits == 0:
            return 0, pos
        val = 0
        for _ in range(nbits):
            val = (val << 1) | get_bit(pos)
            pos += 1
        if nbits > 0 and val < (1 << (nbits - 1)):
            val -= (1 << nbits) - 1
        return val, pos

    comp_ids = [c['id'] for c in frame_info.get('comp', [])]
    if not comp_ids:
        comp_ids = list(comp_tables.keys())

    dc_prev = {cid: 0 for cid in comp_ids}
    jsteg_bits = []
    pos = 0
    W = frame_info.get('w', 0)
    H = frame_info.get('h', 0)
    max_mcus = ((W + 7) // 8) * ((H + 7) // 8) * len(comp_ids) + 1

    for _ in range(max_mcus):
        if pos >= bits_raw - 32:
            break
        for cid in comp_ids:
            if cid not in comp_tables:
                continue
            dc_id, ac_id = comp_tables[cid]
            # DC coefficient
            dc_sym, pos = huff_decode(0, dc_id, pos)
            if dc_sym is None:
                break
            dc_val, pos = coeff_decode(dc_sym, pos)
            dc_prev[cid] = dc_prev.get(cid, 0) + dc_val
            # 63 AC coefficients
            k = 1
            while k < 64:
                ac_sym, pos = huff_decode(1, ac_id, pos)
                if ac_sym is None:
                    k = 64; break
                if ac_sym == 0x00:  # EOB
                    k = 64; break
                run   = (ac_sym >> 4) & 0xF
                nbits = ac_sym & 0xF
                k += run
                if k >= 64:
                    break
                if nbits == 0:
                    k += 1
                    continue
                ac_val, pos = coeff_decode(nbits, pos)
                # JSteg: skip +-1 coefficients (they would become 0 on modif)
                # Standard JSteg skips only 0, but many variants also skip +-1
                if ac_val != 0:
                    jsteg_bits.append(abs(ac_val) & 1)
                k += 1

    if not jsteg_bits:
        return None, 0, 0

    capacity = len(jsteg_bits) // 8
    # Assemble bytes
    payload = bytearray()
    for i in range(0, len(jsteg_bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | jsteg_bits[i + j]
        payload.append(byte)
    return bytes(payload), len(jsteg_bits), capacity


def _jpeg_stego_findings(raw_bytes: bytes, source_label: str = '',
                          wordlist=None, filename: str = '') -> list:
    """
    Run all JPEG-specific steganography detection passes:
      1. Extension mismatch detection (JPEG magic with non-JPEG extension)
      2. JSteg DCT coefficient LSB extraction
      3. JPEG comment field extraction
      4. Capacity analysis
    Returns a list of Finding objects.
    """
    findings = []
    if not raw_bytes or len(raw_bytes) < 4:
        return findings
    if raw_bytes[:2] != b'\xff\xd8':
        return findings

    # ── Pass 1: Extension mismatch ──────────────────────────────────────────
    ext = (filename.rsplit('.', 1)[-1].lower() if '.' in filename else '')
    if ext and ext not in ('jpg', 'jpeg', 'jpe', 'jif', 'jfif'):
        f = Finding(
            method='JPEG extension mismatch',
            result_text=f'File is a JPEG (FFD8FF magic) but has extension .{ext}',
            confidence='HIGH',
            note='Extension mismatch is a common CTF misdirection technique'
        )
        f.score = 72
        f.rrsw_signal = 'RRSW-TRACK'
        f.why = (f'JPEG magic bytes FFD8FF detected in file with .{ext} extension. '
                 f'Tools relying on file extension may misidentify or skip this file. '
                 f'Check for JSteg, F5, or Steghide payloads.')
        findings.append(f)

    # ── Pass 2: JSteg DCT coefficient extraction ────────────────────────────
    payload, n_bits, capacity = _jsteg_extract(raw_bytes)
    if payload and capacity > 0:
        # Analyse the payload
        printable_ratio = sum(1 for b in payload[:512] if 32 <= b <= 126) / min(512, len(payload))
        is_text = printable_ratio > 0.80
        # Check for common file magic in payload
        has_magic = (payload[:2] == b'\x1f\x8b' or  # gzip
                     payload[:4] == b'PK\x03\x04' or  # zip
                     payload[:3] == b'BZh' or          # bzip2
                     payload[:4] == b'\x89PNG' or      # PNG
                     payload[:4] == b'7z\xbc\xaf' or  # 7zip
                     payload[:5] == b'Rar!\x1a')       # rar

        # Score the payload
        score = 30  # base score for any JSteg extraction
        if is_text:
            score += 40
        if has_magic:
            score += 35
        if is_text and wordlist:
            words = [w for w in payload[:1024].decode('utf-8', errors='replace').lower().split() if len(w) >= 3]
            word_hits = sum(1 for w in words if w in wordlist)
            if words:
                score += int(word_hits / max(1, len(words)) * 30)

        if is_text:
            text_preview = payload[:1024].decode('utf-8', errors='replace')
            conf = 'HIGH' if score >= 62 else 'MEDIUM'
        elif has_magic:
            text_preview = f'[Binary payload detected: {payload[:4].hex()} magic bytes]' 
            conf = 'HIGH'
        else:
            text_preview = f'[{len(payload)} bytes extracted, not plaintext]' 
            conf = 'LOW'

        f = Finding(
            method='JSteg DCT coefficient extraction',
            result_text=text_preview,
            result_bytes=payload if not is_text else None,
            confidence=conf,
            note=(f'Extracted from {n_bits} non-zero AC DCT coefficients. '
                  f'JPEG capacity: ~{capacity} bytes. '
                  f'Printable ratio: {printable_ratio:.0%}.')
        )
        f.score = score
        f.rrsw_signal = 'RRSW-TRACK' if score >= 58 else 'RRSW-TRACE'
        f.why = (
            f'JSteg embeds data in the LSBs of non-zero AC DCT coefficients. '
            f'This JPEG has {n_bits} non-zero AC coefficients = {capacity} bytes capacity. '
            f'Payload printable ratio: {printable_ratio:.0%}. '
        )
        findings.append(f)

        # If payload looks like text, also pass it through the analysis engine
        if is_text and len(text_preview.strip()) >= 8:
            # Add a capacity analysis finding regardless
            cap_f = Finding(
                method='JPEG JSteg capacity analysis',
                result_text=(f'JPEG carrier: {capacity} bytes capacity in non-zero AC coefficients. '
                             f'Extension: .{ext}. '
                             f'Payload extracted: {len(payload)} bytes.'),
                confidence='LOW',
                note='JPEG DCT steganography capacity report'
            )
            cap_f.score = 20
            cap_f.rrsw_signal = 'RRSW-NOISE'
            cap_f.why = 'Informational: JPEG carrier analysis for steganography capacity'
            findings.append(cap_f)

    return findings

def analyze_image_visual_stego(data: bytes, filename: str = '', wordlist: set = None,
                               full_nasty: bool = False):
    findings = []
    try:
        from PIL import Image, ImageOps
        import io as _io
        img = Image.open(_io.BytesIO(data))
    except Exception:
        return findings

    seen = set()

    def _push_finding(method: str, raw: bytes, note: str, confidence: str = 'MEDIUM'):
        key = (method, hashlib.md5(raw[:65536]).hexdigest())
        if key in seen:
            return
        seen.add(key)
        ft = detect_filetype(raw)
        if ft:
            findings.append(Finding(
                method=method,
                result_bytes=raw,
                filetype=ft,
                confidence='HIGH',
                note=f'{note} Recovered bytes look like {ft[1]}.'
            ))
            return
        text = ''.join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else ' ' for b in raw[:4096]).strip()
        if _looks_like_meaningful_text(text, wordlist):
            findings.append(Finding(
                method=method,
                result_text=text[:2000],
                result_bytes=raw,
                confidence=confidence,
                note=note
            ))

    def _push_text(method: str, text: str, note: str, confidence: str = 'MEDIUM'):
        key = (method, text[:200])
        if key in seen:
            return
        seen.add(key)
        if text.strip():
            findings.append(Finding(
                method=method,
                result_text=text[:2000],
                confidence=confidence,
                note=note
            ))

    for label, raw in _iter_visual_lsb_candidates(img, full_nasty=full_nasty):
        if raw:
            _push_finding(f'Visual stego LSB extract ({label})', raw,
                          'Recovered from image pixel-channel LSB scan.',
                          confidence='MEDIUM' if not full_nasty else 'HIGH')

    try:
        gray = ImageOps.grayscale(img)
        gray_bits = list(gray.getdata())
        bit_range = range(0, 3) if full_nasty else range(0, 1)
        for bit in bit_range:
            raw = _extract_bit_stream([(px >> bit) & 1 for px in gray_bits],
                                      max_bytes=(262144 if full_nasty else 65536))
            if raw:
                _push_finding(f'Visual stego grayscale LSB extract (bit{bit})', raw,
                              'Recovered from grayscale LSB scan.', confidence='MEDIUM')
    except Exception:
        pass

    for label, text in _visual_background_text(img, wordlist, full_nasty):
        _push_text(f'Visual stego background text ({label})', text,
                   'Text detected in near-background-coloured pixels via contrast enhancement.',
                   confidence='HIGH' if _looks_like_meaningful_text(text, wordlist) else 'MEDIUM')

    for label, text in _visual_alpha_direct(img, wordlist):
        _push_text(f'Visual stego alpha channel ({label})', text,
                   'Text recovered from alpha channel values of semi-transparent pixels.',
                   confidence='HIGH')

    for label, text in _visual_strided_scan(img, wordlist, full_nasty):
        _push_text(f'Visual stego strided scan ({label})', text,
                   'Text recovered by sampling every N-th pixel channel value.',
                   confidence='MEDIUM')

    return findings

def _light_stego_findings(data: bytes, filename: str, full_nasty=False):
    findings = []
    name = (filename or '').lower()
    # JPEG detection by magic bytes, not extension (catches .png-named JPEGs)
    is_jpeg_magic = data[:2] == b'\xff\xd8' if data else False
    is_image_ext = any(name.endswith(ext) for ext in ('.png','.bmp','.jpg','.jpeg','.webp','.tif','.tiff'))
    if not is_image_ext and not is_jpeg_magic:
        return findings
    # Run JPEG DCT stego pass whenever we see JPEG magic bytes
    if is_jpeg_magic:
        findings.extend(_jpeg_stego_findings(data, source_label=filename,
                                              filename=name))
    try:
        from PIL import Image
        import io as _io
        img = Image.open(_io.BytesIO(data))
        img = img.convert('RGB')
        pixels = list(img.getdata())
        channels = {
            'R': [p[0] & 1 for p in pixels],
            'G': [p[1] & 1 for p in pixels],
            'B': [p[2] & 1 for p in pixels],
            'RGB': [(p[0] & 1) for p in pixels] + [(p[1] & 1) for p in pixels] + [(p[2] & 1) for p in pixels],
        }
        for label, bits in channels.items():
            raw = _extract_bit_stream(bits[: 400000 if full_nasty else 120000])
            if not raw:
                continue
            txt = ''.join(chr(b) if 32 <= b < 127 or b in (9,10,13) else ' ' for b in raw[:4096]).strip()
            score = _score_stego_text(txt)
            if score >= (18.0 if full_nasty else 24.0):
                f = Finding(
                    method=f'Light stego LSB extract {label}',
                    result_text=txt[:2000],
                    result_bytes=raw,
                    confidence='MEDIUM',
                    note='LSB bitstream extraction from image channel.'
                )
                f.chain = [f'lsb_{label.lower()}']
                f.score = score + 5.0
                f.signal = 'RRSW-TRACK'
                f.why = 'Image channel LSB stream produced printable text with language-like patterns.'
                findings.append(f)
    except Exception:
        return findings
    return findings

def _write_sidecar(saved_path: str, finding, source_label: str):
    sidecar = {
        'source': source_label,
        'saved_path': saved_path,
        'method': getattr(finding, 'method', ''),
        'filetype': getattr(finding, 'filetype', [None, None])[1] if getattr(finding, 'filetype', None) else None,
        'score': getattr(finding, 'score', 0),
        'entropy': getattr(finding, 'entropy', 0.0),
        'signal': getattr(finding, 'rrsw_signal', 'RRSW-NOISE'),
        'confidence': getattr(finding, 'confidence', 'LOW'),
        'chain': getattr(finding, 'chain', []),
        'why': getattr(finding, 'why', ''),
        'note': getattr(finding, 'note', ''),
    }
    try:
        with open(saved_path + '.json', 'w', encoding='utf-8') as fh:
            json.dump(sidecar, fh, indent=2)
    except Exception:
        pass

def _candidate_bytes_from_finding(f):
    out = []
    seen = set()
    def _push(label, blob):
        if not blob or len(blob) < 8:
            return
        h = hashlib.md5(blob).hexdigest()
        if h in seen:
            return
        seen.add(h)
        out.append((label, blob))
    if getattr(f, 'result_bytes', None):
        _push('raw-bytes', f.result_bytes)
    txt = getattr(f, 'result_text', None)
    if txt:
        try:
            _push('latin1-text', txt.encode('latin-1', errors='ignore'))
        except Exception:
            pass
        for fn_name, fn in (('hex', decode_hex), ('hex-escaped', decode_hex_escaped),
                            ('b64', decode_base64), ('b64url', decode_base64_url),
                            ('b64mime', decode_base64_mime), ('qp', decode_quoted_printable),
                            ('uu', decode_uuencode)):
            try:
                blob = fn(txt)
                if blob:
                    _push(fn_name, blob)
            except Exception:
                pass
    return out

def _file_confidence_bonus(blob: bytes, ft: tuple) -> int:
    score = 35
    if ft[0] in ('e01', 'l01', 'ex01'):
        score += 20
        if len(blob) >= 13 and blob[8] == 0x01:
            score += 10
    if len(blob) > 1024:
        score += 5
    if calc_entropy(blob[:65536]) > 6.0:
        score += 3
    return score

def _collect_recovered_file_candidates(findings):
    candidates = []
    seen = set()
    for idx, f in enumerate(findings):
        for source_kind, blob in _candidate_bytes_from_finding(f):
            ft = detect_filetype(blob)
            if not ft:
                continue
            h = hashlib.md5(blob).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            candidates.append({
                'finding_index': idx,
                'finding': f,
                'bytes': blob,
                'filetype': ft,
                'source_kind': source_kind,
                'score': _file_confidence_bonus(blob, ft),
                'entropy': calc_entropy(blob[:65536]),
            })
    candidates.sort(key=lambda c: (c['score'], len(c['bytes'])), reverse=True)
    return candidates

def _export_recovered_candidate(candidate, run_dir, source_name, suffix_index):
    os.makedirs(run_dir, exist_ok=True)
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', os.path.basename(source_name or 'recovered')).strip('_') or 'recovered'
    ext = candidate['filetype'][0] or 'bin'
    out_dir = os.path.join(run_dir, 'recovered_files')
    os.makedirs(out_dir, exist_ok=True)
    out_name = f"{safe}_recovered_{suffix_index}.{ext}"
    out_path = os.path.join(out_dir, out_name)
    with open(out_path, 'wb') as fh:
        fh.write(candidate['bytes'])
    return out_path


def _artifact_profile(text, raw_bytes=None):
    txt = text or ''
    profile = []
    if re.search(r'\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}', txt) or re.search(r'\b\d{2}:\d{2}:\d{2}\b', txt):
        profile.append('timeline / timestamp evidence')
    if re.search(r'\b(?:GET|POST|Host:|User-Agent:|HTTP/1\.[01])\b', txt, re.I):
        profile.append('http / request artifact')
    if re.search(r'\b(?:src|dst|port|ip|dns|ttl|icmp|tcp|udp)\b', txt, re.I):
        profile.append('network / packet artifact')
    if re.search(r'\b(?:error|warn|info|debug|failed|success|login|auth)\b', txt, re.I):
        profile.append('log-like artifact')
    if re.search(r'\b(?:reg|hklm|hkcu|sam|system32|winevt|evtx)\b', txt, re.I):
        profile.append('windows host artifact')
    if re.search(r'\b(?:sqlite|insert into|select .* from|table|schema|json|xml|yaml)\b', txt, re.I):
        profile.append('structured data / config')
    if raw_bytes and not profile and len(raw_bytes) > 0 and sum(b < 32 and b not in (9,10,13) for b in raw_bytes[:256]) > 8:
        profile.append('binary blob / carved artifact')
    return profile

def _analyst_bundle(f):
    txt = getattr(f, 'result_text', '') or ''
    raw = getattr(f, 'result_bytes', None)
    method = (getattr(f, 'method', '') or '').lower()
    score = int(getattr(f, 'score', 0) or 0)
    ent = float(getattr(f, 'entropy', 0.0) or 0.0)
    conf = getattr(f, 'confidence', 'LOW')
    prof = _artifact_profile(txt, raw)

    interp = []
    hypo = []
    steps = []

    if 'base64' in method or 'base32' in method or 'hex' in method:
        interp.append('encoded data decoded cleanly into a more human-readable form')
        hypo.append('likely an intentional wrapper layer rather than native plaintext')
        steps.append('recurse once more if the result is still not obviously meaningful')
    if 'xor' in method:
        interp.append('xor candidate survived scoring and produced printable output')
        hypo.append('possible ctf obfuscation or lightweight malware-style masking')
        steps.append('inspect for flags, keys, file headers, or a second transform')
    if 'rot' in method or 'atbash' in method or 'vigenere' in method or 'porta' in method:
        interp.append('classical transform output scored above noise')
        hypo.append('likely puzzle or intentionally obfuscated analyst note')
        steps.append('check chain trail and compare nearby candidates for cleaner language')
    if getattr(f, 'filetype', None):
        interp.append(f'decoding exposed a probable file artifact: {f.filetype[1]}')
        hypo.append('this may be a payload, embedded object, or stage transition artifact')
        steps.append('save the file and inspect it directly or recurse into it')
    if 0 < ent < 4.8:
        interp.append('entropy sits in a plaintext or lightly encoded range')
    elif ent >= 6.8:
        interp.append('entropy is high, suggesting compression, encryption, or noisy binary data')
        steps.append('favor file carving, decompression, or key-based transforms over word guessing')
    if score >= 80:
        hypo.append('strong lead - this looks closer to analyst-usable output than random decode trash')
    elif score >= 45:
        hypo.append('plausible lead - worth checking in context with sibling findings')
    else:
        hypo.append('weak lead - keep it only if it aligns with the surrounding artifact story')
    for p in prof:
        interp.append(f'artifact profile suggests {p}')
    if txt:
        low = txt.lower()
        if any(tag in low for tag in ('rrsw{','flag{','ctf{','htb{','picoctf{')):
            hypo.append('possible flag or solution token present')
            steps.insert(0, 'verify exact casing and submit only if it matches the active context')
        if any(w in low for w in ('password','token','secret','apikey','session')):
            steps.append('treat recovered secrets as stage pivots or decryption material, not automatic win states')
        if any(w in low for w in ('http','https','onion','.onion','github.com')):
            steps.append('treat discovered infrastructure references as context or toolkit pivots')
    if not interp:
        interp.append('candidate survived scoring but lacks a strong structural fingerprint')
    if not steps:
        steps.append('inspect the top nearby findings and follow the cleanest transform chain')

    graph = ' -> '.join(getattr(f, 'chain', []) or [getattr(f, 'method', 'input')])
    return {
        'interpretation': '; '.join(dict.fromkeys(interp))[:500],
        'hypothesis': '; '.join(dict.fromkeys(hypo))[:400],
        'next_steps': '; '.join(dict.fromkeys(steps))[:500],
        'artifact_profile': prof,
        'graph': graph
    }


def _print_analyst_block(f, compact=False):
    print(f"       {C.CYAN}interpret:{C.RESET} {getattr(f,'analyst_interpretation','')}")
    print(f"       {C.CYAN}hypothesis:{C.RESET} {getattr(f,'analyst_hypothesis','')}")
    print(f"       {C.CYAN}next:{C.RESET} {getattr(f,'analyst_next_steps','')}")
    prof = getattr(f, 'artifact_profile', []) or []
    if prof:
        print(f"       {C.CYAN}profile:{C.RESET} {', '.join(prof)}")
    if compact:
        return


# ── IOC + Structure detection ─────────────────────────────────────────────
_RE_IPV4    = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_RE_IPV6    = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
_RE_URL     = re.compile(r'https?://[^\s<>"\']{6,}', re.I)
_RE_EMAIL   = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
_RE_DOMAIN  = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|info|biz|xyz|onion)\b', re.I)
_RE_MD5     = re.compile(r'\b[0-9a-fA-F]{32}\b')
_RE_SHA1    = re.compile(r'\b[0-9a-fA-F]{40}\b')
_RE_SHA256  = re.compile(r'\b[0-9a-fA-F]{64}\b')
_RE_JWT     = re.compile(r'ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')
_RE_PEM     = re.compile(r'-----BEGIN [A-Z ]+-----')
_RE_CMD     = re.compile(r'(?:cmd\.exe|powershell|bash|sh|python|perl|ruby|wget|curl|nc|netcat)\s+[\-/]?\w', re.I)

def _extract_iocs(text: str) -> List[Dict]:
    """Extract indicators of compromise from any text string."""
    if not text or len(text) < 4:
        return []
    iocs = []
    seen = set()
    def _add(kind, value, context=''):
        key = (kind, value)
        if key not in seen:
            seen.add(key)
            iocs.append({'type': kind, 'value': value, 'context': context})
    for m in _RE_URL.finditer(text):
        _add('url', m.group())
    for m in _RE_EMAIL.finditer(text):
        _add('email', m.group())
    for m in _RE_IPV4.finditer(text):
        v = m.group()
        if not v.startswith(('127.', '0.', '255.')):
            _add('ipv4', v)
    for m in _RE_IPV6.finditer(text):
        _add('ipv6', m.group())
    for m in _RE_JWT.finditer(text):
        _add('jwt', m.group()[:64] + '...')
    for m in _RE_PEM.finditer(text):
        _add('pem_block', m.group())
    for m in _RE_CMD.finditer(text):
        _add('command', m.group()[:80])
    for m in _RE_SHA256.finditer(text):
        _add('sha256', m.group())
    for m in _RE_SHA1.finditer(text):
        if not any(i['value'] == m.group() for i in iocs):
            _add('sha1', m.group())
    for m in _RE_MD5.finditer(text):
        if not any(i['value'] == m.group() for i in iocs):
            _add('md5', m.group())
    for m in _RE_DOMAIN.finditer(text):
        v = m.group()
        if not any(i['value'] == v for i in iocs):
            _add('domain', v)
    return iocs[:40]


def _detect_structured_type(text: str) -> str:
    """Identify the primary structural type of decoded content."""
    if not text:
        return ''
    t = text.strip()
    # JSON
    if (t.startswith('{') and t.endswith('}')) or (t.startswith('[') and t.endswith(']')):
        try:
            import json as _json; _json.loads(t); return 'json'
        except Exception: pass
    # PEM / key block
    if '-----BEGIN' in t:
        return 'pem'
    # JWT
    if _RE_JWT.search(t):
        return 'jwt'
    # XML / HTML
    if t.startswith('<') and '>' in t:
        tag = t[1:t.index('>')].split()[0] if '>' in t else ''
        return 'html' if tag.lower() in ('html','head','body','div','script') else 'xml'
    # YAML (rough)
    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s*:', t, re.M) and '\n' in t:
        return 'yaml'
    # INI / config
    if re.match(r'^\[', t) and '=' in t:
        return 'ini'
    # URL list
    urls = _RE_URL.findall(t)
    if len(urls) >= 2:
        return 'url_list'
    if _RE_URL.match(t):
        return 'url'
    # CSV / TSV
    lines_t = t.splitlines()[:5]
    if len(lines_t) >= 2:
        commas = [l.count(',') for l in lines_t]
        tabs   = [l.count('\t') for l in lines_t]
        if all(c == commas[0] and c >= 2 for c in commas): return 'csv'
        if all(c == tabs[0]   and c >= 1 for c in tabs):   return 'tsv'
    # Log line
    if re.search(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', t):
        return 'log'
    # Command
    if _RE_CMD.search(t):
        return 'command'
    # Base64 blob
    if re.match(r'^[A-Za-z0-9+/=\s]{40,}$', t) and len(t) % 4 == 0:
        return 'base64_blob'
    return ''


def _corroborate_findings(findings: list) -> None:
    """
    Cross-reference IOCs across all findings.
    When multiple findings share the same IOC value, increment support_count
    on each and annotate why.
    """
    ioc_index: Dict[str, List] = {}   # ioc_value -> [finding, ...]
    for f in findings:
        for ioc in (getattr(f, 'iocs', None) or []):
            v = ioc.get('value', '')
            if v:
                ioc_index.setdefault(v, []).append(f)
    for v, flist in ioc_index.items():
        if len(flist) >= 2:
            methods = list({f.method for f in flist})[:3]
            note    = f'corroborated by: {", ".join(methods)}'
            for f in flist:
                f.support_count = len(flist)
                if note not in (f.why or ''):
                    f.why = ((f.why + '; ') if f.why else '') + note



def _structured_content_findings(text: str, source_label: str) -> list:
    """
    When decoded text contains structured content (JSON, JWT, PEM, URLs, etc.),
    produce a dedicated finding with extracted fields for analyst review.
    Ticket 2.1: structured-content detectors.
    """
    import json as _json
    findings = []
    if not text or len(text) < 8:
        return findings

    t = text.strip()
    stype = _detect_structured_type(t)

    # JSON: extract top-level keys + IOCs
    if stype == 'json':
        try:
            obj = _json.loads(t)
            def _flat(d, depth=0, prefix=''):
                items = {}
                if isinstance(d, dict) and depth < 3:
                    for k, v in d.items():
                        items.update(_flat(v, depth+1, prefix + str(k) + '.'))
                elif isinstance(d, (str, int, float, bool)):
                    items[prefix.rstrip('.')] = str(d)[:200]
                return items
            flat = _flat(obj)
            preview = '  '.join('%s=%s' % (k, v) for k, v in list(flat.items())[:12])
            findings.append(Finding(
                method='Structured content: JSON',
                result_text=preview,
                confidence='HIGH',
                note='JSON object with %d top-level keys' % (len(obj) if isinstance(obj, dict) else 1),
                source_label=source_label,
                structured_type='json',
            ))
        except Exception:
            pass

    # JWT: decode header + payload
    elif stype == 'jwt':
        import base64 as _b64
        try:
            parts = t.strip().split('.')
            if len(parts) >= 2:
                def _b64d(s):
                    s += '=' * (-len(s) % 4)
                    return _b64.urlsafe_b64decode(s).decode('utf-8', errors='replace')
                header  = _json.loads(_b64d(parts[0]))
                payload = _json.loads(_b64d(parts[1]))
                summary = 'alg=%s  typ=%s  claims=%s' % (
                    header.get('alg','?'), header.get('typ','?'),
                    ', '.join('%s=%s' % (k, str(v)[:30]) for k,v in list(payload.items())[:6])
                )
                findings.append(Finding(
                    method='Structured content: JWT',
                    result_text=summary,
                    confidence='HIGH',
                    note='JWT token decoded: header=%s' % _json.dumps(header)[:100],
                    source_label=source_label,
                    structured_type='jwt',
                ))
        except Exception:
            pass

    # PEM block: identify key type
    elif stype == 'pem':
        import re as _re
        for m in _re.finditer(r'-----BEGIN ([^-]+)-----', t):
            findings.append(Finding(
                method='Structured content: PEM block',
                result_text=m.group(0),
                confidence='HIGH',
                note='PEM-encoded cryptographic material: %s' % m.group(1).strip(),
                source_label=source_label,
                structured_type='pem',
            ))

    # URL list: extract all URLs as structured finding
    elif stype in ('url', 'url_list'):
        urls = _RE_URL.findall(t)
        if urls:
            findings.append(Finding(
                method='Structured content: URLs extracted',
                result_text='\n'.join(urls[:20]),
                confidence='HIGH' if len(urls) >= 3 else 'MEDIUM',
                note='%d URL(s) extracted from decoded content' % len(urls),
                source_label=source_label,
                structured_type='url_list',
                iocs=[{'type': 'url', 'value': u} for u in urls[:20]],
            ))

    # Log: surface timestamp ranges
    elif stype == 'log':
        import re as _re
        ts_matches = _re.findall(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', t)
        if ts_matches:
            findings.append(Finding(
                method='Structured content: log data',
                result_text=t[:500],
                confidence='MEDIUM',
                note='Log format detected. %d timestamps. Range: %s to %s' % (
                    len(ts_matches), ts_matches[0], ts_matches[-1]),
                source_label=source_label,
                structured_type='log',
            ))

    return findings



def _build_why(f) -> str:
    """
    Construct a human-readable rationale string for a finding.
    Ticket 5.3: explainability hardening.
    """
    parts = []
    m     = f.method or ''
    conf  = f.confidence
    score = getattr(f, 'score', 0)
    chain = getattr(f, 'chain', []) or []
    stype = getattr(f, 'structured_type', '') or ''
    iocs  = getattr(f, 'iocs', []) or []
    supp  = getattr(f, 'support_count', 1)
    ent   = getattr(f, 'entropy', 0.0)
    rt    = f.result_text or ''

    if chain and len(chain) > 1:
        parts.append('Recovered via chain: %s.' % ' -> '.join(chain))

    if stype:
        parts.append('Output is structured %s.' % stype.upper())

    if iocs:
        kinds = sorted({i['type'] for i in iocs})
        parts.append('Contains %d IOC(s): %s.' % (len(iocs), ', '.join(kinds)))

    if supp > 1:
        parts.append('Independently corroborated by %d passes.' % supp)

    if rt and len(rt) > 12:
        ratio = sum(1 for c in rt if c.isalpha()) / max(1, len(rt))
        if ratio > 0.6:
            parts.append('Output is %.0f%% alphabetic -- likely natural language.' % (ratio * 100))

    if ent > 0:
        if ent > 7.2:
            parts.append('Output entropy %.2f -- high (compressed or encrypted).' % ent)
        elif ent < 2.0 and len(rt) > 20:
            parts.append('Output entropy %.2f -- low (repetitive or structured).' % ent)

    if 'AES' in m or 'aes' in m.lower():
        parts.append('Blob length and entropy profile match AES key material.')

    if 'ROT' in m:
        parts.append('Caesar/ROT cipher: letter substitution by fixed offset.')

    if 'base64' in m.lower() or 'Base64' in m:
        parts.append('Base64 encoding: standard RFC 4648 alphabet.')

    if 'XOR' in m:
        parts.append('XOR decoded: key derived via frequency analysis.')

    if 'Vigenere' in m or 'Vigenère' in m:
        parts.append('Vigenere cipher: key recovered via Kasiski examination and IC analysis.')

    if 'LSB' in m or 'lsb' in m:
        parts.append('Steganographic LSB embedding: data hidden in image channel bit-planes.')

    if 'EXIF' in m:
        parts.append('EXIF metadata field extracted from JPEG segment.')

    if 'JSteg' in m or 'DCT' in m:
        parts.append('JPEG DCT coefficient LSB steganography (JSteg method).')

    if score >= 80:
        parts.append('Score %d -- strong language fitness and/or structure indicators.' % score)
    elif score >= 55:
        parts.append('Score %d -- above high-confidence threshold.' % score)

    if conf == 'CONFIRMED':
        parts.append('Confidence CONFIRMED: English language detection passed.')

    return '  '.join(parts) if parts else 'Found by %s.' % m



def _finalize_findings(findings, source_label, wordlist=None):
    """
    Score, deduplicate, sort, and annotate all findings.
    Deduplicates by CONTENT (same plaintext from different methods → keep best).
    Caps per-method-family to prevent flood: max 2 ROT, max 3 Vigenere, max 3 Affine.
    Filters Bacon results that decode to repeated single letters (AAAAAAA etc).
    """
    seen_method_key = {}  # original method+content dedup
    for f in findings or []:
        if not f.source_label:
            f.source_label = source_label
        payload = f.result_text if f.result_text else (f.result_bytes or b'')
        f.entropy = _hio_entropy(payload)
        f.chain   = _normalize_chain(f)
        f.score   = _score_candidate(f.result_text or '', f.result_bytes or b'', wordlist, f.confidence)
        if f.result_text:
            f.score = int(max(0, f.score
                + _ngram_score(f.result_text) * 12.0
                + _word_density(f.result_text, wordlist) * 35.0))
        m = f.method or ''
        if m in (_KEY_HINT_METHOD, _KEY_PARAM_METHOD, _CIPHER_PROFILE_METHOD):
            f.score += 6
        if 'ZIP Nested' in m:    f.score += 5
        if 'Appended Payload' in m: f.score += 4
        f.rrsw_signal = _rrsw_signal(f.score, f.entropy, f.confidence)
        # Phase-1: provenance, IOC, structured-content enrichment
        _fid = getattr(f, 'finding_id', '')
        if not _fid:
            import hashlib as _hl
            _key = f'{f.method}{f.result_text or ""}{f.source_label}'
            try:
                f.finding_id = _hl.md5(_key.encode('utf-8', 'replace')).hexdigest()[:12]
            except AttributeError:
                pass
        _fiocs = getattr(f, 'iocs', None)
        if _fiocs is None:
            try: f.iocs = []
            except AttributeError: pass
        if f.result_text and not getattr(f, 'iocs', []):
            try: f.iocs = _extract_iocs(f.result_text)
            except AttributeError: pass
        _fstype = getattr(f, 'structured_type', None)
        if _fstype is None:
            try: f.structured_type = ''
            except AttributeError: pass
        if f.result_text and not getattr(f, 'structured_type', ''):
            try: f.structured_type = _detect_structured_type(f.result_text)
            except AttributeError: pass
        # Boost score for structured content with IOCs
        _fiocs2 = getattr(f, 'iocs', []) or []
        if _fiocs2:
            f.score = f.score + min(len(_fiocs2) * 3, 18)
        _fstype2 = getattr(f, 'structured_type', '') or ''
        if _fstype2 in ('json', 'xml', 'pem', 'jwt', 'yaml'):
            f.score = f.score + 12
        # Generate structured findings for high-value content types
        if _fstype2 in ('json', 'jwt', 'pem', 'url', 'url_list', 'log') and f.result_text:
            _struct_extras = _structured_content_findings(f.result_text, f.source_label or source_label)
            seen_method_key.update({_k: _sf for _k, _sf in {(_sf.method + _sf.source_label): _sf for _sf in _struct_extras}.items()})
        if f.score >= 95 and f.rrsw_signal != 'RRSW-SIGMA':
            f.rrsw_signal = 'RRSW-SIGMA'
        bundle = _analyst_bundle(f)
        f.analyst_interpretation = bundle['interpretation']
        f.analyst_hypothesis      = bundle['hypothesis']
        f.analyst_next_steps      = bundle['next_steps']
        f.artifact_profile        = bundle['artifact_profile']
        why_bits = [f.why] if f.why else []
        txt = f.result_text or ''
        raw = f.result_bytes or b''
        if txt and len(txt) >= 20:
            prof = _classify_cipher_profile(txt, b'')
            if prof['family'] != 'unknown':
                why_bits.append(f'profile: {prof["family"]}')
            if prof['layers'] > 1:
                why_bits.append(f'est. layers: {prof["layers"]}')
        if m in (_KEY_HINT_METHOD, _KEY_PARAM_METHOD):
            why_bits.append('statistical estimation — not direct decryption')
        if 'XOR repeating-key' in m:
            why_bits.append('Hamming keysize detection + per-column single-byte XOR')
        if 'Vigenère' in m and 'recovered' in m.lower():
            why_bits.append('key recovered via IC period detection + chi-squared column solving')
        if 'hill-climb' in m.lower():
            why_bits.append('hill-climbing monoalphabetic solver: tetragram + word-density fitness')
        if 'ZIP Nested' in m:
            why_bits.append('archive member recursively analyzed as its own artifact')
        if 'Appended Payload' in m:
            why_bits.append('data found beyond expected file EOF')
        if txt and f.confidence in ('HIGH', 'CONFIRMED', 'MEDIUM'):
            vig = estimate_vigenere_key_lengths(txt, top_n=3)
            if vig: why_bits.append('key-length candidates: ' + ', '.join(map(str, vig)))
        if raw and f.confidence in ('HIGH', 'CONFIRMED'):
            xk = estimate_repeating_xor_keysizes(raw[:512], top_n=3)
            if xk: why_bits.append('xor keysizes: ' + ', '.join(map(str, xk)))
        raw_why = '; '.join(dict.fromkeys(w for w in why_bits if w))[:900]
        f.why = raw_why if raw_why else _build_why(f)
        # Explainability requirement: HIGH/CONFIRMED must always have a why
        if f.confidence in ('HIGH', 'CONFIRMED') and not f.why:
            f.why = _build_why(f)
        key = (m, txt[:400], bytes(raw[:64]) if raw else b'', getattr(f, 'note', '')[:160])
        prev = seen_method_key.get(key)
        cur  = (f.score, len(txt), len(raw), -f.entropy)
        if prev is None or cur > (prev.score, len(prev.result_text or ''), len(prev.result_bytes or b''), -prev.entropy):
            seen_method_key[key] = f

    pre_dedup = list(seen_method_key.values())

    # ── CONTENT-BASED DEDUP ──────────────────────────────────────────────────
    # If multiple methods produce identical plaintext, keep only the best.
    content_seen = {}
    for f in pre_dedup:
        txt = f.result_text or ''
        if not txt:
            content_seen[(f.method, id(f))] = f
            continue
        # Normalize: lowercase, strip punctuation/spaces
        norm = re.sub(r'[^a-z0-9]', '', txt.lower())[:300]
        if not norm:
            content_seen[(f.method, id(f))] = f
            continue
        existing = content_seen.get(norm)
        if existing is None:
            content_seen[norm] = f
        else:
            # Keep the better one (higher score; on tie, shorter method name = simpler)
            if f.score > existing.score or (f.score == existing.score and len(f.method) < len(existing.method)):
                content_seen[norm] = f

    deduped = list(content_seen.values())

    # ── BACON QUALITY FILTER ─────────────────────────────────────────────────
    # Bacon results that decode to a string of mostly identical letters are noise.
    def _bacon_is_garbage(f):
        m = f.method or ''
        if 'bacon' not in m.lower():
            return False
        txt = (f.result_text or '').strip()
        if not txt:
            return True
        alpha = [c for c in txt.upper() if c.isalpha()]
        if not alpha:
            return True
        # Filter if > 55% same letter (AAAAAAAA type noise)
        most_common = max(set(alpha), key=alpha.count)
        if alpha.count(most_common) / len(alpha) > 0.55:
            return True
        # Bacon output is only useful if it contains real words.
        # Raw A-Z letter dumps like ACAJGMMYSB are not plaintext.
        words_in_result = re.findall(r'[A-Za-z]{3,}', txt.lower())
        wl = wordlist or set()
        common = {'the','and','that','this','with','from','have','not','for',
                  'you','are','was','all','can','but','his','her','they',
                  'say','out','word','order','letter','change'}
        has_word = any(w in wl for w in words_in_result) or                    any(w in common for w in words_in_result)
        if not has_word:
            return True  # no recognizable words = garbage
        # Bacon output should contain spaces (it decodes to words)
        if ' ' not in txt:
            return True
        return False

    # Demote Bacon garbage confidence BEFORE applying caps
    clean = []
    for f in deduped:
        if _bacon_is_garbage(f):
            pass  # drop entirely
        else:
            clean.append(f)
    deduped = clean

    # ── PER-FAMILY CAP ───────────────────────────────────────────────────────
    # Prevent ROT1-25 all showing as HIGH, or 80 Vigenere variants flooding output.
    # Structural/analysis findings (cipher profile, param hints, triage) are uncapped.
    STRUCTURAL = {_KEY_HINT_METHOD, _KEY_PARAM_METHOD, _CIPHER_PROFILE_METHOD,
                  _ARTIFACT_TRIAGE_METHOD, _ARTIFACT_TREE_METHOD}

    def _family(f):
        m = f.method or ''
        if m in STRUCTURAL: return '__structural__'
        if m.startswith('[REVERSED]'): m = m[10:].strip()
        if re.match(r'ROT[0-9]+', m):  return 'ROT'
        if 'Rail Fence' in m:          return 'RailFence'
        if 'Columnar' in m:            return 'Columnar'
        if 'Affine' in m:              return 'Affine'
        if 'Vigenère' in m:            return 'Vigenere'
        if 'XOR single-byte' in m:     return 'XOR_single'
        if 'XOR repeating-key' in m:   return 'XOR_repeat'
        if 'XOR multi-byte' in m:      return 'XOR_multi'
        if 'Bacon' in m or 'bacon' in m: return 'Bacon'
        if 'Atbash' in m:              return 'Atbash'
        return m[:30]

    # Sort by confidence + score first so we cap the worst ones
    conf_rank = {'CONFIRMED': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
    deduped.sort(key=lambda f: (conf_rank.get(f.confidence, 0), f.score, -f.entropy), reverse=True)

    FAMILY_CAPS = {
        'ROT':        2,   # show at most 2 ROT variants (the best 2)
        'RailFence':  3,
        'Columnar':   3,
        'Affine':     4,
        'Vigenere':   4,
        'XOR_single': 6,
        'XOR_repeat': 4,
        'XOR_multi':  4,
        'Bacon':      2,
        'Atbash':     1,
    }
    # Bacon can never be CONFIRMED — it decodes to A-Z letters, not English words.
    # If a Bacon result survived the garbage filter it gets HIGH at most.
    for f in capped if False else []:  # placeholder
        pass
    for f in deduped:
        if 'bacon' in (f.method or '').lower() and f.confidence == 'CONFIRMED':
            f.confidence = 'HIGH' 

    family_counts = {}
    capped = []
    for f in deduped:
        fam = _family(f)
        if fam == '__structural__':
            capped.append(f)
            continue
        cap = FAMILY_CAPS.get(fam, 999)
        cnt = family_counts.get(fam, 0)
        if cnt < cap:
            family_counts[fam] = cnt + 1
            capped.append(f)
        # Always keep CONFIRMED regardless of cap
        elif f.confidence == 'CONFIRMED':
            capped.append(f)

    # Final sort
    capped.sort(key=lambda f: (conf_rank.get(f.confidence, 0), f.score, -f.entropy), reverse=True)
    _corroborate_findings(capped)
    return capped


_HIO_ACTIVE_FLAGS: dict = {}

def _engine_init(self, wordlist: set = None, output_dir: str = './output', max_depth: int = 3,
                             stegopw_wordlist: str = None, verbose: bool = True, flags: dict = None):
    self.wordlist = wordlist or set()
    self.output_dir = output_dir
    self.verbose = verbose
    self.flags = flags or {}
    self.max_depth = max_depth
    self.stegopw_wordlist = stegopw_wordlist
    self._analysis_cache = {}
    self._analysis_file_cache = {}
    self._quality_cache = {}
    os.makedirs(output_dir, exist_ok=True)

def _deepcopy_findings(findings):
    try:
        return copy.deepcopy(findings)
    except Exception:
        return findings[:]

def _cache_key_text(data: str, source_label: str, flags: dict, max_depth: int):
    raw = (data or '').encode('utf-8', errors='ignore')
    return (
        hashlib.sha1(raw).hexdigest(),
        source_label,
        tuple(sorted((flags or {}).items())),
        max_depth,
    )

def _cache_key_file(data: bytes, filename: str, flags: dict, max_depth: int):
    return (
        hashlib.sha1(data).hexdigest(),
        os.path.basename(filename),
        tuple(sorted((flags or {}).items())),
        max_depth,
    )












def _get_active_flags(config=None):
    if isinstance(config, dict):
        return config
    return globals().get('_HIO_ACTIVE_FLAGS', {}) or {}

def _fresh_analyze_string(self, data: str, source_label: str = 'INPUT'):
    findings = []
    findings += self._try_structural(data)
    if self._do('rot'):
        findings += self._try_rots(data)
    if self._do('base'):
        findings += self._try_bases(data)
    if self._do('hex'):
        findings += self._try_hex(data)
    if self._do('binary'):
        findings += self._try_binary(data)
    if self._do('url'):
        findings += self._try_url(data)
    if self._do('morse'):
        findings += self._try_morse(data)
    if self._do('cipher'):
        findings += self._try_ciphers(data)
    if self._do('xor'):
        findings += self._try_xor(data)
    if self._do('misc'):
        findings += self._try_misc(data)
    if self._do('stego', 'deep'):
        findings += self._try_text_stego(data)
    if self._do('reverse'):
        for f in self._run_text_passes(data[::-1]):
            f.method = '[REVERSED] ' + f.method
            findings.append(f)
    raw = self._try_get_bytes(data)
    if raw and self._do('stego', 'deep'):
        findings += self._try_binary_stego(raw)
    for f in findings:
        if getattr(f, 'result_bytes', None) and not getattr(f, 'filetype', None):
            ft = detect_filetype(f.result_bytes)
            if ft:
                f.filetype = ft
                f.confidence = 'HIGH'
    hint = _make_key_hint_finding(text=data, raw=raw or b'')
    if hint:
        findings.append(hint)
    triage = _artifact_triage_text(data, raw or b'')
    if triage:
        findings.append(Finding(method=_ARTIFACT_TRIAGE_METHOD, result_text=triage, confidence='LOW', note='structural / artifact-oriented observations'))
    findings = _finalize_findings(findings, source_label, self.wordlist)
    return findings

def _fresh_analyze_file(self, data: bytes, filename: str):
    global _ACTIVE_PROGRESS
    findings = []
    pr = _ACTIVE_PROGRESS

    _upd_t = [None]
    def _upd(label):
        import time as _t
        now = _t.monotonic()
        if pr: pr.update(label)
        if _upd_t[0] is not None:
            _pass_record(label, 'ok', now - _upd_t[0])
        _upd_t[0] = now

    _upd('file type detection')
    ft = detect_filetype(data)
    if ft:
        findings.append(Finding(method='File Magic Bytes (direct)', result_bytes=data, filetype=ft, confidence='HIGH', note=f'Input is {ft[1]}'))
    poly = check_polyglot(data)
    if poly:
        findings.append(Finding(method='Polyglot Detection', result_text='\n'.join(poly), confidence='HIGH', note='File valid in multiple formats simultaneously'))

    _upd('embedded file scan')
    embedded = find_embedded_files(data)
    if embedded:
        summary = '\n'.join(f'  0x{pos:08X} : {desc} (.{ext})' for pos, ext, desc in embedded)
        findings.append(Finding(method='Embedded File Scan (all offsets)', result_text=summary, confidence='HIGH', note=f'{len(embedded)} embedded file type(s) detected'))
        for pos, ext, desc in embedded:
            end = _smart_boundary(data, pos, ext)
            payload = data[pos:end]
            findings.append(Finding(method=f'Extracted: {desc} at offset 0x{pos:x}', result_bytes=payload, filetype=(ext, desc), confidence='MEDIUM', note='Extracted from detected signature using heuristic boundary'))

    if data[:8] == b'\x89PNG\r\n\x1a\n':
        _upd('PNG chunk analysis')
        findings += self._analyze_png(data)
    if data[:3] == b'\xFF\xD8\xFF':
        _upd('JPEG metadata analysis')
        findings += self._analyze_jpeg(data)
    _upd('binary format triage')
    bin_triage = _triage_binary_format(data, filename)
    if bin_triage:
        findings.extend(bin_triage)
    if data[:4] == b'PK\x03\x04':
        _upd('ZIP member extraction')
        findings += self._analyze_zip(data)
        findings += _zip_member_findings(data)

    _upd('LSB steganography scan')
    for label, result in lsb_extract_all_planes(data):
        conf, note = self._text_quality(result)
        findings.append(Finding(method=f'LSB Steganography ({label})', result_text=result, confidence=conf, note=note))

    _upd('zlib decompression')
    decompressed = try_zlib_decompress(data)
    if decompressed:
        ft2 = detect_filetype(decompressed)
        if ft2:
            findings.append(Finding(method='Zlib Decompress → File', result_bytes=decompressed, filetype=ft2, confidence='HIGH', note=f'Decompressed to {ft2[1]}'))
        else:
            text = safe_decode_bytes(decompressed)
            if is_mostly_printable(text):
                conf, note = self._text_quality(text)
                findings.append(Finding(method='Zlib Decompress → Text', result_text=text, confidence=conf, note=note))

    _upd('embedded string scan')
    strings = scan_for_embedded_strings(data, min_len=6)
    interesting = [s for s in strings if self._has_word_content(s)]
    if interesting:
        findings.append(Finding(method='Embedded ASCII Strings', result_text='\n'.join(interesting[:60]), confidence='LOW', note=f'{len(interesting)} readable strings found in binary'))

    _upd('text decode passes')
    text_repr = data.decode('utf-8', errors='ignore')
    _is_known_binary = ft is not None and ft[0] not in ('txt', 'html', 'xml', 'json', 'csv', 'pem', 'sh')
    _sample = text_repr[:4096]
    _printable_ratio = _hio_printable_ratio(_sample) if _sample else 0.0
    _run_text = (text_repr.strip()
                 and not _is_known_binary
                 and _printable_ratio >= 0.80)
    if _run_text:
        for f in self._run_text_passes(text_repr[:65536]):
            findings.append(f)

    _upd('whitespace / unicode stego')
    ws = scan_whitespace_stego(text_repr)
    if ws:
        conf, note = self._text_quality(ws)
        findings.append(Finding(method='Whitespace Steganography (SNOW-style)', result_text=ws, confidence=conf, note='Found in trailing whitespace of text lines'))
    uc = scan_unicode_stego(text_repr)
    if uc:
        conf, note = self._text_quality(uc)
        findings.append(Finding(method='Unicode Zero-Width Steganography', result_text=uc, confidence=conf, note='Decoded from zero-width characters in text'))

    _upd('file carving')
    try:
        findings += self._try_file_carve(data, filename)
    except Exception as e:
        findings.append(Finding(method='File Carver', confidence='LOW', note=f'carver error: {e}'))

    _upd('key hints and triage')
    _text_for_hints = text_repr[:65536] if _run_text else ''
    hint = _make_key_hint_finding(text=_text_for_hints, raw=data[:4096])
    if hint:
        findings.append(hint)
    triage = _artifact_triage_text(_text_for_hints, data)
    if triage:
        findings.append(Finding(method=_ARTIFACT_TRIAGE_METHOD, result_text=triage, confidence='LOW', note='binary / evidence triage hints'))
    _upd('key hints and triage')

    _upd('scoring and deduplication')
    findings = _finalize_findings(findings, filename, self.wordlist)
    return findings

def _fresh_analyze_url(self, url: str):
    fetch = fetch_url(url)
    if fetch.error:
        return [Finding(method='URL Fetch Error', result_text=fetch.error, confidence='LOW', note=fetch.error)]
    if fetch.is_binary:
        return self.analyze_file(fetch.raw_bytes, url)
    text = fetch.text or fetch.raw_bytes.decode('utf-8', errors='ignore')
    return self.analyze_string(text, url)

def _try_ciphers(self, data: str) -> List[Finding]:
    flags = _get_active_flags(getattr(self, 'flags', None))
    findings.extend(_monoalphabetic_findings(data, self.wordlist, full_nasty=flags.get('full_nasty', False)))
    return findings

_original_analyze_file = _fresh_analyze_file

def _analyze_file(self, data: bytes, filename: str):
    global _ACTIVE_PROGRESS
    pr = _ACTIVE_PROGRESS

    def _upd(label):
        if pr: pr.update(label)

    findings = _original_analyze_file(self, data, filename)
    flags = _get_active_flags(getattr(self, 'flags', None))

    if flags.get('stego') or flags.get('full_nasty'):
        _upd('visual stego (PIL multi-channel LSB)')
        findings.extend(_light_stego_findings(
            data, filename, full_nasty=flags.get('full_nasty', False)
        ))

    _upd('binary blob analysis (XOR / headers / padding)')
    try:
        findings.extend(_analyze_binary_findings(findings, self.wordlist))
    except Exception:
        pass

    if flags.get('full_nasty') and flags.get('stego'):
        _upd('L4: raw byte sweep')
        try:
            findings.extend(_l4_run(data, filename, self, flags, self.wordlist))
        except Exception as _l4_err:
            findings.append(Finding(
                method='L4: Orchestrator',
                confidence='LOW',
                note=f'L4 run failed: {_l4_err}',
                result_text='',
            ))

    _upd('final scoring and deduplication')
    return _finalize_findings(findings, filename, self.wordlist)

_L4_B64_CHARS  = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
_L4_B64U_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=')
_L4_B32_CHARS  = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')
_L4_HEX_CHARS  = set('0123456789abcdefABCDEF')

def _l4_tag_candidate(text: str) -> List[str]:
    tags = []
    if not text or len(text) < 4:
        return tags
    s = text.strip()
    clean = s.replace('\n', '').replace('\r', '').replace(' ', '')
    cset = set(clean)

    low = s.lower()
    for marker in ('flag{', 'ctf{', 'rrsw{', 'htb{', 'picoctf{', 'thm{'):
        if marker in low:
            tags.append('flag-like')
            break

    if len(clean) >= 8 and cset <= _L4_B64_CHARS:
        if len(clean) % 4 in (0, 2, 3):
            tags.append('base64-like')
    if len(clean) >= 8 and cset <= _L4_B64U_CHARS and '-' in clean or '_' in clean:
        tags.append('base64url-like')

    if len(clean) >= 8 and cset <= _L4_B32_CHARS and clean == clean.upper():
        if len(clean) % 8 in (0, 2, 4, 5, 7):
            tags.append('base32-like')

    if len(clean) >= 8 and cset <= _L4_HEX_CHARS and len(clean) % 2 == 0:
        tags.append('hex-like')

    if '%' in s and re.search(r'%[0-9a-fA-F]{2}', s):
        tags.append('url-encoded')

    alpha = ''.join(c for c in s.lower() if c.isalpha())
    if len(alpha) >= 8:
        rev = alpha[::-1]
        common_bigrams = {'th','he','in','er','an','re','on','at','en','nd',
                          'ti','es','or','te','of','ed','is','it','al','ar'}
        fwd_hits = sum(1 for i in range(len(alpha)-1) if alpha[i:i+2] in common_bigrams)
        rev_hits = sum(1 for i in range(len(rev)-1)   if rev[i:i+2]   in common_bigrams)
        if rev_hits > fwd_hits + 2:
            tags.append('reversed-looking')

    if clean.count('=') >= 2 and clean.endswith('='):
        tags.append('padded')

    has_upper = any(c.isupper() for c in clean)
    has_lower = any(c.islower() for c in clean)
    has_digit = any(c.isdigit() for c in clean)
    if has_upper and has_lower and has_digit and len(clean) >= 16:
        tags.append('mixed-alnum')

    return tags

def _l4_raw_byte_sweep(data: bytes) -> List[dict]:
    candidates = []
    i = 0
    n = len(data)
    MIN_PRINTABLE = 6
    INTEREST_THRESHOLD = 12
    ENCODED_THRESHOLD  = 16

    while i < n:
        if 32 <= data[i] <= 126 or data[i] in (9, 10, 13):
            start = i
            run = []
            while i < n and (32 <= data[i] <= 126 or data[i] in (9, 10, 13)):
                run.append(chr(data[i]))
                i += 1
            s = ''.join(run).strip()
            if len(s) >= MIN_PRINTABLE:
                tags = []
                if len(s) >= INTEREST_THRESHOLD:
                    tags = _l4_tag_candidate(s)
                candidates.append({
                    'text':   s,
                    'offset': start,
                    'length': i - start,
                    'tags':   tags,
                    'source': 'raw_sweep',
                })
        else:
            i += 1

    return candidates

def _l4_sweep_to_findings(sweep_hits: List[dict], filename: str) -> List['Finding']:
    findings = []
    notable = [h for h in sweep_hits if h['tags'] or len(h['text']) >= 20]
    if not notable:
        return findings

    lines_out = []
    for h in notable[:80]:
        tag_str = ' [' + ', '.join(h['tags']) + ']' if h['tags'] else ''
        preview = h['text'][:120].replace('\n', '↵').replace('\r', '')
        lines_out.append(f"  0x{h['offset']:08X}  len={h['length']:5d}{tag_str}  {preview}")

    f = Finding(
        method='L4: Raw byte sweep',
        result_text='\n'.join(lines_out),
        confidence='LOW',
        note=(
            f"{len(sweep_hits)} printable runs found in {filename}; "
            f"{len(notable)} notable (tagged or long). "
            f"Offsets are file-absolute."
        ),
    )
    f.chain  = ['l4_raw_sweep']
    f.why    = 'Whole-file parser-independent string scan with offset tracking and encoding-family tagging.'
    findings.append(f)
    return findings

def _l4_png_chunk_walk(data: bytes) -> List[dict]:
    PNG_SIG = b'\x89PNG\r\n\x1a\n'
    if not data.startswith(PNG_SIG):
        return []

    KNOWN_CRITICAL   = {b'IHDR', b'PLTE', b'IDAT', b'IEND'}
    KNOWN_ANCILLARY  = {b'cHRM', b'gAMA', b'iCCP', b'sBIT', b'sRGB', b'bKGD',
                        b'hIST', b'tRNS', b'pHYs', b'sPLT', b'tIME',
                        b'tEXt', b'zTXt', b'iTXt', b'oFFs', b'pCAL',
                        b'sCAL', b'gIFg', b'gIFx', b'sTER', b'acTL',
                        b'fcTL', b'fdAT', b'vpAg', b'caNv', b'prVt',
                        b'mkBT', b'mkTS', b'mkBS', b'mkBF'}

    chunks  = []
    pos     = 8
    seen    = []
    iend_seen = False

    while pos + 12 <= len(data):
        chunk_start = pos
        try:
            length     = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            chunk_data = data[pos+8:pos+8+length] if pos+8+length <= len(data) else b''
            crc_stored = data[pos+8+length:pos+12+length] if pos+12+length <= len(data) else b''
        except Exception:
            break

        try:
            import zlib as _z
            crc_calc  = _z.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
            crc_stored_int = struct.unpack('>I', crc_stored)[0] if len(crc_stored) == 4 else None
            crc_ok    = (crc_calc == crc_stored_int) if crc_stored_int is not None else None
        except Exception:
            crc_ok = None

        type_str    = chunk_type.decode('ascii', errors='replace')
        is_critical = chunk_type in KNOWN_CRITICAL
        is_known    = chunk_type in KNOWN_CRITICAL or chunk_type in KNOWN_ANCILLARY

        anomalies = []
        if iend_seen:
            anomalies.append('chunk-after-IEND')
        if chunk_type == b'IHDR' and pos != 8:
            anomalies.append('IHDR-not-first')
        if chunk_type == b'IHDR' and b'IHDR' in seen:
            anomalies.append('duplicate-IHDR')
        if chunk_type == b'IEND' and b'IEND' in seen:
            anomalies.append('duplicate-IEND')
        if not is_known:
            anomalies.append('unknown-chunk-type')
        if crc_ok is False:
            anomalies.append('crc-invalid')
        if length > 0x800000:
            anomalies.append('unusually-large')

        text_content = None
        if chunk_type == b'tEXt' and chunk_data:
            try:
                null = chunk_data.index(0)
                keyword = chunk_data[:null].decode('latin-1', errors='replace')
                value   = chunk_data[null+1:].decode('latin-1', errors='replace')
                text_content = f'{keyword}: {value}'
            except Exception:
                pass
        elif chunk_type == b'zTXt' and chunk_data:
            try:
                null = chunk_data.index(0)
                keyword    = chunk_data[:null].decode('latin-1', errors='replace')
                compressed = chunk_data[null+2:]
                import zlib as _z2
                value = _z2.decompress(compressed).decode('utf-8', errors='replace')
                text_content = f'{keyword}: {value}'
            except Exception:
                pass
        elif chunk_type == b'iTXt' and chunk_data:
            try:
                null = chunk_data.index(0)
                keyword = chunk_data[:null].decode('utf-8', errors='replace')
                rest    = chunk_data[null+1:]
                comp_flag = rest[0] if rest else 0
                text_start = 1
                nulls_found = 0
                for k in range(1, len(rest)):
                    if rest[k] == 0:
                        nulls_found += 1
                        if nulls_found == 2:
                            text_start = k + 1
                            break
                raw_text = rest[text_start:]
                if comp_flag == 1:
                    import zlib as _z3
                    raw_text = _z3.decompress(raw_text)
                value = raw_text.decode('utf-8', errors='replace')
                text_content = f'{keyword}: {value}'
            except Exception:
                pass

        chunk_info = {
            'type':         type_str,
            'offset':       chunk_start,
            'data_offset':  chunk_start + 8,
            'length':       length,
            'crc_ok':       crc_ok,
            'is_critical':  is_critical,
            'is_known':     is_known,
            'anomalies':    anomalies,
            'text_content': text_content,
            'data_preview': chunk_data[:64].hex() if chunk_data else '',
        }
        chunks.append(chunk_info)

        seen.append(chunk_type)
        if chunk_type == b'IEND':
            iend_seen = True
            pos += 12 + length
            break
        pos += 12 + length

    return chunks

def _l4_png_chunk_findings(chunks: List[dict], filename: str) -> List['Finding']:
    findings = []
    if not chunks:
        return findings

    lines_out = []
    for c in chunks:
        flag  = ' [' + ', '.join(c['anomalies']) + ']' if c['anomalies'] else ''
        crc   = '✓' if c['crc_ok'] is True else ('✗' if c['crc_ok'] is False else '?')
        known = '' if c['is_known'] else ' UNKNOWN'
        txt   = f"  [{crc}] {c['type']:<8}{known}  offset=0x{c['offset']:08X}  len={c['length']:7d}{flag}"
        if c['text_content']:
            txt += f"\n       text: {c['text_content'][:200]}"
        lines_out.append(txt)

    f = Finding(
        method='L4: PNG chunk walk',
        result_text='\n'.join(lines_out),
        confidence='LOW',
        note=f"{len(chunks)} chunks parsed with CRC validation, unknown-chunk detection, and text extraction.",
    )
    f.chain = ['l4_png_chunk_walk']
    f.why   = 'Full PNG chunk stream parsed with offsets, CRC validity, and unknown chunk surfacing.'
    findings.append(f)

    for c in chunks:
        if c['anomalies']:
            note_parts = [f"chunk {c['type']} at 0x{c['offset']:08X}"]
            note_parts += c['anomalies']
            fc = Finding(
                method=f"L4: PNG chunk anomaly ({c['type']})",
                result_text=f"type={c['type']}  offset=0x{c['offset']:08X}  len={c['length']}\nanomalies: {', '.join(c['anomalies'])}\npreview: {c['data_preview'][:128]}",
                confidence='MEDIUM',
                note='; '.join(note_parts),
            )
            fc.chain = ['l4_png_chunk_anomaly']
            fc.why   = f"Structural anomaly in PNG chunk stream: {', '.join(c['anomalies'])}"
            findings.append(fc)

        if c['text_content'] and len(c['text_content']) >= 8:
            tags = _l4_tag_candidate(c['text_content'])
            if tags:
                ft = Finding(
                    method=f"L4: PNG {c['type']} text candidate",
                    result_text=c['text_content'],
                    confidence='MEDIUM',
                    note=f"Text extracted from PNG {c['type']} chunk at 0x{c['offset']:08X}. Tags: {', '.join(tags)}",
                )
                ft.chain = ['l4_png_chunk_text']
                ft.why   = f"PNG metadata text chunk contains encoding-tagged candidate: {', '.join(tags)}"
                findings.append(ft)

    return findings

def _l4_post_iend(data: bytes) -> Optional[dict]:
    PNG_SIG = b'\x89PNG\r\n\x1a\n'
    if not data.startswith(PNG_SIG):
        return None

    pos = 8
    iend_end = None
    while pos + 12 <= len(data):
        try:
            length     = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
        except Exception:
            break
        if length > 0x10000000:
            break
        next_pos = pos + 12 + length
        if chunk_type == b'IEND':
            iend_end = next_pos
            break
        if next_pos > len(data):
            break
        pos = next_pos

    if iend_end is None or iend_end >= len(data):
        return None

    tail = data[iend_end:]
    if len(tail) < 4:
        return None
    if set(tail[:64]) <= {0}:
        return None

    tail_ft = None
    try:
        tail_ft = detect_filetype(tail)
    except Exception:
        pass

    tail_text = ''.join(
        chr(b) if (32 <= b <= 126 or b in (9, 10, 13)) else '.'
        for b in tail[:512]
    ).strip('.')

    return {
        'iend_offset': iend_end - 4,
        'tail_offset': iend_end,
        'tail_length': len(tail),
        'tail_preview': tail[:64].hex(),
        'tail_text':   tail_text,
        'tail_ft':     tail_ft,
        'tail_bytes':  tail,
        'tags':        _l4_tag_candidate(tail_text),
    }

def _l4_post_iend_findings(post: Optional[dict], filename: str) -> List['Finding']:
    findings = []
    if not post:
        return findings

    conf = 'HIGH' if post['tail_ft'] or post['tags'] else 'MEDIUM'
    txt  = [
        f"Trailing data begins at file offset 0x{post['tail_offset']:08X}",
        f"Length: {post['tail_length']} bytes",
        f"Hex preview: {post['tail_preview']}",
    ]
    if post['tail_text'].strip('.'):
        txt.append(f"Printable extract: {post['tail_text'][:300]}")
    if post['tail_ft']:
        txt.append(f"Detected type: {post['tail_ft'][1]}")
    if post['tags']:
        txt.append(f"Encoding tags: {', '.join(post['tags'])}")

    f = Finding(
        method='L4: Post-IEND trailing data (chunk-walk derived)',
        result_text='\n'.join(txt),
        result_bytes=post['tail_bytes'][:8192],
        filetype=post['tail_ft'],
        confidence=conf,
        note=(
            f"{post['tail_length']} bytes after true PNG EOF at 0x{post['tail_offset']:08X}. "
            f"Detected by chunk-length walk, not rfind."
        ),
    )
    f.chain = ['l4_post_iend']
    f.why   = 'Data exists beyond the PNG IEND chunk — typical hiding location for appended payloads.'
    findings.append(f)
    return findings

def _l4_sliding_entropy(data: bytes, window: int = 256, step: int = 64) -> List[dict]:
    if len(data) < window:
        return []

    def _win_entropy(buf: bytes) -> float:
        if not buf:
            return 0.0
        counts = [0] * 256
        for b in buf:
            counts[b] += 1
        n = len(buf)
        e = 0.0
        for c in counts:
            if c:
                p = c / n
                e -= p * math.log2(p)
        return round(e, 3)

    baseline = _win_entropy(data)

    anomalies = []
    i = 0
    n = len(data)
    prev_ent = None

    while i + window <= n:
        chunk = data[i:i+window]
        ent   = _win_entropy(chunk)

        region_type = None
        if ent >= 7.5:
            region_type = 'high-entropy (compressed/encrypted/random)'
        elif ent <= 3.0 and baseline >= 5.0:
            region_type = 'low-entropy text island in binary'
        elif prev_ent is not None and abs(ent - prev_ent) >= 2.5:
            region_type = f'entropy boundary (Δ{ent-prev_ent:+.2f})'

        if region_type:
            printable = ''.join(
                chr(b) if 32 <= b <= 126 else '.'
                for b in chunk[:128]
            )
            anomalies.append({
                'offset':      i,
                'length':      window,
                'entropy':     ent,
                'region_type': region_type,
                'printable':   printable,
                'tags':        _l4_tag_candidate(printable),
            })

        prev_ent = ent
        i += step

    return anomalies

def _l4_entropy_findings(anomalies: List[dict], baseline: float, filename: str) -> List['Finding']:
    findings = []
    if not anomalies:
        return findings

    lines_out = [f"  File baseline entropy: {baseline:.3f} bits/byte\n"]
    for a in anomalies[:40]:
        tags = ' [' + ', '.join(a['tags']) + ']' if a['tags'] else ''
        lines_out.append(
            f"  0x{a['offset']:08X}  ent={a['entropy']:.3f}  {a['region_type']}{tags}"
        )
        if a['printable'].replace('.', '').strip():
            lines_out.append(f"    → {a['printable'][:120]}")

    f = Finding(
        method='L4: Sliding-window entropy anomalies',
        result_text='\n'.join(lines_out),
        confidence='LOW',
        note=(
            f"{len(anomalies)} anomalous regions found in {filename}. "
            f"Window=256B, step=64B. Baseline={baseline:.3f} bits/byte."
        ),
    )
    f.chain = ['l4_entropy']
    f.why   = 'Sliding-window entropy reveals hidden text islands, compression boundaries, and payload regions.'
    findings.append(f)
    return findings

def _l4_harvest_candidates(
    prior_findings: List['Finding'],
    raw_hits: List[dict],
) -> List[dict]:
    seen_norm = set()
    candidates = []

    def _push(text: str, source: str, offset: int = -1) -> None:
        text = (text or '').strip()
        if len(text) < 8:
            return
        norm = re.sub(r'\s+', '', text.lower())[:200]
        if norm in seen_norm:
            return
        seen_norm.add(norm)
        tags = _l4_tag_candidate(text)
        candidates.append({
            'text':   text,
            'source': source,
            'offset': offset,
            'tags':   tags,
        })

    for f in prior_findings:
        src = f'prior:{f.method[:40]}'
        if f.result_text:
            for line in f.result_text.splitlines():
                line = line.strip()
                if len(line) >= 8:
                    _push(line, src)
                for tok in line.split():
                    if len(tok) >= 16:
                        _push(tok, src)

    for h in raw_hits:
        if h['tags'] or len(h['text']) >= 16:
            _push(h['text'], 'raw_sweep', h['offset'])
            if h['tags']:
                _push(h['text'][::-1], f"raw_sweep_reversed", h['offset'])

    return candidates

_L4_TRANSFORMS = [
    ('base64',    lambda s: decode_base64(s.strip())),
    ('base64url', lambda s: decode_base64_url(s.strip())),
    ('base32',    lambda s: decode_base32(s.strip())),
    ('hex',       lambda s: decode_hex(s.strip().replace(' ', ''))),
    ('hex_esc',   lambda s: decode_hex_escaped(s.strip())),
    ('url',       lambda s: decode_url(s).encode('utf-8') if decode_url(s) else None),
    ('zlib',      lambda s: try_zlib_decompress(s.encode('latin-1', errors='ignore'))),
    ('reverse',   lambda s: s[::-1].encode('utf-8')),
    ('atbash',    lambda s: decode_atbash(s).encode('utf-8') if decode_atbash(s) else None),
    ('rot13',     lambda s: rot_n(s, 13).encode('utf-8')),
]

def _l4_is_useful(data: bytes, wordlist: Optional[set] = None) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    ratio = printable / len(data)
    if ratio < 0.70:
        return ratio * 0.3
    text = data.decode('utf-8', errors='ignore')
    score = ratio * 0.5
    low = text.lower()
    for marker in ('flag{', 'ctf{', 'rrsw{', 'htb{', 'picoctf{'):
        if marker in low:
            return 1.0
    ng = _ngram_score(text)
    if ng > 0:
        score += min(ng / 5.0, 0.3)
    wd = _word_density(text, wordlist)
    score += wd * 0.2
    return min(score, 1.0)

def _l4_decode_graph(
    candidate: dict,
    wordlist: Optional[set] = None,
    max_depth: int = 4,
) -> List[dict]:
    results = []
    seen_hashes = set()

    def _recurse(current_str: str, current_bytes: Optional[bytes],
                 chain: List[str], depth: int) -> None:
        if depth >= max_depth:
            return

        for name, fn in _L4_TRANSFORMS:
            if chain and chain[-1] == name:
                continue
            try:
                raw = None
                if current_bytes is not None:
                    try:
                        inp = current_bytes.decode('utf-8', errors='strict')
                        raw = fn(inp)
                    except Exception:
                        try:
                            inp = current_bytes.decode('latin-1')
                            raw = fn(inp)
                        except Exception:
                            pass
                else:
                    raw = fn(current_str)

                if not raw or len(raw) < 4:
                    continue

                h = hashlib.md5(raw[:512]).hexdigest()
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)

                score = _l4_is_useful(raw, wordlist)
                if score < 0.30 and depth < max_depth - 1:
                    try:
                        next_str = raw.decode('utf-8', errors='strict')
                        _recurse(next_str, raw, chain + [name], depth + 1)
                    except Exception:
                        pass
                    continue

                try:
                    text = raw.decode('utf-8', errors='replace')
                except Exception:
                    text = raw.decode('latin-1', errors='replace')

                results.append({
                    'chain':        chain + [name],
                    'result_bytes': raw,
                    'result_text':  text,
                    'score':        score,
                    'source':       candidate.get('source', 'unknown'),
                    'src_offset':   candidate.get('offset', -1),
                    'tags':         _l4_tag_candidate(text),
                })

                if score >= 0.50 and depth + 1 < max_depth:
                    try:
                        next_str = raw.decode('utf-8', errors='strict')
                        _recurse(next_str, raw, chain + [name], depth + 1)
                    except Exception:
                        pass

            except Exception:
                continue

    _recurse(candidate['text'], None, [], 0)
    results.sort(key=lambda r: r['score'], reverse=True)
    return results[:12]

def _l4_graph_findings(
    candidates: List[dict],
    wordlist: Optional[set],
) -> List['Finding']:
    findings = []
    seen_result_hashes = set()

    for cand in candidates:
        if not cand.get('tags') and len(cand['text']) < 20:
            continue
        results = _l4_decode_graph(cand, wordlist, max_depth=4)
        for r in results:
            if r['score'] < 0.45:
                continue
            h = hashlib.md5(r['result_bytes'][:256]).hexdigest()
            if h in seen_result_hashes:
                continue
            seen_result_hashes.add(h)

            chain_str = ' → '.join(r['chain'])
            conf = 'HIGH' if r['score'] >= 0.85 else ('MEDIUM' if r['score'] >= 0.60 else 'LOW')
            src_note = f"source: {r['source']}"
            if r['src_offset'] >= 0:
                src_note += f" @ 0x{r['src_offset']:08X}"

            f = Finding(
                method=f"L4: Decode graph ({chain_str})",
                result_text=r['result_text'][:3000],
                result_bytes=r['result_bytes'][:4096],
                confidence=conf,
                note=f"chain: {chain_str} | score: {r['score']:.2f} | {src_note}",
            )
            f.chain  = ['l4_decode_graph'] + r['chain']
            f.why    = (
                f"Decode graph found valid transform path: {chain_str}. "
                f"Plaintext score {r['score']:.2f}. "
                f"Origin: {r['source']}."
            )
            findings.append(f)

    return findings

def _l4_correlate(all_findings: List['Finding']) -> List['Finding']:
    if not all_findings:
        return []

    l4_finds   = [f for f in all_findings if f.method.startswith('L4:')]
    prior_finds = [f for f in all_findings if not f.method.startswith('L4:')]

    content_index: dict = {}
    for f in all_findings:
        txt = (f.result_text or '').strip()
        if len(txt) < 8:
            continue
        key = re.sub(r'\s+', '', txt.lower())[:200]
        content_index.setdefault(key, []).append(f)

    multi_source = [flist for flist in content_index.values() if len(flist) >= 2]

    high_conf   = [f for f in all_findings if f.confidence in ('HIGH', 'CONFIRMED')]
    medium_conf = [f for f in all_findings if f.confidence == 'MEDIUM']
    graph_hits  = [f for f in l4_finds    if 'Decode graph' in f.method]
    anomaly_hits = [f for f in l4_finds   if 'anomaly' in f.method.lower() or 'post-IEND' in f.method]
    sweep_hits  = [f for f in l4_finds    if 'sweep' in f.method.lower() or 'entropy' in f.method.lower()]

    flag_finds  = []
    for f in all_findings:
        txt = (f.result_text or '').lower()
        if any(m in txt for m in ('flag{', 'ctf{', 'rrsw{', 'htb{', 'picoctf{')):
            flag_finds.append(f)

    all_correlated_methods = set()
    for flist in multi_source:
        for f in flist:
            all_correlated_methods.add(f.method)

    likely_decoys = []
    for f in l4_finds:
        if ('sweep' in f.method.lower() or 'chunk' in f.method.lower()):
            if f.method not in all_correlated_methods and f.confidence == 'LOW':
                likely_decoys.append(f)

    narrative_lines = [
        '=' * 70,
        '  L4 EVIDENCE CORRELATION SUMMARY',
        '=' * 70,
        '',
    ]

    if flag_finds:
        narrative_lines.append('  !! POSSIBLE FLAG / SOLUTION TOKEN DETECTED:')
        for f in flag_finds[:3]:
            preview = (f.result_text or '')[:200].replace('\n', ' ')
            narrative_lines.append(f"     [{f.confidence}] {f.method}: {preview}")
        narrative_lines.append('')

    narrative_lines.append(f'  Findings summary:')
    narrative_lines.append(f'    Total findings:      {len(all_findings)}')
    narrative_lines.append(f'    High confidence:     {len(high_conf)}')
    narrative_lines.append(f'    Medium confidence:   {len(medium_conf)}')
    narrative_lines.append(f'    L4 decode graph:     {len(graph_hits)}')
    narrative_lines.append(f'    L4 structural:       {len(anomaly_hits)}')
    narrative_lines.append(f'    Multi-source matches:{len(multi_source)}')
    narrative_lines.append(f'    Likely decoys:       {len(likely_decoys)}')
    narrative_lines.append('')

    if multi_source:
        narrative_lines.append('  CORRELATED (same content found in multiple passes):')
        for flist in multi_source[:5]:
            methods = ', '.join(f.method[:50] for f in flist)
            preview = (flist[0].result_text or '')[:100].replace('\n', ' ')
            narrative_lines.append(f"    → {preview}")
            narrative_lines.append(f"      sources: {methods}")
        narrative_lines.append('')

    if high_conf:
        narrative_lines.append('  HIGH CONFIDENCE FINDINGS (prioritise these):')
        for f in high_conf[:6]:
            preview = (f.result_text or '')[:120].replace('\n', ' ')
            narrative_lines.append(f"    [{f.confidence}] {f.method}")
            narrative_lines.append(f"      {preview}")
        narrative_lines.append('')

    if graph_hits:
        narrative_lines.append('  DECODE GRAPH HITS (valid transform chains):')
        for f in sorted(graph_hits, key=lambda x: x.score, reverse=True)[:5]:
            chain = ' → '.join(f.chain[1:]) if len(f.chain) > 1 else f.method
            preview = (f.result_text or '')[:100].replace('\n', ' ')
            narrative_lines.append(f"    [{f.confidence}] chain: {chain}")
            narrative_lines.append(f"      {preview}")
        narrative_lines.append('')

    if anomaly_hits:
        narrative_lines.append('  STRUCTURAL ANOMALIES (post-IEND, bad chunks, entropy):')
        for f in anomaly_hits[:4]:
            narrative_lines.append(f"    [{f.confidence}] {f.method}")
        narrative_lines.append('')

    if likely_decoys:
        narrative_lines.append('  LIKELY DECOYS (isolated, no cross-correlation):')
        for f in likely_decoys[:3]:
            narrative_lines.append(f"    [decoy?] {f.method}")
        narrative_lines.append('')

    narrative_lines.append('  RECOMMENDATIONS:')
    if flag_finds:
        narrative_lines.append('    1. Inspect flag-containing findings above immediately.')
    if multi_source:
        narrative_lines.append('    2. Correlated multi-source hits are highest priority — may be composite payload.')
    if graph_hits:
        best = sorted(graph_hits, key=lambda x: x.score, reverse=True)[0]
        chain = ' → '.join(best.chain[1:]) if len(best.chain) > 1 else best.method
        narrative_lines.append(f"    3. Best decode path: {chain}")
    if anomaly_hits:
        narrative_lines.append('    4. Inspect structural anomalies — post-IEND data is a primary hiding location.')
    if likely_decoys:
        narrative_lines.append('    5. Ignore likely decoys unless other evidence supports them.')
    narrative_lines.append('')
    narrative_lines.append('=' * 70)

    narrative = Finding(
        method='L4: Evidence narrative',
        result_text='\n'.join(narrative_lines),
        confidence='MEDIUM' if (high_conf or graph_hits) else 'LOW',
        note=(
            f"Correlation across {len(all_findings)} findings: "
            f"{len(multi_source)} cross-source matches, "
            f"{len(flag_finds)} flag hits, "
            f"{len(likely_decoys)} likely decoys."
        ),
    )
    narrative.chain  = ['l4_correlation']
    narrative.score  = 90.0
    narrative.rrsw_signal = 'RRSW-SIGMA' if flag_finds else 'RRSW-TRACK'
    narrative.why    = (
        'Evidence correlation engine: deduplication, clustering, ranking, '
        'decoy classification, and narrative generation across all L4 passes.'
    )

    return [narrative]

def _l4_run(
    data:      bytes,
    filename:  str,
    engine,
    flags:     dict,
    wordlist:  Optional[set],
) -> List['Finding']:
    l4_findings: List['Finding'] = []

    try:
        sweep_hits = _l4_raw_byte_sweep(data)
        l4_findings.extend(_l4_sweep_to_findings(sweep_hits, filename))
    except Exception as e:
        l4_findings.append(Finding(
            method='L4: Raw byte sweep', confidence='LOW',
            note=f'pass failed: {e}', result_text='',
        ))
        sweep_hits = []

    chunks = []
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        try:
            chunks = _l4_png_chunk_walk(data)
            l4_findings.extend(_l4_png_chunk_findings(chunks, filename))
        except Exception as e:
            l4_findings.append(Finding(
                method='L4: PNG chunk walk', confidence='LOW',
                note=f'pass failed: {e}', result_text='',
            ))

        try:
            post = _l4_post_iend(data)
            l4_findings.extend(_l4_post_iend_findings(post, filename))
        except Exception as e:
            l4_findings.append(Finding(
                method='L4: Post-IEND detection', confidence='LOW',
                note=f'pass failed: {e}', result_text='',
            ))

    try:
        if len(data) >= 512:
            anomalies = _l4_sliding_entropy(data, window=256, step=64)
            counts = [0] * 256
            for b in data: counts[b] += 1
            n = len(data)
            baseline = -sum((c/n)*math.log2(c/n) for c in counts if c)
            l4_findings.extend(_l4_entropy_findings(anomalies, round(baseline, 3), filename))
    except Exception as e:
        l4_findings.append(Finding(
            method='L4: Sliding entropy', confidence='LOW',
            note=f'pass failed: {e}', result_text='',
        ))

    try:
        candidates = _l4_harvest_candidates(l4_findings, sweep_hits)
        l4_findings.extend(_l4_graph_findings(candidates, wordlist))
    except Exception as e:
        l4_findings.append(Finding(
            method='L4: Decode graph', confidence='LOW',
            note=f'pass failed: {e}', result_text='',
        ))

    try:
        l4_findings.extend(_l4_correlate(l4_findings))
    except Exception as e:
        l4_findings.append(Finding(
            method='L4: Correlation engine', confidence='LOW',
            note=f'pass failed: {e}', result_text='',
        ))

    return l4_findings

_BINARY_HEADER_SIGS = [
    (b'-----BEGIN PGP',       'PGP message / key block'),
    (b'-----BEGIN RSA',       'RSA private key (PEM)'),
    (b'-----BEGIN EC',        'EC private key (PEM)'),
    (b'-----BEGIN OPENSSH',   'OpenSSH private key'),
    (b'-----BEGIN CERTIFICATE','X.509 certificate (PEM)'),
    (b'\x30\x82',            'DER/ASN.1 encoded structure (cert or key)'),
    (b'\x30\x81',            'DER/ASN.1 short-form structure'),
    (b'SSH-',                 'SSH public key / banner'),
    (b'AAAAB3NzaC1',          'SSH RSA public key (base64)'),
    (b'AAAAE2VjZHNh',         'SSH ECDSA public key (base64)'),
    (b'AAAAC3NzaC1',          'SSH Ed25519 public key (base64)'),
    (b'\x1f\x8b',            'Gzip compressed data'),
    (b'BZh',                  'Bzip2 compressed data'),
    (b'\xfd7zXZ\x00',        'XZ compressed data'),
    (b'PK\x03\x04',          'ZIP archive'),
    (b'Salted__',             'OpenSSL encrypted (salted)'),
    (b'\x00' * 16,           'Possible AES-128 zero-IV or null-padded block'),
    (b'\xff' * 16,           'Possible AES-128 max-byte block / PKCS padding artifact'),
]

def _detect_pkcs7_padding(data: bytes) -> Optional[int]:
    if len(data) < 2:
        return None
    n = data[-1]
    if 1 <= n <= 16 and len(data) >= n:
        if all(b == n for b in data[-n:]):
            return n
    return None

def _detect_repeated_padding(data: bytes, tail: int = 32) -> Optional[str]:
    if len(data) < tail:
        return None
    tail_bytes = data[-tail:]
    unique = set(tail_bytes)
    if len(unique) == 1:
        b = tail_bytes[0]
        return f'0x{b:02X} × {tail} bytes (repeated-byte padding or null fill)'
    diffs = [tail_bytes[i+1] - tail_bytes[i] for i in range(len(tail_bytes)-1)]
    if len(set(diffs)) == 1 and diffs[0] in (1, -1):
        return f'sequential padding pattern (Δ{diffs[0]:+d})'
    return None

def _looks_like_aes_key(data: bytes) -> Optional[str]:
    if len(data) not in (16, 24, 32):
        return None
    ent = _hio_entropy(data)
    if ent >= 6.5:
        bits = len(data) * 8
        return f'possible AES-{bits} raw key (length={len(data)}B, entropy={ent:.2f})'
    return None

def _analyze_binary_blob(blob: bytes, label: str, wordlist=None) -> List[Finding]:
    findings = []
    if not blob or len(blob) < 4:
        return findings

    for sig, desc in _BINARY_HEADER_SIGS:
        if blob.startswith(sig) or blob[:512].find(sig) != -1:
            pos = blob.find(sig)
            preview = blob[pos:pos+256]
            try:
                text = preview.decode('utf-8', errors='replace')
            except Exception:
                text = preview.decode('latin-1', errors='replace')
            f = Finding(
                method=f'Binary header match: {desc}',
                result_text=text,
                result_bytes=preview,
                confidence='HIGH',
                note=f'Signature matched in blob from {label} at offset {pos}.',
            )
            f.chain = ['binary_header_scan']
            f.why   = f'Known binary/crypto header signature: {desc}'
            findings.append(f)

    aes_hint = _looks_like_aes_key(blob)
    if aes_hint:
        f = Finding(
            method=f'Possible AES key material: {aes_hint}',
            result_bytes=blob,
            result_text=blob.hex(),
            confidence='MEDIUM',
            note=f'{aes_hint} — from {label}',
        )
        f.chain = ['aes_key_heuristic']
        f.why   = 'Blob length matches AES key size and entropy is very high.'
        findings.append(f)

    pkcs = _detect_pkcs7_padding(blob)
    if pkcs:
        unpadded = blob[:-pkcs]
        f = Finding(
            method=f'PKCS#7 padding detected (pad byte=0x{pkcs:02X}, {pkcs} bytes)',
            result_bytes=unpadded,
            result_text=unpadded.decode('latin-1', errors='replace'),
            confidence='MEDIUM',
            note=f'Stripped {pkcs} PKCS#7 padding bytes. Unpadded blob is {len(unpadded)}B.',
        )
        f.chain = ['pkcs7_strip']
        f.why   = 'PKCS#7 padding present — blob is likely AES/block-cipher output. Stripped.'
        findings.append(f)
        blob = unpadded

    rep_pad = _detect_repeated_padding(blob)
    if rep_pad:
        f = Finding(
            method=f'Repeated-byte padding: {rep_pad}',
            result_bytes=blob,
            confidence='LOW',
            note=f'Tail of blob from {label} shows: {rep_pad}',
        )
        f.chain = ['repeated_padding_detection']
        f.why   = 'Repeated-byte tail pattern — characteristic of block-cipher padding or deliberate fill.'
        findings.append(f)

    sb_results = try_xor_keys(blob)
    for score, key, text in sorted(sb_results, reverse=True)[:6]:
        f = Finding(
            method=f'Binary blob XOR single-byte (key=0x{key:02X})',
            result_text=text,
            result_bytes=bytes(b ^ key for b in blob),
            confidence='HIGH' if score >= 55 else 'MEDIUM',
            note=f'XOR key 0x{key:02X} on {len(blob)}B binary blob from {label}. Score={score}.',
        )
        f.chain = ['binary_blob', f'xor_0x{key:02X}']
        f.why   = f'Binary blob XOR-decoded with key 0x{key:02X}. Score {score}.'
        findings.append(f)

    if len(blob) >= 16:
        rk_results = break_repeating_key_xor(blob, max_keysize=32, top_n=4)
        seen_rk = set()
        for score, key_bytes, text in sorted(rk_results, reverse=True)[:4]:
            norm = re.sub(r'\s+', '', text.lower())[:120]
            if norm in seen_rk:
                continue
            seen_rk.add(norm)
            key_hex = key_bytes.hex()
            f = Finding(
                method=f'Binary blob XOR repeating-key (keysize={len(key_bytes)}, key=0x{key_hex[:16]}..)',
                result_text=text,
                result_bytes=bytes(blob[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(blob))),
                confidence='HIGH' if score >= 55 else 'MEDIUM',
                note=f'Repeating-key XOR on {len(blob)}B blob from {label}. Key={key_hex}.',
            )
            f.chain = ['binary_blob', f'xor_rk_{len(key_bytes)}']
            f.why   = f'Binary blob repeating-key XOR (keysize={len(key_bytes)}). Score {score}.'
            findings.append(f)

    return findings

def _analyze_binary_findings(prior_findings: List[Finding], wordlist=None) -> List[Finding]:
    new_findings = []
    seen_blob_hashes = set()

    for f in prior_findings:
        blob = getattr(f, 'result_bytes', None)
        if not blob or len(blob) < 8:
            continue
        if getattr(f, 'filetype', None):
            continue
        txt = getattr(f, 'result_text', '') or ''
        if txt and _hio_printable_ratio(txt) > 0.92:
            continue
        if _hio_printable_ratio(blob.decode('latin-1', errors='replace')) > 0.88:
            continue
        probe = blob[:4096]
        h = hashlib.md5(probe).hexdigest()
        if h in seen_blob_hashes:
            continue
        seen_blob_hashes.add(h)

        new_findings.extend(
            _analyze_binary_blob(probe, getattr(f, 'method', 'unknown'), wordlist)
        )

    return new_findings

import threading as _threading

def _size_to_eta(size_bytes: int, has_stego: bool, full_nasty: bool) -> str:
    mb = size_bytes / (1024 * 1024)
    if full_nasty:
        secs = max(5, mb * 3.0)
    elif has_stego:
        secs = max(3, mb * 1.2)
    else:
        secs = max(1, mb * 0.3)
    if secs < 60:
        return f'~{int(secs)}s'
    return f'~{int(secs/60)}m{int(secs%60)}s'

class _ProgressReporter:
    _SPINNER = ['|', '/', '-', '\\']

    def __init__(self, size_bytes: int = 0, quiet: bool = False, flags: dict = None):
        self._quiet   = quiet
        self._flags   = flags or {}
        self._pass    = 'initialising'
        self._start   = time.time()
        self._done    = False
        self._lock    = _threading.Lock()
        self._thread  = None
        self._spin_i  = 0
        self._eta = _size_to_eta(
            size_bytes,
            has_stego=self._flags.get('stego') or self._flags.get('full_nasty'),
            full_nasty=self._flags.get('full_nasty', False),
        )

    def start(self):
        if self._quiet:
            return
        self._thread = _threading.Thread(target=self._spin_loop, daemon=True)
        self._thread.start()

    def update(self, pass_name: str):
        with self._lock:
            self._pass = pass_name

    def finish(self, n_findings: int = 0):
        with self._lock:
            self._done = True
        if self._thread:
            self._thread.join(timeout=1.5)
        if not self._quiet:
            elapsed = time.time() - self._start
            sys.stdout.write('\r\033[K')
            sys.stdout.write(
                '  ' + C.TOXGRN + '[done]' + C.RESET +
                '  ' + C.DIM + f'{elapsed:.1f}s  {n_findings} findings' + C.RESET + '\n'
            )
            sys.stdout.flush()

    def _spin_loop(self):
        while True:
            with self._lock:
                if self._done:
                    break
                pass_name = self._pass
                spin_char = self._SPINNER[self._spin_i % len(self._SPINNER)]
                self._spin_i += 1
            elapsed = time.time() - self._start
            line = (
                '\r\033[K  ' +
                C.CYAN + spin_char + C.RESET + ' ' +
                C.DIM + f'{pass_name:<40}' + C.RESET + ' ' +
                C.DIM + f'{elapsed:5.1f}s  eta {self._eta}' + C.RESET
            )
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.12)

_ACTIVE_PROGRESS: Optional['_ProgressReporter'] = None

AnalysisEngine.analyze             = _fresh_analyze_string
AnalysisEngine.analyze_string      = _fresh_analyze_string
AnalysisEngine.analyze_file        = _analyze_file
AnalysisEngine.analyze_url         = _fresh_analyze_url

def make_run_dir(base_output: str, source_name: str) -> str:
    ts   = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    safe = re.sub(r'[^\w]', '_', os.path.basename(source_name))[:30].strip('_')
    name = f'{safe}_{ts}'
    path = os.path.join(base_output, name)
    os.makedirs(path, exist_ok=True)
    return path

def clean_filename(method: str, ext: str, offset: int) -> str:
    label = re.sub(r'[^\w]', '_', method.lower())[:30].strip('_')
    return f'{label}_{ext}_{offset:#x}.{ext}'

def save_decoded_file(data: bytes, run_dir: str, method: str, ext: str, offset: int = 0) -> str:
    os.makedirs(run_dir, exist_ok=True)
    filename = clean_filename(method, ext, offset)
    path = os.path.join(run_dir, filename)
    if os.path.exists(path):
        filename = clean_filename(method, ext, offset) + f'_{id(data)%10000}'
        path = os.path.join(run_dir, filename)
    with open(path, 'wb') as fh: fh.write(data)
    return path

def save_report(report_text: str, run_dir: str) -> str:
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(run_dir, f'HIO_{ts}.txt')
    with open(path, 'w', encoding='utf-8', errors='replace') as fh: fh.write(report_text)
    return path


def _save_jsonl(findings, source_label, path):
    import json as _json
    with open(path, 'w', encoding='utf-8') as fh:
        for f in findings:
            obj = {
                'finding_id':      getattr(f, 'finding_id', ''),
                'source':          source_label,
                'method':          getattr(f, 'method', ''),
                'confidence':      getattr(f, 'confidence', 'LOW'),
                'signal':          getattr(f, 'rrsw_signal', 'RRSW-NOISE'),
                'score':           getattr(f, 'score', 0),
                'entropy':         round(getattr(f, 'entropy', 0.0), 3),
                'structured_type': getattr(f, 'structured_type', ''),
                'support_count':   getattr(f, 'support_count', 1),
                'chain':           getattr(f, 'chain', []) or [],
                'iocs':            getattr(f, 'iocs', []) or [],
                'why':             getattr(f, 'why', ''),
                'note':            (getattr(f, 'note', '') or '')[:400],
                'result_text':     (getattr(f, 'result_text', None) or '')[:2000] or None,
                'byte_offset':     getattr(f, 'byte_offset', -1),
                'input_sha256':    getattr(f, 'input_sha256', ''),
                'timestamp':       str(getattr(f, 'timestamp', '')),
            }
            fh.write(_json.dumps(obj, ensure_ascii=False) + '\n')


def _save_html_report(findings, source_label, input_preview, path):
    import json as _json, html as _hl
    import datetime as _dt

    ts = _dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conf_rank = {'CONFIRMED': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
    sorted_f  = sorted(findings,
                       key=lambda f: (conf_rank.get(f.confidence, 0), f.score),
                       reverse=True)
    conf_colors = {
        'CONFIRMED': '#39FF14', 'HIGH': '#ff4444',
        'MEDIUM':    '#ffaa00', 'LOW':  '#888899',
    }

    def esc(s):
        return _hl.escape(str(s or ''))

    def finding_row(f, idx):
        col    = conf_colors.get(f.confidence, '#888899')
        method = esc(f.method or '')
        conf   = esc(f.confidence)
        score  = getattr(f, 'score', 0)
        result = esc((f.result_text or '')[:600])
        why    = esc(f.why or '')
        chain  = esc(' -> '.join(getattr(f, 'chain', []) or []))
        stype  = esc(getattr(f, 'structured_type', '') or '')
        supp   = getattr(f, 'support_count', 1)
        iocs   = getattr(f, 'iocs', []) or []
        fid    = esc(getattr(f, 'finding_id', '') or '')
        rb     = getattr(f, 'result_bytes', None)
        hx     = rb[:64].hex() if rb else ''

        ioc_rows = ''
        for ioc in iocs[:10]:
            ioc_rows += (
                '<tr>'
                '<td style="color:#aaa;font-size:11px;padding:1px 8px">' + esc(ioc.get('type','')) + '</td>'
                '<td style="font-family:monospace;font-size:11px;padding:1px 8px">' + esc(ioc.get('value','')) + '</td>'
                '</tr>'
            )
        ioc_table = ('<table style="margin-top:6px;border-collapse:collapse">' + ioc_rows + '</table>') if ioc_rows else ''

        badges = ''
        if stype:
            badges += '<span style="background:#1e3a5f;color:#7ab3e0;padding:1px 6px;border-radius:3px;font-size:10px;margin-right:4px">' + stype + '</span>'
        if supp > 1:
            badges += '<span style="background:#1a3a1a;color:#39FF14;padding:1px 6px;border-radius:3px;font-size:10px">corroborated x' + str(supp) + '</span>'

        hex_block = ''
        if hx:
            hex_block = '<div style="font-family:monospace;font-size:10px;color:#555;margin-top:4px">' + esc(hx) + '...</div>'

        return (
            '<div style="border:1px solid #2a2a3a;border-left:3px solid ' + col + ';padding:10px 14px;margin:6px 0;background:#111118;border-radius:4px">'
            '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
            '<span style="color:' + col + ';font-weight:500;font-size:12px">[' + conf + ']</span>'
            '<span style="color:#ddd;font-size:12px">' + method + '</span>'
            '<span style="color:#555;font-size:11px">score ' + str(score) + '</span>'
            '<span style="color:#444;font-size:10px;margin-left:auto">#' + fid + '</span>'
            '</div>'
            + badges
            + '<div style="font-family:monospace;font-size:12px;color:#c8ffb0;margin-top:6px;white-space:pre-wrap;word-break:break-all">' + result + '</div>'
            + hex_block
            + ioc_table
            + '<details style="margin-top:6px"><summary style="color:#555;font-size:11px;cursor:pointer">why / chain</summary>'
            '<div style="color:#666;font-size:11px;margin-top:4px">' + why + '</div>'
            '<div style="color:#555;font-size:11px;font-family:monospace">' + chain + '</div>'
            '</details>'
            '</div>'
        )

    # IOC summary across all findings
    all_iocs = {}
    for f in sorted_f:
        for ioc in (getattr(f, 'iocs', []) or []):
            t = ioc.get('type', '')
            all_iocs.setdefault(t, set()).add(ioc.get('value', ''))

    ioc_summary = ''
    if all_iocs:
        rows = ''
        for t, vals in sorted(all_iocs.items()):
            for v in sorted(vals)[:8]:
                rows += (
                    '<tr>'
                    '<td style="color:#aaa;font-size:11px;padding:2px 8px">' + esc(t) + '</td>'
                    '<td style="font-family:monospace;font-size:11px;padding:2px 8px">' + esc(v) + '</td>'
                    '</tr>'
                )
        ioc_summary = (
            '<div style="background:#0a0a18;border:1px solid #1e2a1e;border-radius:6px;padding:12px;margin-bottom:18px">'
            '<div style="color:#39FF14;font-weight:500;margin-bottom:8px;font-size:12px">extracted indicators</div>'
            '<table style="border-collapse:collapse">' + rows + '</table>'
            '</div>'
        )

    counts = {'CONFIRMED': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in sorted_f:
        counts[f.confidence] = counts.get(f.confidence, 0) + 1

    count_pills = ''
    for c in ('CONFIRMED', 'HIGH', 'MEDIUM', 'LOW'):
        if counts.get(c):
            col = conf_colors[c]
            count_pills += (
                '<span class="count-pill" style="background:' + col + '22;color:' + col + '">'
                + str(counts[c]) + ' ' + c
                + '</span>'
            )

    findings_html = ''.join(finding_row(f, i) for i, f in enumerate(sorted_f[:50], 1))
    overflow = ''
    if len(sorted_f) > 50:
        overflow = '<div style="color:#555;font-size:11px;margin-top:12px">... and ' + str(len(sorted_f)-50) + ' more findings in --report --json</div>'

    html = (
        '<!DOCTYPE html>\n'
        '<html><head><meta charset="utf-8">\n'
        '<title>Hash It Out -- ' + esc(source_label) + '</title>\n'
        '<style>\n'
        '*{box-sizing:border-box;margin:0;padding:0}\n'
        'body{background:#0d0d1a;color:#ccc;font-family:system-ui,sans-serif;padding:24px;line-height:1.5}\n'
        'h1{color:#39FF14;font-size:18px;font-weight:500;margin-bottom:4px}\n'
        'h2{color:#7ab3e0;font-size:13px;font-weight:500;margin:18px 0 6px;letter-spacing:.06em;text-transform:uppercase}\n'
        '.meta{color:#555;font-size:11px;margin-bottom:20px}\n'
        '.counts{display:flex;gap:16px;margin-bottom:18px}\n'
        '.count-pill{padding:3px 10px;border-radius:4px;font-size:11px;font-weight:500}\n'
        '</style>\n'
        '</head><body>\n'
        '<h1>Hash It Out</h1>\n'
        '<div class="meta">source: ' + esc(source_label) + ' &nbsp;·&nbsp; ' + ts + ' &nbsp;·&nbsp; ' + str(len(sorted_f)) + ' findings</div>\n'
        '<div class="counts">' + count_pills + '</div>\n'
        '<h2>input preview</h2>\n'
        '<div style="font-family:monospace;font-size:11px;color:#666;background:#0a0a18;padding:8px;border-radius:4px;margin-bottom:18px;white-space:pre-wrap">' + esc(input_preview[:300]) + '</div>\n'
        + ioc_summary
        + '<h2>findings</h2>\n'
        + findings_html
        + overflow
        + '\n</body></html>'
    )

    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(html)


def _parse_exif_simple(seg_data: bytes) -> str:
    """Extract key EXIF fields from an APP1 segment without PIL."""
    import struct
    try:
        tiff = seg_data[6:]
        if len(tiff) < 8: return ''
        bom = tiff[:2]
        endian = '<' if bom == b'II' else '>' if bom == b'MM' else None
        if not endian: return ''
        ifd_off = struct.unpack(endian + 'I', tiff[4:8])[0]
        if ifd_off + 2 > len(tiff): return ''
        n = struct.unpack(endian + 'H', tiff[ifd_off:ifd_off+2])[0]
        TAGS = {0x010F:'Make',0x0110:'Model',0x0132:'DateTime',
                0x013B:'Artist',0x8298:'Copyright',0x0131:'Software',
                0x9003:'DateTimeOriginal',0xA002:'PixelXDimension',0xA003:'PixelYDimension'}
        out = []
        pos = ifd_off + 2
        for _ in range(min(n, 32)):
            if pos + 12 > len(tiff): break
            tag, typ, count, vraw = struct.unpack(endian + 'HHI4s', tiff[pos:pos+12])
            pos += 12
            if tag not in TAGS: continue
            if typ == 2:
                voff = struct.unpack(endian + 'I', vraw)[0] if count > 4 else 0
                val = (tiff[voff:voff+count] if count <= 4 or voff+count <= len(tiff)
                       else vraw[:4]).rstrip(b'\x00').decode('utf-8', errors='replace')
                if val.strip(): out.append(f"{TAGS[tag]}: {val.strip()}")
            elif typ in (3, 4):
                voff = struct.unpack(endian + 'I', vraw)[0] if typ==4 else struct.unpack(endian + 'H', vraw[:2])[0]
                out.append(f"{TAGS[tag]}: {voff}")
        return '  '.join(out[:10])
    except Exception: return ''


def _parse_iptc_simple(seg_data: bytes) -> str:
    """Extract IPTC fields from a Photoshop APP13 block."""
    import struct
    IPTC = {5:'ObjectName',25:'Keywords',80:'Byline',85:'BylineTitle',
            90:'City',92:'State',95:'Country',105:'Headline',110:'Credit',
            115:'Source',116:'Copyright',120:'Caption',55:'DateCreated'}
    out = []
    pos = 0
    try:
        while pos < len(seg_data) - 4:
            if seg_data[pos] != 0x1C: pos += 1; continue
            rec = seg_data[pos+1]; tag = seg_data[pos+2]
            length = struct.unpack('>H', seg_data[pos+3:pos+5])[0]
            val = seg_data[pos+5:pos+5+length]
            pos += 5 + length
            if rec == 2 and tag in IPTC:
                out.append(f"{IPTC[tag]}: {val.decode('utf-8', errors='replace').strip()}")
        return '  '.join(out[:12])
    except Exception: return ''


def _triage_pe(data: bytes, source_label: str) -> list:
    """PE (Windows executable) header triage — arch, timestamp, sections, entropy."""
    import struct
    findings = []
    try:
        if data[:2] != b'MZ': return []
        pe_off = struct.unpack('<I', data[0x3c:0x40])[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off+4] != b'PE\x00\x00': return []
        machine = struct.unpack('<H', data[pe_off+4:pe_off+6])[0]
        n_sec   = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
        tstamp  = struct.unpack('<I', data[pe_off+8:pe_off+12])[0]
        opt_sz  = struct.unpack('<H', data[pe_off+20:pe_off+22])[0]
        chars   = struct.unpack('<H', data[pe_off+22:pe_off+24])[0]
        arch_n  = {0x14c:'x86',0x8664:'x64',0x1c0:'ARM',0xaa64:'ARM64'}.get(machine, f'0x{machine:04x}')
        kind    = 'DLL' if chars & 0x2000 else 'EXE'
        import datetime as _dt
        ts_str  = _dt.datetime.utcfromtimestamp(tstamp).strftime('%Y-%m-%d %H:%M:%S UTC')
        lines2  = [f'type:{kind}  arch:{arch_n}  sections:{n_sec}  compiled:{ts_str}']
        sec_off = pe_off + 24 + opt_sz
        for i in range(min(n_sec, 16)):
            so = sec_off + i*40
            if so + 40 > len(data): break
            name    = data[so:so+8].rstrip(b'\x00').decode('ascii', errors='replace')
            raw_off = struct.unpack('<I', data[so+20:so+24])[0]
            raw_sz  = struct.unpack('<I', data[so+16:so+20])[0]
            ch      = struct.unpack('<I', data[so+36:so+40])[0]
            sd      = data[raw_off:raw_off+raw_sz] if raw_off+raw_sz <= len(data) else b''
            ent     = _hio_entropy(sd) if sd else 0.0
            flag    = 'X' if ch & 0x20000000 else ' '
            lines2.append(f'  {name:<10} raw={raw_sz:>6,}  entropy={ent:.2f}  [{flag}]')
        note = f'{kind} {arch_n}, compiled {ts_str}'
        high_ent = [l for l in lines2 if 'entropy=7.' in l or 'entropy=8.' in l]
        if high_ent: lines2.append(f'WARNING: {len(high_ent)} high-entropy section(s) — possible packing')
        findings.append(Finding(method='PE triage', result_text='\n'.join(lines2),
                                confidence='HIGH' if high_ent else 'MEDIUM',
                                note=note, source_label=source_label))
    except Exception: pass
    return findings


def _triage_elf(data: bytes, source_label: str) -> list:
    """ELF binary triage — class, arch, type, interpreter."""
    import struct
    findings = []
    try:
        if data[:4] != b'\x7fELF': return []
        ei_class = data[4]; ei_data = data[5]
        endian   = '<' if ei_data == 1 else '>'
        bits     = 32 if ei_class == 1 else 64
        e_type   = struct.unpack(endian+'H', data[16:18])[0]
        e_mach   = struct.unpack(endian+'H', data[18:20])[0]
        types    = {1:'relocatable',2:'executable',3:'shared',4:'core'}
        machines = {0x03:'x86',0x3E:'x86-64',0x28:'ARM',0xB7:'AArch64',0x08:'MIPS'}
        t_str    = types.get(e_type, f'type-{e_type}')
        m_str    = machines.get(e_mach, f'arch-0x{e_mach:x}')
        e_shnum  = struct.unpack(endian+'H', data[60:62] if bits==64 else data[48:50])[0]
        e_phnum  = struct.unpack(endian+'H', data[56:58] if bits==64 else data[44:46])[0]
        interp   = ''
        for tag in (b'/lib/', b'/usr/lib/'):
            idx = data.find(tag)
            if idx > 0:
                end = data.index(b'\x00', idx)
                interp = data[idx:end].decode('ascii', errors='replace')
                break
        summary  = f'{bits}-bit {t_str}  arch:{m_str}  sections:{e_shnum}  segments:{e_phnum}'
        if interp: summary += f'  interp:{interp}'
        findings.append(Finding(method='ELF triage', result_text=summary,
                                confidence='MEDIUM', source_label=source_label))
    except Exception: pass
    return findings


def _triage_pdf(data: bytes, source_label: str) -> list:
    """PDF triage — version, page count, suspicious indicator flags."""
    import re as _re
    findings = []
    try:
        if not data.startswith(b'%PDF-'): return []
        ver  = (_re.match(rb'%PDF-(\d+\.\d+)', data) or [None,b'?'])[1]
        ver  = ver.decode() if isinstance(ver, bytes) else '?'
        n_obj    = len(_re.findall(rb'\d+ \d+ obj', data))
        n_streams= len(_re.findall(rb'stream\r?\n', data))
        pg_m     = _re.search(rb'/Count\s+(\d+)', data)
        n_pages  = pg_m.group(1).decode() if pg_m else '?'
        flags    = []
        if _re.search(rb'/JavaScript|/JS\b', data):    flags.append('JavaScript')
        if _re.search(rb'/Launch', data):               flags.append('Launch action')
        if _re.search(rb'/EmbeddedFile', data):         flags.append('EmbeddedFile')
        if _re.search(rb'/OpenAction', data):           flags.append('OpenAction')
        if _re.search(rb'/Encrypt', data):              flags.append('Encrypted')
        if _re.search(rb'/AcroForm', data):             flags.append('AcroForm')
        summary = f'PDF {ver}  pages:{n_pages}  objects:{n_obj}  streams:{n_streams}'
        if flags: summary += f'\nflags: {", ".join(flags)}'
        conf = 'HIGH' if any(f in ('JavaScript','Launch action','EmbeddedFile') for f in flags) else 'MEDIUM'
        findings.append(Finding(method='PDF triage', result_text=summary,
                                confidence=conf,
                                note=f'PDF v{ver}, flags: {", ".join(flags) or "none"}',
                                source_label=source_label))
    except Exception: pass
    return findings


def _triage_binary_format(data: bytes, source_label: str) -> list:
    """Dispatch to PE/ELF/PDF triage."""
    results = []
    if not data or len(data) < 8: return results
    if data[:2] == b'MZ':         results.extend(_triage_pe(data, source_label))
    if data[:4] == b'\x7fELF':   results.extend(_triage_elf(data, source_label))
    if data[:4] == b'%PDF':       results.extend(_triage_pdf(data, source_label))
    return results


def _build_timeline(findings) -> list:
    """Extract timestamps from findings and return sorted (datetime_str, method) pairs."""
    import re as _re
    timeline, seen = [], set()
    PATS = [
        _re.compile(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'),
        _re.compile(r'\b(\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2})'),
        _re.compile(r'\b(\d{4}-\d{2}-\d{2})\b'),
    ]
    for f in findings:
        txt = f.result_text or ''
        if not txt: continue
        method = f.method or ''
        for pat in PATS:
            for m in pat.finditer(txt):
                raw  = m.group(1)
                norm = raw.replace(':','-',2) if re.match(r'\d{4}:\d{2}:\d{2}', raw) else raw
                key  = (norm, method[:40])
                if key not in seen:
                    seen.add(key)
                    timeline.append((norm, method[:50]))
    timeline.sort(key=lambda x: x[0])
    return timeline[:100]


def _format_timeline(timeline) -> str:
    if not timeline: return ''
    out, prev = [], ''
    for ts, src_method in timeline:
        date = ts[:10]
        if date != prev:
            out.append(f'  {date}')
            prev = date
        out.append(f'    {ts}  {src_method}')
    return '\n'.join(out)


def generate_text_report(findings, source_label, input_preview, saved_files):
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = [
        '=' * 88,
        f'  HASH IT OUT v{VERSION}  -  ANALYSIS REPORT',
        f'  generated : {ts}',
        f'  source    : {source_label}',
        f'  input len : {len(input_preview)} characters',
        '=' * 88,
        '',
        'input preview (first 200 chars):',
        input_preview[:200] + ('...' if len(input_preview) > 200 else ''),
        ''
    ]
    if saved_files:
        lines += ['-' * 88, 'saved files:']
        for sf in saved_files:
            lines.append(f'  [saved] {sf}')
        lines.append('')
    counts = {'CONFIRMED': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        counts[getattr(f, 'confidence', 'LOW')] = counts.get(getattr(f, 'confidence', 'LOW'), 0) + 1
    lines += [
        '-' * 88,
        'summary:',
        f'  total      : {len(findings)}',
        f'  confirmed  : {counts.get("CONFIRMED", 0)}',
        f'  high       : {counts.get("HIGH", 0)}',
        f'  medium     : {counts.get("MEDIUM", 0)}',
        f'  low        : {counts.get("LOW", 0)}',
        ''
    ]
    lead = findings[0] if findings else None
    if lead:
        lines += [
            'lead signal:',
            f'  method     : {lead.method}',
            f'  signal     : {getattr(lead, "rrsw_signal", "RRSW-NOISE")}',
            f'  score      : {getattr(lead, "score", 0)}',
            f'  entropy    : {getattr(lead, "entropy", 0.0):.3f}',
            f'  chain      : {" -> ".join(getattr(lead, "chain", []) or [])}',
            f'  why        : {getattr(lead, "why", "")}',
            ''
        ]
    # Timeline
    timeline = _build_timeline(findings)
    if timeline:
        tl_text = _format_timeline(timeline)
        lines += ['-' * 88, 'timeline:', tl_text, '']
    lines += ['-' * 88, 'findings:', '']
    for i, f in enumerate(findings, 1):
        lines.append(f'[{i:03d}] method      : {f.method}')
        lines.append(f'     confidence  : {getattr(f, "confidence", "LOW")}')
        lines.append(f'     signal      : {getattr(f, "rrsw_signal", "RRSW-NOISE")}')
        lines.append(f'     score       : {getattr(f, "score", 0)}')
        lines.append(f'     entropy     : {getattr(f, "entropy", 0.0):.3f}')
        lines.append(f'     chain       : {" -> ".join(getattr(f, "chain", []) or [])}')
        lines.append(f'     why         : {getattr(f, "why", "")}')
        if getattr(f, 'filetype', None):
            lines.append(f'     file type   : {f.filetype[1]}')
        if getattr(f, 'note', ''):
            lines.append(f'     note        : {str(f.note)[:500]}')
        if getattr(f, 'result_text', None):
            lines.append(f'     output      : {str(f.result_text)[:600]}')
        elif getattr(f, 'result_bytes', None):
            lines.append(f'     bytes       : {len(f.result_bytes):,}')
        lines.append('')
    lines += ['=' * 88, 'Hash It Out  -  github.com/RRSWSEC/Hash-It-Out', '=' * 88]
    return '\n'.join(lines)

def save_csv_report(findings, source_label, run_dir: str):
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(run_dir, f'HIO_findings_{ts}.csv')
    with open(path, 'w', newline='', encoding='utf-8', errors='replace') as fh:
        w = csv.writer(fh)
        w.writerow(['confidence', 'signal', 'score', 'entropy', 'method', 'chain', 'why', 'source', 'note', 'result_preview'])
        for f in findings:
            w.writerow([
                getattr(f, 'confidence', 'LOW'),
                getattr(f, 'rrsw_signal', 'RRSW-NOISE'),
                getattr(f, 'score', 0),
                f'{getattr(f, "entropy", 0.0):.3f}',
                getattr(f, 'method', ''),
                ' -> '.join(getattr(f, 'chain', []) or []),
                getattr(f, 'why', ''),
                getattr(f, 'source_label', source_label),
                (getattr(f, 'note', '') or '')[:240],
                (getattr(f, 'result_text', '') or '')[:240],
            ])
    return path

def results_to_json(findings, source_label):
    return {
        'source': source_label,
        'version': VERSION,
        'timestamp': datetime.datetime.now().isoformat(),
        'total': len(findings),
        'findings': [
            {
                'method': getattr(f, 'method', ''),
                'confidence': getattr(f, 'confidence', 'LOW'),
                'signal': getattr(f, 'rrsw_signal', 'RRSW-NOISE'),
                'score': getattr(f, 'score', 0),
                'entropy': getattr(f, 'entropy', 0.0),
                'chain': getattr(f, 'chain', []) or [],
                'why': getattr(f, 'why', ''),
                'note': getattr(f, 'note', ''),
                'result_text': (getattr(f, 'result_text', None)[:2000] if getattr(f, 'result_text', None) else None),
            }
            for f in findings
        ]
    }

def _write_report(findings, source_label, input_data, saved_files,
                  flags, run_dir, save_json, quiet):
    if flags.get('noreport'): return
    auto = any(f.confidence in ('CONFIRMED','HIGH','MEDIUM') for f in findings)
    if not (flags.get('report') or auto): return
    os.makedirs(run_dir, exist_ok=True)
    report_text = generate_text_report(findings, source_label,
                                        str(input_data), saved_files)
    report_path = save_report(report_text, run_dir)
    try:
        csv_path = save_csv_report(findings, source_label, run_dir)
        if not quiet: print(f"\n  {C.GREEN}[+] csv  saved : {csv_path}{C.RESET}")
    except Exception: pass
    if save_json:
        j     = results_to_json(findings, source_label)
        jpath = report_path.replace('.txt', '.json')
        with open(jpath, 'w', encoding='utf-8') as fh: import json; json.dump(j, fh, indent=2)
        if not quiet: print(f"  {C.GREEN}[+] json saved : {jpath}{C.RESET}")
    if not quiet: print(f"  {C.GREEN}[+] report saved: {report_path}{C.RESET}")
    # Analyst profile: auto-write JSONL alongside text report
    if flags.get('analyst') and _save_jsonl:
        _auto_jsonl = report_path.replace('.txt', '.jsonl')
        try:
            _save_jsonl(findings, source_label, _auto_jsonl)
            if not quiet:
                print(f"  {C.GREEN}[+] JSONL saved : {_auto_jsonl}{C.RESET}")
        except Exception:
            pass
    # JSONL export
    _out_jsonl = getattr(flags, 'out_jsonl', None) or ''
    if not _out_jsonl:
        import sys as _sys
        for i, a in enumerate(_sys.argv):
            if a in ('--out-jsonl', '--out_jsonl') and i+1 < len(_sys.argv):
                _out_jsonl = _sys.argv[i+1]; break
    if _out_jsonl:
        _save_jsonl(findings, source_label, _out_jsonl)
        if not quiet: print(f"  {C.GREEN}[+] JSONL saved : {_out_jsonl}{C.RESET}")
    # HTML report
    _out_html = getattr(flags, 'out_html', None) or ''
    if not _out_html:
        import sys as _sys
        for i, a in enumerate(_sys.argv):
            if a in ('--out-html', '--out_html') and i+1 < len(_sys.argv):
                _out_html = _sys.argv[i+1]; break
    if _out_html:
        _save_html_report(findings, source_label, str(input_data)[:500], _out_html)
        if not quiet: print(f"  {C.GREEN}[+] HTML report : {_out_html}{C.RESET}")

def _save_findings(findings, flags, run_dir, source_label):
    saved = []
    if not flags.get('savefile'):
        return saved
    for f in findings:
        if f.result_bytes and f.filetype and f.filetype[0]:
            try:
                m = re.search(r'0x([0-9a-fA-F]+)', f.method or '')
                offset = int(m.group(1), 16) if m else 0
                fp = save_decoded_file(f.result_bytes, run_dir,
                                       f.method, f.filetype[0], offset)
                saved.append(fp)
                print_file_saved(fp, f.method, f.filetype[1])
            except Exception as e:
                print(f"  {C.RED}[!] could not save: {e}{C.RESET}")
    return saved

def print_file_saved(filepath, method, filetype):
    name = os.path.basename(filepath)
    print(f"  {C.GREEN}[+] extracted:{C.RESET} {C.WHITE}{name}{C.RESET}  {C.GREY}({filetype or method}){C.RESET}")

def print_report_saved(path, csv_path=None, json_path=None):
    print(f"\n  {C.GREEN}[+] report:{C.RESET}  {path}")
    if csv_path:
        print(f"  {C.GREEN}[+] csv:   {C.RESET}  {csv_path}")
    if json_path:
        print(f"  {C.GREEN}[+] json:  {C.RESET}  {json_path}")

def print_url_header(url, status, content_type, size, error=None):
    print(f"\n{C.CYAN}  [*] fetching : {C.WHITE}{url}{C.RESET}")
    if error:
        print(f"  {C.RED}[!] error    : {error}{C.RESET}")
        return
    print(f"{C.CYAN}  [*] status   : {C.WHITE}{status}{C.RESET}")
    print(f"{C.CYAN}  [*] type     : {C.WHITE}{content_type}{C.RESET}")
    print(f"{C.CYAN}  [*] size     : {C.WHITE}{size:,} bytes{C.RESET}")

def _shell_show_finding(f, idx):
    print(f"\n  [{idx:03d}] {getattr(f, 'method', '')}")
    print(f"        confidence : {getattr(f, 'confidence', 'LOW')}  |  score {getattr(f, 'score', 0)}")
    print(f"        signal     : {getattr(f, 'rrsw_signal', 'RRSW-NOISE')}")
    if getattr(f, 'filetype', None):
        print(f"        type       : {f.filetype[1]}")
    if getattr(f, 'note', ''):
        print(f"        note       : {str(f.note)[:200]}")
    if getattr(f, 'result_text', None):
        preview = str(f.result_text)[:400].replace('\n', ' ')
        print(f"        output     : {preview}")
    elif getattr(f, 'result_bytes', None):
        print(f"        bytes      : {len(f.result_bytes):,}")
    print(f"        why        : {getattr(f, 'why', '')}")
    if getattr(f, 'child_count', 0):
        print(f"        children   : {getattr(f, 'child_count', 0)}")


def _shell_analyze_blob(blob, label, flags, output_base, wordlist, quiet, save_json, max_depth, stegopw_wordlist):
    engine = AnalysisEngine(wordlist=wordlist, output_dir=output_base,
                            verbose=(not quiet), flags=flags, max_depth=max_depth,
                            stegopw_wordlist=stegopw_wordlist)
    if isinstance(blob, bytes):
        findings = engine.analyze_file(blob, label)
        if not quiet:
            print_results(findings, label, len(blob), verbose=True, nocolor=flags.get('nocolor', False))
    else:
        findings = run_analysis(blob, label, flags, output_base, wordlist, quiet,
                                nodelay=True, save_json=save_json,
                                max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
    return findings

def _children_for_finding(findings, target):
    key = getattr(target, 'method', '')
    out = []
    for i, f in enumerate(findings, 1):
        if getattr(f, 'parent_artifact', '') == key:
            out.append((i, f))
    return out

def _meta_for_finding(f):
    rows = [
        f'method={getattr(f,"method","")}',
        f'confidence={getattr(f,"confidence","LOW")}',
        f'signal={getattr(f,"rrsw_signal","RRSW-NOISE")}',
        f'score={getattr(f,"score",0)}',
        f'entropy={getattr(f,"entropy",0.0):.4f}',
        f'filetype={(getattr(f,"filetype",(None,None))[1] if getattr(f,"filetype",None) else "")}',
        f'chain={" -> ".join(getattr(f,"chain",[]) or [])}',
    ]
    if getattr(f, 'artifact_profile', None):
        rows.append('artifact_profile=' + ', '.join(getattr(f, 'artifact_profile', []) or []))
    if getattr(f, 'why', ''):
        rows.append('why=' + getattr(f, 'why', ''))
    return '\n'.join(rows)

def _render_key_hints(f):
    txt = getattr(f, 'result_text', '') or ''
    raw = getattr(f, 'result_bytes', b'') or b''
    hints = _parameter_hint_finding(txt, raw)
    return hints.result_text if hints else 'no key/parameter hints available'

def run_from_dir(dirpath, flags, output_base, wordlist,
                 quiet=False, nodelay=False, save_json=False,
                 max_depth=3, stegopw_wordlist=None, recursive=False):
    if not os.path.isdir(dirpath):
        print(f"  {C.RED}[!] not a directory: {dirpath}{C.RESET}")
        return
    if recursive:
        files = []
        for root, _, fnames in os.walk(dirpath):
            for fn in fnames: files.append(os.path.join(root, fn))
    else:
        files = [os.path.join(dirpath, f) for f in os.listdir(dirpath)
                 if os.path.isfile(os.path.join(dirpath, f))]
    files.sort()
    if not quiet:
        print(f"\n{C.CYAN}[*] directory: {C.WHITE}{dirpath}{C.RESET}")
        print(f"{C.CYAN}[*] files    : {C.WHITE}{len(files)}{C.RESET}")
    case_findings = []
    for filepath in files:
        run_from_file(filepath, flags, output_base, wordlist,
                      quiet, nodelay, save_json, max_depth, stegopw_wordlist)
    # ── Case-wide summary ─────────────────────────────────────────────
    if not quiet and len(files) > 1:
        import hashlib as _hl
        print()
        print(f"  {C.TOXGRN}{'='*_W}{C.RESET}")
        print(f"  {C.TOXGRN}  CORPUS SUMMARY  --  {len(files)} files analyzed{C.RESET}")
        print(f"  {C.TOXGRN}{'='*_W}{C.RESET}")
        # Re-scan output dir for all CSV reports to aggregate findings
        csv_dir = output_base
        import glob as _glob, csv as _csv
        all_csvs = sorted(_glob.glob(os.path.join(csv_dir, '**', 'HIO_findings_*.csv'), recursive=True))
        if all_csvs:
            conf_counts: dict = {}
            method_counts: dict = {}
            ioc_types: dict = {}
            for csv_path in all_csvs:
                try:
                    with open(csv_path, newline='', encoding='utf-8', errors='replace') as fh:
                        for row in _csv.DictReader(fh):
                            c = row.get('confidence','LOW')
                            conf_counts[c] = conf_counts.get(c, 0) + 1
                            m = row.get('method','')[:40]
                            method_counts[m] = method_counts.get(m, 0) + 1
                except Exception:
                    pass
            if conf_counts:
                parts = []
                for c in ('CONFIRMED','HIGH','MEDIUM','LOW'):
                    if conf_counts.get(c):
                        col = _CONF_COLOR.get(c, C.GREY)
                        parts.append(f"{col}{conf_counts[c]} {c}{C.RESET}")
                print(f"  total findings:  {'  |  '.join(parts)}")
            if method_counts:
                top_methods = sorted(method_counts.items(), key=lambda x: -x[1])[:8]
                print(f"  top methods:     {',  '.join('%s(%d)' % (m, n) for m,n in top_methods)}")
        print()

def run_from_file(filepath, flags, output_base, wordlist,
                  quiet=False, nodelay=False, save_json=False,
                  max_depth=3, stegopw_wordlist=None):
    global _ACTIVE_PROGRESS
    if not os.path.exists(filepath):
        print(f"  {C.RED}[!] file not found: {filepath}{C.RESET}")
        return []
    size = os.path.getsize(filepath)
    if not quiet:
        print(f"\n{C.CYAN}[*] file     : {C.WHITE}{filepath}{C.RESET}")
        print(f"{C.CYAN}[*] size     : {C.WHITE}{size:,} bytes{C.RESET}")
        print(f"{C.CYAN}[*] depth    : {C.WHITE}{max_depth} level(s){C.RESET}")
        print(f"{C.CYAN}[*] wordlist : {C.WHITE}{len(wordlist):,} words{C.RESET}")
    if not nodelay:
        time.sleep(DISPLAY_DELAY)
    try:
        with open(filepath, 'rb') as fh:
            raw_bytes = fh.read()
    except Exception as e:
        print(f"  {C.RED}[!] cannot read file: {e}{C.RESET}")
        return []

    pr = _ProgressReporter(size_bytes=size, quiet=quiet, flags=flags)
    _ACTIVE_PROGRESS = pr
    pr.start()
    findings = []
    try:
        engine = AnalysisEngine(wordlist=wordlist, output_dir=output_base,
                                verbose=(not quiet), flags=flags, max_depth=max_depth,
                                stegopw_wordlist=stegopw_wordlist)
        source = os.path.basename(filepath)
        findings = engine.analyze_file(raw_bytes, source)
    finally:
        pr.finish(len(findings))
        _ACTIVE_PROGRESS = None

    run_dir = make_run_dir(output_base, source)
    if not quiet:
        if flags.get('analyst'):
            print_results_analyst(findings, source, len(raw_bytes))
        else:
            print_results(findings, source, len(raw_bytes), verbose=flags.get('verbose', False), nocolor=flags.get('nocolor', False))
    saved_files = _save_findings(findings, flags, run_dir, source)
    _write_report(findings, source, raw_bytes[:MAX_REPORT_STRING_LEN].decode('latin-1', errors='ignore'), saved_files, flags, run_dir, save_json, quiet)
    if findings and (not quiet) and flags.get('explain'):
        _print_explain_top(findings)
    return findings

def run_from_url(url, flags, output_base, wordlist,
                 quiet=False, nodelay=False, save_json=False,
                 max_depth=3, stegopw_wordlist=None):
    global _ACTIVE_PROGRESS
    if not quiet:
        print(f"\n{C.CYAN}[*] fetching : {C.WHITE}{url}{C.RESET}")
    fetch = fetch_url(url)
    if not quiet:
        print_url_header(url=url, status=fetch.status, content_type=fetch.content_type, size=len(fetch.raw_bytes), error=fetch.error)
    if fetch.error:
        return []
    if not quiet:
        print(f"{C.CYAN}[*] binary   : {C.WHITE}{fetch.is_binary}{C.RESET}")
        if fetch.detected_type:
            print(f"{C.CYAN}[*] detected : {C.WHITE}{fetch.detected_type[1]}{C.RESET}")
        print(f"{C.CYAN}[*] depth    : {C.WHITE}{max_depth} level(s){C.RESET}")
        print(f"{C.CYAN}[*] wordlist : {C.WHITE}{len(wordlist):,} words{C.RESET}")
    if not nodelay:
        time.sleep(DISPLAY_DELAY)

    pr = _ProgressReporter(size_bytes=len(fetch.raw_bytes), quiet=quiet, flags=flags)
    _ACTIVE_PROGRESS = pr
    pr.start()
    findings = []
    try:
        engine = AnalysisEngine(wordlist=wordlist, output_dir=output_base,
                                verbose=(not quiet), flags=flags, max_depth=max_depth,
                                stegopw_wordlist=stegopw_wordlist)
        findings = engine.analyze_url(url)
    finally:
        pr.finish(len(findings))
        _ACTIVE_PROGRESS = None

    source = f'URL:{url}'
    run_dir = make_run_dir(output_base, url)
    if not quiet:
        if flags.get('analyst'):
            print_results_analyst(findings, url, len(fetch.raw_bytes))
        else:
            print_results(findings, url, len(fetch.raw_bytes), verbose=flags.get('verbose', False), nocolor=flags.get('nocolor', False))
    saved_files = _save_findings(findings, flags, run_dir, source)
    if findings and (not quiet) and flags.get('explain'):
        _print_explain_top(findings)
    return findings

def run_analysis(input_data, source_label, flags, output_base,
                 wordlist, quiet=False, nodelay=False, save_json=False,
                 max_depth=3, stegopw_wordlist=None):
    if flags.get('artifact_mode'):
        flags['deep'] = True
    if flags.get('key_hints'):
        flags['cipher'] = True
        flags['xor'] = True
    if not quiet:
        print_input_header(
            source=source_label,
            size=len(input_data),
            wordlist_size=len(wordlist),
            depth=max_depth,
            entropy=_hio_entropy(input_data),
        )
    if not nodelay:
        time.sleep(DISPLAY_DELAY)
    engine = AnalysisEngine(wordlist=wordlist, output_dir=output_base,
                            verbose=(not quiet), flags=flags, max_depth=max_depth,
                            stegopw_wordlist=stegopw_wordlist)
    findings = engine.analyze_string(input_data, source_label)
    run_dir = make_run_dir(output_base, source_label)
    if not quiet:
        if flags.get('analyst'):
            print_results_analyst(findings, source_label, len(input_data))
        else:
            print_results(findings, source_label, len(input_data),
                          verbose=flags.get('verbose', False))
        if flags.get('debug_passes'):
            _print_pass_timing()
        if flags.get('explain'):
            _print_explain_top(findings)
    saved_files = _save_findings(findings, flags, run_dir, source_label)
    _write_report(findings, source_label, input_data, saved_files,
                  flags, run_dir, save_json, quiet)
    return findings

def _apply_aliases_and_presets(args, flags):
    if getattr(args, 'decode_basic', False):
        for k in ('rot','base','hex','binary','morse'):
            flags[k] = True
    if getattr(args, 'decode_classical', False):
        flags['cipher'] = True
    if getattr(args, 'analyze_files', False):
        flags['stego'] = True
        flags['deep'] = True
    if getattr(args, 'analyze_everything', False):
        flags['all'] = True
    if getattr(args, 'try_reversed', False):
        flags['reverse'] = True

    if getattr(args, 'fast', False):
        for k in ('rot','base','hex','binary','morse'):
            flags[k] = True
        flags['cipher'] = False
        flags['xor'] = False
        flags['stego'] = False
        flags['deep'] = False
    if getattr(args, 'standard', False):
        for k in ('rot','base','hex','binary','morse','xor'):
            flags[k] = True
    if getattr(args, 'deep_mode', False):
        for k in ('rot','base','hex','binary','morse','cipher','xor','stego','deep','reverse'):
            flags[k] = True
    if getattr(args, 'ctf', False):
        for k in ('rot','base','hex','binary','morse','cipher','xor','reverse'):
            flags[k] = True
    if getattr(args, 'forensics', False):
        for k in ('base','hex','binary','stego','deep'):
            flags[k] = True
        flags['report'] = True
        flags['savefile'] = True
    return flags

def _preset_depth(args, run_all):
    if args.depth is not None:
        return max(1, min(50, args.depth))
    if getattr(args, 'fast', False):
        return 1
    if getattr(args, 'deep_mode', False):
        return 6
    if getattr(args, 'ctf', False):
        return 5
    if getattr(args, 'forensics', False):
        return 5
    if run_all and not args.quiet:
        return _ask_depth({}, args.nodelay)
    return 3

def _ask_depth(flags, nodelay):
    if nodelay: return 3
    print(f"""
{C.TOXGRN}  +--------------------------------------------------+
  |  HIO v4.1  -  Analysis Depth Configuration      |
  |  [1] Quick - 1 level (fast)  [2] Standard - 3   |
  |  [3] Deep - 5 levels         [4] Max - 10 (slow)|
  |  [5] Custom                                      |
  +--------------------------------------------------+{C.RESET}""")
    depth_map = {'1':1,'2':3,'3':5,'4':10}
    depth = 3
    try:
        choice = input(f"  {C.CYAN}depth [1-5, default=2]: {C.RESET}").strip()
        if choice in depth_map: depth = depth_map[choice]
        elif choice == '5':
            raw = input(f"  {C.CYAN}enter depth: {C.RESET}").strip()
            depth = max(1, min(50, int(raw))) if raw.isdigit() else 3
        rev = input(f"  {C.CYAN}also analyze reversed input? [Y/n]: {C.RESET}").strip().lower()
        flags['reverse'] = (rev != 'n')
    except (EOFError, KeyboardInterrupt): pass
    print(f"  {C.DIM}depth set to {depth}. starting analysis...{C.RESET}\n")
    return depth

def _print_explain_top(findings, limit=5):
    if not findings:
        print(f"  {C.GREY}nothing to explain{C.RESET}")
        return
    print(f"\n{C.TOXGRN}{C.BOLD}  [ Explanation Mode ]{C.RESET}")
    for i, f in enumerate(findings[:limit], 1):
        print(f"  {str(i).rjust(2)}. {getattr(f,'method','')}")
        print(f"      rank : {getattr(f,'confidence','LOW')}  |  signal {getattr(f,'rrsw_signal','RRSW-NOISE')}  |  score {getattr(f,'score',0)}  |  entropy {getattr(f,'entropy',0.0):.3f}")
        print(f"      why  : {getattr(f,'why','')}")
        ch = ' -> '.join(getattr(f,'chain',[]) or [])
        if ch:
            print(f"      chain: {ch}")

def _print_modes():
    print('  --profile ctf        broad, fast, all families active')
    print('  --profile stego      image/file steganography focus')
    print('  --profile forensics  DFIR — full passes, all IOCs, verbose')
    print('  --profile triage     fast first-pass, shallow depth')
    print('  --profile deep       maximum depth, slow, thorough')
    print('  --profile low-noise  high-confidence findings only')
    print('  --profile analyst    IOC-first, evidence-grade, defensible output')
    print()
    print('  --debug-passes       show per-pass timing after analysis')
    print('  --out-jsonl PATH     write findings as JSONL (pipeline-friendly)')
    print('  --out-html  PATH     write portable HTML investigation report')
    print('  --list-profiles      show all profiles and exit')

def _print_decoders():
    print('  encoding : base64/32/16/8/2, base58/62/85/91/92, url, html, uuencode')
    print('  classical: rot 1-25, atbash, vigenere (auto key recovery), affine, bacon')
    print('             rail fence, polybius, tap code, nihilist, playfair, ADFGVX')
    print('  stego    : PNG LSB R/G/B/A, JPEG DCT/COM/EXIF, visual bg/alpha/strided')
    print('  binary   : XOR single-byte, repeating-key (Hamming), chain analysis')
    print('  file     : magic bytes (41 types), embedded carving, PE/ELF/PDF triage')
    print('  IOC      : IPv4/6, URLs, emails, JWTs, PEM blocks, hashes, commands')

def print_help():
    help_text = f"""
{C.TOXGRN}{C.BOLD}  HASHITOUT - usage{C.RESET}

{C.WHITE}  quick use:{C.RESET}
    hashitout "string"
    hashitout -f file.bin
    hashitout -d ./samples/
    hashitout -u https://example.com/blob
    hashitout --shell

{C.WHITE}  core modes:{C.RESET}
    --full-nasty    go deeper, slower, more aggressive
    --analyst       show reasoning and context
    --artifact-mode focus on carving and artifact triage
    --key-hints     show likely key lengths and parameters
    --graph         show transformation chains
    --savefile      write extracted artifacts to disk

{C.WHITE}  decoder families:{C.RESET}
    --all       run everything (default)
    --rot       ROT / Caesar family
    --base      Base encoding family
    --hex       hex decoding
    --binary    binary / bit-level
    --morse     Morse and NATO alphabet
    --cipher    classical ciphers + brute-force
    --xor       XOR brute-force
    --stego     steganography checks
    --reverse   also run all decoders on reversed input

{C.WHITE}  shell:{C.RESET}
    show <n>    inspect a finding
    why <n>     explain why it ranked
    graph <n>   show chain path
    children <n> show nested children
    meta <n>    show metadata
    keyhints <n> show parameter hints
    focus text|files
    rerank

{C.WHITE}  note:{C.RESET}
    no neural networks, no machine learning, no AI.
    deterministic, heuristic, and classical methods only.

{C.GREY}  only run against files and URLs you own or have authorization to analyze.{C.RESET}
"""
    print(help_text)

def run_shell(flags, output_base, wordlist, quiet=False,
              save_json=False, max_depth=3, stegopw_wordlist=None):
    print(f"\n{C.TOXGRN}{C.BOLD}  [ hashitout :: interactive shell ]{C.RESET}")
    print(f"  {C.DIM}commands: <string>  file <path>  dir <path>  url <url>  top [n]  show <n>  why <n>  use <n>  chain <n>  graph <n>  children <n>  meta <n>  keyhints <n>  save <n>  last  clear  flags  help  exit{C.RESET}\n")
    last_findings = []
    last_source = 'shell'
    while True:
        try:
            raw = input(f"{C.TOXGRN}hashitout>{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not raw:
            continue
        cmd = raw.lower()
        parts = raw.split()
        try:
            if cmd in ('exit','quit','q',':q','bye'):
                print(f"\n  {C.TOXGRN}Stay sharp.{C.RESET}\n")
                break
            elif cmd.startswith('file '):
                last_findings = []
                for p in raw[5:].strip().split():
                    last_findings = run_from_file(p, flags, output_base, wordlist, quiet,
                                                  nodelay=True, save_json=save_json,
                                                  max_depth=max_depth, stegopw_wordlist=stegopw_wordlist) or []
                    last_source = p
            elif cmd.startswith('dir '):
                run_from_dir(raw[4:].strip(), flags, output_base, wordlist, quiet,
                             nodelay=True, save_json=save_json,
                             max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
            elif cmd.startswith('url '):
                last_findings = []
                for u in raw[4:].strip().split():
                    last_findings = run_from_url(u, flags, output_base, wordlist, quiet,
                                                 nodelay=True, save_json=save_json,
                                                 max_depth=max_depth, stegopw_wordlist=stegopw_wordlist) or []
                    last_source = u
            elif cmd in ('help','?'):
                print_help()
            elif cmd == 'flags':
                for k in sorted(flags):
                    print(f"  {k}={flags[k]}")
            elif cmd == 'last':
                print(f"  last source: {last_source}")
                if last_findings:
                    print(f"  findings   : {len(last_findings)}")
            elif cmd.startswith('top'):
                try:
                    n = int(parts[1]) if len(parts) > 1 else 10
                except Exception:
                    n = 10
                for i, f in enumerate(last_findings[:n], 1):
                    print(f"  [{i:03d}] {getattr(f, 'signal', 'RRSW-TRACE'):>10}  score={getattr(f,'score',0):>5.1f}  {f.method}")
            elif parts and parts[0] in ('show','chain','save','use','why','children','meta','keyhints','graph'):
                if len(parts) < 2 or not parts[1].isdigit():
                    print(f"  {C.RED}[!] usage: {parts[0]} <n>{C.RESET}")
                    continue
                idx = int(parts[1]) - 1
                if idx < 0 or idx >= len(last_findings):
                    print(f"  {C.RED}[!] no finding {parts[1]}{C.RESET}")
                    continue
                f = last_findings[idx]
                if parts[0] == 'show':
                    _shell_show_finding(f, idx + 1)
                elif parts[0] == 'chain':
                    print(f"  {C.CYAN}{' -> '.join(getattr(f, 'chain', []) or [])}{C.RESET}")
                elif parts[0] == 'graph':
                    chain = getattr(f, 'chain', []) or []
                    print(f"  source")
                    for step in chain:
                        print(f"    -> {step}")
                    print(f"    -> result")
                elif parts[0] == 'save':
                    if not f.result_bytes:
                        print(f"  {C.RED}[!] finding has no binary payload to save{C.RESET}")
                    else:
                        run_dir = make_run_dir(output_base, f'shell_{idx+1}')
                        ext = f.filetype[0] if f.filetype else 'bin'
                        path = save_decoded_file(f.result_bytes, run_dir, f.method, ext, idx+1)
                        try:
                            _write_sidecar(path, f, last_source)
                        except Exception:
                            pass
                        print(f"  {C.GREEN}[+] saved: {path}{C.RESET}")
                elif parts[0] == 'use':
                    payload = f.result_bytes if f.result_bytes else (f.result_text or '')
                    label = f'shell_finding_{idx+1}'
                    last_findings = _shell_analyze_blob(payload, label, flags, output_base, wordlist, quiet, save_json, max_depth, stegopw_wordlist) or []
                    last_source = label
                elif parts[0] == 'why':
                    print(getattr(f, 'why', '(no reasoning available)'))
                elif parts[0] == 'children':
                    for child in _children_for_finding(last_findings, f):
                        print(f"  - {child.method}")
                elif parts[0] == 'meta':
                    print(_meta_for_finding(f))
                elif parts[0] == 'keyhints':
                    print(_render_key_hints(f))
            elif cmd == 'rerank':
                last_findings = _finalize_findings(last_findings, last_source, wordlist)
                print(f"  reranked {len(last_findings)} findings")
            elif cmd == 'focus text':
                last_findings = [f for f in last_findings if getattr(f, 'result_text', None)]
                print(f"  text findings: {len(last_findings)}")
            elif cmd == 'focus files':
                last_findings = [f for f in last_findings if getattr(f, 'result_bytes', None)]
                print(f"  binary findings: {len(last_findings)}")
            elif cmd == 'clear':
                print('\033c', end='')
            elif cmd.startswith('http'):
                last_findings = run_from_url(raw, flags, output_base, wordlist, quiet,
                                             nodelay=True, save_json=save_json,
                                             max_depth=max_depth, stegopw_wordlist=stegopw_wordlist) or []
                last_source = raw
            else:
                last_findings = run_analysis(raw, 'SHELL INPUT', flags, output_base, wordlist,
                                             quiet, nodelay=True, save_json=save_json,
                                             max_depth=max_depth, stegopw_wordlist=stegopw_wordlist) or []
                last_source = 'SHELL INPUT'
        except Exception as e:
            print(f"  {C.RED}[!] shell error: {e}{C.RESET}")

def load_wordlist() -> set:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wordlists', 'english.txt')
    words = set()
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                w = line.strip().lower()
                if w: words.add(w)
    return words

def _warn_special_chars():
    argv_raw = ' '.join(sys.argv[1:])
    SHELL_SPECIAL = set('!`$')
    if any(c in argv_raw for c in SHELL_SPECIAL):
        print(f"  {C.YELLOW}[!] bash quoting warning:{C.RESET}")
        print(f"  {C.GREY}    Your input may contain bash special characters (!  `  $  \'  \")")
        print(f"       bash expands these BEFORE hashitout sees them, silently mangling input.")
        print(f"       To avoid this:{C.RESET}")
        print(f"  {C.CYAN}       1. Pipe from echo (safest):  printf '%s' 'your string' | hashitout --stdin{C.RESET}")
        print(f"  {C.CYAN}       2. Save to file then:         hashitout -f input.txt{C.RESET}")
        print(f"  {C.CYAN}       3. Disable bash history:      set +H  (current session only){C.RESET}")
        print(f"  {C.CYAN}       4. Use $\'...\'  quoting:     hashitout $\'string with !bangs\'")
        print(f"  {C.CYAN}       5. Use --stdin flag:          hashitout --stdin < input.txt{C.RESET}")
        print()
    elif not sys.stdin.isatty() and '--stdin' not in sys.argv and '-' not in sys.argv:
        pass


def _read_stdin_input():
    try:
        data = sys.stdin.buffer.read()
        return data.decode('utf-8', errors='replace').rstrip('\n')
    except Exception as e:
        print(f"  {C.RED}[!] stdin read error: {e}{C.RESET}")
        return None



# ── Triage profiles ───────────────────────────────────────────────────────
_PROFILES = {
    'ctf': {
        'description': 'CTF competitions — broad, fast, noisy OK',
        'max_depth':    5,
        'top_n':        5,
        'flags': {'all': True, 'stego': False, 'verbose': False},
        'note': 'All decoder families active, stego optional, depth 5',
    },
    'stego': {
        'description': 'Image/file steganography focus',
        'max_depth':    3,
        'top_n':        8,
        'flags': {'stego': True, 'all': False},
        'note': 'Stego passes prioritised; decode families still run',
    },
    'forensics': {
        'description': 'DFIR / incident response — evidence discipline',
        'max_depth':    5,
        'top_n':        10,
        'flags': {'all': True, 'stego': True, 'verbose': True},
        'note': 'Full passes, verbose output, all IOCs surfaced',
    },
    'triage': {
        'description': 'Fast first-pass — breadth over depth',
        'max_depth':    2,
        'top_n':        5,
        'flags': {'all': True, 'stego': False, 'verbose': False},
        'note': 'Shallow depth, fastest path to a signal',
    },
    'deep': {
        'description': 'Maximum depth — slow, thorough',
        'max_depth':    10,
        'top_n':        None,
        'flags': {'all': True, 'stego': True, 'verbose': True, 'deep': True},
        'note': 'All passes, all depth, full output',
    },
    'low-noise': {
        'description': 'High-confidence only — minimal false positives',
        'max_depth':    3,
        'top_n':        3,
        'flags': {'all': True, 'stego': False, 'verbose': False},
        'note': 'Tight confidence thresholds, top 3 only',
    },
    'analyst': {
        'description': 'DFIR analyst — IOC-first, evidence-grade, defensible output',
        'max_depth':    5,
        'top_n':        10,
        'flags': {'all': True, 'stego': True, 'verbose': False, 'analyst': True},
        'note': 'IOC summary first, timeline, analyst narrative, JSONL auto-export',
    },
}

def _apply_profile(profile_name: str, flags: dict, args) -> int:
    """Apply a named profile to flags and return override max_depth."""
    p = _PROFILES.get(profile_name)
    if not p:
        return getattr(args, 'depth', None) or 3
    for k, v in p.get('flags', {}).items():
        flags[k] = v
    return p['max_depth']


def _list_profiles():
    print()
    for name, p in _PROFILES.items():
        print(f"  --profile {name:<12}  {p['description']}")
        print(f"  {'':16}  depth {p['max_depth']}  top_n {str(p['top_n']):<5}  {p['note']}")
        print()


def build_parser():
    p = argparse.ArgumentParser(prog='hashitout', add_help=False)
    p.add_argument('-f', '--file', metavar='PATH', nargs='+')
    p.add_argument('-d', '--dir', metavar='PATH')
    p.add_argument('-s', '--string', metavar='STRING')
    p.add_argument('-u', '--url', metavar='URL', nargs='+')
    p.add_argument('-o', '--output', metavar='DIR', default='./output')
    p.add_argument('input_string', nargs='?', default=None)
    for flag in ('all','rot','base','hex','binary','morse','cipher','xor','misc','stego','deep','reverse','verbose'):
        p.add_argument(f'--{flag}', action='store_true')
    p.add_argument('--depth', metavar='N', type=int, default=None)
    p.add_argument('--recursive', action='store_true')
    p.add_argument('--stegopw', metavar='WORDLIST')
    for flag in ('savefile','report','noreport','quiet','nocolor','json','nodelay','shell','version','stdin'):
        p.add_argument(f'--{flag}', action='store_true')
    p.add_argument('--help', '-h', action='store_true')
    for flag in ('fast', 'standard', 'deep_mode', 'ctf', 'forensics', 'explain', 'list_modes', 'list_decoders', 'decode_basic', 'decode_classical', 'analyze_files', 'analyze_everything', 'try_reversed'):
        p.add_argument(f'--{flag.replace("_","-")}', dest=flag, action='store_true')
    p.add_argument('--profile',      metavar='NAME',
                   help='Triage profile: ctf, stego, forensics, triage, deep, low-noise, analyst')
    p.add_argument('--debug-passes', dest='debug_passes', action='store_true',
                   help='Show pass timing and failure info after analysis')
    p.add_argument('--out-jsonl',    metavar='PATH',
                   help='Write findings as JSONL (one JSON object per line)')
    p.add_argument('--out-html',     metavar='PATH',
                   help='Write a portable HTML investigation report')
    p.add_argument('--list-profiles', dest='list_profiles', action='store_true',
                   help='List available triage profiles and exit')
    return p

def main():
    _m = os.path.join(os.path.expanduser('~/.local/bin'), 'hashitout.installed')
    if not os.path.exists(_m) and not os.path.abspath(__file__).endswith('hashitout'):
        _self_install()
    parser = build_parser()
    args, extra = parser.parse_known_args()
    if extra and not getattr(args, 'input_string', None):
        args.input_string = ' '.join(extra)
    if args.nocolor:
        for attr in [a for a in dir(C) if not a.startswith('_') and isinstance(getattr(C, a), str)]:
            setattr(C, attr, '')
    if args.version:
        print(f"  Hash It Out v{VERSION}\n  github.com/RRSWSEC/Hash-It-Out\n")
        return
    if getattr(args, 'list_modes', False):
        _print_modes()
        return
    if getattr(args, 'list_decoders', False):
        _print_decoders()
        return
    if not args.quiet:
        print_banner()
    if args.help:
        print_help()
        if not any([args.shell, args.file, args.dir, args.string, args.url, args.input_string]):
            return
    flags = {k: getattr(args, k, False) for k in ('all','rot','base','hex','binary','morse','cipher','xor','misc','stego','deep','reverse','verbose','savefile','report','noreport','nocolor','analyst','graph','artifact_mode','key_hints','full_nasty','debug_passes')}
    flags['explain'] = getattr(args, 'explain', False)
    _HIO_ACTIVE_FLAGS.clear(); _HIO_ACTIVE_FLAGS.update(flags)
    _apply_aliases_and_presets(args, flags)
    # ── Profile override ─────────────────────────────────────────────────────
    if getattr(args, 'list_profiles', False):
        _list_profiles(); return
    _profile_name = getattr(args, 'profile', None) or ''
    if _profile_name:
        _profile_depth = _apply_profile(_profile_name, flags, args)
        if not args.quiet:
            _pd = _PROFILES.get(_profile_name, {})
            print(f"  {C.CYAN}[profile] {_profile_name}: {_pd.get('description', '')}{C.RESET}")
    else:
        _profile_depth = None
    if flags.get('full_nasty'):
        flags['cipher'] = True
        flags['xor'] = True
        flags['deep'] = True
        flags['artifact_mode'] = True
        flags['key_hints'] = True
        flags['analyst'] = True
        flags['graph'] = True
    run_all = flags.get('all') or not any(flags.get(k) for k in ('rot','base','hex','binary','morse','cipher','xor','misc','stego','deep'))
    flags['all'] = run_all
    if run_all:
        for k in ('rot','base','hex','binary','morse','cipher','xor','stego','deep'):
            flags[k] = True
    if flags.get('artifact_mode'):
        flags['deep'] = True
    if flags.get('key_hints'):
        flags['cipher'] = True
        flags['xor'] = True
    if flags.get('cipher') or flags.get('deep') or getattr(args, 'deep_mode', False) or flags.get('full_nasty'):
        print(f"  {C.YELLOW}[!] brute-force or deep analysis enabled - this may be slow on large inputs{C.RESET}")
    max_depth = _profile_depth or _preset_depth(args, run_all)
    if flags.get('full_nasty'):
        max_depth = max(max_depth, _FULL_NASTY_PROFILE['beam_depth'])
    stegopw_wordlist = getattr(args, 'stegopw', None)
    output_base = args.output
    os.makedirs(output_base, exist_ok=True)
    wordlist = load_wordlist()
    quiet = args.quiet
    nodelay = args.nodelay
    save_json = args.json
    ran = False
    if getattr(args, 'stdin', False) or (not sys.stdin.isatty() and not args.file and not args.url and not getattr(args,'dir',None) and not (args.string or args.input_string)):
        stdin_data = _read_stdin_input()
        if stdin_data is not None:
            run_analysis(stdin_data, 'STDIN', flags, output_base, wordlist, quiet, nodelay, save_json, max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
            ran = True
    if args.file:
        for filepath in args.file:
            run_from_file(filepath, flags, output_base, wordlist, quiet, nodelay, save_json, max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        ran = True
    if args.dir:
        run_from_dir(args.dir, flags, output_base, wordlist, quiet, nodelay, save_json, max_depth=max_depth, stegopw_wordlist=stegopw_wordlist, recursive=args.recursive)
        ran = True
    if args.url:
        for url in args.url:
            run_from_url(url, flags, output_base, wordlist, quiet, nodelay, save_json, max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        ran = True
    input_str = args.string or args.input_string
    if input_str:
        run_analysis(input_str, 'CLI INPUT', flags, output_base, wordlist, quiet, nodelay, save_json, max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        ran = True
    if args.shell or not ran:
        run_shell(flags, output_base, wordlist, quiet, save_json, max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)

if __name__ == '__main__':
    main()
