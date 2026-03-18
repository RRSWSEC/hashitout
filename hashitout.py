#!/usr/bin/env python3
# Hash It Out v4.2.0 - single file
# github.com/RRSWSEC/Hash-It-Out

import base64
import string
import struct
import io
import quopri
from typing import Optional, List, Tuple
import zlib
from typing import Optional, Tuple, List
import os
import hashlib
import math
from dataclasses import dataclass, field
from typing import List, Optional
from typing import List
import io, os
from typing import Optional
import csv
import json
import datetime
import re
import sys
from typing import Optional, List
import urllib.request
import urllib.error
import urllib.parse
import argparse
import time

def _self_install():
    import shutil, stat as _st
    src = os.path.abspath(__file__)
    for d in [os.path.expanduser("~/.local/bin"), "/usr/local/bin"]:
        os.makedirs(d, exist_ok=True)
        dst = os.path.join(d, "hashitout")
        try:
            shutil.copy2(src, dst)
            os.chmod(dst, os.stat(dst).st_mode | _st.S_IEXEC | _st.S_IXGRP | _st.S_IXOTH)
            open(dst + ".installed","w").write("ok")
            print("  installed: " + dst)
            return
        except PermissionError: continue
    print("  install failed")

# ---- core/decoders.py ----

import base64
import string
import struct
import io
import quopri
from typing import Optional, List, Tuple


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  ROT / Caesar family
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  BASE ENCODINGS  Base2 â Base92
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  HEX variants
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  URL / HTML
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def decode_url(data: str) -> Optional[str]:
    try:
        from urllib.parse import unquote
        decoded = unquote(data.strip())
        return decoded if decoded != data.strip() else None
    except Exception:
        return None

def decode_url_double(data: str) -> Optional[str]:
    try:
        from urllib.parse import unquote
        first = unquote(data.strip())
        second = unquote(first)
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


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  Morse Code
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  Classical & CTF ciphers
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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

COMMON_VIGENERE_KEYS = [
    'key','secret','password','abc','flag','cipher','hack','leet',
    'admin','root','code','virus','ctf','crypto','hidden','stego',
    'pass','test','hio','hashitout','pwn','exploit','hacker',
    'hello','world','python','linux','windows','security','reverse',
    'decode','encode','base','shift','alpha','beta','gamma','delta',
]

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


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  Misc encodings
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def decode_quoted_printable(data: str) -> Optional[bytes]:
    try:
        result = quopri.decodestring(data.encode())
        return result if result != data.encode() else None
    except Exception:
        return None

def decode_uuencode(data: str) -> Optional[bytes]:
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            import uu
        lines = data.strip().split('\n')
        if not lines[0].startswith('begin'):
            return None
        in_buf = io.BytesIO(data.encode())
        out_buf = io.BytesIO()
        uu.decode(in_buf, out_buf, quiet=True)
        return out_buf.getvalue()
    except Exception:
        return None

def decode_punycode(data: str) -> Optional[str]:
    try:
        if 'xn--' not in data.lower():
            return None
        decoded = data.strip().encode('ascii').decode('idna')
        return decoded if decoded != data.strip() else None
    except Exception:
        return None


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  XOR
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def try_xor_keys(data: bytes) -> List[Tuple[int, str]]:
    results = []
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        try:
            text = decoded.decode('ascii')
            if is_mostly_printable(text):
                results.append((key, text))
        except Exception:
            pass
    return results

def try_xor_multibyte(data: bytes) -> List[Tuple[bytes, str]]:
    common_keys = [
        b'\xde\xad', b'\xbe\xef', b'\xca\xfe', b'\xba\xbe',
        b'\xff\xfe', b'\xaa\x55', b'\x55\xaa', b'\xde\xad\xbe\xef',
        b'\xca\xfe\xba\xbe', b'\x13\x37', b'\x41\x41', b'\x00\xff',
    ]
    results = []
    for key in common_keys:
        decoded = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        try:
            text = decoded.decode('ascii')
            if is_mostly_printable(text):
                results.append((key, text))
        except Exception:
            pass
    return results


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  Helpers
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  TRIFID CIPHER DETECTION
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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

# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  HILL CIPHER 2x2 BRUTE FORCE
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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

# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  PORTA CIPHER (13 keys - full brute force)
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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

# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  NIHILIST CIPHER
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def _nihilist_square(kw):
    kw = kw.lower().replace("j","i")
    seen = []
    for c in kw:
        if c.isalpha() and c not in seen: seen.append(c)
    for c in "abcdefghiklmnopqrstuvwxyz":
        if c not in seen: seen.append(c)
    return {c: (i//5+1)*10+(i%5+1) for i,c in enumerate(seen)}

def decode_nihilist(ct, keyword):
    import re
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
    import re
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

# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  ADFGX / ADFGVX CIPHER
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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

# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  ENIGMA MACHINE
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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
        # step rotors
        notches = [r_data[i][1] for i in range(len(rotors))]
        if len(pos)>=3 and chr(pos[1]+65) in notches[1]:
            pos[0]=(pos[0]+1)%26; pos[1]=(pos[1]+1)%26
        elif len(pos)>=3 and chr(pos[2]+65) in notches[2]:
            pos[1]=(pos[1]+1)%26
        pos[-1]=(pos[-1]+1)%26
        # encode
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


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  A1Z26
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def decode_a1z26(text):
    import re
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

# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  BIFID CIPHER
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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

# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  BAUDOT (ITA2)
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

_BAUDOT_LTRS = [None,"E","\n","A"," ","S","I","U","\r","D","R","J","N","F","C","K","T","Z","L","W","H","Y","P","Q","O","B","G","F-SHIFT","M","X","V","LTRS"]
_BAUDOT_FIGS = [None,"3","\n","-"," ","'","8","7","\r","ENQ","4","\a",",","!",":",  "(", "+","\"",")","2","#","6","0","1","9","?","&","E-SHIFT",".","/"," ","FIGS"]

def decode_baudot(data):
    import re
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

# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  PUNYCODE
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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

# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  HASH IDENTIFICATION
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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
    import re
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

# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  RC4 (wordlist key attack)
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  ENIGMA CIPHERTEXT DETECTION (no key needed)
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def detect_enigma(text):
    """
    detect possible enigma ciphertext by statistical fingerprint.
    enigma produces IC ~0.038-0.046 (close to random, no letter encodes to itself).
    returns note string if likely, None otherwise.
    """
    alpha = "".join(c.upper() for c in text if c.isalpha())
    if len(alpha) < 20: return None

    # IC check - enigma output is close to random
    freq = {}
    for c in alpha: freq[c] = freq.get(c,0) + 1
    n = len(alpha)
    ic = sum(f*(f-1) for f in freq.values()) / (n*(n-1)) if n > 1 else 0
    if not (0.035 <= ic <= 0.050): return None

    # enigma never encodes a letter to itself
    # (no way to verify without knowing the plaintext, but we can check
    #  that the distribution looks flat - no letter dominates)
    max_freq = max(freq.values()) / n
    if max_freq > 0.12: return None

    # length should be reasonable for a message
    if n < 20: return None

    return ("possible Enigma ciphertext  ic=%.4f  "
            "no letter encodes to itself  "
            "use --enigma to brute-force positions or provide settings" % ic)


# ==============================================================
#  ENCRYPTION TYPE CLASSIFIER
# ==============================================================

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
    import re as _re
    if _re.match(r"^\*[0-9A-F]{40}$", raw.upper()): return "MySQL password hash"
    n = len(raw_b)
    if n < 8: return None
    freq = [0] * 256
    for b in raw_b: freq[b] += 1
    entropy = -sum((f/n) * math.log2(f/n) for f in freq if f > 0)
    # size-adjusted entropy threshold - small samples have lower measured entropy
    if n < 16:   _eth = 3.5
    elif n < 32: _eth = 4.5
    elif n < 64: _eth = 5.2
    elif n < 128: _eth = 5.8
    elif n < 256: _eth = 6.5
    elif n < 512: _eth = 7.0
    else:         _eth = 7.4
    _high = entropy >= _eth

    # RSA ciphertext: exact key sizes - check before AES (256b is both RSA-2048 and 16 AES blocks)
    if n in (128, 256, 384, 512) and _high:
        return "RSA-%d ciphertext possible - %d bytes entropy=%.2f" % (n*8, n, entropy)

    # AES-ECB: repeating 16-byte blocks
    if n >= 32 and n % 16 == 0:
        blocks = [raw_b[i:i+16] for i in range(0, n, 16)]
        if len(blocks) != len(set(blocks)):
            return "AES-ECB ciphertext likely - %d bytes, repeating block detected (ECB mode)" % n
        if _high:
            return "AES-CBC/ECB ciphertext likely - %d bytes (%d blocks) entropy=%.2f" % (n, len(blocks), entropy)

    # DES/3DES: 8-byte aligned, not 16-byte aligned
    if n >= 8 and n % 8 == 0 and n % 16 != 0 and _high:
        return "DES/3DES ciphertext possible - %d bytes entropy=%.2f" % (n, entropy)

    # stream cipher: non-block-aligned, high entropy
    if _high and n > 16 and n % 16 != 0 and n % 8 != 0:
        return "stream cipher possible (ChaCha20/RC4/Salsa20) - %d bytes entropy=%.2f" % (n, entropy)

    # generic high entropy blob
    if _high and n >= 16:
        return "high entropy data - %d bytes entropy=%.2f - possibly encrypted or compressed" % (n, entropy)
    return None


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  CHAINED CIPHER DETECTION
#  tries common multi-step combinations automatically
#  each chain: transform -> score -> surface if english detected
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def _score_text(text, wordlist):
    """score plaintext candidate by english word hits"""
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
    """
    try common layered cipher combinations.
    returns list of (score, chain_description, plaintext).
    chains tried:
      - reverse then each ROT/atbash
      - atbash then each ROT
      - each ROT then atbash
      - each ROT then reverse then each ROT
      - atbash then reverse
      - reverse then atbash then each ROT
      - base64 decode then each cipher (handled by engine already)
    """
    results = []
    seen = set()

    def _add(score, chain, plain):
        if score >= min_score and plain not in seen:
            seen.add(plain)
            results.append((score, chain, plain))

    # step 1: reversed input
    rev = _rev(text)

    # rev -> ROT n
    for n in range(26):
        p = _rot(rev, n)
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "reverse -> ROT%d" % n, p)

    # rev -> atbash
    p = _atbash(rev)
    s = _score_text(p, wordlist)
    if s >= min_score:
        _add(s, "reverse -> Atbash", p)

    # rev -> atbash -> ROT n
    p_ab = _atbash(rev)
    for n in range(26):
        p = _rot(p_ab, n)
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "reverse -> Atbash -> ROT%d" % n, p)

    # atbash -> reverse
    p = _rev(_atbash(text))
    s = _score_text(p, wordlist)
    if s >= min_score:
        _add(s, "Atbash -> reverse", p)

    # atbash -> ROT n
    p_ab = _atbash(text)
    for n in range(26):
        p = _rot(p_ab, n)
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "Atbash -> ROT%d" % n, p)

    # atbash -> ROT n -> reverse
    for n in range(26):
        p = _rev(_rot(_atbash(text), n))
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "Atbash -> ROT%d -> reverse" % n, p)

    # ROT n -> atbash
    for n in range(26):
        p = _atbash(_rot(text, n))
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "ROT%d -> Atbash" % n, p)

    # ROT n -> atbash -> reverse
    for n in range(26):
        p = _rev(_atbash(_rot(text, n)))
        s = _score_text(p, wordlist)
        if s >= min_score:
            _add(s, "ROT%d -> Atbash -> reverse" % n, p)

    # ROT n -> reverse -> ROT m
    for n in range(26):
        r = _rev(_rot(text, n))
        for m in range(26):
            p = _rot(r, m)
            s = _score_text(p, wordlist)
            if s >= min_score:
                _add(s, "ROT%d -> reverse -> ROT%d" % (n,m), p)

    results.sort(reverse=True)
    return results[:8]


# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  BEAM SEARCH CHAIN DECODER
#  tries all transforms at each depth level
#  keeps only top N candidates (beam) - fast even at depth 10
# ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

# ── common words for fast scoring ──────────────────────────────────────────
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

# ── tetragram scoring ────────────────────────────────────────────────────────
_TG = {
    "TION":-1.0,"THER":-1.1,"WITH":-1.2,"HERE":-1.3,"IGHT":-1.4,
    "THAT":-1.5,"MENT":-1.6,"IONS":-1.8,"ATIO":-1.9,"OULD":-2.0,
    "FROM":-2.1,"THEM":-2.2,"THIS":-2.3,"TING":-2.4,"HAVE":-2.5,
    "EVER":-2.6,"NTER":-2.8,"ENCE":-2.9,"OUGH":-3.0,"WERE":-3.1,
    "EACH":-3.2,"WHEN":-3.3,"YOUR":-3.4,"COME":-3.5,"BEEN":-3.9,
    "INTO":-4.1,"TIME":-4.2,"SOME":-4.3,"THAN":-4.4,"ONLY":-4.5,
}
_TGF = -8.5  # floor for unknown tetragrams

# ── english letter frequencies for chi-squared ───────────────────────────────
_EF = {
    "a":8.2,"b":1.5,"c":2.8,"d":4.3,"e":12.7,"f":2.2,"g":2.0,"h":6.1,
    "i":7.0,"j":0.15,"k":0.77,"l":4.0,"m":2.4,"n":6.7,"o":7.5,"p":1.9,
    "q":0.1,"r":6.0,"s":6.3,"t":9.1,"u":2.8,"v":0.98,"w":2.4,"x":0.15,
    "y":2.0,"z":0.07,
}

def _tetragram_score(text):
    """4-char n-gram score. Strongest cheap signal for classical ciphers -
    works even when no complete words are formed yet."""
    import re as _re
    letters = _re.sub(r'[^A-Za-z]', '', text.upper())
    if len(letters) < 4: return 0.0
    total = sum(_TG.get(letters[i:i+4], _TGF) for i in range(len(letters)-3))
    return total / max(len(letters)-3, 1)

def _ic(text):
    """Index of Coincidence. English ~0.065. Random/encoded ~0.038.
    Monoalphabetic substitution PRESERVES IC - key signal for layered ciphers."""
    from collections import Counter
    letters = [c.lower() for c in text if c.isalpha()]
    N = len(letters)
    if N < 20: return 0.0
    counts = Counter(letters)
    return sum(n*(n-1) for n in counts.values()) / (N*(N-1))

def _chi_sq(text):
    """Chi-squared vs English. High IC + high chi = one sub layer remaining."""
    from collections import Counter
    letters = [c.lower() for c in text if c.isalpha()]
    N = len(letters)
    if N < 20: return 9999.0
    counts = Counter(letters)
    return sum((counts.get(ch,0) - N*exp/100)**2 / (N*exp/100)
               for ch,exp in _EF.items())

def _repeat_token_signal(tl):
    """Function-word frequency preserved under monoalpha substitution."""
    import re as _re
    from collections import Counter
    tokens = _re.findall(r"[a-z']+", tl)
    if len(tokens) < 6: return 0.0
    counts = Counter(tokens)
    score = 0.0
    single = [t for t in tokens if len(t)==1]
    if 1 <= len(set(single)) <= 2 and single: score += 4.0
    score += min(sum(3.0 for t,c in counts.items() if len(t)<=3 and c>=3), 12.0)
    return score

def _ic_signal(text):
    """Return (ic, chi, signal_type) for recommend-deeper logic."""
    ic = _ic(text)
    chi = _chi_sq(text)
    if ic > 0.060:   return ic, chi, 'monoalpha'
    elif ic > 0.055: return ic, chi, 'likely_sub'
    elif ic > 0.048: return ic, chi, 'possible_poly'
    return ic, chi, 'none'

def _chain_score(text, wordlist):
    """Calibrated multi-signal scoring combining:
    - common word fast set (70 words, no wordlist scan needed)
    - space/entropy sweet spots (natural text vs encoded data)
    - tetragram n-grams (works on partial decodes, no words needed)
    - IC + chi-squared gap (monoalpha layer detection)
    - repeat token signal (function word frequency under substitution)
    - full wordlist hits
    - flag patterns
    """
    import re as _re
    if not text or len(text) < 2: return 0
    score = 0.0
    tl = text.lower()

    # printable + alpha ratios
    n = max(len(text), 1)
    pr = sum(1 for c in text if 32 <= ord(c) <= 126) / n
    ar = sum(c.isalpha() for c in text) / n
    sr = text.count(' ') / n
    score += pr * 20.0
    score += min(ar, 0.9) * 10.0

    # space ratio sweet spot: natural English prose 8-30%
    if 0.08 <= sr <= 0.30:   score += 10.0
    elif sr > 0.40:           score -= 5.0

    # entropy sweet spot: natural text 3.2-5.5, encoded data 5.5+
    import math
    freq = {}
    for c in text: freq[c] = freq.get(c,0)+1
    ent = -sum((v/n)*math.log2(v/n) for v in freq.values()) if n>1 else 0
    if 3.2 <= ent <= 5.5:    score += 8.0
    elif ent > 6.2:           score -= 8.0

    # flag patterns
    for pat in ('ctf{','htb{','flag{','thm{','picoctf{','ictf{','root{',
                'hackthebox','tryhackme','rrsw{'):
        if pat in tl: score += 100.0

    # common word fast set
    words = _re.findall(r"[a-z']+", tl)
    common_hits = sum(1 for w in words if w in _CW)
    score += min(common_hits * 3.0, 35.0)

    # full wordlist hits
    if wordlist:
        for w in wordlist:
            if len(w) > 5 and w in tl: score += 3
            elif len(w) > 3 and w in tl: score += 1

    # english shape bonuses
    if any(c in text for c in ',.;:!?'):   score += 3.0
    if _re.search(r'\b(the|and|that|this|with|from|into|have|there)\b', tl): score += 12.0

    # tetragram - strongest cheap classical cipher signal
    score += _tetragram_score(text) * 5.0

    # IC-based monoalpha layer detection
    ic = _ic(tl)
    chi = _chi_sq(tl)
    if ic > 0.060:
        score += 12.0 if common_hits == 0 else 6.0   # high IC + no words = one layer away
    elif ic > 0.055: score += 6.0
    elif ic > 0.048: score += 2.0
    if ic > 0.055 and chi > 200: score += 5.0        # IC/chi gap = monoalpha fingerprint

    # repeat token signal
    score += _repeat_token_signal(tl)

    # penalties
    ctrl = sum(1 for c in text if ord(c)<32 and c not in '\t\n\r')
    score -= ctrl * 10.0
    import re as _re2
    score -= len(_re2.findall(r'[^A-Za-z0-9\s]{4,}', text)) * 4.0

    return max(0, int(score))

def _apply_transform(text, name):
    """apply a named transform to text - returns result or None if not applicable"""
    import base64, binascii, urllib.parse, html

    try:
        if name == 'reverse':
            return text[::-1]

        elif name == 'atbash':
            return "".join(
                chr(65+25-(ord(c)-65)) if c.isupper() else
                chr(97+25-(ord(c)-97)) if c.islower() else c
                for c in text)

        elif name.startswith('rot'):
            n = int(name[3:])
            return "".join(
                chr((ord(c)-65+n)%26+65) if c.isupper() else
                chr((ord(c)-97+n)%26+97) if c.islower() else c
                for c in text)

        elif name == 'base64':
            r = base64.b64decode(text + '==').decode('utf-8', errors='ignore')
            return r if len(r) > 2 else None

        elif name == 'base64url':
            r = base64.urlsafe_b64decode(text + '==').decode('utf-8', errors='ignore')
            return r if len(r) > 2 else None

        elif name == 'base32':
            r = base64.b32decode(text.upper() + '=' * ((8 - len(text)%8)%8)).decode('utf-8', errors='ignore')
            return r if len(r) > 2 else None

        elif name == 'hex':
            clean = text.replace(' ','').replace('0x','').replace('\\x','')
            if all(c in '0123456789abcdefABCDEF' for c in clean) and len(clean) % 2 == 0:
                return bytes.fromhex(clean).decode('utf-8', errors='ignore')
            return None

        elif name == 'url':
            r = urllib.parse.unquote(text)
            return r if r != text else None

        elif name == 'html':
            r = html.unescape(text)
            return r if r != text else None

        elif name == 'morse':
            from core.decoders import decode_morse
            return decode_morse(text)

        elif name == 'binary':
            tokens = text.strip().split()
            if all(all(c in '01' for c in t) and len(t) == 8 for t in tokens):
                return ''.join(chr(int(t,2)) for t in tokens)
            return None

        elif name == 'a1z26':
            import re as _re
            tokens = _re.split(r'[\s,.-]+', text.strip())
            try:
                nums = [int(t) for t in tokens if t]
                if all(1 <= n <= 26 for n in nums):
                    return ''.join(chr(n+64) for n in nums)
            except: pass
            return None

        elif name == 'caesar_brute':
            # returns None - handled as rot1-rot25 individually
            return None

    except Exception:
        return None
    # --- bacon cipher ---
    if name in ('bacon_ab', 'bacon_01', 'bacon_io'):
        try:
            import re as _re
            t = text.upper().replace(' ','')
            if name == 'bacon_01': t = t.replace('0','A').replace('1','B')
            elif name == 'bacon_io': t = t.replace('I','A').replace('O','B')
            bacon_map = {
                'AAAAA':'A','AAAAB':'B','AAABA':'C','AAABB':'D','AABAA':'E',
                'AABAB':'F','AABBA':'G','AABBB':'H','ABAAA':'I','ABAAB':'J',
                'ABABA':'K','ABABB':'L','ABBAA':'M','ABBAB':'N','ABBBA':'O',
                'ABBBB':'P','BAAAA':'Q','BAAAB':'R','BAABA':'S','BAABB':'T',
                'BABAA':'U','BABAB':'V','BABBA':'W','BABBB':'X','BBAAA':'Y','BBAAB':'Z'
            }
            result = ''
            clean = _re.sub(r'[^AB]','',t)
            if len(clean) < 5: return None
            for i in range(0, len(clean)-4, 5):
                chunk = clean[i:i+5]
                result += bacon_map.get(chunk, '?')
            return result.lower() if '?' not in result and result else None
        except: return None

    # --- polybius square ---
    if name in ('polybius', 'polybius_reverse'):
        try:
            import re as _re
            pairs = _re.findall(r'[1-5][1-5]', text.replace(' ',''))
            if len(pairs) < 2: return None
            sq = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
            result = ''
            for p in pairs:
                r,c = int(p[0])-1, int(p[1])-1
                idx = r*5+c
                result += sq[idx] if idx < 25 else '?'
            return result.lower() if '?' not in result else None
        except: return None

    # --- tap code ---
    if name == 'tap_code':
        try:
            import re as _re
            pairs = _re.findall(r'(\d)\s+(\d)', text)
            if not pairs: return None
            sq = 'ABDEFGHIKLMNOPQRSTUVWXYZ'
            result = ''
            for r,c in pairs:
                idx = (int(r)-1)*5 + (int(c)-1)
                result += sq[idx] if 0 <= idx < len(sq) else '?'
            return result.lower() if '?' not in result else None
        except: return None

    # --- nihilist decode - subtract common key polybius values ---
    if name == 'nihilist_decode':
        try:
            pairs = re.findall(r'\b(\d{2})\b', text)
            if len(pairs) < 3: return None
            sq = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
            nums = [int(p) for p in pairs]
            for sub in [0,11,12,13,21,22,23,24,25,31,32,33,34,35,41,42,43,44,45]:
                result = ''
                ok = True
                for n in nums:
                    v = n - sub
                    r2, c2 = v // 10 - 1, v % 10 - 1
                    if not (0 <= r2 < 5 and 0 <= c2 < 5):
                        ok = False; break
                    result += sq[r2*5+c2]
                if ok and result:
                    return result.lower()
            return None
        except: return None
    # --- railfence variants ---
    if name in ('railfence2','railfence3','railfence4','railfence5'):
        try:
            rails = int(name[-1])
            t = text.replace(' ','') if len(text.replace(' ','')) > 4 else text
            n = len(t)
            if n < rails: return None
            fence = [[] for _ in range(rails)]
            rail, direction = 0, 1
            for i in range(n):
                fence[rail].append(i)
                if rail == 0: direction = 1
                elif rail == rails-1: direction = -1
                rail += direction
            order = [i for r in fence for i in r]
            result = [''] * n
            for i, pos in enumerate(order):
                result[pos] = t[i]
            return ''.join(result)
        except: return None

    # --- scytale ---
    if name in ('scytale2','scytale3','scytale4','scytale5'):
        try:
            cols = int(name[-1])
            t = text.replace(' ','')
            n = len(t)
            if n < cols: return None
            rows = (n + cols - 1) // cols
            padded = t.ljust(rows * cols)
            result = ''
            for r in range(rows):
                for c in range(cols):
                    result += padded[c * rows + r]
            return result.strip()
        except: return None

    # --- vigenere common keys ---
    if name.startswith('vigenere_'):
        try:
            key_map = {'key':'key','secret':'secret','password':'password',
                       'crypto':'crypto','flag':'flag'}
            key = key_map.get(name[9:])
            if not key: return None
            result = ''
            ki = 0
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    shift = ord(key[ki % len(key)].upper()) - ord('A')
                    result += chr((ord(c.upper()) - ord('A') - shift) % 26 + base)
                    ki += 1
                else:
                    result += c
            return result
        except: return None

    # --- xor single byte ---
    if name.startswith('xor_0x'):
        try:
            key = int(name[4:], 16)
            result = ''.join(chr(ord(c) ^ key) for c in text)
            if sum(1 for c in result if 32 <= ord(c) <= 126) / max(len(result),1) > 0.8:
                return result
            return None
        except: return None

    # --- phone keypad ---
    if name == 'phone_keypad':
        try:
            keymap = {'2':'a','22':'b','222':'c','3':'d','33':'e','333':'f',
                      '4':'g','44':'h','444':'i','5':'j','55':'k','555':'l',
                      '6':'m','66':'n','666':'o','7':'p','77':'q','777':'r','7777':'s',
                      '8':'t','88':'u','888':'v','9':'w','99':'x','999':'y','9999':'z'}
            tokens = text.strip().split()
            result = ''.join(keymap.get(t,'?') for t in tokens)
            return result if '?' not in result and result else None
        except: return None

    # --- bit ops ---
    if name == 'nibble_swap':
        try:
            result = ''.join(chr(((ord(c)&0x0F)<<4)|((ord(c)&0xF0)>>4)) for c in text)
            return result if sum(1 for c in result if 32<=ord(c)<=126)/max(len(result),1)>0.8 else None
        except: return None

    if name == 'bits_reverse':
        try:
            result = ''.join(chr(int(f'{ord(c):08b}'[::-1],2)) for c in text)
            return result if sum(1 for c in result if 32<=ord(c)<=126)/max(len(result),1)>0.8 else None
        except: return None

    # --- mirror / keyboard ---
    if name == 'mirror_alphabet':
        try:
            result = ''
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    result += chr(base + 25 - (ord(c) - base))
                else:
                    result += c
            return result
        except: return None

    if name == 'dvorak_to_qwerty':
        try:
            qwerty = 'qwertyuiopasdfghjklzxcvbnm'
            dvorak = 'pyfgcrlaoeuidhtnsqjkxbmwvz'
            result = ''.join(qwerty[dvorak.index(c)] if c in dvorak else c for c in text.lower())
            return result
        except: return None

    if name == 'keyboard_shift':
        try:
            qwerty = 'qwertyuiopasdfghjklzxcvbnm'
            dvorak = 'pyfgcrlaoeuidhtnsqjkxbmwvz'
            result = ''.join(dvorak[qwerty.index(c)] if c in qwerty else c for c in text.lower())
            return result
        except: return None

    if name == 'leet_speak_decode':
        try:
            leet = {'0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','@':'a','!':'i'}
            return ''.join(leet.get(c,c) for c in text.lower())
        except: return None

    if name == 'decimal_bytes':
        try:
            import re as _re
            nums = [int(x) for x in _re.split(r'[\s,]+', text.strip()) if x.isdigit()]
            if not nums or len(nums) < 2: return None
            result = ''.join(chr(n) for n in nums if 32 <= n <= 126)
            return result if len(result) == len(nums) else None
        except: return None

    if name == 'a1z26_reverse':
        try:
            import re as _re
            nums = [int(x) for x in _re.split(r'[\s,\-]+', text.strip()) if x.isdigit()]
            if not nums: return None
            return ''.join(chr(ord('z') - n + 1) for n in nums if 1 <= n <= 26)
        except: return None

    return None

# all transforms to try at each level
_FAST_TRANSFORMS = (
    ['reverse', 'atbash'] +
    [f'rot{n}' for n in range(1,26)] +
    ['base64', 'base64url', 'base32', 'hex', 'url', 'html', 'binary', 'a1z26', 'morse']
)

def beam_chain_decode(text, wordlist, max_depth=6, beam_width=40, min_score=4,
                      show_progress=True):
    """
    beam search through transform chains.
    at each depth: apply all transforms to all current candidates,
    score each result, keep top beam_width.
    surfaces anything above min_score at any depth.
    preserves ALL characters - no dropping.
    """
    import sys, time, random

    _MATRIX_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*<>?/"
    _GRN = "\033[38;5;82m"
    _DIM = "\033[2m"
    _RST = "\033[0m"
    _CLR = "\033[2K\r"

    t_start = time.time()
    total_ops = max_depth * beam_width * len(_FAST_TRANSFORMS)
    op_count = 0

    def _progress(current_transform, chain_steps, hits):
        nonlocal op_count
        op_count += 1
        if not show_progress or op_count % 40 != 0:
            return
        elapsed = time.time() - t_start
        rate = op_count / elapsed if elapsed > 0 else 1
        eta = max(0, (total_ops - op_count) / rate)
        # matrix noise: 32 chars of rapid randomness
        noise = "".join(random.choice(_MATRIX_CHARS) for _ in range(32))
        chain_str = (" -> ".join(chain_steps) + " -> " + current_transform)[-28:]
        sys.stderr.write(
            f"{_CLR}  {_GRN}{noise}{_RST}  "
            f"{_DIM}depth {len(chain_steps)+1}  "
            f"chain: {chain_str:<30}  "
            f"hits: {hits}  ~{eta:.0f}s{_RST}"
        )
        sys.stderr.flush()

    # each candidate: (score, [chain_steps], current_text)
    candidates = [(0, [], text)]
    found = []
    seen_texts = {text}

    for depth in range(1, max_depth + 1):
        next_candidates = []

        for _, chain, current in candidates:
            for transform in _FAST_TRANSFORMS:
                _progress(transform, chain, len(found))
                result = _apply_transform(current, transform)
                if not result or result in seen_texts:
                    continue
                if len(result) < 2:
                    continue

                seen_texts.add(result)
                score = _chain_score(result, wordlist)
                new_chain = chain + [transform]

                if score >= min_score:
                    found.append((score, ' -> '.join(new_chain), result))

                next_candidates.append((score, new_chain, result))

        if not next_candidates:
            break

        # keep top beam_width*2 candidates between steps so chained encodings
        # (e.g. base32->rot18) survive even if intermediate scores low
        next_candidates.sort(key=lambda x: x[0], reverse=True)
        candidates = next_candidates[:beam_width * 2]

    # clear progress line
    if show_progress:
        elapsed = time.time() - t_start
        sys.stderr.write(f"{_CLR}  {_GRN}chain analysis complete{_RST}  {_DIM}{elapsed:.2f}s  {len(found)} candidates{_RST}\n")
        sys.stderr.flush()

    # deduplicate and sort found
    seen_out = set()
    results = []
    for score, chain, text in sorted(found, reverse=True):
        if text not in seen_out:
            seen_out.add(text)
            results.append((score, chain, text))

    return results[:10]


# ---- core/filetypes.py ----

import struct
import zlib
from typing import Optional, Tuple, List


FILE_SIGNATURES = [
    # Images
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
    # Documents
    (b'%PDF-',                  0,  'pdf',    'PDF Document'),
    (b'\xD0\xCF\x11\xE0',      0,  'doc',    'MS Office Legacy'),
    (b'%!PS-Adobe',             0,  'ps',     'PostScript'),
    (b'{\rtf',                  0,  'rtf',    'Rich Text Format'),
    # Archives
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
    # Executables
    (b'\x7fELF',                0,  'elf',    'ELF Executable'),
    (b'MZ',                     0,  'exe',    'PE Executable'),
    (b'\xCA\xFE\xBA\xBE',      0,  'class',  'Java Class'),
    (b'\xCE\xFA\xED\xFE',      0,  'macho',  'Mach-O 32-bit'),
    (b'\xCF\xFA\xED\xFE',      0,  'macho',  'Mach-O 64-bit'),
    (b'#!',                     0,  'sh',     'Shell Script'),
    (b'dex\n',                  0,  'dex',    'Android DEX'),
    # Audio/Video
    (b'OggS',                   0,  'ogg',    'OGG'),
    (b'fLaC',                   0,  'flac',   'FLAC Audio'),
    (b'ID3',                    0,  'mp3',    'MP3 (ID3)'),
    (b'\xFF\xFB',               0,  'mp3',    'MP3'),
    (b'ftyp',                   4,  'mp4',    'MPEG-4'),
    (b'WAVEfmt',                8,  'wav',    'WAV Audio'),
    (b'\x30\x26\xB2\x75',      0,  'wmv',    'Windows Media'),
    (b'FWS',                    0,  'swf',    'Flash SWF'),
    (b'CWS',                    0,  'swf',    'Flash SWF (compressed)'),
    # Network
    (b'\xD4\xC3\xB2\xA1',      0,  'pcap',   'PCAP (LE)'),
    (b'\xA1\xB2\xC3\xD4',      0,  'pcap',   'PCAP (BE)'),
    (b'\x0a\x0d\x0d\x0a',      0,  'pcapng', 'PCAPng'),
    # Code/Text
    (b'<?xml',                  0,  'xml',    'XML'),
    (b'<?php',                  0,  'php',    'PHP'),
    (b'<!DOCTYPE',              0,  'html',   'HTML'),
    (b'<html',                  0,  'html',   'HTML'),
    (b'{"',                     0,  'json',   'JSON'),
    (b'[{',                     0,  'json',   'JSON Array'),
    # Crypto/Keys
    (b'-----BEGIN',             0,  'pem',    'PEM Key/Cert'),
    (b'ssh-rsa',                0,  'pub',    'SSH RSA Key'),
    (b'ssh-ed25519',            0,  'pub',    'SSH Ed25519 Key'),
    (b'OpenSSH',                0,  'key',    'OpenSSH Private Key'),
    (b'PuTTY',                  0,  'ppk',    'PuTTY Key'),
    # Fax / TIFF variants (CTF-relevant)
    (b'II\x2a\x00',             0,  'tif',    'TIFF/FAX (LE)'),
    (b'MM\x00\x2a',             0,  'tif',    'TIFF/FAX (BE)'),
    # Misc
    (b'SQLite format 3',        0,  'db',     'SQLite DB'),
    (b'StegHide',               0,  'steg',   'Steghide marker'),
    (b'SIMPLE  =',              0,  'fits',   'FITS Astronomical Data'),
    (b'wOFF',                   0,  'woff',   'Web Font WOFF'),
    (b'\x00\x01\x00\x00',      0,  'ttf',    'TrueType Font'),
    (b'OTTO',                   0,  'otf',    'OpenType Font'),
]


def detect_filetype(data: bytes) -> Optional[Tuple[str, str]]:
    if data.startswith(b'EVF\x09\x0d\x0a\xff\x00'):
        return ('e01', 'Expert Witness Format (EWF/E01)')
    if data.startswith(b'LVF\x09\x0d\x0a\xff\x00'):
        return ('l01', 'Logical Expert Witness Format (EWF/L01)')
    if data.startswith(b'EVF2\x0d\x0a\x81'):
        return ('ex01', 'Expert Witness Format v2 (Ex01)')
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


def find_embedded_files(data: bytes) -> List[Tuple[int, str, str]]:
    """
    Scan entire binary for file signatures at any offset.
    Catches files hidden/appended inside other files  -  core CTF technique.
    """
    found = []
    limit = min(len(data), 100_000_000)
    for magic, offset_hint, ext, desc in FILE_SIGNATURES:
        start = 1
        while True:
            pos = data.find(magic, start, limit)
            if pos == -1:
                break
            found.append((pos, ext, desc))
            start = pos + 1
    seen = set()
    deduped = []
    for pos, ext, desc in sorted(found):
        if ext not in seen:
            seen.add(ext)
            deduped.append((pos, ext, desc))
    return deduped


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
    for plane in range(8):
        try:
            bits = [(byte >> plane) & 1 for byte in data]
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
    """SNOW-style: trailing spaces=0, tabs=1"""
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
    """Zero-width character steganography"""
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


# ---- core/carver.py ----

import io
import os
import struct
import hashlib
import math
from dataclasses import dataclass, field
from typing import List, Optional


# magic signatures table
# (sig_bytes, extension, label, min_size)
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


# format-specific end finders

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
    # read number of sections and optional header size
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
    if ei_class == 1:   # 32-bit
        e_shoff     = struct.unpack('<I', data[start+32:start+36])[0]
        e_shentsize = struct.unpack('<H', data[start+46:start+48])[0]
        e_shnum     = struct.unpack('<H', data[start+48:start+50])[0]
    elif ei_class == 2: # 64-bit
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
    import zlib
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
    """
    scan binary data for embedded files by magic bytes.
    uses format-specific end finders for proper bounded extraction.
    recursively carves extracted content up to max_depth.
    """

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
        h = hashlib.md5(data).hexdigest()
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


# ---- core/stego_deep.py ----
# _Finding_early
class Finding:
    def __init__(self, method: str, result_text: str = None,
                 result_bytes: bytes = None, filetype: tuple = None,
                 confidence: str = 'LOW', note: str = ''):
        self.method = method
        self.result_text = result_text
        self.result_bytes = result_bytes
        self.filetype = filetype
        self.confidence = confidence
        self.note = note
        self.timestamp = datetime.datetime.now()

    def display_result(self) -> str:
        if self.result_text:
            return self.result_text
        if self.result_bytes:
            return bytes_to_hex_display(self.result_bytes)
        return '[no output]'




from typing import List

# Finding is defined in engine.py - available at call time in combined build
def analyze_image_deep(data: bytes, source_label: str = '') -> List[Finding]:
    """
    Deep stego analysis entry point.
    Routes to format-specific analyzers based on file magic.
    Returns list of Finding objects.
    """
    findings = []

    # jpeg
    if data[:3] == b'\xff\xd8\xff':
        findings.extend(_analyze_jpeg(data, source_label))

    # png
    elif data[:8] == b'\x89PNG\r\n\x1a\n':
        findings.extend(_analyze_png(data, source_label))

    # bmp
    elif data[:2] == b'BM':
        findings.extend(_analyze_bmp(data, source_label))

    return findings


def _analyze_jpeg(data, source_label):
    findings = []
    # check for appended data after JPEG EOI marker
    eoi = data.rfind(b'\xff\xd9')
    if eoi != -1 and eoi + 2 < len(data):
        appended = data[eoi + 2:]
        printable = sum(1 for b in appended if 32 <= b <= 126 or b in (9, 10, 13))
        if printable / len(appended) > 0.6:
            findings.append(Finding(
                method='JPEG appended data (after EOI)',
                confidence='HIGH',
                note=f'{len(appended)} bytes after JPEG end marker',
                result_text=appended.decode('latin-1'),
                source_label=source_label,
            ))
    return findings


def _analyze_png(data, source_label):
    findings = []
    try:
        import io
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert('RGBA')
        pixels = list(img.getdata())

        # check R channel LSB
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
    # bmp pixel data starts at offset stored in header
    if len(data) < 54:
        return findings
    import struct
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


# ---- core/renderer.py ----
import io, os
from typing import Optional
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
            tr,tg,tb = px[r*fnw+c]
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


# ---- core/reporter.py ----
"""
core/reporter.py  -  Hash It Out v4.1
handles all terminal output and file report generation.
clean filenames, per-run output subfolders, proper v4 branding.
"""

import os
import csv
import json
import datetime
import re


class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'
    TOXGRN = '\033[38;5;82m'
    DRIP   = '\033[38;5;51m'


def make_run_dir(base_output: str, source_name: str) -> str:
    """create a timestamped subfolder for this run's output"""
    ts   = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    safe = re.sub(r'[^\w]', '_', os.path.basename(source_name))[:30].strip('_')
    name = f'{safe}_{ts}'
    path = os.path.join(base_output, name)
    os.makedirs(path, exist_ok=True)
    return path


def clean_filename(method: str, ext: str, offset: int) -> str:
    label = re.sub(r'[^\w]', '_', method.lower())[:30].strip('_')
    return f'{label}_{ext}_{offset:#x}.{ext}'


def _print_finding(f, index, color=None):
    color = color or C.WHITE
    print(f"\n  [{index:03d}] {f.method}")
    print(f"        Confidence : {f.confidence}  |  FILE: {f.filetype[1] if f.filetype else 'n/a'}")
    print(f"        Note       : {f.note}")
    if f.result_text:
        lines = str(f.result_text)[:2000].split('\n')
        print(f"        Output     :")
        for line in lines[:30]:
            print(f"          | {line}")
        if len(lines) > 30:
            print(f"          | ... [{len(str(f.result_text))} chars total]")


def generate_text_report(findings, source_label, input_preview, saved_files):
    import datetime
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = ['='*72,'  HASH IT OUT v4.1  -  ANALYSIS REPORT',f'  generated : {ts}',f'  source    : {source_label}',f'  input len : {len(input_preview)} characters','='*72,'','input preview (first 200 chars):',input_preview[:200]+('...' if len(input_preview)>200 else ''),'']
    if saved_files:
        lines.append('-'*72); lines.append('extracted files:')
        for sf in saved_files: lines.append(f'  [saved] {sf}')
        lines.append('')
    counts = {'HIGH':0,'MEDIUM':0,'LOW':0}
    for f in findings:
        if f.confidence in counts: counts[f.confidence] += 1
    lines += ['-'*72,'summary:',f'  total   : {len(findings)}',f'  high    : {counts["HIGH"]}',f'  medium  : {counts["MEDIUM"]}',f'  low     : {counts["LOW"]}','','-'*72,'findings:','']
    for i, f in enumerate(findings, 1):
        lines.append(f'[{i:03d}] method     : {f.method}')
        lines.append(f'     confidence: {f.confidence}')
        if f.filetype: lines.append(f'     file type : {f.filetype[1]}')
        lines.append(f'     note      : {f.note}')
        if f.result_text: lines.append(f'     output    : {str(f.result_text)[:500]}')
        lines.append('')
    lines += ['='*72,'Hash It Out v4.1  -  github.com/RRSWSEC/Hash-It-Out','='*72]
    return '\n'.join(lines)


def save_report(report_text: str, run_dir: str) -> str:
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(run_dir, f'HIO_{ts}.txt')
    with open(path, 'w', encoding='utf-8', errors='replace') as fh: fh.write(report_text)
    return path


def save_csv_report(findings, source_label, run_dir: str) -> str:
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(run_dir, f'HIO_findings_{ts}.csv')
    with open(path, 'w', newline='', encoding='utf-8', errors='replace') as fh:
        w = csv.writer(fh)
        w.writerow(['confidence', 'method', 'source', 'note', 'result_preview'])
        for f in findings:
            w.writerow([f.confidence, f.method, getattr(f,'source_label',source_label),(f.note or '')[:200],(f.result_text or '')[:200]])
    return path


def save_decoded_file(data: bytes, run_dir: str, method: str, ext: str, offset: int = 0) -> str:
    os.makedirs(run_dir, exist_ok=True)
    filename = clean_filename(method, ext, offset)
    path = os.path.join(run_dir, filename)
    if os.path.exists(path):
        filename = clean_filename(method, ext, offset) + f'_{id(data)%10000}'
        path = os.path.join(run_dir, filename)
    with open(path, 'wb') as fh: fh.write(data)
    return path


def results_to_json(findings, source_label):
    return {'source':source_label,'timestamp':datetime.datetime.now().isoformat(),'total':len(findings),'findings':[{'method':f.method,'confidence':f.confidence,'note':f.note,'result_text':f.result_text[:2000] if f.result_text else None} for f in findings]}


# ---- core/display.py ----
import os
import sys

# ── color codes ────────────────────────────────────────────────
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
    # confidence colors
    HIGH    = '\033[38;5;196m'   # red - pay attention
    MEDIUM  = '\033[38;5;226m'   # yellow - worth checking
    LOW     = '\033[38;5;245m'   # grey - fyi

_W = 72  # display width

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

# ── banner ─────────────────────────────────────────────────────
BANNER = r"""
 _   _    _    ____  _   _   ___ _____    ___  _   _ _____
| | | |  / \  / ___|| | | | |_ _|_   _|  / _ \| | | |_   _|
| |_| | / _ \ \___ \| |_| |  | |  | |   | | | | | | | | |
|  _  |/ ___ \ ___) |  _  |  | |  | |   | |_| | |_| | | |
|_| |_/_/   \_\____/|_| |_| |___| |_|    \___/ \___/  |_|"""

def print_banner(version='4.2.0'):
    print(f"{C.TOXGRN}{C.BOLD}{BANNER}{C.RESET}")
    print(f"{C.TOXGRN}  decoder  |  reverser  |  file carver  |  stego scanner  |  crypto detector{C.RESET}")
    print(f"{C.GREY}  v{version}  |  github.com/RRSWSEC/Hash-It-Out  |  RRSW Corp{C.RESET}")
    print(f"{C.GREY}  {'+'+'='*54+'+'}{C.RESET}")
    print(f"{C.GREY}  |  for educational and authorized research use only   |{C.RESET}")
    print(f"{C.GREY}  {'+'+'='*54+'+'}{C.RESET}")
    print()

# ── input header ───────────────────────────────────────────────
def print_input_header(source, size, filetype=None, entropy=None,
                        wordlist_size=0, depth=None, enc_type=None):
    """clean header card for each input - shows type, size, entropy, enc classification"""
    print()
    print(f"{C.CYAN}  {_line('=', C.CYAN)}{C.RESET}")

    # source line
    label = os.path.basename(source) if os.path.sep in source else source
    if len(label) > 50: label = label[:47] + '...'
    print(f"{C.CYAN}  {C.BOLD}[*]{C.RESET}{C.WHITE} {label}{C.RESET}")

    # type + size line
    meta = []
    if filetype:
        meta.append(f"{C.WHITE}{filetype}{C.RESET}")
    if size:
        s = f"{size:,} bytes" if isinstance(size, int) else str(size)
        meta.append(f"{C.GREY}{s}{C.RESET}")
    if entropy is not None:
        # color entropy by level
        if entropy > 7.5:   ecol = C.RED
        elif entropy > 6.0: ecol = C.YELLOW
        else:               ecol = C.GREY
        meta.append(f"{ecol}entropy {entropy:.2f}{C.RESET}")
    if depth is not None:
        meta.append(f"{C.GREY}depth {depth}{C.RESET}")
    if wordlist_size:
        meta.append(f"{C.GREY}{wordlist_size:,} words{C.RESET}")
    if meta:
        print(f"      {'  |  '.join(meta)}")

    # encryption/classification line - shown prominently if present
    if enc_type:
        print(f"      {C.YELLOW}[enc] {enc_type}{C.RESET}")

    print(f"{C.CYAN}  {_line('=', C.CYAN)}{C.RESET}")
    print()

# ── findings display ───────────────────────────────────────────
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
    """clean up output text for inline display"""
    if not text: return ''
    text = text.strip().replace('\n', ' ').replace('\r', '')
    if len(text) > maxlen:
        return text[:maxlen-3] + '...'
    return text

def _method_label(method, maxlen=50):
    """shorten method name for display"""
    m = method
    # strip common prefixes
    for prefix in ('Extracted: ', 'Carved: ', 'Carved (nested): ', '[REVERSED] '):
        if m.startswith(prefix):
            m = m[len(prefix):]
            break
    if len(m) > maxlen:
        m = m[:maxlen-2] + '..'
    return m

def print_results(findings, source_label, input_size, saved_files=None, verbose=True, nocolor=False):
    """
    main results display - grouped by confidence with clean inline output.
    replaces the old block-format results printer.
    """
    if not findings:
        print(f"{C.GREY}  no findings{C.RESET}")
        return

    confirmed = [f for f in findings if f.confidence == 'CONFIRMED' and 'leet' not in (f.method or '').lower()]
    high   = [f for f in findings if f.confidence == 'HIGH']
    medium = [f for f in findings if f.confidence == 'MEDIUM']
    low    = [f for f in findings if f.confidence == 'LOW']

    saved = saved_files or []
    extracted = [s for s in saved if s]

    def _print_finding(f, idx):
        icon  = _CONF_ICON.get(f.confidence, '  [?]')
        color = _CONF_COLOR.get(f.confidence, C.WHITE)
        label = _method_label(f.method)
        out   = _format_output(f.result_text or f.note or '', maxlen=500)

        # method + output on one line if short enough
        method_col = f"{color}{label:<50}{C.RESET}"
        if out:
            print(f"{icon} {method_col}  {C.WHITE}{out}{C.RESET}")
        else:
            print(f"{icon} {method_col}")

        # secondary info: filetype, note (if not already shown), extracted file
        extras = []
        if f.filetype and f.filetype[1]:
            extras.append(f"type: {f.filetype[1]}")
        if f.note and f.note != out and len(f.note) < 100:
            note_clean = _format_output(f.note, 60)
            if note_clean and note_clean != out:
                extras.append(note_clean)

        # check if a file was extracted for this finding
        for s in saved:
            if s and label.lower().replace(' ','_') in s.lower():
                extras.append(f"saved: {os.path.basename(s)}")
                break

        if extras:
            print(f"       {C.GREY}{('  |  ').join(extras)}{C.RESET}")

    # HIGH section
    if confirmed:
        _W2 = _W
        print("  \033[38;5;82m\033[1m" + chr(9473)*_W2 + "\033[0m")
        print("  \033[38;5;82m\033[1m  [\u2713] CONFIRMED PLAINTEXT  \u2014  natural English detected\033[0m")
        print("  \033[38;5;82m\033[1m" + chr(9473)*_W2 + "\033[0m")
        for _f in confirmed:
            _lbl = _method_label(_f.method)
            _out = _format_output(_f.result_text or _f.note or "", maxlen=500)
            print("  \033[38;5;82m\033[1m  [\u2713]\033[0m  \033[38;5;82m%-50s\033[0m  \033[97m%s\033[0m" % (_lbl, _out))
            if _f.note and _f.note != _out:
                print("       \033[38;5;245m%s\033[0m" % _f.note)
        print()

    if high:
        print(f"  {C.HIGH}{C.BOLD}HIGH CONFIDENCE{C.RESET}  {C.HIGH}{_line('-')}{C.RESET}")
        for i, f in enumerate(high, 1):
            _print_finding(f, i)
        print()

    # MEDIUM section
    if medium:
        print(f"  {C.MEDIUM}{C.BOLD}MEDIUM CONFIDENCE{C.RESET}  {C.MEDIUM}{_line('-')}{C.RESET}")
        for i, f in enumerate(medium, 1):
            _print_finding(f, i)
        print()

    # LOW section
    if low:
        print(f"  {C.LOW}LOW CONFIDENCE{C.RESET}  {C.LOW}{_line('-')}{C.RESET}")
        for i, f in enumerate(low, 1):
            _print_finding(f, i)
        print()

    # summary bar
    co = len(confirmed)
    h = len(high)
    m = len(medium)
    l = len(low)
    e = len(extracted)

    parts = []
    if co: parts.append("\033[38;5;82m\033[1m%d CONFIRMED\033[0m" % co)
    if h: parts.append(f"{C.HIGH}{h} HIGH{C.RESET}")
    if m: parts.append(f"{C.MEDIUM}{m} MEDIUM{C.RESET}")
    if l: parts.append(f"{C.LOW}{l} LOW{C.RESET}")
    if e: parts.append(f"{C.GREEN}{e} file{'s' if e!=1 else ''} extracted{C.RESET}")

    print(f"  {C.GREY}{_line('=')}{C.RESET}")
    print(f"  {('  |  ').join(parts)}")
    print()

# ── file saved notification ─────────────────────────────────────
def print_file_saved(filepath, method, filetype):
    name = os.path.basename(filepath)
    print(f"  {C.GREEN}[+] extracted:{C.RESET} {C.WHITE}{name}{C.RESET}  {C.GREY}({filetype or method}){C.RESET}")

# ── report saved notification ───────────────────────────────────
def print_report_saved(path, csv_path=None, json_path=None):
    print(f"\n  {C.GREEN}[+] report:{C.RESET}  {path}")
    if csv_path:
        print(f"  {C.GREEN}[+] csv:   {C.RESET}  {csv_path}")
    if json_path:
        print(f"  {C.GREEN}[+] json:  {C.RESET}  {json_path}")

# ── URL fetch header ────────────────────────────────────────────
def print_url_header(url, status, content_type, size, error=None):
    print(f"\n{C.CYAN}  [*] fetching : {C.WHITE}{url}{C.RESET}")
    if error:
        print(f"  {C.RED}[!] error    : {error}{C.RESET}")
        return
    print(f"{C.CYAN}  [*] status   : {C.WHITE}{status}{C.RESET}")
    print(f"{C.CYAN}  [*] type     : {C.WHITE}{content_type}{C.RESET}")
    print(f"{C.CYAN}  [*] size     : {C.WHITE}{size:,} bytes{C.RESET}")

# ── help ────────────────────────────────────────────────────────
def print_help():
    help_text = f"""
{C.TOXGRN}{C.BOLD}  HASH IT OUT v4.2.0 - usage{C.RESET}

{C.WHITE}  inputs:{C.RESET}
    hashitout "string"
    hashitout -f file.png
    hashitout -f file1 file2 file3
    hashitout -d ./samples/
    hashitout -u https://example.com/file.bin
    hashitout --shell

{C.WHITE}  decoder flags:{C.RESET}
    --all       run everything (default)
    --rot       ROT / Caesar family
    --base      Base encoding family
    --hex       hex decoding
    --binary    binary / bit-level
    --morse     Morse and NATO alphabet
    --cipher    classical ciphers + brute-force (Bifid, Porta, Nihilist, Hill, ADFGVX)
    --xor       XOR brute-force
    --stego     steganography checks
    --enigma    Enigma machine position brute-force (17576 combos, shows progress)
    --reverse   also run all decoders on reversed input

{C.WHITE}  output flags:{C.RESET}
    --depth N       carving recursion depth (default: 3)
    --savefile      save extracted / decoded files
    --report        force save text report
    --noreport      suppress report
    --json          also save JSON results
    --quiet         no display output
    --nodelay       skip startup delay
    --nocolor       plain text output
    --stegopw FILE  steghide password wordlist

{C.WHITE}  auto-detection (no flag needed):{C.RESET}
    hash types      MD5 / SHA-1/256/512 / bcrypt / NTLM / MySQL / Django / WordPress
    encryption      AES-ECB/CBC / DES / RSA / stream ciphers / JWT / PGP / SSH keys
    cipher detect   Trifid / Enigma statistical fingerprinting
    file carving    PE / PNG / BMP / JPEG / GZIP / ZIP / MP3 + bounded end-finders

{C.GREY}  only run against files and URLs you own or have authorization to analyze.{C.RESET}
"""
    print(help_text)


# ---- core/engine.py ----

import os
import string
import datetime
from typing import Optional, List


MAX_REPORT_STRING_LEN = 1240


class Finding:
    def __init__(self, method: str, result_text: str = None,
                 result_bytes: bytes = None, filetype: tuple = None,
                 confidence: str = 'LOW', note: str = ''):
        self.method = method
        self.result_text = result_text
        self.result_bytes = result_bytes
        self.filetype = filetype
        self.confidence = confidence
        self.note = note
        self.timestamp = datetime.datetime.now()

    def display_result(self) -> str:
        if self.result_text:
            return self.result_text
        if self.result_bytes:
            return bytes_to_hex_display(self.result_bytes)
        return '[no output]'


import urllib.request
import urllib.error
import urllib.parse
import re

MAX_URL_BYTES = 10 * 1024 * 1024
URL_TIMEOUT = 20


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

    # ── Main entry ───────────────────────────────────────────────

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
        """alias for analyze() - v4.1 compatibility"""
        return self.analyze(data, source_label)



    def analyze_url(self, url: str) -> List[Finding]:
        # fetch url and route through appropriate analysis pipeline
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
        # keep only findings where result is printable ascii
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
        # use proper bounded extraction via FileCarver
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
            # recurse into children
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

    # ── Format-specific deep dives ───────────────────────────────

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

    # ── Text decoder passes ──────────────────────────────────────


    def _try_structural(self, data: str):
        """
        Pre-decode artifact intelligence layer.
        Runs first on every input. Identifies all recognizable components
        in any order, any combination, without assumptions about structure.
        """
        import re as _rs
        findings = []
        seen = set()

        def _add(method, text, conf, note):
            key = method + text[:40]
            if key not in seen:
                seen.add(key)
                findings.append(Finding(method=method, result_text=text,
                                        confidence=conf, note=note))

        # ── Hash family detection (any position in input) ─────────────────
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
        for m in _rs.finditer(r'[0-9a-fA-F]{8,128}', data):
            h = m.group(0)
            for length, name in HASH_SIGS:
                if len(h) == length:
                    _add('Hash Detected: ' + name, h, 'HIGH',
                         '%d hex chars = %s  |  position %d in input' % (length, name, m.start()))

        # ── Base64 blob detection ─────────────────────────────────────────
        for m in _rs.finditer(r'[A-Za-z0-9+/]{20,}={0,2}', data):
            blob = m.group(0)
            try:
                import base64
                decoded = base64.b64decode(blob + '==').decode('utf-8', errors='strict')
                if all(32 <= ord(c) <= 126 for c in decoded):
                    conf = 'CONFIRMED' if _rs.search(r'[a-z0-9_]{2,}_[a-z0-9_]{2,}|\{[^}]{3,}\}', decoded, _rs.I) else 'HIGH'
                    _add('Base64 Component', decoded, conf,
                         'base64 blob at position %d decoded to printable text' % m.start())
            except Exception:
                pass

        # ── Compound artifact detection (multiple components in one input) ─
        parts = _rs.split(r'(?<=[=])|(?=[0-9a-fA-F]{32,})', data.strip())
        parts = [p for p in parts if p.strip()]
        if len(parts) >= 2:
            summary = []
            for i, part in enumerate(parts):
                part = part.strip()
                if _rs.match(r'^[0-9a-fA-F]{32}$', part):
                    summary.append('part %d: MD5 hash (%s)' % (i+1, part))
                elif _rs.match(r'^[0-9a-fA-F]{40}$', part):
                    summary.append('part %d: SHA1 hash (%s)' % (i+1, part))
                elif _rs.match(r'^[0-9a-fA-F]{64}$', part):
                    summary.append('part %d: SHA256 hash (%s)' % (i+1, part))
                elif _rs.match(r'^[A-Za-z0-9+/]{10,}={0,2}$', part):
                    try:
                        import base64
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

        # ── Fragment series marker ────────────────────────────────────────
        frag = _rs.search(r'fragment[_\-]([a-z0-9]+)', data, _rs.I)
        if frag:
            _add('Fragment Series Marker',
                 'fragment_%s detected' % frag.group(1),
                 'CONFIRMED',
                 'Part of a multi-fragment challenge. Look for other fragments (a, b, c... or 1, 2, 3...). Collect all to reconstruct the full artifact.')

        # ── CTF flag pattern ──────────────────────────────────────────────
        flag = _rs.search(r'([A-Za-z0-9_]{2,}\{[^}]{3,}\})', data)
        if flag:
            _add('CTF Flag Pattern', flag.group(1), 'CONFIRMED',
                 'Standard CTF flag format detected: wrapper{content}')

        # ── Hex blob (non-hash length) ────────────────────────────────────
        for m in _rs.finditer(r'\b([0-9a-fA-F]{10,31}|[0-9a-fA-F]{33,39}|[0-9a-fA-F]{41,})\b', data):
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
            ('Base2 (Binary)',           decode_base2),
            ('Base8 (Octal)',            decode_base8),
            ('Base10 (Decimal bytes)',   decode_base10),
            ('Base16 (Hex)',             decode_base16),
            ('Base32',                   decode_base32),
            ('Base32 (Extended Hex)',    decode_base32hex),
            ('Base32 (Crockford)',       decode_base32_crockford),
            ('Base36',                   decode_base36),
            ('Base45',                   decode_base45),
            ('Base58 (Bitcoin)',         decode_base58),
            ('Base58 (Flickr)',          decode_base58_flickr),
            ('Base62',                   decode_base62),
            ('Base64',                   decode_base64),
            ('Base64 (URL-safe)',        decode_base64_url),
            ('Base64 (MIME)',            decode_base64_mime),
            ('Base85 (Python)',          decode_base85),
            ('Base85 (ASCII85/Adobe)',   decode_ascii85),
            ('Base85 (Z85/ZeroMQ)',      decode_z85),
            ('Base91',                   decode_base91),
            ('Base92',                   decode_base92),
        ]
        for name, fn in bases:
            result = fn(data)
            if not result:
                continue
            ft = detect_filetype(result)
            if ft:
                findings.append(Finding(
                    method=name, result_bytes=result,
                    filetype=ft, confidence='HIGH',
                    note=f'decoded binary → {ft[1]}'))
            else:
                text = safe_decode_bytes(result)
                if is_mostly_printable(text, threshold=0.75):
                    conf, note = self._text_quality(text)
                    findings.append(Finding(method=name, result_text=text,
                                            confidence=conf, note=note))
        return findings

    def _try_hex(self, data: str) -> List[Finding]:
        findings = []
        for label, fn in [('Hexadecimal', decode_hex),
                           ('Hex (escaped \\x/% format)', decode_hex_escaped)]:
            result = fn(data)
            if not result:
                continue
            ft = detect_filetype(result)
            if ft:
                findings.append(Finding(method=f'{label} → Binary',
                                        result_bytes=result, filetype=ft,
                                        confidence='HIGH',
                                        note=f'hex decoded to {ft[1]}'))
            else:
                text = safe_decode_bytes(result)
                conf, note = self._text_quality(text)
                if conf in ('HIGH', 'MEDIUM'):
                    findings.append(Finding(method=f'{label} → ASCII',
                                            result_text=text,
                                            confidence=conf, note=note))
        return findings

    def _try_binary(self, data: str) -> List[Finding]:
        findings = []
        for label, fn in [('Binary (01 string)', decode_base2),
                           ('Octal', decode_base8)]:
            result = fn(data)
            if result:
                text = safe_decode_bytes(result)
                conf, note = self._text_quality(text)
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

        # bacon robust recovery
        for _bs,_bd,_bt in decode_bacon_robust(data, self.wordlist):
            _bc="CONFIRMED" if _bs>=15 else "HIGH" if _bs>=6 else "MEDIUM"
            if _bt not in {f.result_text for f in findings if f.result_text}:
                findings.append(Finding(method=_bd,result_text=_bt,confidence=_bc,note="bacon %.1f"%_bs))
        for _rs,_rc,_rt in decode_railfence_then_bacon(data, self.wordlist):
            _rcc="CONFIRMED" if _rs>=20 else "HIGH" if _rs>=10 else "MEDIUM"
            if _rt not in {f.result_text for f in findings if f.result_text}:
                findings.append(Finding(method=_rc,result_text=_rt,confidence=_rcc,note="rf+bacon %.1f"%_rs))
        # a1z26
        a1 = decode_a1z26(data)
        if a1 and len(a1) > 1:
            findings.append(Finding(method="A1Z26", result_text=a1,
                confidence="HIGH" if sum(1 for w in self.wordlist if w in a1.lower() and len(w)>3)>2 else "MEDIUM",
                note="decoded A=1 B=2 ... Z=26"))

        # hash identification
        ht = identify_hash(data.strip())
        if ht:
            findings.append(Finding(method="Hash Identification",
                result_text=ht, confidence="HIGH",
                note=ht))

        # encryption type classifier
        enc_type = classify_encryption(data)
        if enc_type:
            findings.append(Finding(method="Encryption Classifier",
                result_text=enc_type, confidence="MEDIUM", note=enc_type))

        # encryption type classifier
        enc_type = classify_encryption(data)
        if enc_type:
            findings.append(Finding(method="Encryption Classifier",
                result_text=enc_type, confidence="MEDIUM", note=enc_type))

        # trifid detection
        tri = detect_trifid(data)
        if tri:
            findings.append(Finding(method="Trifid Cipher (detected)",
                result_text=tri, confidence="MEDIUM", note=tri))

        # baudot
        baud = decode_baudot(data)
        if baud:
            findings.append(Finding(method="Baudot/ITA2",
                result_text=baud,
                confidence="HIGH" if sum(1 for w in self.wordlist if w in baud.lower() and len(w)>3)>2 else "MEDIUM",
                note="decoded Baudot ITA2"))

        # punycode
        pun = decode_punycode(data)
        if pun:
            findings.append(Finding(method="Punycode",
                result_text=pun, confidence="HIGH",
                note="decoded punycode/IDN"))

        # enigma detection - always runs, fast
        _enigma_det = detect_enigma(data)
        if _enigma_det:
            findings.append(Finding(method="Enigma (detected)",
                result_text=_enigma_det, confidence="MEDIUM", note=_enigma_det))

        # brute-force ciphers - only when --cipher or --deep flag set
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
        # beam search chain decoder - multi-layer transforms
        if len(data) >= 4:
            for score, chain, plain in beam_chain_decode(
                    data, self.wordlist, max_depth=6, beam_width=25, min_score=5):
                findings.append(Finding(
                    method="Decoded chain: %s" % chain,
                    result_text=plain,
                    confidence="HIGH" if score > 8 else "MEDIUM",
                    note="chain depth %d  score %d" % (chain.count('->')+1, score)
                ))

        return findings

    def _try_xor(self, data: str) -> List[Finding]:
        findings = []
        try:
            raw = data.encode('latin-1')
        except Exception:
            return findings
        for key, text in try_xor_keys(raw):
            conf, note = self._text_quality(text)
            if conf == 'HIGH':
                findings.append(Finding(
                    method=f'XOR single-byte (key=0x{key:02X})',
                    result_text=text, confidence=conf, note=note))
        for key, text in try_xor_multibyte(raw):
            conf, note = self._text_quality(text)
            if conf == 'HIGH':
                findings.append(Finding(
                    method=f'XOR multi-byte (key=0x{key.hex().upper()})',
                    result_text=text, confidence=conf, note=note))
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

    # ── Helpers ──────────────────────────────────────────────────

    def _run_text_passes(self, data: str) -> List[Finding]:
        findings = []
        findings += self._try_rots(data)
        findings += self._try_bases(data)
        findings += self._try_hex(data)
        findings += self._try_binary(data)
        findings += self._try_url(data)
        findings += self._try_morse(data)
        findings += self._try_ciphers(data)
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
        ratio = sum(1 for c in text if c in string.printable) / len(text)
        word_match = is_mostly_words(text, self.wordlist) if self.wordlist else False
        if word_match and ratio > 0.85:
            return ('HIGH', 'matches dictionary words')
        elif ratio > 0.95:
            return ('MEDIUM', 'mostly printable ASCII')
        elif ratio > 0.75:
            return ('LOW', 'partially printable')
        return ('LOW', 'low printable ratio')

    def _has_word_content(self, text: str) -> bool:
        if not self.wordlist:
            return len(text) > 8
        tokens = text.lower().split()
        return any(t.strip(string.punctuation) in self.wordlist for t in tokens)

# ---- main ----
import re
#!/usr/bin/env python3
"""
hashitout  -  Hash It Out v4.2.0
elite decoder, reverser, file rebuilder, stego scanner, URL content analyzer
github.com/RRSWSEC/Hash-It-Out

every input - strings, files, directories, URLs - is analyzed
forward and reversed through every known decoder, cipher, and
steganographic technique. extracted files are properly bounded
using format-specific parsers, not sliced to EOF.
zero external dependencies for core functionality.
"""

import sys
import os
import argparse
import time
import json



VERSION       = '4.2.0'
DISPLAY_DELAY = 2.0


def load_wordlist() -> set:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wordlists', 'english.txt')
    words = set()
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                w = line.strip().lower()
                if w: words.add(w)
    return words


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

def _maybe_offer_recovered_exports(findings, flags, run_dir, source_name, quiet=False):
    if not (flags.get('artifact_mode') or flags.get('export_recovered') or flags.get('full_nasty')):
        return []
    candidates = _collect_recovered_file_candidates(findings)
    if not candidates:
        return []
    if not quiet:
        print(f"\n  {C.CYAN}[+] recovered file candidate(s){C.RESET}")
        for i, c in enumerate(candidates[:5], 1):
            print(f"    {i}. {c['filetype'][1]}  |  {len(c['bytes']):,} bytes  |  entropy {c['entropy']:.2f}  |  from {c['finding'].method}")
    exported = []
    auto = flags.get('export_recovered') and not sys.stdin.isatty()
    if auto:
        chosen = '1'
    elif sys.stdin.isatty() and not quiet:
        try:
            chosen = input(f"  {C.CYAN}export recovered file candidate(s)? [n/1/2/all]: {C.RESET}").strip().lower() or 'n'
        except (EOFError, KeyboardInterrupt):
            chosen = 'n'
    else:
        chosen = 'n'
    if chosen == 'all':
        picks = list(range(1, min(len(candidates), 5) + 1))
    elif chosen.isdigit():
        val = int(chosen)
        picks = [val] if 1 <= val <= min(len(candidates), 5) else []
    else:
        picks = []
    for n in picks:
        c = candidates[n-1]
        try:
            out_path = _export_recovered_candidate(c, run_dir, source_name, n)
            exported.append(out_path)
            if not quiet:
                print(f"  {C.GREEN}[+] recovered export: {out_path}{C.RESET}")
        except Exception as e:
            if not quiet:
                print(f"  {C.RED}[!] recovered export failed for candidate {n}: {e}{C.RESET}")
    return exported


def run_analysis(input_data, source_label, flags, output_base,
                 wordlist, quiet=False, nodelay=False, save_json=False,
                 max_depth=3, stegopw_wordlist=None):
    if not quiet:
        print_input_header(
            source=source_label,
            size=len(input_data),
            wordlist_size=len(wordlist),
            depth=max_depth,
        )
    if not nodelay: time.sleep(DISPLAY_DELAY)
    engine   = AnalysisEngine(wordlist=wordlist, output_dir=output_base,
                               verbose=True, flags=flags, max_depth=max_depth,
                               stegopw_wordlist=stegopw_wordlist)
    findings = engine.analyze_string(input_data, source_label)
    run_dir = make_run_dir(output_base, source_label)
    if not quiet:
        print_results(findings, source_label, len(input_data), verbose=True)
    saved_files = _save_findings(findings, flags, run_dir, source_label)
    _write_report(findings, source_label, input_data, saved_files,
                  flags, run_dir, save_json, quiet)


def run_from_file(filepath, flags, output_base, wordlist,
                  quiet=False, nodelay=False, save_json=False,
                  max_depth=3, stegopw_wordlist=None):
    if not os.path.exists(filepath):
        print(f"  {C.RED}[!] file not found: {filepath}{C.RESET}")
        return
    size = os.path.getsize(filepath)
    if not quiet:
        print(f"\n{C.CYAN}[*] file     : {C.WHITE}{filepath}{C.RESET}")
        print(f"{C.CYAN}[*] size     : {C.WHITE}{size:,} bytes{C.RESET}")
        print(f"{C.CYAN}[*] depth    : {C.WHITE}{max_depth} level(s){C.RESET}")
        print(f"{C.CYAN}[*] wordlist : {C.WHITE}{len(wordlist):,} words{C.RESET}")
    if not nodelay: time.sleep(DISPLAY_DELAY)
    try:
        with open(filepath, 'rb') as fh:
            raw_bytes = fh.read()
    except Exception as e:
        print(f"  {C.RED}[!] cannot read file: {e}{C.RESET}")
        return
    engine   = AnalysisEngine(wordlist=wordlist, output_dir=output_base,
                               verbose=True, flags=flags, max_depth=max_depth,
                               stegopw_wordlist=stegopw_wordlist)
    source   = os.path.basename(filepath)
    findings = engine.analyze_file(raw_bytes, source)
    run_dir = make_run_dir(output_base, source)
    if not quiet:
        print_results(findings, source, len(raw_bytes), verbose=True,
                      nocolor=flags.get('nocolor', False))
    saved_files = _save_findings(findings, flags, run_dir, source)
    saved_files += _maybe_offer_recovered_exports(findings, flags, run_dir, source, quiet=quiet)
    _write_report(findings, source,
                  raw_bytes[:MAX_REPORT_STRING_LEN].decode('latin-1'),
                  saved_files, flags, run_dir, save_json, quiet)


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
    for filepath in files:
        run_from_file(filepath, flags, output_base, wordlist,
                      quiet, nodelay, save_json, max_depth, stegopw_wordlist)


def run_from_url(url, flags, output_base, wordlist,
                 quiet=False, nodelay=False, save_json=False,
                 max_depth=3, stegopw_wordlist=None):
    if not quiet:
        print(f"\n{C.CYAN}[*] fetching : {C.WHITE}{url}{C.RESET}")
    fetch = fetch_url(url)
    if not quiet:
        print_url_header(url=url, status=fetch.status,
                         content_type=fetch.content_type,
                         size=len(fetch.raw_bytes), error=fetch.error)
    if fetch.error: return
    if not quiet:
        print(f"{C.CYAN}[*] binary   : {C.WHITE}{fetch.is_binary}{C.RESET}")
        if fetch.detected_type:
            print(f"{C.CYAN}[*] detected : {C.WHITE}{fetch.detected_type[1]}{C.RESET}")
        print(f"{C.CYAN}[*] depth    : {C.WHITE}{max_depth} level(s){C.RESET}")
        print(f"{C.CYAN}[*] wordlist : {C.WHITE}{len(wordlist):,} words{C.RESET}")
    if not nodelay: time.sleep(DISPLAY_DELAY)
    engine   = AnalysisEngine(wordlist=wordlist, output_dir=output_base,
                               verbose=True, flags=flags, max_depth=max_depth,
                               stegopw_wordlist=stegopw_wordlist)
    findings = engine.analyze_url(url)
    source   = f'URL:{url}'
    run_dir = make_run_dir(output_base, url)
    if not quiet:
        print_results(findings, url, len(fetch.raw_bytes), verbose=True,
                      nocolor=flags.get('nocolor', False))
    saved_files = _save_findings(findings, flags, run_dir, source)
    input_preview = (fetch.text if not fetch.is_binary
                     else fetch.raw_bytes[:MAX_REPORT_STRING_LEN].decode('latin-1'))
    _write_report(findings, source, input_preview, saved_files,
                  flags, run_dir, save_json, quiet)


def run_shell(flags, output_base, wordlist, quiet=False,
              save_json=False, max_depth=3, stegopw_wordlist=None):
    print(f"\n{C.TOXGRN}{C.BOLD}  [ Hash It Out v4.2.0 :: Interactive Shell ]{C.RESET}")
    print(f"  {C.DIM}commands: <string>  file <path>  dir <path>  url <url>  help  exit{C.RESET}\n")
    while True:
        try:
            raw = input(f"{C.TOXGRN}hashitout>{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not raw: continue
        cmd = raw.lower()
        if cmd in ('exit','quit','q',':q','bye'):
            print(f"\n  {C.TOXGRN}Stay sharp.{C.RESET}\n")
            break
        elif cmd.startswith('file '):
            for p in raw[5:].strip().split():
                run_from_file(p, flags, output_base, wordlist, quiet,
                              nodelay=True, save_json=save_json,
                              max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        elif cmd.startswith('dir '):
            run_from_dir(raw[4:].strip(), flags, output_base, wordlist, quiet,
                         nodelay=True, save_json=save_json,
                         max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        elif cmd.startswith('url '):
            for u in raw[4:].strip().split():
                run_from_url(u, flags, output_base, wordlist, quiet,
                             nodelay=True, save_json=save_json,
                             max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        elif cmd in ('help','?'):
            print_help()
        elif cmd.startswith('http'):
            run_from_url(raw, flags, output_base, wordlist, quiet,
                         nodelay=True, save_json=save_json,
                         max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        else:
            run_analysis(raw, 'SHELL INPUT', flags, output_base, wordlist,
                         quiet, nodelay=True, save_json=save_json,
                         max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)


def _save_findings(findings, flags, run_dir, source_label):
    import re as _re
    saved = []
    if not flags.get('savefile'):
        return saved
    for f in findings:
        if f.result_bytes and f.filetype and f.filetype[0]:
            try:
                m = _re.search(r'0x([0-9a-fA-F]+)', f.method or '')
                offset = int(m.group(1), 16) if m else 0
                fp = save_decoded_file(f.result_bytes, run_dir,
                                       f.method, f.filetype[0], offset)
                saved.append(fp)
                print_file_saved(fp, f.method, f.filetype[1])
            except Exception as e:
                print(f"  {C.RED}[!] could not save: {e}{C.RESET}")
    return saved

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


def build_parser():
    p = argparse.ArgumentParser(prog='hashitout', add_help=False)
    p.add_argument('-f','--file', metavar='PATH', nargs='+')
    p.add_argument('-d','--dir', metavar='PATH')
    p.add_argument('-s','--string', metavar='STRING')
    p.add_argument('-u','--url', metavar='URL', nargs='+')
    p.add_argument('-o','--output', metavar='DIR', default='./output')
    p.add_argument('input_string', nargs='?', default=None)
    for flag in ('all','rot','base','hex','binary','morse',
                 'cipher','xor','misc','stego','deep','reverse','verbose',
                 'artifact-mode','full-nasty','export-recovered'):
        p.add_argument(f'--{flag}', action='store_true')
    p.add_argument('--depth', metavar='N', type=int, default=None)
    p.add_argument('--recursive', action='store_true')
    p.add_argument('--stegopw', metavar='WORDLIST')
    for flag in ('savefile','report','noreport','quiet','nocolor',
                 'json','nodelay','shell','version'):
        p.add_argument(f'--{flag}', action='store_true')
    p.add_argument('--help','-h', action='store_true')
    return p


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


def main():
    _m=os.path.join(os.path.expanduser('~/.local/bin'),'hashitout.installed')
    if not os.path.exists(_m) and not os.path.abspath(__file__).endswith('hashitout'):
        _self_install()
    parser = build_parser()
    args, extra = parser.parse_known_args()
    if extra and not args.input_string:
        args.input_string = ' '.join(extra)
    if args.nocolor:
        for attr in [a for a in dir(C) if not a.startswith('_')
                     and isinstance(getattr(C,a), str)]:
            setattr(C, attr, '')
    if not args.quiet: print_banner()
    if args.version:
        print(f"  Hash It Out v{VERSION}")
        print(f"  github.com/RRSWSEC/Hash-It-Out\n")
        return
    if args.help:
        print_help()
        if not any([args.shell, args.file, args.dir, args.string,
                    args.url, args.input_string]): return
    flags = {k: getattr(args, k, False) for k in
             ('all','rot','base','hex','binary','morse','cipher','xor',
              'misc','stego','deep','reverse','verbose',
              'savefile','report','noreport','nocolor','artifact_mode',
              'full_nasty','export_recovered')}
    # warn user if brute-force ciphers are enabled
    if flags.get('cipher') or flags.get('deep') or flags.get('full_nasty'):
        print(f"  {C.YELLOW}[!] brute-force or deep analysis enabled - this may be slow on large inputs{C.RESET}")

    if flags.get('full_nasty'):
        flags['deep'] = True
        flags['cipher'] = True
    run_all = flags.get('all') or not any(
        flags.get(k) for k in ('rot','base','hex','binary','morse',
                                'cipher','xor','misc','stego','deep'))
    flags['all'] = run_all
    if args.depth is not None: max_depth = max(1, min(50, args.depth))
    elif flags.get('full_nasty'): max_depth = 8
    elif run_all and not args.quiet: max_depth = _ask_depth(flags, args.nodelay)
    else: max_depth = 3
    stegopw_wordlist = getattr(args, 'stegopw', None)
    output_base = args.output
    os.makedirs(output_base, exist_ok=True)
    wordlist = load_wordlist()
    quiet = args.quiet; nodelay = args.nodelay; save_json = args.json
    ran = False
    if args.file:
        for filepath in args.file:
            run_from_file(filepath, flags, output_base, wordlist,
                          quiet, nodelay, save_json,
                          max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        ran = True
    if args.dir:
        run_from_dir(args.dir, flags, output_base, wordlist,
                     quiet, nodelay, save_json,
                     max_depth=max_depth, stegopw_wordlist=stegopw_wordlist,
                     recursive=args.recursive)
        ran = True
    if args.url:
        for url in args.url:
            run_from_url(url, flags, output_base, wordlist,
                         quiet, nodelay, save_json,
                         max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        ran = True
    input_str = args.string or args.input_string
    if input_str:
        run_analysis(input_str, 'CLI INPUT', flags, output_base, wordlist,
                     quiet, nodelay, save_json,
                     max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        ran = True
    if args.shell or not ran:
        run_shell(flags, output_base, wordlist, quiet, save_json,
                  max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)


if __name__ == '__main__':
    main()