import tkinter as tk
from tkinter import ttk
import base64

try:
    from tkinter import messagebox
except Exception:
    messagebox = None
import urllib.parse
import html
import codecs
import quopri
import encodings.idna
import gzip
import zlib
import hashlib
import json
import io
import subprocess
import sys
import binascii
import tkinter.filedialog as filedialog

# Dependency checks
try:
    import base58
    HAS_BASE58 = True
except ImportError:
    HAS_BASE58 = False
    BASE58_ERROR = "Error: base58 library not installed. Please install with: pip install base58"

try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False
    JWT_ERROR = "Error: PyJWT library not installed. Please install with: pip install PyJWT"

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    CRYPTO_ERROR = "Error: cryptography library not installed. Please install with: pip install cryptography"

try:
    import cbor2
    HAS_CBOR2 = True
except ImportError:
    HAS_CBOR2 = False
    CBOR2_ERROR = "Error: cbor2 library not installed. Please install with: pip install cbor2"

try:
    from Crypto.Hash import Whirlpool
    HAS_WHIRLPOOL = True
except ImportError:
    HAS_WHIRLPOOL = False
    WHIRLPOOL_ERROR = "Error: pycryptodome library not installed. Please install with: pip install pycryptodome"

# Morse Code dictionary
morse_dict = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    ' ': '/'
}
reverse_morse = {v: k for k, v in morse_dict.items()}

# Base58
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(text):
    num = int.from_bytes(text.encode('utf-8'), 'big')
    if num == 0:
        return BASE58_ALPHABET[0]
    encoded = ''
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = BASE58_ALPHABET[rem] + encoded
    return encoded

def base58_decode(text):
    num = 0
    for char in text:
        num = num * 58 + BASE58_ALPHABET.index(char)
    return num.to_bytes((num.bit_length() + 7) // 8, 'big').decode('utf-8')

# Atbash
atbash_dict = {chr(i): chr(155 - i) for i in range(65, 91)} | {chr(i): chr(219 - i) for i in range(97, 123)}

# Caesar
def caesar_encode(text, shift=3):
    result = []
    for c in text:
        if c.isupper():
            result.append(chr((ord(c) - 65 + shift) % 26 + 65))
        elif c.islower():
            result.append(chr((ord(c) - 97 + shift) % 26 + 97))
        else:
            result.append(c)
    return ''.join(result)

def caesar_decode(text, shift=3):
    return caesar_encode(text, -shift)

# Vigenère
def vigenere_encode(text, key="KEY"):
    key = key.upper()
    result = []
    key_index = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            if c.isupper():
                result.append(chr((ord(c) - 65 + shift) % 26 + 65))
            else:
                result.append(chr((ord(c) - 97 + shift) % 26 + 97))
            key_index += 1
        else:
            result.append(c)
    return ''.join(result)

def vigenere_decode(text, key="KEY"):
    key = key.upper()
    result = []
    key_index = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            if c.isupper():
                result.append(chr((ord(c) - 65 - shift) % 26 + 65))
            else:
                result.append(chr((ord(c) - 97 - shift) % 26 + 97))
            key_index += 1
        else:
            result.append(c)
    return ''.join(result)

# Leetspeak
leetspeak_dict = {'A': '4', 'E': '3', 'I': '1', 'O': '0', 'T': '7', 'S': '5'}
reverse_leetspeak = {v: k for k, v in leetspeak_dict.items()}

# Base91 (simple implementation)
BASE91_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""

def base91_encode(text):
    data = text.encode('utf-8')
    result = []
    b = 0
    n = 0
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            result.append(BASE91_ALPHABET[v % 91])
            result.append(BASE91_ALPHABET[v // 91])
    if n:
        result.append(BASE91_ALPHABET[b % 91])
        if n > 7 or b > 90:
            result.append(BASE91_ALPHABET[b // 91])
    return ''.join(result)

def base91_decode(text):
    result = []
    b = 0
    n = 0
    v = -1
    for char in text:
        c = BASE91_ALPHABET.index(char)
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if v & 8191 > 88 else 14
            v = -1
            while n > 7:
                result.append(b & 255)
                b >>= 8
                n -= 8
    if v != -1:
        result.append(b | v << n & 255)
    return bytes(result).decode('utf-8')

# Base45 (simple implementation)
BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

def base45_encode(text):
    data = text.encode('utf-8')
    result = []
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            val = (data[i] << 8) + data[i + 1]
        else:
            val = data[i] << 8
        for j in range(3):
            result.append(BASE45_ALPHABET[val % 45])
            val //= 45
    return ''.join(result)

def base45_decode(text):
    result = []
    for i in range(0, len(text), 3):
        val = 0
        for j in range(min(3, len(text) - i)):
            val += BASE45_ALPHABET.index(text[i + j]) * (45 ** j)
        if i + 2 < len(text) or len(text) % 3 == 0:
            result.append(val >> 8)
        result.append(val & 255)
    return bytes(result).decode('utf-8')

# XOR
def xor_encode(text, key=42):
    return ''.join(chr(ord(c) ^ key) for c in text)

# Affine
def affine_encode(text, a=5, b=8):
    result = []
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            result.append(chr((a * (ord(c) - base) + b) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)

def affine_decode(text, a=5, b=8):
    a_inv = pow(a, -1, 26)
    result = []
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            result.append(chr((a_inv * (ord(c) - base - b)) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)

# Rail Fence
def rail_fence_encode(text, rails=3):
    if rails == 1:
        return text
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    return ''.join(''.join(row) for row in fence)

def rail_fence_decode(text, rails=3):
    if rails == 1:
        return text
    fence = [[] for _ in range(rails)]
    rail_lengths = [0] * rails
    rail = 0
    direction = 1
    for i in range(len(text)):
        rail_lengths[rail] += 1
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    idx = 0
    for r in range(rails):
        for _ in range(rail_lengths[r]):
            fence[r].append(text[idx])
            idx += 1
    result = []
    rail = 0
    direction = 1
    rail_indices = [0] * rails
    for _ in range(len(text)):
        result.append(fence[rail][rail_indices[rail]])
        rail_indices[rail] += 1
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    return ''.join(result)

# Playfair
def playfair_encode(text, key="KEYWORD"):
    key = key.upper().replace('J', 'I')
    matrix = []
    seen = set()
    for char in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in seen:
            matrix.append(char)
            seen.add(char)
    text = text.upper().replace('J', 'I').replace(' ', '')
    if len(text) % 2 == 1:
        text += 'X'
    result = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        row_a, col_a = divmod(matrix.index(a), 5)
        row_b, col_b = divmod(matrix.index(b), 5)
        if row_a == row_b:
            result.append(matrix[row_a * 5 + (col_a + 1) % 5])
            result.append(matrix[row_b * 5 + (col_b + 1) % 5])
        elif col_a == col_b:
            result.append(matrix[((row_a + 1) % 5) * 5 + col_a])
            result.append(matrix[((row_b + 1) % 5) * 5 + col_b])
        else:
            result.append(matrix[row_a * 5 + col_b])
            result.append(matrix[row_b * 5 + col_a])
    return ''.join(result)

def playfair_decode(text, key="KEYWORD"):
    key = key.upper().replace('J', 'I')
    matrix = []
    seen = set()
    for char in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in seen:
            matrix.append(char)
            seen.add(char)
    result = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        row_a, col_a = divmod(matrix.index(a), 5)
        row_b, col_b = divmod(matrix.index(b), 5)
        if row_a == row_b:
            result.append(matrix[row_a * 5 + (col_a - 1) % 5])
            result.append(matrix[row_b * 5 + (col_b - 1) % 5])
        elif col_a == col_b:
            result.append(matrix[((row_a - 1) % 5) * 5 + col_a])
            result.append(matrix[((row_b - 1) % 5) * 5 + col_b])
        else:
            result.append(matrix[row_a * 5 + col_b])
            result.append(matrix[row_b * 5 + col_a])
    return ''.join(result).rstrip('X')

# Emoji
EMOJI_LIST = ["😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇", "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚", "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓", "😎", "🤩", "🥳", "😏", "😒", "😞", "😔", "😟", "😕", "🙁", "☹️", "😣", "😖", "😫", "😩", "🥺", "😢", "😭", "😤", "😠", "😡", "🤬", "🤯", "😳", "🥵", "🥶", "😱", "😨", "😰", "😥", "😓", "🤗", "🤔", "🤭", "🤫", "🤥", "😶", "😐", "😑", "😬", "🙄", "😯", "😦", "😧", "😮", "😲", "🥱", "😴", "🤤", "😪", "😵", "🤐", "🥴", "🤢", "🤮", "🤧", "😷", "🤒", "🤕", "🤑", "🤠", "😈", "👿", "👹", "👺", "🤡", "💩", "👻", "💀", "☠️", "👽", "👾", "🤖", "🎃", "😺", "😸", "😹", "😻", "😼", "😽", "🙀", "😿", "😾"]

def emoji_encode(text):
    return ''.join(EMOJI_LIST[b] for b in text.encode('utf-8'))

def emoji_decode(text):
    result = []
    i = 0
    while i < len(text):
        for j in range(1, 5):  # emojis are 1-4 chars
            if text[i:i+j] in EMOJI_LIST:
                result.append(EMOJI_LIST.index(text[i:i+j]))
                i += j
                break
        else:
            raise ValueError("Invalid emoji")
    return bytes(result).decode('utf-8')

# DNA
DNA_MAP = {'00': 'A', '01': 'C', '10': 'G', '11': 'T'}
REVERSE_DNA = {v: k for k, v in DNA_MAP.items()}

def dna_encode(text):
    binary = ''.join(format(b, '08b') for b in text.encode('utf-8'))
    return ''.join(DNA_MAP[binary[i:i+2]] for i in range(0, len(binary), 2))

def dna_decode(text):
    binary = ''.join(REVERSE_DNA[c] for c in text.upper())
    bytes_list = [int(binary[i:i+8], 2) for i in range(0, len(binary), 8)]
    return bytes(bytes_list).decode('utf-8')

# Braille
BRAILLE_DICT = {
    'A': '⠁', 'B': '⠃', 'C': '⠉', 'D': '⠙', 'E': '⠑', 'F': '⠋', 'G': '⠛', 'H': '⠓', 'I': '⠊', 'J': '⠚', 'K': '⠅', 'L': '⠇', 'M': '⠍', 'N': '⠝', 'O': '⠕', 'P': '⠏', 'Q': '⠟', 'R': '⠗', 'S': '⠎', 'T': '⠞', 'U': '⠥', 'V': '⠧', 'W': '⠺', 'X': '⠭', 'Y': '⠽', 'Z': '⠵',
    ' ': '⠀'
}
REVERSE_BRAILLE = {v: k for k, v in BRAILLE_DICT.items()}

def braille_encode(text):
    return ''.join(BRAILLE_DICT.get(c.upper(), '?') for c in text)

def braille_decode(text):
    return ''.join(REVERSE_BRAILLE.get(c, '?') for c in text)

def jwt_decode_manual(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        header_b64 = parts[0]
        payload_b64 = parts[1]
        signature_b64 = parts[2]
        # Add padding to make length multiple of 4
        header_b64 += '=' * (4 - len(header_b64) % 4) % 4
        payload_b64 += '=' * (4 - len(payload_b64) % 4) % 4
        header = json.loads(base64.urlsafe_b64decode(header_b64).decode('utf-8'))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
        return {
            "header": header,
            "payload": payload,
            "signature": signature_b64
        }
    except Exception as e:
        raise ValueError(f"Invalid JWT: {str(e)}")

# Base36
def base36_encode(text):
    num = int.from_bytes(text.encode('utf-8'), 'big')
    if num == 0:
        return '0'
    chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    result = ''
    while num > 0:
        result = chars[num % 36] + result
        num //= 36
    return result

def base36_decode(text):
    chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    num = 0
    for c in text.upper():
        num = num * 36 + chars.index(c)
    return num.to_bytes((num.bit_length() + 7) // 8, 'big').decode('utf-8')

# Base62
BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def base62_encode(text):
    num = int.from_bytes(text.encode('utf-8'), 'big')
    if num == 0:
        return '0'
    result = ''
    while num > 0:
        result = BASE62_ALPHABET[num % 62] + result
        num //= 62
    return result

def base62_decode(text):
    num = 0
    for c in text:
        num = num * 62 + BASE62_ALPHABET.index(c)
    return num.to_bytes((num.bit_length() + 7) // 8, 'big').decode('utf-8')

# CRC32
def crc32_encode(text):
    return hex(zlib.crc32(text.encode('utf-8')))[2:]

# SHA3
def sha3_224_encode(text):
    return hashlib.sha3_224(text.encode('utf-8')).hexdigest()

def sha3_256_encode(text):
    return hashlib.sha3_256(text.encode('utf-8')).hexdigest()

def sha3_512_encode(text):
    return hashlib.sha3_512(text.encode('utf-8')).hexdigest()

# RIPEMD160
def ripemd160_encode(text):
    return hashlib.new('ripemd160', text.encode('utf-8')).hexdigest()

# Polybius Square Cipher
POLYBIUS = {
    'A': '11', 'B': '12', 'C': '13', 'D': '14', 'E': '15',
    'F': '21', 'G': '22', 'H': '23', 'I': '24', 'J': '24', 'K': '25',
    'L': '31', 'M': '32', 'N': '33', 'O': '34', 'P': '35',
    'Q': '41', 'R': '42', 'S': '43', 'T': '44', 'U': '45',
    'V': '51', 'W': '52', 'X': '53', 'Y': '54', 'Z': '55'
}

REVERSE_POLYBIUS = {v: k for k, v in POLYBIUS.items()}

def polybius_encode(text):
    return ''.join(POLYBIUS.get(c.upper(), '') for c in text)

def polybius_decode(text):
    result = ''
    for i in range(0, len(text), 2):
        pair = text[i:i+2]
        result += REVERSE_POLYBIUS.get(pair, '')
    return result

# Tap Code Cipher
TAP_DICT = {
    'A': '11', 'B': '12', 'C': '13', 'D': '14', 'E': '15',
    'F': '21', 'G': '22', 'H': '23', 'I': '24', 'J': '25',
    'K': '31', 'L': '32', 'M': '33', 'N': '34', 'O': '35',
    'P': '41', 'Q': '42', 'R': '43', 'S': '44', 'T': '45',
    'U': '51', 'V': '52', 'W': '53', 'X': '54', 'Y': '55',
    'Z': '55'
}

REVERSE_TAP = {v: k for k, v in TAP_DICT.items()}

def tap_code_encode(text):
    return ' '.join(TAP_DICT.get(c.upper(), '') for c in text)

def tap_code_decode(text):
    pairs = text.split()
    return ''.join(REVERSE_TAP.get(pair, '') for pair in pairs)

# Zalgo Text
def zalgo_encode(text):
    zalgo_chars = ['\u0300', '\u0301', '\u0302', '\u0303', '\u0304', '\u0305', '\u0306', '\u0307', '\u0308', '\u0309', '\u030a', '\u030b', '\u030c', '\u030d', '\u030e', '\u030f', '\u0310', '\u0311', '\u0312', '\u0313', '\u0314', '\u0315', '\u0316', '\u0317', '\u0318', '\u0319', '\u031a', '\u031b', '\u031c', '\u031d', '\u031e', '\u031f', '\u0320', '\u0321', '\u0322', '\u0323', '\u0324', '\u0325', '\u0326', '\u0327', '\u0328', '\u0329', '\u032a', '\u032b', '\u032c', '\u032d', '\u032e', '\u032f', '\u0330', '\u0331', '\u0332', '\u0333', '\u0334', '\u0335', '\u0336', '\u0337', '\u0338', '\u0339', '\u033a', '\u033b', '\u033c', '\u033d', '\u033e', '\u033f', '\u0340', '\u0341', '\u0342', '\u0343', '\u0344', '\u0345', '\u0346', '\u0347', '\u0348', '\u0349', '\u034a', '\u034b', '\u034c', '\u034d', '\u034e', '\u034f', '\u0350', '\u0351', '\u0352', '\u0353', '\u0354', '\u0355', '\u0356', '\u0357', '\u0358', '\u0359', '\u035a', '\u035b', '\u035c', '\u035d', '\u035e', '\u035f', '\u0360', '\u0361', '\u0362', '\u0363', '\u0364', '\u0365', '\u0366', '\u0367', '\u0368', '\u0369', '\u036a', '\u036b', '\u036c', '\u036d', '\u036e', '\u036f']
    result = ''
    for c in text:
        result += c
        for _ in range(5):
            result += zalgo_chars[ord(c) % len(zalgo_chars)]
    return result

def zalgo_decode(text):
    import unicodedata
    return ''.join(c for c in text if unicodedata.category(c) != 'Mn')

# Soundex
def soundex_encode(text):
    text = text.upper()
    if not text:
        return '0000'
    first = text[0]
    text = text[1:]
    mapping = {'B': '1', 'F': '1', 'P': '1', 'V': '1',
               'C': '2', 'G': '2', 'J': '2', 'K': '2', 'Q': '2', 'S': '2', 'X': '2', 'Z': '2',
               'D': '3', 'T': '3',
               'L': '4',
               'M': '5', 'N': '5',
               'R': '6'}
    code = first
    prev = mapping.get(first, '')
    for c in text:
        if c in mapping and mapping[c] != prev:
            code += mapping[c]
            prev = mapping[c]
    code += '0' * (4 - len(code))
    return code[:4]

# Brainfuck Encoder
def brainfuck_encode(text):
    bf = ''
    for c in text:
        bf += '+' * ord(c) + '.'
    return bf

def encode_text(text, method):
    try:
        if method == 'Base64':
            return base64.b64encode(text.encode('utf-8')).decode('utf-8')
        elif method == 'Hex':
            return text.encode('utf-8').hex()
        elif method == 'URL':
            return urllib.parse.quote(text)
        elif method == 'HTML Entities':
            return html.escape(text)
        elif method == 'ROT13':
            return codecs.encode(text, 'rot_13')
        elif method == 'Binary':
            return ' '.join(format(ord(c), '08b') for c in text)
        elif method == 'Morse Code':
            return ' '.join(morse_dict.get(c.upper(), '?') for c in text)
        elif method == 'ASCII':
            return ' '.join(str(ord(c)) for c in text)
        elif method == 'UTF-8':
            return ' '.join(str(b) for b in text.encode('utf-8'))
        elif method == 'UTF-16':
            return ' '.join(str(b) for b in text.encode('utf-16'))
        elif method == 'UTF-32':
            return ' '.join(str(b) for b in text.encode('utf-32'))
        elif method == 'Unicode':
            return ' '.join(f"U+{ord(c):04X}" for c in text)
        elif method == 'Base85':
            return base64.b85encode(text.encode('utf-8')).decode('utf-8')
        elif method == 'Base58':
            return base58_encode(text)
        elif method == 'Quoted-Printable':
            return quopri.encodestring(text.encode('utf-8')).decode('utf-8')
        elif method == 'Punycode':
            return text.encode('idna').decode('ascii')
        elif method == 'Atbash Cipher':
            return ''.join(atbash_dict.get(c, c) for c in text)
        elif method == 'Caesar Cipher':
            return caesar_encode(text)
        elif method == 'Vigenère Cipher':
            return vigenere_encode(text)
        elif method == 'Leetspeak':
            return ''.join(leetspeak_dict.get(c.upper(), c) for c in text)
        elif method == 'Gzip':
            return base64.b64encode(gzip.compress(text.encode('utf-8'))).decode('utf-8')
        elif method == 'Zlib':
            return base64.b64encode(zlib.compress(text.encode('utf-8'))).decode('utf-8')
        elif method == 'MD5':
            return hashlib.md5(text.encode('utf-8')).hexdigest()
        elif method == 'SHA-1':
            return hashlib.sha1(text.encode('utf-8')).hexdigest()
        elif method == 'SHA-256':
            return hashlib.sha256(text.encode('utf-8')).hexdigest()
        elif method == 'Base32':
            return base64.b32encode(text.encode('utf-8')).decode('utf-8')
        elif method == 'Base91':
            return base91_encode(text)
        elif method == 'Base45':
            return base45_encode(text)
        elif method == 'XOR Cipher':
            return xor_encode(text)
        elif method == 'Affine Cipher':
            return affine_encode(text)
        elif method == 'Rail Fence Cipher':
            return rail_fence_encode(text)
        elif method == 'Playfair Cipher':
            return playfair_encode(text)
        elif method == 'Emoji Encoding':
            return emoji_encode(text)
        elif method == 'DNA Encoding':
            return dna_encode(text)
        elif method == 'Braille Encoding':
            return braille_encode(text)
        elif method == 'JWT Decode':
            return "Error: JWT is for decoding only"
        elif method == 'Base36':
            return base36_encode(text)
        elif method == 'Base62':
            return base62_encode(text)
        elif method == 'CRC32':
            return crc32_encode(text)
        elif method == 'SHA3-224':
            return sha3_224_encode(text)
        elif method == 'SHA3-256':
            return sha3_256_encode(text)
        elif method == 'SHA3-512':
            return sha3_512_encode(text)
        elif method == 'RIPEMD160':
            return ripemd160_encode(text)
        elif method == 'Polybius Square Cipher':
            return polybius_encode(text)
        elif method == 'Tap Code Cipher':
            return tap_code_encode(text)
        elif method == 'Zalgo Text':
            return zalgo_encode(text)
        elif method == 'Soundex':
            return soundex_encode(text)
        elif method == 'Brainfuck Encoder':
            return brainfuck_encode(text)
        elif method == 'QR Code':
            try:
                import qrcode
            except ImportError:
                try:
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'qrcode[pil]'])
                    import qrcode
                except subprocess.CalledProcessError:
                    try:
                        messagebox.showerror("Error", "QR Code feature requires the 'qrcode' library. Please install manually: pip install qrcode[pil]")
                    except:
                        print("QR Code feature requires the 'qrcode' library. Please install manually: pip install qrcode[pil]")
                    return "Error: qrcode library not installed"
            qr = qrcode.QRCode()
            qr.add_data(text)
            qr.make()
            img = qr.make_image()
            img.save('qrcode.png')
            try:
                messagebox.showinfo("QR Code", "QR code saved as qrcode.png")
            except:
                print("QR code saved as qrcode.png")
            return "QR code generated"
        elif method == 'Base128':
            data = text.encode('utf-8')
            return ''.join(chr(b + 128) for b in data)
        elif method == 'Base65536':
            data = text.encode('utf-8')
            return ''.join(chr(b + 256) for b in data)
        elif method == 'Ascii85':
            return base64.a85encode(text.encode('utf-8')).decode('utf-8')
        elif method == 'Z85':
            try:
                from zmq.utils import z85
                return z85.encode(text.encode('utf-8')).decode('utf-8')
            except ImportError:
                return "Error: z85 library not installed. Please install with: pip install z85"
        elif method == 'ROT47':
            result = []
            for c in text:
                if 33 <= ord(c) <= 126:
                    result.append(chr((ord(c) - 33 + 47) % 94 + 33))
                else:
                    result.append(c)
            return ''.join(result)
        elif method == 'Whirlpool':
            if not HAS_WHIRLPOOL:
                messagebox.showerror("Library Missing", WHIRLPOOL_ERROR)
                return ""
            return Whirlpool.new(text.encode('utf-8')).hexdigest()
        elif method == 'Bencode':
            def bencode(data):
                if isinstance(data, str):
                    return f"{len(data)}:{data}"
                elif isinstance(data, int):
                    return f"i{data}e"
                elif isinstance(data, list):
                    return f"l{''.join(bencode(item) for item in data)}e"
                elif isinstance(data, dict):
                    return f"d{''.join(bencode(k) + bencode(v) for k, v in data.items())}e"
                else:
                    return ""
            return bencode(text)
        elif method == 'S-Expressions':
            return f"({text})"
        elif method == 'MessagePack':
            try:
                import msgpack
                return base64.b64encode(msgpack.packb(text)).decode('utf-8')
            except ImportError:
                return "Error: msgpack library not installed. Please install with: pip install msgpack"
        elif method == 'CBOR':
            if not HAS_CBOR2:
                messagebox.showerror("Library Missing", CBOR2_ERROR)
                return ""
            return base64.b64encode(cbor2.dumps(text)).decode('utf-8')
        elif method == 'DES':
            if not HAS_CRYPTO:
                messagebox.showerror("Library Missing", CRYPTO_ERROR)
                return ""
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            key = b'12345678'
            iv = b'12345678'
            cipher = Cipher(algorithms.DES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padded_text = text.encode('utf-8') + b'\0' * (8 - len(text.encode('utf-8')) % 8)
            return base64.b64encode(encryptor.update(padded_text) + encryptor.finalize()).decode('utf-8')
        elif method == 'AES':
            if not HAS_CRYPTO:
                messagebox.showerror("Library Missing", CRYPTO_ERROR)
                return ""
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            key = b'1234567890123456'
            iv = b'1234567890123456'
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padded_text = text.encode('utf-8') + b'\0' * (16 - len(text.encode('utf-8')) % 16)
            return base64.b64encode(encryptor.update(padded_text) + encryptor.finalize()).decode('utf-8')
        elif method == 'RSA':
            if not HAS_CRYPTO:
                messagebox.showerror("Library Missing", CRYPTO_ERROR)
                return ""
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import hashes
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            ciphertext = public_key.encrypt(
                text.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(ciphertext).decode('utf-8')
        elif method == 'Fernet':
            if not HAS_CRYPTO:
                messagebox.showerror("Library Missing", CRYPTO_ERROR)
                return ""
            from cryptography.fernet import Fernet
            key = Fernet.generate_key()
            f = Fernet(key)
            return f.encrypt(text.encode('utf-8')).decode('utf-8')
        elif method == 'JWT Signed':
            if not HAS_JWT:
                messagebox.showerror("Library Missing", JWT_ERROR)
                return ""
            token = jwt.encode({'data': text}, 'secret', algorithm='HS256')
            return token
        elif method == 'Base58Check':
            if not HAS_BASE58:
                messagebox.showerror("Library Missing", BASE58_ERROR)
                return ""
            return base58.b58encode_check(text.encode('utf-8')).decode('utf-8')
        elif method == 'Bech32':
            try:
                import bech32
                hrp = 'bc'
                data = [ord(c) for c in text]
                return bech32.encode(hrp, data)
            except ImportError:
                return "Error: bech32 library not installed. Please install with: pip install bech32"
        elif method == 'Armor64':
            return binascii.b2a_base64(text.encode('utf-8')).decode('utf-8')
        elif method == 'BinHex':
            return binascii.b2a_hex(text.encode('utf-8')).decode('utf-8')
        elif method == 'Emoji Sequences':
            hex_to_emoji = {'0': '0️⃣', '1': '1️⃣', '2': '2️⃣', '3': '3️⃣', '4': '4️⃣', '5': '5️⃣', '6': '6️⃣', '7': '7️⃣', '8': '8️⃣', '9': '9️⃣', 'a': '🅰️', 'b': '🅱️', 'c': '©️', 'd': '🇩', 'e': '📧', 'f': '🇫'}
            hex_str = text.encode('utf-8').hex()
            return ''.join(hex_to_emoji.get(c, c) for c in hex_str)
        elif method == 'Binary-to-Music':
            binary = ''.join(format(ord(c), '08b') for c in text)
            notes = ['c', 'd', 'e', 'f', 'g', 'a', 'b']
            mml = ''
            for b in binary:
                if b == '1':
                    mml += 'c'
                else:
                    mml += 'r'
            return mml
    except Exception as e:
        return f"Error: {str(e)}"

def decode_text(text, method):
    try:
        if method == 'Base64':
            return base64.b64decode(text).decode('utf-8')
        elif method == 'Hex':
            return bytes.fromhex(text).decode('utf-8')
        elif method == 'URL':
            return urllib.parse.unquote(text)
        elif method == 'HTML Entities':
            return html.unescape(text)
        elif method == 'ROT13':
            return codecs.decode(text, 'rot_13')
        elif method == 'Binary':
            return ''.join(chr(int(b, 2)) for b in text.split())
        elif method == 'Morse Code':
            return ''.join(reverse_morse.get(code, '?') for code in text.split())
        elif method == 'ASCII':
            return ''.join(chr(int(code)) for code in text.split())
        elif method == 'UTF-8':
            return bytes(int(b) for b in text.split()).decode('utf-8')
        elif method == 'UTF-16':
            return bytes(int(b) for b in text.split()).decode('utf-16')
        elif method == 'UTF-32':
            return bytes(int(b) for b in text.split()).decode('utf-32')
        elif method == 'Unicode':
            return ''.join(chr(int(code[2:], 16)) for code in text.split())
        elif method == 'Base85':
            return base64.b85decode(text).decode('utf-8')
        elif method == 'Base58':
            return base58_decode(text)
        elif method == 'Quoted-Printable':
            return quopri.decodestring(text).decode('utf-8')
        elif method == 'Punycode':
            return text.encode('ascii').decode('idna')
        elif method == 'Atbash Cipher':
            return ''.join(atbash_dict.get(c, c) for c in text)
        elif method == 'Caesar Cipher':
            return caesar_decode(text)
        elif method == 'Vigenère Cipher':
            return vigenere_decode(text)
        elif method == 'Leetspeak':
            return ''.join(reverse_leetspeak.get(c, c) for c in text)
        elif method == 'Gzip':
            return gzip.decompress(base64.b64decode(text)).decode('utf-8')
        elif method == 'Zlib':
            return zlib.decompress(base64.b64decode(text)).decode('utf-8')
        elif method in ['MD5', 'SHA-1', 'SHA-256']:
            return "Error: One-way hashing, cannot decode"
        elif method == 'Base32':
            return base64.b32decode(text).decode('utf-8')
        elif method == 'Base91':
            return base91_decode(text)
        elif method == 'Base45':
            return base45_decode(text)
        elif method == 'XOR Cipher':
            return xor_encode(text)  # symmetric
        elif method == 'Affine Cipher':
            return affine_decode(text)
        elif method == 'Rail Fence Cipher':
            return rail_fence_decode(text)
        elif method == 'Playfair Cipher':
            return playfair_decode(text)
        elif method == 'Emoji Encoding':
            return emoji_decode(text)
        elif method == 'DNA Encoding':
            return dna_decode(text)
        elif method == 'Braille Encoding':
            return braille_decode(text)
        elif method == 'JWT Decode':
            data = jwt_decode_manual(text)
            return json.dumps(data, indent=2)
        elif method == 'Base36':
            return base36_decode(text)
        elif method == 'Base62':
            return base62_decode(text)
        elif method in ['CRC32', 'SHA3-224', 'SHA3-256', 'SHA3-512', 'RIPEMD160', 'Soundex', 'Brainfuck Encoder']:
            return "Error: One-way encoding, cannot decode"
        elif method == 'Polybius Square Cipher':
            return polybius_decode(text)
        elif method == 'Tap Code Cipher':
            return tap_code_decode(text)
        elif method == 'Zalgo Text':
            return zalgo_decode(text)
        elif method == 'QR Code':
            return "Error: QR Code is for encoding only"
        elif method == 'Base128':
            return bytes(ord(c) - 128 for c in text).decode('utf-8')
        elif method == 'Base65536':
            return bytes(ord(c) - 256 for c in text).decode('utf-8')
        elif method == 'Ascii85':
            return base64.a85decode(text).decode('utf-8')
        elif method == 'Z85':
            try:
                from zmq.utils import z85
                return z85.decode(text).decode('utf-8')
            except ImportError:
                return "Error: z85 library not installed"
        elif method == 'ROT47':
            result = []
            for c in text:
                if 33 <= ord(c) <= 126:
                    result.append(chr((ord(c) - 33 - 47) % 94 + 33))
                else:
                    result.append(c)
            return ''.join(result)
        elif method == 'Whirlpool':
            return "Error: One-way hashing, cannot decode"
        elif method == 'Bencode':
            def bdecode(data):
                if data.startswith('i'):
                    end = data.find('e')
                    return int(data[1:end])
                elif data[0].isdigit():
                    colon = data.find(':')
                    length = int(data[:colon])
                    return data[colon+1:colon+1+length]
                elif data.startswith('l'):
                    result = []
                    i = 1
                    while data[i] != 'e':
                        item, i = bdecode(data[i:])
                        result.append(item)
                    return result
                elif data.startswith('d'):
                    result = {}
                    i = 1
                    while data[i] != 'e':
                        key, i = bdecode(data[i:])
                        value, i = bdecode(data[i:])
                        result[key] = value
                    return result
                return None
            return bdecode(text)
        elif method == 'S-Expressions':
            return text.strip('()')
        elif method == 'MessagePack':
            try:
                import msgpack
                return msgpack.unpackb(base64.b64decode(text))
            except ImportError:
                return "Error: msgpack library not installed"
        elif method == 'CBOR':
            if not HAS_CBOR2:
                messagebox.showerror("Library Missing", CBOR2_ERROR)
                return ""
            return cbor2.loads(base64.b64decode(text))
        elif method == 'DES':
            if not HAS_CRYPTO:
                messagebox.showerror("Library Missing", CRYPTO_ERROR)
                return ""
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            key = b'12345678'
            iv = b'12345678'
            cipher = Cipher(algorithms.DES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(base64.b64decode(text)) + decryptor.finalize()
            return decrypted.rstrip(b'\0').decode('utf-8')
        elif method == 'AES':
            if not HAS_CRYPTO:
                messagebox.showerror("Library Missing", CRYPTO_ERROR)
                return ""
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            key = b'1234567890123456'
            iv = b'1234567890123456'
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(base64.b64decode(text)) + decryptor.finalize()
            return decrypted.rstrip(b'\0').decode('utf-8')
        elif method == 'RSA':
            # RSA is asymmetric, decode would need private key, but for demo, assume same key
            return "Error: RSA decode requires private key, not implemented"
        elif method == 'Fernet':
            try:
                from cryptography.fernet import Fernet
                # For demo, assume key is known, but since key is generated, can't decode without it
                return "Error: Fernet decode requires key, not implemented"
            except ImportError:
                return "Error: cryptography library not installed"
        elif method == 'JWT Signed':
            if not HAS_JWT:
                messagebox.showerror("Library Missing", JWT_ERROR)
                return ""
            try:
                payload = jwt.decode(text, 'secret', algorithms=['HS256'])
                return payload['data']
            except:
                return "Error: Invalid JWT"
        elif method == 'Base58Check':
            if not HAS_BASE58:
                messagebox.showerror("Library Missing", BASE58_ERROR)
                return ""
            return base58.b58decode_check(text).decode('utf-8')
        elif method == 'Bech32':
            try:
                import bech32
                hrp, data = bech32.decode(text)
                return ''.join(chr(d) for d in data)
            except ImportError:
                return "Error: bech32 library not installed"
        elif method == 'Armor64':
            return binascii.a2b_base64(text).decode('utf-8')
        elif method == 'BinHex':
            return binascii.a2b_hex(text).decode('utf-8')
        elif method == 'Emoji Sequences':
            emoji_to_hex = {v: k for k, v in {'0': '0️⃣', '1': '1️⃣', '2': '2️⃣', '3': '3️⃣', '4': '4️⃣', '5': '5️⃣', '6': '6️⃣', '7': '7️⃣', '8': '8️⃣', '9': '9️⃣', 'a': '🅰️', 'b': '🅱️', 'c': '©️', 'd': '🇩', 'e': '📧', 'f': '🇫'}.items()}
            hex_str = ''.join(emoji_to_hex.get(c, c) for c in text)
            return bytes.fromhex(hex_str).decode('utf-8')
        elif method == 'Binary-to-Music':
            binary = ''.join('1' if c == 'c' else '0' for c in text)
            bytes_list = [int(binary[i:i+8], 2) for i in range(0, len(binary), 8)]
            return bytes(bytes_list).decode('utf-8')
    except Exception as e:
        return f"Error: {str(e)}"

def show_credits():
    credits_text = "Created by: Zion\nGitHub: https://github.com/Zionn69\nReddit: https://www.reddit.com/user/Zionn67/"
    if messagebox:
        messagebox.showinfo("Credits", credits_text)
    else:
        print(credits_text)

root = tk.Tk()
root.title("Universal Encoder/Decoder")

menubar = tk.Menu(root)
root.config(menu=menubar)
help_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="Credits", command=show_credits)

favorites = set()
history = []
max_history = 20
current_history_index = -1

def filter_methods():
    query = search_var.get().lower()
    main_menu.delete(0, 'end')
    # Favorites first
    fav_methods = sorted([m for m in favorites if query in m.lower()])
    if fav_methods:
        fav_menu = tk.Menu(main_menu, tearoff=0)
        main_menu.add_cascade(label="Favorites", menu=fav_menu)
        for method in fav_methods:
            fav_menu.add_command(label=method, command=lambda m=method: method_var.set(m))
    for cat, methods in categories.items():
        filtered_methods = sorted([m for m in methods if query in m.lower() and m not in favorites])
        if filtered_methods:
            cat_menu = tk.Menu(main_menu, tearoff=0)
            main_menu.add_cascade(label=cat, menu=cat_menu)
            for method in filtered_methods:
                cat_menu.add_command(label=method, command=lambda m=method: method_var.set(m))

def toggle_favorite():
    method = method_var.get()
    if method in favorites:
        favorites.remove(method)
        star_button.config(text="☆")
    else:
        favorites.add(method)
        star_button.config(text="★")
    filter_methods()

def copy_output():
    output = output_box.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(output)

def paste_input():
    try:
        pasted = root.clipboard_get()
        input_box.delete("1.0", tk.END)
        input_box.insert(tk.END, pasted)
    except:
        pass

def save_output():
    output = output_box.get("1.0", tk.END).strip()
    if not output:
        messagebox.showerror("Error", "No output to save")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(output)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

def load_input():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            input_box.delete("1.0", tk.END)
            input_box.insert(tk.END, content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")

def detect_codec():
    input_text = input_box.get("1.0", tk.END).strip()
    if not input_text:
        messagebox.showerror("Error", "No input to detect")
        return
    # Try common decodes
    common_methods = ['Base64', 'Hex', 'Base32', 'Base58', 'Base85', 'Quoted-Printable', 'ROT13', 'Binary']
    for method in common_methods:
        try:
            decoded = decode_text(input_text, method)
            if decoded and not decoded.startswith("Error"):
                method_var.set(method)
                messagebox.showinfo("Detected", f"Detected as {method}")
                return
        except:
            pass
    messagebox.showinfo("Not Detected", "Could not detect codec")

def add_to_history(inp, out, meth):
    global current_history_index
    history.append({'input': inp, 'output': out, 'method': meth})
    if len(history) > max_history:
        history.pop(0)
    current_history_index = len(history) - 1
    update_history_display()

def update_history_display():
    history_box.delete("1.0", tk.END)
    for i, entry in enumerate(history):
        history_box.insert(tk.END, f"{i+1}. {entry['method']}: {entry['output'][:50]}...\n")

def undo():
    global current_history_index
    if current_history_index > 0:
        current_history_index -= 1
        entry = history[current_history_index]
        input_box.delete("1.0", tk.END)
        input_box.insert(tk.END, entry['input'])
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, entry['output'])
        method_var.set(entry['method'])

def redo():
    global current_history_index
    if current_history_index < len(history) - 1:
        current_history_index += 1
        entry = history[current_history_index]
        input_box.delete("1.0", tk.END)
        input_box.insert(tk.END, entry['input'])
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, entry['output'])
        method_var.set(entry['method'])

# Method selection
method_frame = tk.Frame(root)
method_frame.pack()
tk.Label(method_frame, text="Select Method:").pack(side=tk.LEFT)
search_var = tk.StringVar()
search_entry = tk.Entry(method_frame, textvariable=search_var)
search_entry.pack(side=tk.LEFT)
search_entry.bind('<KeyRelease>', lambda e: filter_methods())
method_var = tk.StringVar(value='Base64')
method_menu_button = tk.Menubutton(method_frame, textvariable=method_var, indicatoron=True)
method_menu_button.pack(side=tk.LEFT)
star_button = tk.Button(method_frame, text="☆", command=toggle_favorite)
star_button.pack(side=tk.LEFT)

main_menu = tk.Menu(method_menu_button, tearoff=0)
method_menu_button['menu'] = main_menu

categories = {
    "Common / Frequently Used": ["Base64", "Base32", "Base36", "Base45", "Base58", "Base58Check", "Base62", "Base85", "Base91", "Ascii85", "Z85", "Hex", "ASCII", "UTF-8", "UTF-16", "UTF-32", "Unicode", "Quoted-Printable", "Punycode", "HTML Entities"],
    "Serialization Formats": ["Bencode", "MessagePack", "CBOR", "S-Expressions"],
    "Security / Cryptography": ["JWT Signed", "JWT Decode", "Fernet", "DES", "AES", "RSA", "Whirlpool", "Armor64"],
    "Media / Special": ["QR Code", "Bech32", "BinHex", "Base65536", "Base128"],
    "Fun / Obscure": [
        "ROT13", "ROT47", "Emoji Encoding", "Binary-to-Music", "Morse Code", "Braille Encoding", "Binary", "URL",
        "Atbash Cipher", "Caesar Cipher", "Vigenère Cipher", "Affine Cipher", "Playfair Cipher", "Rail Fence Cipher",
        "Polybius Square Cipher", "Tap Code Cipher", "XOR Cipher", "Leetspeak", "DNA Encoding", "Zalgo Text",
        "Soundex", "Brainfuck Encoder", "Gzip", "Zlib", "MD5", "SHA-1", "SHA-256", "SHA3-224", "SHA3-256", "SHA3-512",
        "RIPEMD160", "CRC32", "Emoji Sequences"
    ]
}

def filter_methods():
    query = search_var.get().lower()
    main_menu.delete(0, 'end')
    # Favorites first
    fav_methods = sorted([m for m in favorites if query in m.lower()])
    if fav_methods:
        fav_menu = tk.Menu(main_menu, tearoff=0)
        main_menu.add_cascade(label="Favorites", menu=fav_menu)
        for method in fav_methods:
            fav_menu.add_command(label=method, command=lambda m=method: method_var.set(m))
    for cat, methods in categories.items():
        filtered_methods = sorted([m for m in methods if query in m.lower() and m not in favorites])
        if filtered_methods:
            cat_menu = tk.Menu(main_menu, tearoff=0)
            main_menu.add_cascade(label=cat, menu=cat_menu)
            for method in filtered_methods:
                cat_menu.add_command(label=method, command=lambda m=method: method_var.set(m))

def toggle_favorite():
    method = method_var.get()
    if method in favorites:
        favorites.remove(method)
        star_button.config(text="☆")
    else:
        favorites.add(method)
        star_button.config(text="★")
    filter_methods()

# Input
tk.Label(root, text="Input:").pack()
input_frame = tk.Frame(root)
input_frame.pack()
input_scroll = tk.Scrollbar(input_frame)
input_scroll.pack(side=tk.RIGHT, fill=tk.Y)
input_box = tk.Text(input_frame, height=10, width=50, yscrollcommand=input_scroll.set)
input_box.pack(side=tk.LEFT)
input_scroll.config(command=input_box.yview)

input_button_frame = tk.Frame(root)
input_button_frame.pack()
paste_button = tk.Button(input_button_frame, text="Paste", command=paste_input)
paste_button.pack(side=tk.LEFT)

# Output
tk.Label(root, text="Output:").pack()
output_frame = tk.Frame(root)
output_frame.pack()
output_scroll = tk.Scrollbar(output_frame)
output_scroll.pack(side=tk.RIGHT, fill=tk.Y)
output_box = tk.Text(output_frame, height=10, width=50, yscrollcommand=output_scroll.set)
output_box.pack(side=tk.LEFT)
output_scroll.config(command=output_box.yview)

output_button_frame = tk.Frame(root)
output_button_frame.pack()
copy_button = tk.Button(output_button_frame, text="Copy", command=copy_output)
copy_button.pack(side=tk.LEFT)
save_button = tk.Button(output_button_frame, text="Save to File", command=save_output)
save_button.pack(side=tk.LEFT)
load_button = tk.Button(output_button_frame, text="Load from File", command=load_input)
load_button.pack(side=tk.LEFT)

batch_var = tk.StringVar(value="single")
tk.Label(root, text="Batch Mode:").pack()
batch_frame = tk.Frame(root)
batch_frame.pack()
tk.Radiobutton(batch_frame, text="Single", variable=batch_var, value="single").pack(side=tk.LEFT)
tk.Radiobutton(batch_frame, text="Multi-line", variable=batch_var, value="multiline").pack(side=tk.LEFT)
tk.Radiobutton(batch_frame, text="Multi-file", variable=batch_var, value="multifile").pack(side=tk.LEFT)

# Buttons
button_frame = tk.Frame(root)
button_frame.pack()

def encode():
    input_text = input_box.get("1.0", tk.END).strip()
    method = method_var.get()
    batch = batch_var.get()
    if batch == "single":
        result = encode_text(input_text, method)
    elif batch == "multiline":
        lines = input_text.split('\n')
        results = [encode_text(line, method) for line in lines]
        result = '\n'.join(results)
    elif batch == "multifile":
        file_paths = filedialog.askopenfilenames(filetypes=[("All files", "*.*")])
        results = []
        for path in file_paths:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                encoded = encode_text(content, method)
                results.append(f"{path}: {encoded}")
            except Exception as e:
                results.append(f"{path}: Error {e}")
        result = '\n'.join(results)
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, result)
    add_to_history(input_text, result, method)

def decode():
    input_text = input_box.get("1.0", tk.END).strip()
    method = method_var.get()
    batch = batch_var.get()
    if batch == "single":
        result = decode_text(input_text, method)
    elif batch == "multiline":
        lines = input_text.split('\n')
        results = [decode_text(line, method) for line in lines]
        result = '\n'.join(results)
    elif batch == "multifile":
        file_paths = filedialog.askopenfilenames(filetypes=[("All files", "*.*")])
        results = []
        for path in file_paths:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                decoded = decode_text(content, method)
                results.append(f"{path}: {decoded}")
            except Exception as e:
                results.append(f"{path}: Error {e}")
        result = '\n'.join(results)
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, result)
    add_to_history(input_text, result, method)

def clear():
    input_box.delete("1.0", tk.END)
    output_box.delete("1.0", tk.END)

tk.Button(button_frame, text="Encode", command=encode).pack(side=tk.LEFT)
tk.Button(button_frame, text="Decode", command=decode).pack(side=tk.LEFT)
tk.Button(button_frame, text="Clear", command=clear).pack(side=tk.LEFT)
detect_button = tk.Button(button_frame, text="Detect", command=detect_codec)
detect_button.pack(side=tk.LEFT)

tk.Label(root, text="History:").pack()
history_frame = tk.Frame(root)
history_frame.pack()
history_scroll = tk.Scrollbar(history_frame)
history_scroll.pack(side=tk.RIGHT, fill=tk.Y)
history_box = tk.Text(history_frame, height=5, width=50, yscrollcommand=history_scroll.set)
history_box.pack(side=tk.LEFT)
history_scroll.config(command=history_box.yview)

history_button_frame = tk.Frame(root)
history_button_frame.pack()
undo_button = tk.Button(history_button_frame, text="Undo", command=undo)
undo_button.pack(side=tk.LEFT)
redo_button = tk.Button(history_button_frame, text="Redo", command=redo)
redo_button.pack(side=tk.LEFT)

def copy_output():
    output = output_box.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(output)

def paste_input():
    try:
        pasted = root.clipboard_get()
        input_box.delete("1.0", tk.END)
        input_box.insert(tk.END, pasted)
    except:
        pass

def save_output():
    output = output_box.get("1.0", tk.END).strip()
    if not output:
        messagebox.showerror("Error", "No output to save")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(output)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

def load_input():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            input_box.delete("1.0", tk.END)
            input_box.insert(tk.END, content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")

def detect_codec():
    input_text = input_box.get("1.0", tk.END).strip()
    if not input_text:
        messagebox.showerror("Error", "No input to detect")
        return
    # Try common decodes
    common_methods = ['Base64', 'Hex', 'Base32', 'Base58', 'Base85', 'Quoted-Printable', 'ROT13', 'Binary']
    for method in common_methods:
        try:
            decoded = decode_text(input_text, method)
            if decoded and not decoded.startswith("Error"):
                method_var.set(method)
                messagebox.showinfo("Detected", f"Detected as {method}")
                return
        except:
            pass
    messagebox.showinfo("Not Detected", "Could not detect codec")

def add_to_history(inp, out, meth):
    global current_history_index
    history.append({'input': inp, 'output': out, 'method': meth})
    if len(history) > max_history:
        history.pop(0)
    current_history_index = len(history) - 1
    update_history_display()

def update_history_display():
    history_box.delete("1.0", tk.END)
    for i, entry in enumerate(history):
        history_box.insert(tk.END, f"{i+1}. {entry['method']}: {entry['output'][:50]}...\n")

def undo():
    global current_history_index
    if current_history_index > 0:
        current_history_index -= 1
        entry = history[current_history_index]
        input_box.delete("1.0", tk.END)
        input_box.insert(tk.END, entry['input'])
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, entry['output'])
        method_var.set(entry['method'])

def redo():
    global current_history_index
    if current_history_index < len(history) - 1:
        current_history_index += 1
        entry = history[current_history_index]
        input_box.delete("1.0", tk.END)
        input_box.insert(tk.END, entry['input'])
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, entry['output'])
        method_var.set(entry['method'])

filter_methods()

root.mainloop()
