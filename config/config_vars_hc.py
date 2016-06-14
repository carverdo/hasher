HC_HASH_TYPE_DICT = {
    'MySQL': '300',
    'SHA-1 (Django)': '800',
    'MD5(Sun)': '3300',
    'md5(md5(md5($pass)))': '3500',
    'md5(md5($salt).$pass)': '3610',
    'md5($pass.md5($salt))': '3720',
    'md5($salt.$pass.$salt)': '3810',
    'md5(md5($pass).md5($salt))': '3910',
    'md5($salt.md5($salt.$pass))': '4010',
    'md5($salt.md5($pass.$salt))': '4110',
    'md5($username.0.$pass)': '4210',
    'md5(strtoupper(md5($pass)))': '4300',
    'sha1(sha1(sha1($pass)))': '4600',
    'Fortigate (FortiOS)': '7000',
    'Plaintext': '9999',
    'EPi': '123',
    'WebEdition CMD': '3721'
}
HC_CMD_SHORT_SWITCH = {
    'rules-file': 'r',
    'salt-file': 'e',
    'table-file': 't',
    'threads': 'n',
    'words-limit': 'l',
    'words-skip': 's'
}
HC_CMD_EQUAL_REQUIRED = [
    'perm-max',
    'perm-min',
    'pw-max',
    'pw-min',
    'table-max',
    'table-min',
    'toggle-max',
    'toggle-min'
]
HC_IGNORE_VARS = []
