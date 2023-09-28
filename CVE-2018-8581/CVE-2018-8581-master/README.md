## CVE-2018-8581

这是一个邮箱层面的横向渗透和提权漏洞

它可以在拥有了一个普通权限邮箱账号密码后，完成对其他用户(包括域管理员)邮箱收件箱的委托接管

本EXP脚本是在[原PoC](https://github.com/thezdi/PoC/tree/master/CVE-2018-8581)基础上修改的增强版一键脚本，它将在配置好相关参数后，自动完成目标邮箱inbox收件箱的添加委托和删除委托操作，以方便甲方安全部门和红队对授权企业完成一次模拟攻击过程

原PoC是两个脚本配合使用完成添加收信规则的操作，在甲方红队实际工作中不怎么实用，而原PoC除了需要邮箱外，还需要设置目标邮箱用户的SID，但在参考[文章](https://www.zerodayinitiative.com/blog/2018/12/19/an-insincere-form-of-flattery-impersonating-users-on-microsoft-exchange)中提到的获取用户SID的方法，我在实际环境中测试Exchange Server 2010和2013版本中均未成功复现(2010无相关操作选项，2013会提示无权限操作)，最后我的思路是通过先完成一次反向委托来获取目标邮箱用户的SID再移除委托

### 如何使用

- 安装python-ntlm

  `pip install python-ntlm`

- 在脚本以下代码中进行相关参数配置

  ``` Python
  ...
  # Exchange server config
  IP = 'mail.target_domain.com'
  PORT = 443
  PROTO = 'https'
  # PORT = 80
  # PROTO = 'http'

  # CONTROLLED_EMAIL and TARGET_EMAIL config
  USER = 'the_email_u_have'
  DOMAIN = 'the_domain_name'
  PASS = 'password_of_the_email_u_have'

  TARGET_EMAIL = "the_target_email_u_want@target_domain.com"
  CONTROLLED_EMAIL = "the_email_u_have@target_domain"

  # FLAG == 1 --> AddDelegate, FLAG == 0 --> RemoveDelegate
  FLAG = 1

  # Exchange server version 
  # EXCHANGE_VERSION = "Exchange2010_SP1"
  EXCHANGE_VERSION = "Exchange2010_SP2"
  # EXCHANGE_VERSION = "Exchange2010_SP3"
  # EXCHANGE_VERSION = "Exchange2013"
  # EXCHANGE_VERSION = "Exchange2016"

  #Port and url of ur HTTP server that will use NTLM hashes for impersonation of TARGET_EMAIL
  HTTPPORT = 8080
  EVIL_HTTPSERVER_URL = "http://ur_http_server_ip:8080/"
  ...
  ```

- 运行脚本，然后喝口枸杞茶，等待一分钟

  ![img1](http://imglf4.nosdn.127.net/img/TnVEN1Q3NkoyR0pyTisrVjdxbVBtQnJwRERHR3Z2NUNkSWFWcktaWWRWb3UweEJhRU5maDdBPT0.jpg?=imageView&thumbnail=500x0&quality=96&stripmeta=0&type=jpg%7Cwatermark&type=2)

- 此时已成功将TARGET_EMAIL的inbox收件箱委托给CONTROLLED_EMAIL

- 在owa或者outlook中查看目标邮箱收件箱

  ![img2](http://imglf3.nosdn.127.net/img/TnVEN1Q3NkoyR0pyTisrVjdxbVBtSXRMV1c0Ni9aN0p1cUh5dEEzSzgvcVg1WXJHeEE4TjN3PT0.jpg?=imageView&thumbnail=500x0&quality=96&stripmeta=0&type=jpg%7Cwatermark&type=2)

- 将FLAG改为0，再次运行脚本，然后再次喝口枸杞茶，再次等待一分钟，即可移除之前添加的委托

  ![img3](http://imglf3.nosdn.127.net/img/TnVEN1Q3NkoyR0pyTisrVjdxbVBtQWc1cnZKRTZkT3ZqRDZxakFKNTA5bDd1c3JtVStPMllnPT0.jpg?=imageView&thumbnail=500x0&quality=96&stripmeta=0&type=jpg%7Cwatermark&type=2)

- 已无权限再次访问

### 适用环境

- Python 2.7.14

- Exchange Server 2010 (比较稳定，测试基本Exchange Server 2010都能成功)

- Exchange Server 2013 (环境差异可能失败)

- Exchange Server 2016 (环境差异可能失败)


### 更多

  更多EWS SOAP API请求可以在make_relay_body()函数内修改

  在尝试进一步利用中继Net-NTLM hash攻击其他不需SMB签名主机的实验中，发现获取到的hash都是ExchangeServer的...也许在ExchangeServer禁用SMB签名的情况下可以用来跨协议中继攻击ExchangeServer，不过这种情况基本上很难遇到...

### 说明

  脚本仅供学习交流使用，请使用者遵守当地相关法律，如作他用所承受的法律责任一概与作者无关，下载使用即代表使用者同意上述观点
