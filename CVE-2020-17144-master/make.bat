@echo off
c:\windows\microsoft.net\framework\v3.5\csc /t:library e.cs
c:\windows\microsoft.net\framework\v3.5\csc /r:Microsoft.Exchange.WebServices.dll cve-2020-17144.cs