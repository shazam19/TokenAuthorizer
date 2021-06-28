using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TokenAuthorizer.CustomAttribute
{
    [System.AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
    public class SzAttribute : Attribute
    {
        // See the attribute guidelines at 
        //  http://go.microsoft.com/fwlink/?LinkId=85236
        readonly string positionalString;

        // This is a positional argument
        public SzAttribute(string positionalString)
        {
            this.positionalString = positionalString;

            // TODO: Implement code here

            //throw new NotImplementedException();
        }

        /// <summary>
        /// test property in attribute
        /// </summary>
        public string PositionalString
        {
            get { return positionalString; }
        }

        // This is a named argument
        public int NamedInt { get; set; }
    }
}
