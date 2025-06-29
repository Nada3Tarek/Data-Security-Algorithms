using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES des = new DES();
            //decrypt encrypt decrypt
            string key1 = key[0];
            string key2 = key[1];
            string key3;
            if (key.Count == 3)
            {
                key3 = key[2];
            }
            else
            {
                key3 = key[0];
            }
            string dec = des.Decrypt(cipherText, key1);
            string enc = des.Encrypt(dec, key2);
            string final = des.Decrypt(enc, key3);
            return final;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES des = new DES();
            //encrypt decrypt encrypt 
            string key1 = key[0];
            string key2 = key[1];
            string key3;
            if (key.Count == 3)
            {
                key3 = key[2];
            }
            else
            {
                key3 = key[0];
            }
            string enc = des.Encrypt(plainText, key1);
            string dec = des.Decrypt(enc, key2);
            string final = des.Encrypt(dec, key3);
            return final;
            //throw new NotImplementedException();
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
