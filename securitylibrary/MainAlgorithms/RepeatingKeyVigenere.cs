using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            StringBuilder key = new StringBuilder();

            for (int i = 0; i < plainText.Length; i++)
            {
                //nkhly hrof fe range 0-25 ASCII
                int plain1 = char.ToUpper(plainText[i]) - 65;
                int cipher1 = char.ToUpper(cipherText[i]) - 65;
                int keyChar = (cipher1 - plain1 + 26) % 26;
                key.Append((char)(65 + keyChar));
            }

            for (int len = 1; len <= key.Length; len++)
            {
                string potentialKey = key.ToString().Substring(0, len);
                string checking = Encrypt(plainText, potentialKey);

                if (checking.Equals(cipherText))
                {
                    return potentialKey;
                }
            }
            return key.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            StringBuilder plain_text = new StringBuilder();
            StringBuilder new_key = new StringBuilder();

            for (int i = 0; i < cipherText.Length; i++)
            {
                new_key.Append(key[i % key.Length]);
            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                //nkhly hrof fe range 0-25 ASCII
                int cipher1 = char.ToUpper(cipherText[i]) - 65;
                int key1 = char.ToUpper(new_key[i]) - 65;
                int decrypt1 = (cipher1 - key1 + 26) % 26;
                plain_text.Append((char)(65 + decrypt1));
            }
            return plain_text.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            StringBuilder cipher_text = new StringBuilder();
            StringBuilder new_key = new StringBuilder();

            for (int i = 0; i < plainText.Length; i++)
            {
                new_key.Append(key[i % key.Length]);
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                //nkhly hrof fe range 0-25 ASCII
                int plain1 = char.ToUpper(plainText[i]) - 65;
                int key1 = char.ToUpper(new_key[i]) - 65;
                int encrypt1 = (plain1 + key1) % 26;
                cipher_text.Append((char)(65 + encrypt1));
            }
            return cipher_text.ToString();
        }
    }
}