using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {

        public static bool IsSubString(string str1, string str2)
        {
            string cleanStr1 = str1.TrimEnd('-');
            string cleanStr2 = str2.TrimEnd('-');
            string tmp = str1.Substring(1);


            if (string.IsNullOrEmpty(cleanStr1) || string.IsNullOrEmpty(cleanStr2))
            {
                return false; //don't compare with nothing
            }
            if (cleanStr1.Length >= str1.Length - 1 && cleanStr2.Length >= str2.Length - 1)  //don't compare aletter with a string
            {
                if (cleanStr1.Contains(cleanStr2) || cleanStr2.Contains(cleanStr1))
                {
                    return true;
                }
                else if (tmp.Contains(cleanStr2) || cleanStr2.Contains(tmp))
                {
                    return true;
                }
            }
            return false;

        }



        public List<int> Analyse(string plainText, string cipherText)
        {
            List<int> key = new List<int>();

            for (int cols = 2; cols <= plainText.Length / 2; cols++)
            {

                int rows = (int)Math.Ceiling((double)cipherText.Length / cols);

                char[,] plain_text = new char[rows, cols];
                string[] ciph_text = new string[cols];
                string[] cleanedplain = new string[cols];

                int plain_cnt = 0;

                // Initialize arrays
                for (int i = 0; i < cols; i++)
                {
                    cleanedplain[i] = "";
                    ciph_text[i] = "";
                }

                // Fill the plaintext matrix by row

                for (int i = 0; i < rows; i++)
                {
                    for (int j = 0; j < cols; j++)
                    {
                        if (plain_cnt < plainText.Length)
                            plain_text[i, j] = plainText[plain_cnt++];
                        else
                            plain_text[i, j] = '-';  // Padding

                    }

                }

                // Extract column-wise text from the plaintext matrix
                string colString = "";
                for (int j = 0; j < cols; j++)
                {
                    for (int i = 0; i < rows; i++)
                    {
                        if (plain_text[i, j] != '-')
                        {
                            colString += plain_text[i, j];
                        }
                    }
                }



                // Divide `colString` and `cipherText` into column-wise strings
                int index = 0, index2 = 0;
                for (int i = 0; i < cols; i++)
                {
                    for (int j = 0; j < rows; j++)
                    {
                        if (index < colString.Length)
                            cleanedplain[i] += colString[index++];
                        else
                            cleanedplain[i] += "-"; // Padding

                        if (index2 < cipherText.Length)
                            ciph_text[i] += cipherText[index2++];
                        else
                            ciph_text[i] += "-"; // Padding
                    }
                }

                // Compare cleanedplain with ciph_text 
                key.Clear();
                for (int i = 0; i < cleanedplain.Length; i++)
                {
                    for (int j = 0; j < ciph_text.Length; j++)
                    {
                        if (cleanedplain[i].ToUpper() == ciph_text[j].ToUpper() || IsSubString(cleanedplain[i].ToUpper(), ciph_text[j].ToUpper()))
                        {
                            key.Add(j + 1);
                            break; // Stop after finding the first match
                        }

                    }
                }

                //Console.WriteLine("\n Key: " + string.Join(", ", key));

                if (key.Count == cols)
                {
                    break;
                }
            }

            return key;

            //throw new NotImplementedException();
        }




        public string Decrypt(string cipherText, List<int> key)
        {
            int key_size = key.Count();
            int rows = (int)Math.Ceiling((double)cipherText.Length / key_size);

            char[,] cols = new char[rows, key_size];
            List<int> sorted_key = new List<int>(key);
            sorted_key.Sort();
            string plain_txt = "";

            int txt_cnt = 0;
            foreach (int col in sorted_key)
            {
                int origIndex = key.IndexOf(col);
                for (int i = 0; i < rows; i++)
                {
                    if (txt_cnt < cipherText.Length)
                    {
                        cols[i, origIndex] = cipherText[txt_cnt];
                        txt_cnt++;
                    }
                    else
                    {
                        cols[i, origIndex] = '-';
                    }
                }
            }

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < key_size; j++)
                {
                    if (cols[i, j] != '-')
                    {
                        plain_txt += cols[i, j];
                    }


                }
            }

            return plain_txt.ToString().ToUpper();


            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {

            plainText = plainText.Replace(" ", "");
            int key_size = key.Count();
            int rows = (int)Math.Ceiling((double)plainText.Length / key_size);


            char[,] cols = new char[rows, key_size];

            int txt_cnt = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < key_size; j++)
                {
                    if (txt_cnt < plainText.Length)
                    {
                        cols[i, j] = plainText[txt_cnt];
                        txt_cnt++;
                    }
                    else
                    {
                        cols[i, j] = '-';

                    }

                }
            }

            List<int> sorted_key = new List<int>(key);
            sorted_key.Sort();

            string cipher_txt = "";
            foreach (int col in sorted_key)
            {
                int origIndex = key.IndexOf(col);
                for (int i = 0; i < rows; i++)
                {
                    if (cols[i, origIndex] != '-')
                    {
                        cipher_txt += cols[i, origIndex];
                    }
                }
            }
            return cipher_txt.ToString().ToUpper();

            //throw new NotImplementedException();
        }
    }
}
