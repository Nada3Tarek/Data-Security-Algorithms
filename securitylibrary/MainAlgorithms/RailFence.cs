using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            for (int key = 2; key <= plainText.Length / 2; key++)
            {
                string encryptedText = Encrypt(plainText, key);
                if (encryptedText == cipherText)
                {
                    return key; // Found the correct key
                }
            }

            return -1;

        }

        //Dycreption using RailFence
        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();

            if (key <= 1) return cipherText;

            int rows = key;


            int cols = (cipherText.Length + key - 1) / key;

            char[,] rail = new char[rows, cols];

            int index = 0;
            for (int i = 0; i < rows; i++)
            {

                for (int j = 0; j < cols; j++)
                {

                    if (index < cipherText.Length)
                    {
                        rail[i, j] = cipherText[index];
                        index++;
                    }
                    else
                    {
                        rail[i, j] = ' ';
                    }

                }
            }

            StringBuilder originalText = new StringBuilder(); //dynamic string initialization

            //reading the matrix to get the original text
            for (int i = 0; i < cols; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    if (rail[j, i] != ' ')
                    {
                        originalText.Append(rail[j, i]);
                    }


                }

            }

            return originalText.ToString();


        }


        //Encryption using RailFence
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();

            if (key <= 1) return plainText;

            int rows = key;

            // First, remove spaces
            plainText = plainText.Replace(" ", "");

            int cols = (plainText.Length + key - 1) / key;

            char[,] rail = new char[rows, cols];

            //index of each letter in the string without including spaces
            int index = 0;

            for (int i = 0; i < cols; i++)
            {

                for (int j = 0; j < rows; j++)
                {

                    if (index < plainText.Length)
                    {
                        rail[j, i] = plainText[index];
                        index++;
                    }
                    else
                    {
                        rail[j, i] = ' ';
                    }

                }
            }

            StringBuilder cipherText = new StringBuilder(); //dynamic string initialization

            //reading the matrix to get the cipher text
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    if (rail[i, j] != ' ')

                    {
                        cipherText.Append(rail[i, j]);
                    }


                }

            }

            return cipherText.ToString().ToUpper(); ;
        }
    }
}
