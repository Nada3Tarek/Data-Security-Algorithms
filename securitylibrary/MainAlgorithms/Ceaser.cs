using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;



namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {//C = (index of P + key) mod 26
        public string Encrypt(string plainText, int key)
        {   //to store ciphertxt
            char[] arr = new char[plainText.Length];
            //loop in the plaintxt
            for (int i = 0; i < plainText.Length; i++)
            {     //each letter
                char x = plainText[i];
                //check if it is letter or not
                if (char.IsLetter(x))
                {//check if it is upper case or not
                    if (char.IsUpper(x))
                        //  get the letter of ciphertxt 
                        // (x - 'A') :convert x to number from 0 to 25
                        arr[i] = (char)('A' + (x - 'A' + key) % 26);
                    else
                        //  convert lowercase to uppercase
                        //  get the letter of ciphertxt 
                        arr[i] = (char)('A' + (x - 'a' + key) % 26);
                }
                else
                {//write as it
                    arr[i] = x;
                }
            }

            return new string(arr);
        }

        public string Decrypt(string cipherText, int key)
        {// to store plaintxt
            char[] arr = new char[cipherText.Length];
            //loop in the ciphertxt
            for (int i = 0; i < cipherText.Length; i++)
            { //each letter
                char x = cipherText[i];
                //check if it is letter or not
                if (char.IsLetter(x))
                {//check if it is upper case or not
                    if (char.IsUpper(x))
                        //  get the letter of plaintxt 
                        // (x - 'A') :convert x to number from 0 to 25
                        arr[i] = (char)('A' + (x - 'A' - key + 26) % 26);
                    else
                        //  get the letter of plaintxt
                        arr[i] = (char)('A' + (x - 'a' - key + 26) % 26); // Convert lowercase to uppercase
                }
                else
                {    //write as it
                    arr[i] = x;
                }
            }

            return new string(arr);
        }

        public int Analyse(string plainText, string cipherText)
        {  // get plaintxt len
            int size1 = plainText.Length;
            // get ciphertxt Len
            int size2 = cipherText.Length;
            //check if plainText or cipherText or size of them is empty or null
            if (string.IsNullOrEmpty(plainText) || string.IsNullOrEmpty(cipherText) || size1 != size2)
                return -1;
            //  Convert plaintxt to uppercase
            plainText = plainText.ToUpper();
            //  Convert ciphertxt to uppercase
            cipherText = cipherText.ToUpper();

            //key of the first letter[0] so we begin from 1 in for loop
            int key = (cipherText[0] - plainText[0] + 26) % 26;

            for (int i = 1; i < size1; i++)
            {    //to get key
                // (+26) to avoid negative results
                //(% 26) to make sure that the result range between 0 to 25 
                int currentKey = (cipherText[i] - plainText[i] + 26) % 26;
                //if currentKey != key,this means it is not ceaser
                if (currentKey != key)
                    return -1;
            }

            return key;
        }

    }
}

