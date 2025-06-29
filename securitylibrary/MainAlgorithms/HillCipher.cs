using System;
using System.Numerics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {


            //throw new NotImplementedException();
            // this funcion its purpose is to get the key 2*2 matrix that can convert this plaintext into this cipher text

            /*
             بسم الله توكلنا على الله ولا حول ولا قوة الا بالله
            استغفر الله و الحمدلله و سبحان الله  و الله اكبر
             
             */
            //first thing we will need to handle that if the list its size is mmore than 4 items
            // so in this case we will have 2 approaches the first one the sliding window technique but this will not give a correct output in special testcases
            // so we will use the another approach with taking all the combinations poosible in trying to find a matrix is invertable
            //so first we will need to divide each list into pairs
            // we will define list of pairs for each list .... the pair here is the same as tuple
            List<Tuple<int, int>> plainpairs = new List<Tuple<int, int>>();
            // because the pairs each one will have 2 items so we will need to check first that the size is even to get correct output
            if (plainText.Count % 2 != 0)
                throw new ArgumentException("The list must contain an even number of elements.");
            //other wise now we will convert the plaintext list into the pairs
            for (int i = 0; i < plainText.Count; i += 2)
            {
                plainpairs.Add(new Tuple<int, int>(plainText[i], plainText[i + 1]));
            }
            // and we will make the same thing for the cipher text we will divide it into pairs
            List<Tuple<int, int>> cipherpairs = new List<Tuple<int, int>>();
            // because the pairs each one will have 2 items so we will need to check first that the size is even to get correct output
            if (cipherText.Count % 2 != 0)
                throw new ArgumentException("The list must contain an even number of elements.");
            //other wise now we will convert the plaintext list into the pairs
            for (int i = 0; i < cipherText.Count; i += 2)
            {
                cipherpairs.Add(new Tuple<int, int>(cipherText[i], cipherText[i + 1]));
            }

            // now we will start taking each pair with all other next pairs to it
            int sizeee = cipherpairs.Count;
            for (int hola = 0; hola < sizeee - 1; hola++)
            {
                for (int bela = hola + 1; bela < sizeee; bela++)
                {
                    // in each iteration we will take the outer pair with the current inner pair
                    //define the 2 matrcies of the plain and for the cipher 
                    int[,] plainmatrix = new int[2, 2];
                    // now we will need to iterate over the list to fill this matrix with its values
                    plainmatrix[0, 0] = plainpairs[hola].Item1;        //first item in first pair 
                    plainmatrix[0, 1] = plainpairs[bela].Item1;      //first item in second pair
                    plainmatrix[1, 0] = plainpairs[hola].Item2;     //second item in first pair
                    plainmatrix[1, 1] = plainpairs[bela].Item2;    //second item in second pair
                    // make the same with the ciphertext
                    int[,] ciphermatrix = new int[2, 2];
                    ciphermatrix[0, 0] = cipherpairs[hola].Item1;        //first item in first pair 
                    ciphermatrix[0, 1] = cipherpairs[bela].Item1;      //first item in second pair
                    ciphermatrix[1, 0] = cipherpairs[hola].Item2;     //second item in first pair
                    ciphermatrix[1, 1] = cipherpairs[bela].Item2;    //second item in second pair
                                                                     // now calculating the determinant of the plainmatrix
                    int det = plainmatrix[0, 0] * plainmatrix[1, 1] - plainmatrix[0, 1] * plainmatrix[1, 0];
                    int finaldet = det % 26;
                    if (finaldet < 0)
                        finaldet += 26;

                    // Check if the plaintext matrix is invertible: finalDet must be nonzero and gcd(finalDet, 26) must equal 1.
                    int gcd = mygcd(finaldet, 26);
                    if (finaldet == 0 || gcd != 1)
                        continue; // try the another next 2 pairs
                    //otherwise it means this plainmatrix is invertable so i will now get its invertable
                    int temp = plainmatrix[1, 1];
                    plainmatrix[1, 1] = plainmatrix[0, 0];
                    plainmatrix[0, 0] = temp;
                    //second thing is to multiply -1 in this 2 indcies [0,1] and [1,0]
                    plainmatrix[0, 1] = plainmatrix[0, 1] * -1;
                    plainmatrix[1, 0] = plainmatrix[1, 0] * -1;
                    // this way to divide the 1 over finaldet is wrong because it always will give 0 cause of integer division so we can not use it 
                    /// finaldet = (1 / finaldet);
                    // to get the 1 over detmerninant we will use another way
                    int finalfinaldet = 0;
                    for (int x = 1; x < 26; x++)
                    {
                        if ((finaldet * x) % 26 == 1)
                        {
                            finalfinaldet = x;
                            break;
                        }
                    }
                    // now the last step is to iterate over this matrix and multiply each index with 1/det (finalfinaldet) and take the mod 26
                    for (int i = 0; i < 2; i++)
                    {
                        for (int h = 0; h < 2; h++)
                        {
                            plainmatrix[i, h] = finalfinaldet * plainmatrix[i, h];
                            plainmatrix[i, h] = plainmatrix[i, h] % 26;
                            if (plainmatrix[i, h] < 0)
                                plainmatrix[i, h] += 26;
                        }
                    }
                    // now we get the inverse matrix of the plaintext so
                    //now the final final step is to multiply the cipher matrix and the invertable plaintext matrix
                    int[,] keyMatrix = new int[2, 2];

                    for (int i = 0; i < 2; i++)
                    {
                        for (int j = 0; j < 2; j++)
                        {
                            int sum = 0;
                            for (int k = 0; k < 2; k++)
                            {
                                sum += ciphermatrix[i, k] * plainmatrix[k, j];
                            }
                            keyMatrix[i, j] = sum % 26;
                        }
                    }
                    // now converting this key matrix into list of integers

                    List<int> resultkey = new List<int>();

                    for (int i = 0; i < 2; i++)
                    {
                        for (int h = 0; h < 2; h++)
                        {
                            int item = keyMatrix[i, h];
                            resultkey.Add(item);
                        }

                    }
                    return resultkey;





                }
            }


            //otherwise if we finish all the combinations of pairs we can get and we do not find an invertable plaintext matrix so we will throw this exception
            throw new InvalidAnlysisException();

        }




        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<List<int>> keyMatrix = new List<List<int>>();
            int m = (int)Math.Sqrt(key.Count);
            //getting matrix shape from key
            for (int i = 0; i < m; i++)
            {
                keyMatrix.Add(new List<int>());
                for (int j = 0; j < m; j++)
                {
                    keyMatrix[i].Add(key[j + (i * m)]);
                }
            }
            //step 1-get deteriminant
            int det = Determinant(keyMatrix, m);
            int moddet = det % 26;
            if (moddet < 0) moddet += 26;

            //step 2 Calculate b = det(k)^-1 ==> ( b x det(k) mod 26 =1 )
            int b = -1;
            for (int i = 1; i < 26; i++)
            {
                if ((moddet * i) % 26 == 1)
                {
                    b = i;
                    break;
                }

            }
            int gcdd = mygcd(26, moddet);


            if (moddet == 0 || b == -1 || gcdd != 1)
            {

                throw new InvalidOperationException("invalidd");

            }
            // step 3 Apply rule kij ={b x (-1)i+j * Dij mod 26} mod 26
            List<List<int>> for_trans = new List<List<int>>();
            int sign = 1;
            for (int i = 0; i < m; i++)
            {
                for_trans.Add(new List<int>());
                for (int j = 0; j < m; j++)
                {
                    List<List<int>> submatrix = Get_submatrix(m, keyMatrix, i, j);
                    if ((i + j) % 2 == 0) sign = 1;
                    else sign = -1;
                    int x = (sign * Determinant(submatrix, m - 1)) % 26;
                    if (x < 0) x += 26;
                    int val = (b * x) % 26;
                    for_trans[i].Add(val);

                }
            }
            List<List<int>> Transpose = new List<List<int>>();
            //step 4 TRANSPOSE
            for (int i = 0; i < m; i++)
            {
                Transpose.Add(new List<int>());
                for (int j = 0; j < m; j++)
                {
                    Transpose[i].Add(for_trans[j][i]);
                }
            }

            //step 5 get plain text
            List<int> cipher = new List<int>(cipherText);
            List<int> final_plainText = new List<int>();
            for (int i = 0; i < cipherText.Count; i += m)
            {
                for (int j = 0; j < m; j++)
                {
                    int sum = 0;
                    for (int l = 0; l < m; l++)
                    {
                        if (i + l < cipherText.Count)
                        {

                            sum += cipher[i + l] * Transpose[l][j];

                        }
                    }
                    sum = sum % 26;

                    final_plainText.Add(sum);
                }
            }

            return final_plainText;
        }

        public int Determinant(List<List<int>> keyMatrix, int m)
        {
            if (m == 1) return keyMatrix[0][0];
            if (m == 2) return keyMatrix[0][0] * keyMatrix[1][1] - keyMatrix[0][1] * keyMatrix[1][0];

            int sign = 1;
            int det = 0;
            for (int i = 0; i < m; i++)
            {

                List<List<int>> submatrix = Get_submatrix(m, keyMatrix, i, 0);
                det += (sign) * keyMatrix[0][i] * Determinant(submatrix, m - 1);
                sign *= -1;

            }
            return det;
        }

        //get submatrix2 for skipping each row for step 3 for decryption
        public List<List<int>> Get_submatrix(int m, List<List<int>> keyMatrix, int startCol, int row)
        {
            int rowindex = 0;
            List<List<int>> sub_keyMatrix = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                if (row == i) continue;
                sub_keyMatrix.Add(new List<int>());
                for (int j = 0; j < m; j++)
                {
                    if (startCol == j) continue;
                    sub_keyMatrix[rowindex].Add(keyMatrix[i][j]);
                }
                rowindex++;
            }
            return sub_keyMatrix;
        }
        //NUM1 takes the bigger number
        int mygcd(int num1, int num2)
        {

            if (num2 == 0) return num1;
            else return mygcd(num2, num1 % num2);
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            Dictionary<char, int> mapping_letter = new Dictionary<char, int>();
            Dictionary<int, char> mapping_number = new Dictionary<int, char>();
            List<int> pt_to_num = new List<int>(plainText);
            List<int> final_plainText = new List<int>();

            int m = 0;
            for (int i = 0; i < 26; i++)
            {
                mapping_letter.Add((char)('A' + i), i);
                mapping_number.Add(i, (char)('A' + i));
            }
            m = (int)Math.Sqrt(key.Count);

            for (int i = 0; i < plainText.Count; i++)
            {
                if (plainText[i] == ' ')
                {
                    continue;
                }
                char text = char.ToUpper((char)plainText[i]);
                if (!mapping_letter.ContainsKey(text))
                {
                    continue;
                }
                pt_to_num.Add(mapping_letter[text]);
            }
            if (pt_to_num.Count % m != 0)
            {
                for (int i = 0; i < pt_to_num.Count % m; i++)
                {
                    pt_to_num.Add(mapping_letter['X']);
                }
            }
            //this is for the repeatition of the matrices with the rest of the plain text
            for (int i = 0; i < pt_to_num.Count; i += m)
            {
                for (int j = 0; j < m; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < m; k++)
                    {
                        if (i + k < pt_to_num.Count && j * m + k < key.Count)
                        {

                            sum += pt_to_num[i + k] * key[j * m + k];

                        }
                    }
                    sum = sum % 26;

                    final_plainText.Add(sum);
                }
            }
            return final_plainText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {

            int[,] plain_matrix = new int[3, 3];
            int[,] cipher_matrix = new int[3, 3];

            // fill matrices 
            int plaincnt = 0, ciphercnt = 0;
            for (int j = 0; j < 3; j++)
            {
                for (int i = 0; i < 3; i++)
                {
                    plain_matrix[i, j] = plainText[plaincnt++];
                    cipher_matrix[i, j] = cipherText[ciphercnt++];
                }
            }


            // compute determinant
            int det = ((plain_matrix[0, 0] * (plain_matrix[1, 1] * plain_matrix[2, 2] - plain_matrix[1, 2] * plain_matrix[2, 1]))
                      - (plain_matrix[0, 1] * (plain_matrix[1, 0] * plain_matrix[2, 2] - plain_matrix[1, 2] * plain_matrix[2, 0]))
                      + (plain_matrix[0, 2] * (plain_matrix[1, 0] * plain_matrix[2, 1] - plain_matrix[1, 1] * plain_matrix[2, 0]))) % 26;
            det = (det % 26 + 26) % 26;


            int GCD(int a, int b)
            {
                while (b != 0)
                {
                    int temp = b;
                    b = a % b;
                    a = temp;
                }
                return a;
            }

            int gcd = GCD(det, 26);
            if (det == 0 || gcd != 1)
            {
                return new List<int>(); // return empty list
            }

            // mod inv of determinant

            int mod_inv(int p)
            {
                for (int x = 1; x < 26; x++)
                {
                    if ((p * x) % 26 == 1)
                        return x;
                }
                return -1;
            }

            int inv = mod_inv(det);
            if (inv == -1)
            {
                return new List<int>();  // no mod inv found
            }

            // cofactor matrix
            int[,] adj = cofactors(plain_matrix);

            // then get the transpose
            int[,] trans = new int[3, 3];

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    trans[j, i] = adj[i, j];
                }
            }

            // multiply trans matrix by det inv with mod 26
            int[,] inverse_matrix = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    inverse_matrix[i, j] = (trans[i, j] * inv) % 26;
                    if (inverse_matrix[i, j] < 0)
                        inverse_matrix[i, j] += 26;
                }
            }

            // multiply cipher matrix with inv_matrix to get the key
            int[,] key_matrix = new int[3, 3];

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    key_matrix[i, j] = 0;
                    for (int x = 0; x < 3; x++)
                    {
                        key_matrix[i, j] += cipher_matrix[i, x] * inverse_matrix[x, j];
                    }
                    key_matrix[i, j] = (key_matrix[i, j] % 26 + 26) % 26;
                }
            }

            // convert key matrix to list
            List<int> key = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    key.Add(key_matrix[i, j]);
                }
            }

            return key;
            //throw new NotImplementedException();
        }



        int[,] cofactors(int[,] matrix)
        {
            int[,] adj = new int[3, 3];

            adj[0, 0] = (matrix[1, 1] * matrix[2, 2] - matrix[1, 2] * matrix[2, 1]);
            adj[0, 1] = (-(matrix[1, 0] * matrix[2, 2] - matrix[1, 2] * matrix[2, 0]));
            adj[0, 2] = (matrix[1, 0] * matrix[2, 1] - matrix[1, 1] * matrix[2, 0]);

            adj[1, 0] = (-(matrix[0, 1] * matrix[2, 2] - matrix[0, 2] * matrix[2, 1]));
            adj[1, 1] = (matrix[0, 0] * matrix[2, 2] - matrix[0, 2] * matrix[2, 0]);
            adj[1, 2] = (-(matrix[0, 0] * matrix[2, 1] - matrix[0, 1] * matrix[2, 0]));

            adj[2, 0] = (matrix[0, 1] * matrix[1, 2] - matrix[0, 2] * matrix[1, 1]);
            adj[2, 1] = (-(matrix[0, 0] * matrix[1, 2] - matrix[0, 2] * matrix[1, 0]));
            adj[2, 2] = (matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0]);
            //PrintMatrix(adj);

            // taking the mod
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    adj[i, j] = (adj[i, j] % 26 + 26) % 26;
                }
            }


            return adj;
        }

    }
}