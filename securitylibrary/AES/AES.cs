using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        // Encryption
        readonly string[,] sbox = new string[,] {
            {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
            {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
            {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
            {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
            {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
            {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
            {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
            {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
            {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
            {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
            {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
            {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
            {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
            {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
            {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
            {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}};

        // Decryption
        readonly string[,] inverse_sbox = new string[,] {
            {"52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb"},
            {"7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb"},
            {"54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e"},
            {"08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25"},
            {"72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92"},
            {"6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84"},
            {"90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06"},
            {"d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b"},
            {"3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73"},
            {"96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e"},
            {"47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b"},
            {"fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4"},
            {"1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f"},
            {"60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef"},
            {"a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61"},
            {"17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"}};

        // MixColumns & Inverse MixColumns
        // Encryption
        readonly string[,] MixColumnFactor = new string[,]{
            {"02","03", "01", "01"},
            {"01","02", "03", "01"},
            {"01","01", "02", "03"},
            {"03","01", "01", "02"}
            };

        // Decryption
        readonly string[,] Inverse_MixColumnFactor = new string[,]{
            {"0E","0B", "0D", "09"},
            {"09","0E", "0B", "0D"},
            {"0D","09", "0E", "0B"},
            {"0B","0D", "09", "0E"}
            };

        public string[,] Rcon = new string[,]{
        {"01","02","04","08","10","20","40","80","1b","36"},
        {"00","00","00","00","00","00","00","00","00","00"},
        {"00","00","00","00","00","00","00","00","00","00"},
        {"00","00","00","00","00","00","00","00","00","00"}};

        public string[,] KeyExpansion(string key)
        {
            int Nk = 4; // Number of columns in the original key
            int Nr = 10; // Number of rounds
            int Nb = 4; // Number of columns in each state

            // Convert key from hex to 4x4 array
            string[,] w = new string[4, Nb * (Nr + 1)];
            for (int i = 0; i < 16; i++)
            {
                w[i % 4, i / 4] = key.Substring(i * 2, 2);
            }

            for (int col = Nk; col < Nb * (Nr + 1); col++)
            {
                string[] temp = new string[4];
                for (int row = 0; row < 4; row++)
                    temp[row] = w[row, col - 1];

                if (col % Nk == 0)
                {
                    temp = RotWord(temp);
                    temp = SubWord(temp);
                    for (int row = 0; row < 4; row++)
                    {
                        string rcon = Rcon[row, (col / Nk) - 1];
                        temp[row] = XOR(temp[row], rcon);
                    }
                }

                for (int row = 0; row < 4; row++)
                {
                    w[row, col] = XOR(w[row, col - Nk], temp[row]);
                }
            }

            return w;
        }

        private string[] RotWord(string[] word)
        {
            return new string[] { word[1], word[2], word[3], word[0] };
        }

        private string[] SubWord(string[] word)
        {
            for (int i = 0; i < 4; i++)
            {
                int row = Convert.ToInt32(word[i][0].ToString(), 16);
                int col = Convert.ToInt32(word[i][1].ToString(), 16);
                word[i] = sbox[row, col];
            }
            return word;
        }

        private string XOR(string a, string b)
        {
            int aa = Convert.ToInt32(a, 16);
            int bb = Convert.ToInt32(b, 16);
            return (aa ^ bb).ToString("X2");
        }

        public string[,] SubBytes(string[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int row = Convert.ToInt32(state[i, j][0].ToString(), 16);
                    int col = Convert.ToInt32(state[i, j][1].ToString(), 16);
                    state[i, j] = sbox[row, col];
                }
            }
            return state;
        }

        public string[,] ShiftRows(string[,] state)
        {
            string[,] temp = new string[4, 4];

            // First row stays the same
            for (int col = 0; col < 4; col++)
                temp[0, col] = state[0, col];

            // Second row shifts left by 1
            for (int col = 0; col < 4; col++)
                temp[1, col] = state[1, (col + 1) % 4];

            // Third row shifts left by 2
            for (int col = 0; col < 4; col++)
                temp[2, col] = state[2, (col + 2) % 4];

            // Fourth row shifts left by 3
            for (int col = 0; col < 4; col++)
                temp[3, col] = state[3, (col + 3) % 4];

            return temp;
        }

        // FIXED: Enhanced GFMultiply to handle all multiplication factors
        private string GFMultiply(string hex, string factor)
        {
            int a = Convert.ToInt32(hex, 16);
            int b = Convert.ToInt32(factor, 16);
            int result = 0;

            // Handle simple cases
            if (b == 0x01)
            {
                return hex; // Multiplication by 1 is identity
            }

            // General case using polynomial multiplication in GF(2^8)
            while (b > 0)
            {
                if ((b & 1) != 0)    // If rightmost bit of b is 1
                    result ^= a;     // XOR with the current value of a

                // Check if leftmost bit of a is 1 (would overflow in next shift)
                bool highBitSet = (a & 0x80) != 0;

                // Shift a left by 1 (multiply by x)
                a <<= 1;

                // If high bit was set, XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
                if (highBitSet)
                    a ^= 0x1B;

                // Keep a in bounds of byte
                a &= 0xFF;

                // Shift b right by 1 for next iteration
                b >>= 1;
            }

            return result.ToString("X2");
        }

        public string[,] MixColumns(string[,] state)
        {
            string[,] mixedState = new string[4, 4];
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    mixedState[row, col] = MixColumnElement(state, row, col);
                }
            }
            return mixedState;
        }

        private string MixColumnElement(string[,] state, int row, int col)
        {
            string result = "00";
            for (int i = 0; i < 4; i++)
            {
                string multiplier = MixColumnFactor[row, i];
                string value = state[i, col];
                string product = GFMultiply(value, multiplier);
                result = XOR(result, product);
            }
            return result;
        }

        public string[,] AddRoundKey(string[,] state, string[,] roundKey)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = XOR(state[i, j], roundKey[i, j]);
                }
            }
            return state;
        }

        private static byte[] HexStringToBytes(string hex)
        {
            if (hex.Length % 2 != 0)
                throw new ArgumentException("The hex string must have an even length.");

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        private static string BytesToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        private string[,] GetRoundKey(string[,] roundKeys, int round)
        {
            string[,] roundKey = new string[4, 4];
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    roundKey[row, col] = roundKeys[row, round * 4 + col];
                }
            }
            return roundKey;
        }

        private string[,] InverseShiftRows(string[,] state)
        {
            string[,] temp = new string[4, 4];

            // First row stays the same
            for (int col = 0; col < 4; col++)
                temp[0, col] = state[0, col];

            // Second row shifts right by 1
            for (int col = 0; col < 4; col++)
                temp[1, col] = state[1, (col - 1 + 4) % 4];

            // Third row shifts right by 2
            for (int col = 0; col < 4; col++)
                temp[2, col] = state[2, (col - 2 + 4) % 4];

            // Fourth row shifts right by 3
            for (int col = 0; col < 4; col++)
                temp[3, col] = state[3, (col - 3 + 4) % 4];

            return temp;
        }

        private string[,] InverseSubBytes(string[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int row = Convert.ToInt32(state[i, j][0].ToString(), 16);
                    int col = Convert.ToInt32(state[i, j][1].ToString(), 16);
                    state[i, j] = inverse_sbox[row, col];
                }
            }
            return state;
        }

        private string[,] InverseMixColumns(string[,] state)
        {
            string[,] mixedState = new string[4, 4];
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    mixedState[row, col] = InverseMixColumnElement(state, row, col);
                }
            }
            return mixedState;
        }

        private string InverseMixColumnElement(string[,] state, int row, int col)
        {
            string result = "00";
            for (int i = 0; i < 4; i++)
            {
                string multiplier = Inverse_MixColumnFactor[row, i];
                string value = state[i, col];
                string product = GFMultiply(value, multiplier);
                result = XOR(result, product);
            }
            return result;
        }

        private static void ValidateKeyLength(byte[] key)
        {
            if (key.Length != 16)
            {
                throw new ArgumentException("The key length must be 16 bytes (128 bits).");
            }
        }

        public override string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.Replace("0x", "").ToUpper();
            key = key.Replace("0x", "").ToUpper();

            string[,] state = new string[4, 4];

            // Convert input to 4x4 matrix
            for (int i = 0; i < 16; i++)
            {
                state[i % 4, i / 4] = cipherText.Substring(i * 2, 2);
            }

            // Key expansion
            string[,] roundKeys = KeyExpansion(key);

            // Initial round - add the last round key
            state = AddRoundKey(state, GetRoundKey(roundKeys, 10));

            // Rounds 9 to 1 (reverse of encryption)
            for (int round = 9; round > 0; round--)
            {
                state = InverseShiftRows(state);
                state = InverseSubBytes(state);
                state = AddRoundKey(state, GetRoundKey(roundKeys, round));
                state = InverseMixColumns(state);
            }

            // Final round
            state = InverseShiftRows(state);
            state = InverseSubBytes(state);
            state = AddRoundKey(state, GetRoundKey(roundKeys, 0));

            // Convert matrix to plaintext
            StringBuilder plainText = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plainText.Append(state[j, i]);
                }
            }

            return "0x" + plainText.ToString().ToUpper();
        }

        public override string Encrypt(string plainText, string key)
        {
            plainText = plainText.Replace("0x", "").ToUpper();
            key = key.Replace("0x", "").ToUpper();

            string[,] state = new string[4, 4];

            // Convert input to 4x4 matrix
            for (int i = 0; i < 16; i++)
            {
                state[i % 4, i / 4] = plainText.Substring(i * 2, 2);
            }

            // Key expansion
            string[,] roundKeys = KeyExpansion(key);

            // Initial round - add the first round key
            state = AddRoundKey(state, GetRoundKey(roundKeys, 0));

            // Main rounds
            for (int round = 1; round < 10; round++)
            {
                state = SubBytes(state);
                state = ShiftRows(state);
                state = MixColumns(state);
                state = AddRoundKey(state, GetRoundKey(roundKeys, round));
            }

            // Final round
            state = SubBytes(state);
            state = ShiftRows(state);
            state = AddRoundKey(state, GetRoundKey(roundKeys, 10));

            // Convert matrix to ciphertext
            StringBuilder cipherText = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    cipherText.Append(state[j, i]);
                }
            }

            return "0x" + cipherText.ToString().ToUpper();
        }

        public static string[,] EncShiftLeft(string[,] M)
        {
            for (int r = 1; r < 4; r++)
            {
                for (int c = 0; c < r; c++)
                {
                    string temp = M[r, 0];
                    M[r, 0] = M[r, 1];
                    M[r, 1] = M[r, 2];
                    M[r, 2] = M[r, 3];
                    M[r, 3] = temp;
                }
            }
            return M;
        }

        public static string[,] DecShiftRight(string[,] M)
        {
            for (int r = 1; r < 4; r++)
            {
                for (int c = 0; c < r; c++)
                {
                    string temp = M[r, 3];
                    M[r, 3] = M[r, 2];
                    M[r, 2] = M[r, 1];
                    M[r, 1] = M[r, 0];
                    M[r, 0] = temp;
                }
            }
            return M;
        }
    }
}