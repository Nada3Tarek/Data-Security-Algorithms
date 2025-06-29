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
    public class DES : CryptographicTechnique
    {
        public static int[] PC_1 = {
                                    57, 49, 41, 33, 25, 17, 9,
                                    1, 58, 50, 42, 34, 26, 18,
                                    10, 2, 59, 51, 43, 35, 27,
                                    19, 11, 3, 60, 52, 44, 36,
                                    63, 55, 47, 39, 31, 23, 15,
                                    7, 62, 54, 46, 38, 30, 22,
                                    14, 6, 61, 53, 45, 37, 29,
                                    21, 13, 5, 28, 20, 12, 4
                                   };
        public static int[] PC_2 = {
                                    14, 17, 11, 24, 1, 5,
                                    3, 28, 15, 6, 21, 10,
                                    23, 19, 12, 4, 26, 8,
                                    16, 7, 27, 20, 13, 2,
                                    41, 52, 31, 37, 47, 55,
                                    30, 40, 51, 45, 33, 48,
                                    44, 49, 39, 56, 34, 53,
                                    46, 42, 50, 36, 29, 32
                                  };
        public static int[] permutationTable = {
                                    58, 50, 42, 34, 26, 18, 10, 2,
                                    60, 52, 44, 36, 28, 20, 12, 4,
                                    62, 54, 46, 38, 30, 22, 14, 6,
                                    64, 56, 48, 40, 32, 24, 16, 8,
                                    57, 49, 41, 33, 25, 17, 9, 1,
                                    59, 51, 43, 35, 27, 19, 11, 3,
                                    61, 53, 45, 37, 29, 21, 13, 5,
                                    63, 55, 47, 39, 31, 23, 15, 7
                                };
        public static int[] inverseIP = {
                                    40, 8, 48, 16, 56, 24, 64, 32,
                                    39, 7, 47, 15, 55, 23, 63, 31,
                                    38, 6, 46, 14, 54, 22, 62, 30,
                                    37, 5, 45, 13, 53, 21, 61, 29,
                                    36, 4, 44, 12, 52, 20, 60, 28,
                                    35, 3, 43, 11, 51, 19, 59, 27,
                                    34, 2, 42, 10, 50, 18, 58, 26,
                                    33, 1, 41, 9, 49, 17, 57, 25
                                };
        public static int[] expansionTable = {
                                    32, 1, 2, 3, 4, 5,
                                    4, 5, 6, 7, 8, 9,
                                    8, 9, 10, 11, 12, 13,
                                    12, 13, 14, 15, 16, 17,
                                    16, 17, 18, 19, 20, 21,
                                    20, 21, 22, 23, 24, 25,
                                    24, 25, 26, 27, 28, 29,
                                    28, 29, 30, 31, 32, 1
                                };
        public static int[,,] sbox =
                {
                    {
                        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
                    },
                    {
                        { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
                        { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
                        { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
                        { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
                    },
                    {
                        { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
                        { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
                        { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
                        { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
                    },
                    {
                        { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
                        { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
                        { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
                        { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
                    },
                    {
                        { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
                        { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
                        { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
                        { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
                    },
                    {
                        { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
                        { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
                        { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
                        { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
                    },
                    {
                        { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                        { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                        { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                        { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
                    },
                    {
                        { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
                        { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
                        { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
                        { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
                    }
            };
        public static int[] sbox_permutation = {
                                                16, 7, 20, 21,
                                                29, 12, 28, 17,
                                                1, 15, 23, 26,
                                                5, 18, 31, 10,
                                                2, 8, 24, 14,
                                                32, 27, 3, 9,
                                                19, 13, 30, 6,
                                                22, 11, 4, 25
                                            };

        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string binKey = PC1(HexToBinary(key));
            string binCipher = Permute(HexToBinary(cipherText));
            string left = binCipher.Substring(0, 32);
            string right = binCipher.Substring(32, 32);
            string[] keyArr = new string[17];
            string subKey = binKey;
            for (int i = 1; i <= 16; i++)
            {
                subKey = GenerateSubKey(subKey, i);
                keyArr[i] = subKey;
            }
            for (int i = 16; i >= 1; i--)
            {
                string expandedRight = ExpandRightPart(PC2(keyArr[i]), right);
                string sBoxed = PermuteAfterSBox(SBox(expandedRight));
                string new_R = XOR(left, sBoxed);
                left = right;
                right = new_R;
            }
            return BinaryToHex(InversePermute(right + left));
        }
        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string binKey = PC1(HexToBinary(key));
            string binText = Permute(HexToBinary(plainText));
            string left = binText.Substring(0, 32);
            string right = binText.Substring(32, 32);
            string subKey = binKey;
            for (int i = 1; i <= 16; i++)
            {
                subKey = GenerateSubKey(subKey, i);
                string permutedTwo = PC2(subKey);
                string expandedRight = ExpandRightPart(permutedTwo, right);
                string sBoxed = PermuteAfterSBox(SBox(expandedRight));
                string new_R = XOR(left, sBoxed);
                left = right;
                right = new_R;
            }
            return BinaryToHex(InversePermute(right + left));
        }
        public static string PC1(string key)
        {
            string permuted = "";
            for (int i = 0; i < PC_1.Length; i++)
            {
                int keyIndex = PC_1[i] - 1;
                permuted += key[keyIndex];
            }
            return permuted;
        }
        public static string PC2(string key)
        {
            string permuted = "";
            for (int i = 0; i < PC_2.Length; i++)
            {
                int subKeyIndex = PC_2[i] - 1;
                permuted += key[subKeyIndex];
            }
            return permuted;
        }
        public static string HexToBinary(string hex)
        {
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                hex = hex.Substring(2);
            string bin = "";
            Dictionary<char, string> hexToBin = new Dictionary<char, string>
            {
            {'0', "0000"}, {'1', "0001"}, {'2', "0010"}, {'3', "0011"},
            {'4', "0100"}, {'5', "0101"}, {'6', "0110"}, {'7', "0111"},
            {'8', "1000"}, {'9', "1001"}, {'A', "1010"}, {'B', "1011"},
            {'C', "1100"}, {'D', "1101"}, {'E', "1110"}, {'F', "1111"}
            };
            for (int i = 0; i < hex.Length; i++)
            {
                char x = hex[i];
                bin += hexToBin[x];
            }
            return bin;
        }
        public static string BinaryToHex(string bin)
        {
            string hex = "";
            Dictionary<string, char> binToHex = new Dictionary<string, char>
            {
            {"0000", '0'}, {"0001", '1'}, {"0010", '2'}, {"0011", '3'},
            {"0100", '4'}, {"0101", '5'}, {"0110", '6'}, {"0111", '7'},
            {"1000", '8'}, {"1001", '9'}, {"1010", 'A'}, {"1011", 'B'},
            {"1100", 'C'}, {"1101", 'D'}, {"1110", 'E'}, {"1111", 'F'}
            };
            while (bin.Length % 4 != 0)
            {
                bin = "0" + bin;
            }
            for (int i = 0; i < bin.Length; i += 4)
            {
                string bits = bin.Substring(i, 4);
                if (binToHex.ContainsKey(bits))
                    hex += binToHex[bits];
            }
            return "0x" + hex.ToString();
        }
        public static string XOR(string binary1, string binary2)
        {
            if (binary1.Length != binary2.Length)
                return "-1";

            char[] xorResult = new char[binary1.Length];
            for (int i = 0; i < binary1.Length; i++)
            {
                if (binary1[i] == binary2[i])
                    xorResult[i] = '0';
                else
                    xorResult[i] = '1';
            }
            return new string(xorResult);
        }
        public static string ExpandRightPart(string permutedTwo, string inputBits)
        {
            string expandedBits = "";
            for (int i = 0; i < expansionTable.Length; i++)
            {
                expandedBits += inputBits[expansionTable[i] - 1];
            }
            return XOR(expandedBits, permutedTwo);
        }
        public static string PermuteAfterSBox(string permute)
        {
            string permuted = "";
            for (int i = 0; i < sbox_permutation.Length; i++)
            {
                permuted += permute[sbox_permutation[i] - 1];
            }
            return permuted;
        }
        public static string Permute(string key)
        {
            int size = permutationTable.Length;
            char[] permutedKey = new char[size];
            for (int i = 0; i < size; i++)
            {
                permutedKey[i] = key[permutationTable[i] - 1];
            }
            return new string(permutedKey);
        }
        public static string InversePermute(string cipherText)
        {
            // Convert binary string to ulong for bitwise operations
            ulong inp = Convert.ToUInt64(cipherText, 2);
            char[] permutedChars = new char[64];
            for (int h = 0; h < 64; h++)
            {
                // Get source position from inverse IP table (1-based to 0-based)
                int pos = inverseIP[h] - 1;
                int bit = (int)((inp >> (63 - pos)) & 0x01);
                permutedChars[h] = (char)(bit + '0');
            }
            return new string(permutedChars);
        }
        public static string GenerateSubKey(string permutedKey, int iter)
        {
            string subkey = "";
            //Second split into C and D(28 - bit each)
            string C = permutedKey.Substring(0, 28); //left Side
            string D = permutedKey.Substring(28, 28);//right side
            C = LeftCircularShift(C, iter);
            D = LeftCircularShift(D, iter);
            subkey = C + D;
            return subkey;
        }
        private static string LeftCircularShift(string input, int iterationNumber)
        {
            if (iterationNumber == 1 || iterationNumber == 2 ||
                iterationNumber == 9 || iterationNumber == 16)
            {
                // 1-bit shift for rounds 1, 2, 9, 16
                char firstBit = input[0];
                return input.Substring(1) + firstBit;
            }
            else
            {
                // 2-bit shift for other rounds
                string firstTwoBits = input.Substring(0, 2);
                return input.Substring(2) + firstTwoBits;
            }
        }
        public static string SBox(string inp)
        {
            StringBuilder res = new StringBuilder(32);
            for (int h = 0; h < 8; h++)
            {
                int bits = Convert.ToInt32(inp.Substring(h * 6, 6), 2);
                int r = ((bits & 0x20) >> 4) | (bits & 0x01);
                // first and last bits
                int c = (bits >> 1) & 0x0F;
                // the middle bits
                res.Append(Convert.ToString(sbox[h, r, c], 2).PadLeft(4, '0'));
            }
            return res.ToString();
        }
    }
}