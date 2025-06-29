using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 
        // we will take this one from the RSA too to we will use it here in encryption
        public static long fun_Enc_Dec(int num, int pow, int mod)
        {
            long result = 1;
            for (int i = 0; i < pow; i++)
            {
                result = (result * num) % mod;
            }
            return result;
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //throw new NotImplementedException();
            //بسم الله الرحمن الرحيم 

            // c1 = alpha^k mod q
            long c1 = fun_Enc_Dec(alpha, k, q);

            // c2 = m * y^k mod q
            long c2 = (m * fun_Enc_Dec(y, k, q)) % q;

            return new List<long> { c1, c2 };

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {

            long s = Power(c1, x, q);  // s = c1^x mod q

            long sInv = modInv(s, q); // s -> s^(-1) mod q

            long plain = (c2 * sInv) % q;  // plain = (c2 * s^(-1)) mod q

            return (int)plain;
            //throw new NotImplementedException();

        }
public static int Power(int baseNum, int power, int mod)
        {
            int result = 1;
            for (int i = 0; i < power; i++)
            {
                result = (result * baseNum) % mod;
            }
            return result;
        }
        public static long modInv(long num, long mod)
        {
            long prevmod = mod;
            long a = 1;
            long b = 0;

            while (num > 1)
            {
                long q = num / mod;

                long tmp = mod;
                mod = num % mod;
                num = tmp;

                long temp2 = b;
                b = a - q * b;
                a = temp2;
            }

            if (a < 0)
                a += prevmod;

            return a;
        }
    }
}
