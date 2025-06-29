using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public static int fun_Enc_Dec(int num, int pow, int mod)
        {
            int result = 1;
            for (int i = 0; i < pow; i++)
            {
                result = (result * num) % mod;
            }
            return result;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            // anyone can encrypt the message with public key (e, n)
            // Cipher = M^e mod n ---> n = p*q
            int n = p * q;
            int cipher = fun_Enc_Dec(M, e, n);
            return cipher;
        }
        public int Decrypt(int p, int q, int C, int e)
        {
            // only who have private key can decrypt (d, n)
            // Plain = C^d mod n ---> n = p*q
            // d = e^-1 mod (p-1*q-1)
            int n = p * q;
            int phi_n = (p - 1) * (q - 1);
            int d = new ExtendedEuclid().GetMultiplicativeInverse(e, phi_n);
            int message = fun_Enc_Dec(C, d, n);
            return message;
        }

    }
}
