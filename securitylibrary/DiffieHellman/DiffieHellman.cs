using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {

        public static int Power(int baseNum, int power, int mod)
        {
            int result = 1;
            for (int i = 0; i < power; i++)
            {
                result = (result * baseNum) % mod;
            }
            return result;
        }


        // The idea is that two parties have different private keys,
        // and they want to agree on a shared secret key for data encryption,
        // without revealing their private keys to each other or anyone else.
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            //throw new NotImplementedException();

            // Compute public keys for both => A&B 
            int publicKeyA = Power(alpha, xa, q); // Public key for A => publicKeyA = alpha^xa % q
            int publicKeyB = Power(alpha, xb, q); // Public key for B => publicKeyB = alpha^xb % q

            // Derive shared secret keys using the other party's public key
            int sharedKeyA = Power(publicKeyB, xa, q); // A computes shared key => sharedKeyA = publicKeyB^xa % q
            int sharedKeyB = Power(publicKeyA, xb, q); // B computes shared key => sharedKeyB = publicKeyA^xb % q

            // Return both shared keys (should be equal to each other)
            return new List<int> { sharedKeyA, sharedKeyB };

        }
    }
}
