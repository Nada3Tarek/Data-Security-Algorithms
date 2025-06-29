using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();

            int t = 0, newT = 1;
            int r = baseN, newR = number;

            while (newR != 0)
            {
                int quotient = r / newR;

                // تحديث t و r
                int tempT = t;
                t = newT;
                newT = tempT - quotient * newT;

                int tempR = r;
                r = newR;
                newR = tempR - quotient * newR;
            }

            if (r > 1)
            {
                return -1; // لا يوجد معامل عكسي
            }

            if (t < 0)
            {
                t = t + baseN;
            }

            return t;
        }
    }
}
