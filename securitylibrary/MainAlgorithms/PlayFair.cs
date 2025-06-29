using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Analyse(string largeCipher)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            //it was implemented by 5*5 2d matrix
            //return "";
            /* 
                                                                 إذا ذَبُلتْ بنا الأحلامُ يومًا
                                        سيحييها الذي يُحيي الرفَاتَ
                                                                  ويُجريها إذا ما شاء نهرًا
                                          يضاهي في عذوبته الفراتَ

             بسم الله توكلنا على الله يا رب سدد الخطى 
             */

            // we will make the same part of the code in the encryption 
            // creating the 5*5 matrix and fill it with the key first and then fill it with the rest of the letters

            // and we will need to make the same as key in checking that it doesnot have any special characters
            if (!cipherText.All(c => (c >= 'A' && c <= 'Z')))
            {
                throw new ArgumentException("Cipher text contains invalid characters.");
            }

            // there is another sepical case we need to handle it like key is empty or the cipher is empty
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentException("Key cannot be empty.");
            }

            if (string.IsNullOrWhiteSpace(cipherText))
            {
                throw new ArgumentException("Cipher text cannot be empty.");
            }

            // first declare the 5*5 matrix with static fixed size
            char[,] matrixx = new char[5, 5];
            // and define hashset to help me not putting duplicate characters in the matrix
            HashSet<char> currentchars = new HashSet<char>();
            // define the sandard string we will continue filling the matrix with it
            string allletters = "ABCDEFGHIKLMNOPQRSTUVWXYZ";// i just put the i and will treat j as i so i will not insert j
                                                            // now will ensure that the key is in upper case to sure that all things same
            key = key.ToUpper().Replace('J', 'I');

            // now we will iterating over this 2d matrix and start fill it with the key first
            int row = 0, col = 0;
            for (int i = 0; i < key.Length; i++)
            {
                // there is a special case that the key maybe have a letter not in the 26 english letters so we will terminate
                //and will not encrypt 
                if (key[i] < 'A' || key[i] > 'Z')
                {
                    throw new ArgumentException("Invalid character in the key. Only English letters are allowed.");
                }

                //now we need to know if it was added before or no 
                if (currentchars.Contains(key[i]) == false)//it means it is not found
                {
                    // so we will fill this index in the matrix with it 
                    matrixx[row, col] = key[i];
                    //and insert it in the hash set to prevent duplicate
                    currentchars.Add(key[i]);
                    // now we need to increase the indeces and handle if it is reaches to the end
                    col++;
                    // if col now be 5 so we will make it 0 and do to the next row
                    if (col == 5)
                    {
                        col = 0;
                        row++;
                    }
                }
            }

            //now after finishing the first part that we fill the matrix by the key letters we will need to fill it 
            // by the other remining english letters to start encrypt
            for (int i = 0; i < allletters.Length; i++)
            {
                // we will make the same steps that happened in the previous loop 

                if (currentchars.Contains(allletters[i]) == false)//it means it is not found
                {
                    // so we will fill this index in the matrix with it 
                    matrixx[row, col] = allletters[i];
                    //and insert it in the hash set to prevent duplicate
                    currentchars.Add(allletters[i]);
                    // now we need to increase the indeces and handle if it is reaches to the end
                    col++;
                    // if col now be 5 so we will make it 0 and do to the next row
                    if (col == 5)
                    {
                        col = 0;
                        row++;
                    }
                }
            }

            // now we will start decryption with the same opposite logic in the encryption part
            // first we will ensure that the cipher text is in the rules of we make it in the encryption
            cipherText = cipherText.ToUpper().Replace('J', 'I');
            // and define the string that we will return on it the original text 
            string result = "";
            // now iterate over the cipher to get each 2 characters to decrypt them 
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char first = cipherText[i];
                char second;
                if (i + 1 >= cipherText.Length)
                {
                    second = 'X';
                }
                else
                    second = cipherText[i + 1];

                // now we will need to check if the second char is added x in encryption
                // so we will know that if we find that i==i+2 if both are equal so that means second which is x will removed cause it is extra
                //we will need to check if we find 2 duplicated letters and between them letter x and x in odd index
                if (i + 2 < cipherText.Length &&cipherText[i] == cipherText[i + 2] && cipherText[i + 1] == 'X' && (i + 1) % 2 == 1)
                {
                 // if this condition happen we will need to check if this x in the middle is original or padding and that by comparing with i+3 index
                 if(i + 3 >= cipherText.Length || cipherText[i + 2] == cipherText[i + 3])
                  {
                        // so now we make sure that this x is padding was addes in the encryption so we will ignore it
                    second = cipherText[i + 2];
                    i++;  // Skip the extra X
                   }
                 //other wise we make sure that the letter x is original so we will make it as it is and convert it normally
                    
                }

                //now we get the 2 characters we will decrypt them we will need to get their indecies
                // we will make the same as we made in the encryption function
                int frow = -1, fcol = -1, srow = -1, scol = -1;
                bool foundFirst = false, foundSecond = false;

                for (int r = 0; r < 5; r++)
                {
                    for (int c = 0; c < 5; c++)
                    {
                        if (matrixx[r, c] == first)
                        {
                            frow = r;
                            fcol = c;
                            foundFirst = true;
                        }
                        if (matrixx[r, c] == second)
                        {
                            srow = r;
                            scol = c;
                            foundSecond = true;
                        }
                        if (foundFirst && foundSecond) break;
                    }
                    if (foundFirst && foundSecond) break;
                }

                // now we get the index we will use the matrix to get the corresponding characters of the original text
                // now the decryption will be the same of the encryption but in opposite
                if (frow == srow)//they are in the same row so  i will move one col step left
                {
                    fcol = (fcol + 4) % 5;
                    scol = (scol + 4) % 5;
                }
                else if (fcol == scol)// same col so we will move just one row step up 
                {
                    frow = (frow + 4) % 5;
                    srow = (srow + 4) % 5;
                }
                else// so that means they are make a rectangle so we will make the same right encryption 
                {
                    // just swap the columns
                    (fcol, scol) = (scol, fcol);
                }
                // now added this original letters and add them into the string result to return it
                result += matrixx[frow, fcol].ToString();
                result += matrixx[srow, scol].ToString();
            }

            // this part of code delete any extra x existed in the result
            string finalResult = "";
            for (int i = 0; i < result.Length; i++)
            {
                if (i > 0 && i < result.Length - 1 && result[i] == 'X' && result[i - 1] == result[i + 1] && i % 2 == 1)
                {
                    continue; // Skip this X (assumed artificial)
                }
                finalResult += result[i];
            }

            // Option 1: Remove trailing X only if you are sure it was padding.
            // Comment out the following if you're not sure:
            if (finalResult.Length > 1 && finalResult[finalResult.Length - 1] == 'X')
            {
                if (cipherText.Length % 2 == 1 || (finalResult.Length > 2 && finalResult[finalResult.Length - 2] != 'X'))
                {
                    finalResult = finalResult.Substring(0, finalResult.Length - 1);
                }
            }

            //Console.WriteLine("the ciphertext is : " + cipherText);
            //Console.WriteLine("the key is : " + key);

            Console.WriteLine("the finalResult is : "+ finalResult);

            return finalResult;
        }


        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            // بسم الله الرحمن الرحيم اللهم اني توكلت علك فانت خير وكيل اللهم دبر لي امري فانا لا احسن التدبير
            /*
                                     عمّال أبالغ في الأمل واليأس
                   يوم أزِف الفرحة زف
                                                    ويوم أعاني
                  يوم أقول الموت أخف
                                     ويوم مكانتش الدنيا سيعاني.

                         - فؤاد حداد.
             */

            // first declare the 5*5 matrix with static fixed size
            char[,] matrixx = new char[5, 5];
            // and define hashset to help me not putting duplicate characters in the matrix
            HashSet<char> currentchars = new HashSet<char>();
            // define the sandard string we will continue filling the matrix with it
            string allletters = "ABCDEFGHIKLMNOPQRSTUVWXYZ";// i just put the i and will treat j as i so i will not insert j
            // now will ensure that the key is in upper case to sure that all things same
            key = key.ToUpper().Replace('J', 'I');

            // now we will iterating over this 2d matrix and start fill it with the key first
            int row = 0, col = 0;
            for (int i = 0; i < key.Length; i++)
            {
                // there is a special case that the key maybe have a letter not in the 26 english letters so we will terminate
                //and will not encrypt 
                if (key[i] < 'A' || key[i] > 'Z')
                {
                    throw new ArgumentException("Invalid character in the key. Only English letters are allowed.");
                    //Console.WriteLine("there is invalid character in the key not in the 26 E letters enter the key again. ");
                    //return null;
                }



                //now we need to know if it was added before or no 
                if (currentchars.Contains(key[i]) == false)//it means it is not found
                {
                    // so we will fill this index in the matrix with it 
                    matrixx[row, col] = key[i];
                    //and insert it in the hash set to prevent duplicate
                    currentchars.Add(key[i]);
                    // now we need to increase the indeces and handle if it is reaches to the end
                    col++;
                    // if col now be 5 so we will make it 0 and do to the next row
                    if (col == 5)
                    {
                        col = 0;
                        row++;
                    }
                }
            }

            //now after finishing the first part that we fill the matrix by the key letters we will need to fill it 
            // by the other remining english letters to start encrypt
            for (int i = 0; i < allletters.Length; i++)
            {
                // we will make the same steps that happened in the previous loop 

                if (currentchars.Contains(allletters[i]) == false)//it means it is not found
                {
                    // so we will fill this index in the matrix with it 
                    matrixx[row, col] = allletters[i];
                    //and insert it in the hash set to prevent duplicate
                    currentchars.Add(allletters[i]);
                    // now we need to increase the indeces and handle if it is reaches to the end
                    col++;
                    // if col now be 5 so we will make it 0 and do to the next row
                    if (col == 5)
                    {
                        col = 0;
                        row++;
                    }
                }


            }

            //now we will start encrypt the plain text 

            // but first we will make the plain text as the other strings here 
            plainText = plainText.ToUpper().Replace('J', 'I');
            // and making a string for store inside it the result
            string result = "";
            // now start iterating over the plain text
            for (int i = 0; i < plainText.Length; i += 2)
            {
                char first = plainText[i];
                char second;
                // first we will need to get the next character
                // but there is 3 cases
                if (i + 1 >= plainText.Length)//so it means the size is odd so the second char will be x
                                              //if (first == 'X') // if the last character is 'X'
                                              //    second = 'Q'; // pad with 'Q' (or another character)
                                              //else
                    second = 'X'; // otherwise, pad with 'X'
                else
                {
                    // so i first will need to check if the second char is the same char like the first one or no
                    if (plainText[i + 1] == first)
                    {
                        second = 'X';
                        i--;
                    }
                    else
                    {
                        second = plainText[i + 1];
                    }
                }

                // now we will need to get for each character its index in the matrix
                int frow = -2, fcol = -2, srow = -2, scol = -2;
                Boolean flag1 = false;
                Boolean flag2 = false;
                for (int k = 0; k < 5; k++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (matrixx[k, j] == first)
                        {
                            frow = k;
                            fcol = j;
                            flag1 = true;
                        }
                        else if (matrixx[k, j] == second)
                        {
                            srow = k;
                            scol = j;
                            flag2 = true;
                        }
                        if (flag1 && flag2)
                            break;

                    }
                    if (flag1 && flag2)
                        break;
                }

                // after get the indcies now convert each of them and concatenate with the result string
                if (frow == srow)//ow they are in the same row so i will move righ one step
                {
                    fcol = (fcol + 1) % 5;
                    scol = (scol + 1) % 5;
                }

                else if (fcol == scol)// that means they are in the same col so i will move just one step into down
                {
                    frow = (frow + 1) % 5;
                    srow = (srow + 1) % 5;
                }

                else // it menas they are rectangle so in each i will just get the char that in the same row but in the col of other char
                {
                    int swapp = fcol;
                    fcol = scol;
                    scol = swapp;
                }

                // now we get the characters of the encrypted thie part of the plain text
                // so now we will concatenate it in he result string to get the another 2 characters
                result += matrixx[frow, fcol].ToString();
                result += matrixx[srow, scol].ToString();
            }

            return result;

        }

    }
}
/*
 largeCipher  QXQFQLKBWAWDBOHQNKKZSDTRCQNKNKRTKZZKBPPKNKKTCZOPDBBDPAWFMHSMVCPRQFDWZKTRNZZKBPNKBTGKNUMLKBDRVDHQHQHAASERWOKQKNKBDRONPKNKRTKZZKBPPKNKDOURGSCRQKTSDBRDXPVPNUQUGWMBKXKQLKBWSTDWAWDKZKBTKWISMCRPCKQZKQHQLKBZERFPOWPKLKBMORNRKEPNMRKNZXZECFHIZECFXBATKENKRDASNZZKBLPXBISWSWWFDPNRDKHQQHMHHQNKRZSUORFURKNKSMBEPETBDPMBBTCGMHHQNKREBTZKELKBTKWCPEEMAKKZKBCPKQKNKBEWMXBTQKSTPHPEGKNUQFMHHQNKRKGYRCUIGYKZSDTREWXBQKLZZKNKREFWKBEFCZUNDEFINEDUNDEFINEDEKQBCUOLDVBOWSKDSTCOPZMRCDDOTZKBTDBSWSKDHQZECGFDDVAHEPPRWPUNDEFINEDTRNZXZKBPPXBINKOMKPDRVSLATRUNDEFINEDRTXTPOPFUUNDEFINEDCREWTDUNDEFINEDKBNUTPOPFUUNDEFINEDUNDEFINEDMBVDOLKBTAZLSTNKKTCZMORNUNDEFINEDKGTBRBRBUNDEFINEDSUORMBSMXLEWNVTAQNSTAKDPNLWEATRUKZKZKBGKMSMRKHDPUNDEFINEDNKXKZOPTRNZZKBPPKNKRBKHDPVDDREWXBGCRDRBSWNKKESUAPWHZKEWBLRDWPGPDREQSMFMCKQLKBTKZQSDTRUNDEFINEDEZKZKBDRMPQKZDAPWHQKSTPKNKREPETBXBPPKNKHWDREQSMFMUNDEFINEDNKBTSARUZQKBKPNUTPCQMHKPXPFFPTRUNDEFINEDHQPEBRUNDEFINEDZEDOBIASFCPKTRNZZKBPHQNKROMPHQZKZNNANUNDEFINEDHREZFNKZZKBPPDKZKBWSTDUNDEFINEDEPQMZWTBTRNZXZKCFPNRKUNDEFINEDUNDEFINEDBVGDUNDEFINEDUNDEFINEDPGZKELKBGKBPLMKZZKUNDEFINEDBTEDUWNZNKBTCOASFCSMBESTQKLXUNDEFINEDUNDEFINEDUNDEFINEDKLKBTRNZZKBPSAORPDSTNKBODVRDPOPKZWPFMORNUNDEFINEDXDRRUWDKZKBQAKQKNKBTRNZZKBPZENKCKCFNVTDCGOMRDKHKNDRWAREQKZDQUUNDEFINEDXDPSUWFMHPDPZMBZENKRTRKNOGCKEKLKBEPCQGPTRNZZKCFQLKBPEKHHQPMASFCOSWPQLKBCFHINOGCKEKLKBEPUNDEFINEDNANKGNKRTKZZKBPSAORPDSTNKBODVREPTVLTSIUPZELSDTRUNDEFINEDROMPERNKDTCQNKNKRTKZXZKBPGQTDCGOMRTXCRTPODRWAREQKZDQUUNDEFINEDXDPSUWFMHPDPZMBZENKKZPAWHBRPKNKREPTVLQHGPTRNZZKCFQLKBPEKHHQPMASFCOSWPQLKBESNZZENAGCKEKLKBEWUPNQNANUNDEFINEDKLKBTRNZZKBPPDBTEZSTNKBODVRDPOPEEWUPNQUNDEFINEDROMPERNKDTCQNKNKRTKZXZKBPSTNKBODVRDPODRWAREQKZDQURXMONZNKKENKRDASFCPKEWBLRDWPKLKBDREQSMFMRBRKHQRBCXNKKECFHKMSURWGUNDEFINEDNKXKEDBRDHWGQAPELSMUNDEFINEDNKRKFCONTRNZXZKEPKLKBBTEDUWZKRAWGCFONKBSTKZGSLMKCWPQLKBWSTDEPOSONKBGKBPLMKZZKEPKLKBRUWGQLBZLOWGUNDEFINEDUNDEFINEDAERECUOLUNDEFINEDOBNKCKMXRDOBUNDEFINEDSUAPWHZKUNDEFINEDKLKBMPONUNDEFINEDPUBOUNDEFINEDMBNKUNDEFINEDONSWUNDEFINEDUNDEFINEDBDPAWFMHSMZCZNDPUNDEFINEDUNDEFINEDUNDEFINEDUNDEFINEDUNDEFINEDONGSMESTEZVDTKOBXBCKQLKBGKMSMNBOWSKDSIBTGKQHBNRBNANUNDEFINEDX";
 largePlain = nylinthespacesinthetablewiththelettersofthekeyworddroppinganyduplicatelettersthenfilltheremainingspaceswiththerestofthelettersofthealphabetinorderusuallyiandhzittfcsoncapsegteeniohwqdpueityitintfexceruwsoftfdnpelbeoslldhtyvtorightorinsomeotherpatternsuchasaspiralbeginningintheupperlefthandcornerandendinginthecenterthekeywordtogetherwiththeconventionsforfillinginthefivebyfivetableconstitutethecipherkeyxlrckhtbrvmbrkhqcroencryptamessageonewouldbreakthemessageintodigramsgroupsoxlrckhtbemblyvterssuchthatforexamplexlrckhtbrenzloworlxlrckhtbrbecoqrvmbrkhqcrhelloworlxlrckhtbrvmbrkhqcrndmapthemoutonthekeytablxlrckhtbegkmdederxmbrkhqcrppendanuncommonmonogramtocompletethefinaldigraxlrckhtbbmhzetwolettersofthedigramareconsideredastheoppositecornersofarectangleinthekeytablexlrckhtbrctetedrdlwletavosinholohtferooksnrsofthisrectanglxlrckhtbbmhenopdzytiehslzlwrnlgisuurrulexlrckhtbbglwcdplmbrkhqcrtoeachpairoflettersintheplaintextmslxmbrkhqcrfbothlettersarethesamexlrckhtbrcwltvoqenblyvterislefxlrckhtbrvmbrkhqcrddaxlrckhtbrvmbrkhqcrafterthefirstlettexlrckhtbrdkorvsqxtheqewpphbwndboqnftvzmbrkhqcrxlrckhtbrvmbrkhqcrfthelettersappearonthesamerowofyourtablxlrckhtbbvreplacethemwiththeletterstotheirimmediaterightrespectivelyxlrckhtbbvrappingaroundtotheleftsideoftherowifaletterintheoriginalpairwasontherightsideoftheroxlrckhtbbmsmifthelettersappearonthesamecolumnofyourtablexlrckhtbreatorblgeqenmhtfekeyvtersimmediatelybelowrespectivelyxlrckhtbbvrappingaroundtothetopsideofthecolumnifaletterintheoriginalpairwasonthebottomsideofthecolumnmslxmbrkhqcrfthelettersarenotonthesameroworcolumnxlrckhtbreatorblgeqenmhtfekeyvtersonthesamerowrespectivelybutattheotherpairofcornersoftherectangledefinedbytheoriginalpaixlrckhtbbmhzeorderisimportanxlrckhtbbmfeikewmqblyvteroftheencryptedpairistheonethatliesonthesamerowasthefirstletteroftheplaintextpaixlrckhtbrvmbrkhqcrodecryptxlrckhtbeashiegtubearxmbrkhqcrppositexlrckhtbegtfdnowlxmbrkhqcrulesxlrckhtbagshfzmbrkhqcrstasxlrckhtbrvmbrkhqcrdroppinganyextraxlrckhtbrvmbrkhqcrxlrckhtbrvmbrkhqcrxlrckhtbeamhanbokoyuemezsndbittfdhgtanhswsohbahcmkitbslbshsmxlrckhtbbv";
   result:    NNILTFCSPSRDSKNMIIXOEMEBNMHTFEKEYYHEOOHTIIQETZARDDRAPSGLBXGMRWCLGROYEKBLYYHESLHEMKHTVLTFDRDUBGNINIPPOBCPZETITHDREPLSHTFEKEYYHEOOHTGEPZDFWBCLEKABDEBVAUSLYLVFAQEHZHNTHESAMESPACETHEKEYCANBEWRITTENINTHETOPROWSOFTHETABLEFROMLEFTXVYCBKGKYCBHUDSKEBTFEAVXHYYHEFUNSHWSASSGRSLERIGNNGNGGNMFEXOZPPRLPHTHONDROOKDRALDDQEDGGGNMFECDKTEOTFENIORWCCGVIITEDBOFTITHDCAQNSQNHOLOFSDKHTYLGLGGNMFEIFUCRYHFZIXOEMECSYCNFTYYHTFERKOIDCIRYZMBRKHQCRXLRCKHTBRCITDBZPMRXDWSOHBAQEWOVTEBRRZKTEENRDASOHBGTYCBFKRRMVKBOOCPULMBRKHQCRLETXVYHEOONSHQEZTGARDUPNOMPLMBRKHQCRELZNOWURZZMBRKHQCRBECOMEXLRCKHTBEGSHZLOWURZZMBRKHQCRXLRCKHTBAGDXEATFENOVNPQMIIQEVTPELXMBRKHQCRIFNEEDEDXLRCKHTBBAZPDLSXNVTRSQZMWMHXMOGESLQPDOLEZFTETEDHGTANEFGBULMBRKHQCRTHZHTZOLBLYYHEOOHTFEEHGBAURRECSYDHBERESSQIIBOVPOSKXEOSCFPCAAFARECNWLGQDITTFENETNWEMPLMBRKHQCROTETHERELATIVEPOSITIONOFTHECORNENSOOHTIGACECNWLGLVMBRKHQCRTHENAPPLYTHEFOLLOWINGFOUSKKOLPLMBRKHQCRINORDEXLRCKHTBEVCRSEGWPHRWEKBLYYHESFNMFEATSFTYETMMSMXLRCKHTBBGECUKTHYYHEOOEGTECSONRVMBRKHQCRRONLYONELETXVYIERULBFZMBRKHQCRXLRCKHTBRDMDRVMBRKHQCRXLRCKHTBRAKVEOTFDHHEUFTGYYFZMBRKHQCRENCRYPTTHENEWPAIRANDCONTINUXLRCKHTBRVMBRKHQCRXLRCKHTBEGTFENBLYYHEOAPWPUBAQMHEAEUDRAWOETSOGLPELXMBRKHQCRVBEEYPEGTECNOGTITHENBLYYHEOUBTIEIEHLZMRBKALDEGGIMBCPPDCTETCMZZMBRKHQCRVBOAYPGLFSRAVTEXBTFELEHTAKEIOETFDCWRMIOLBLYYIEILTFRSOEGGLWGVPHEWASWLTFDBKGHQAKEIOETFDCULMBRKHQCRMSTHHMFEKEYYHEOAPWPUBAQMHEAEUDROMZTQWHLUTONPEMPLMBRKHQCREPLACETHEMWITHTHELETVYHEAFNQRBKALDNZBELOAECPPDCTETCMZZMBRKHQCRVBOAYPGLFSRAVTEXBTIIUOPSBSPUHTFEROMZTNGFOLBLYYIEILTFRSOEGGLWGVPHEWASWLTFDCXHYYBTVDEIOETFDCPYSLNMSMXLRCKHTBEGTFENBLYYHEOORDKOXOQMHEAEUDRAWOCCPYSLLYMBRKHQCREPLACETHEMWITHTHELETVYHEOAQMHEAEUDRAAECPPDCTETCMLPVNSTXTIIBTFEAVPHRWEOSCFPCAOFTFDRECNWLGLDDEIGLCDBNHIICBKGGTPXCPFVMBRKHQCRTHZHCRDEBGAIMWORNPLVMBRKHQCRTHEFIRSTLETXVYEOOFTFDDKORVOYFEPSIDKPTHSXKEVKPNTGWYWLTFCSONRCOWAWTHDHHEUFTGYYEOOFTFDEYPIMNRUTWSFVMBRKHQCRXLRCKHTBAVCECBZPFLMBRKHQCRSETHEINVERSEXLRCKHTBBAVPOSKXFZMBRKHQCRFTHELASTXLRCKHTBRAXRPZMBRKHQCRNDTHXLRCKHTBEAHXPYMBRKHQCRXLRCKHTBRDRAPSGLBXTVEYMBULMBRKHQCRXLRCKHTBRVMBRKHQCRXLRCKHTBRVMBRKHQCRSTHATDONOTMAKESENSEINTHEFINALMESSAGEWHENFINISHEDMSLXMBRKHQCRVV
   

 
 
 */
