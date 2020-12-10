using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Text.RegularExpressions;

namespace OTPTest
{
    class Program
    {
        private const String secretkey = "MySecretKey";
        private const String salt = "MustBeMoreThanEightCharacters";
        private const int expiresMinute = 1;
        private const string alphanumericCharacters =
       "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
       "abcdefghijklmnopqrstuvwxyz" +
       "0123456789";

        static void Main(string[] args)
        {
            String dataInput = "hasan.widjaya@gmail.com";
            string sOTP = GetUniqueKey(6, alphanumericCharacters);

            String test1 = CreateNewOTP(dataInput, sOTP);
            Console.WriteLine( test1 );
            Console.WriteLine( " --------------------------- " );

            bool verifiedOTP = false;
            String valOTPKeyIn = "";
            int attempt = 0;

            do
            {
                Console.Clear();
                if(attempt > 0)
                {
                    Console.WriteLine("You have entered invalid OTP or the OTP has expired,  please retry again");
                }
                    
                Console.WriteLine("Your OTP number is " + sOTP);
                Console.Write("Key in your OTP : ");
                valOTPKeyIn = Console.ReadLine();

                attempt += 1;

                verifiedOTP = VerifyOTP(test1, dataInput, valOTPKeyIn);

            } while (!verifiedOTP && attempt != 10);

            if (verifiedOTP)
            {
                Console.WriteLine("INFO : Congratulation,  you have entered valid OTP");
            }
            else
            {
                Console.WriteLine("ERROR : Program exited with unsuccesful OTP");
            }
            Console.ReadKey();
            System.Diagnostics.Process.GetCurrentProcess().Kill();
       
        }

        private static string GetUniqueKey(int length, IEnumerable<char> characterSet)
        {
            if (length < 0)
                throw new ArgumentException("length must not be negative", "length");
            if (length > int.MaxValue / 8) // 250 million chars ought to be enough for anybody
                throw new ArgumentException("length is too big", "length");
            if (characterSet == null)
                throw new ArgumentNullException("characterSet");
            var characterArray = characterSet.Distinct().ToArray();
            if (characterArray.Length == 0)
                throw new ArgumentException("characterSet must not be empty", "characterSet");

            var bytes = new byte[length * 8];
            var result = new char[length];
            using (var cryptoProvider = new RNGCryptoServiceProvider())
            {
                cryptoProvider.GetBytes(bytes);
            }
            for (int i = 0; i < length; i++)
            {
                ulong value = BitConverter.ToUInt64(bytes, i * 8);
                result[i] = characterArray[value % (uint)characterArray.Length];
            }
            return new string(result);


        }

        private static String CreateNewOTP(String dataInput, String sOTP)
        {
            long expires = ((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds() + (expiresMinute * 60);
            String data = String.Concat(dataInput, sOTP);

            return Encrypt(String.Concat(hashValue(Encoding.ASCII.GetBytes(data)), '|', expires.ToString()), sOTP);
        }

        public static bool VerifyOTP(String hashInput, String dataInput, String sOTP)
        {
            try
            {
                //Generate random sleeptime sleep for 3-10 sec to prevent bruteforce attack
                Random waitTime = new Random();
                int seconds = waitTime.Next(3 * 1000, 11 * 1000);

                //Put the thread to sleep
                System.Threading.Thread.Sleep(seconds);

                String[] decryptValue = Decrypt(hashInput, sOTP).Split('|');

                if (!hashValue(Encoding.ASCII.GetBytes(String.Concat(dataInput, sOTP))).Equals(decryptValue[0]))
                {
                    Console.WriteLine("Hash values differ! Signed file has been tampered with!");
                    return false;
                }

                if (((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds() > (long)Convert.ToDouble(decryptValue[1]))
                {
                    Console.WriteLine("OTP expires");
                    return false;
                }

                return true;
            }
            catch(Exception ex){
                return false;
            }

        } //end VerifyOTP

        public static string hashValue(byte[] data)
        {
            // Initialize the keyed hash object.
            var hash = new StringBuilder();
            using (HMACSHA256 hmac = new HMACSHA256(Encoding.ASCII.GetBytes(secretkey)))
            {
                // Compute the hash of the input file.
                byte[] hashValue = hmac.ComputeHash(data);
                foreach (var theByte in hashValue)
                {
                    hash.Append(theByte.ToString("x2"));
                }
            }

            return hash.ToString();
        }

        public static string Encrypt(string clearText, string sOTP)
        {
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(secretkey + sOTP.Trim(), Encoding.ASCII.GetBytes(salt));
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return clearText;
        }
        
        public static string Decrypt(string cipherText, string sOTP)
        {
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(secretkey + sOTP.Trim(), Encoding.ASCII.GetBytes(salt));
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }
    }
}
