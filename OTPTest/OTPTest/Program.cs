using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace OTPTest
{
    class Program
    {
        private const String secretkey = "MySecretKey";
        private const String salt = "MustBeMoreThanEightCharacters";
        private const int expiresMinute = 1;

        static void Main(string[] args)
        {
            String dataInput = "hasan.widjaya@gmail.com";

            Random generator = new Random();
            int r = generator.Next(1, 1000000);
            string sOTP = r.ToString().PadLeft(6, '0');

            String test1 = CreateNewOTP(dataInput, sOTP);
            Console.WriteLine( test1 );
            Console.ReadKey();

            bool test2 = VerifyOTP(test1, dataInput, sOTP);
            Console.WriteLine(test2);
            Console.ReadKey();

            test2 = VerifyOTP(test1, dataInput, sOTP);
            Console.WriteLine(test2);
            Console.ReadKey();
        }

        private static String CreateNewOTP(String dataInput, String sOTP)
        {
            long expires = ((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds() + (expiresMinute * 60);
            String data = String.Concat(dataInput, sOTP);

            return Encrypt(String.Concat(hashValue(Encoding.ASCII.GetBytes(data)), '|', expires.ToString()));
        }

        public static bool VerifyOTP(String hashInput, String dataInput, String sOTP)
        {
            String[] decryptValue = Decrypt(hashInput).Split('|');

            if(!hashValue(Encoding.ASCII.GetBytes(String.Concat(dataInput, sOTP))).Equals(decryptValue[0])) {
                Console.WriteLine("Hash values differ! Signed file has been tampered with!");
                return false;
            }

            if (((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds() > (long)Convert.ToDouble(decryptValue[1]))
            {
                Console.WriteLine("OTP expires");
                return false;
            }

            return true;
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

        public static string Encrypt(string clearText)
        {
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(secretkey, Encoding.ASCII.GetBytes(salt));
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
        
        public static string Decrypt(string cipherText)
        {
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(secretkey, Encoding.ASCII.GetBytes(salt));
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
