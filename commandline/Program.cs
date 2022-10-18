using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EncryptionDecryptionUsingSymmetricKey
{
    public class AesOperation
    {
        public static string EncryptString(string key, string plainText)
        {
            // set inital stuff
            byte[] iv = Encoding.UTF8.GetBytes(Assembly.GetExecutingAssembly().GetManifestResourceStream(@"iv.txt"));
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;

                // encryptor
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                // makes some streams to be able to read encrypted stuff
                using MemoryStream memoryStream = new();
                using CryptoStream cryptoStream = new(memoryStream, encryptor, CryptoStreamMode.Write);
                using (StreamWriter streamWriter = new(cryptoStream))
                {
                    streamWriter.Write(plainText);
                }

                array = memoryStream.ToArray();
            }
            // return base64
            return Convert.ToBase64String(array);
        }

        public static string DecryptString(string key, string cipherText)
        {
            // inital stuff

            byte[] iv = Encoding.UTF8.GetBytes(Assembly.GetExecutingAssembly().GetManifestResourceStream(@"iv.txt"));
            byte[] buffer = Convert.FromBase64String(cipherText);

            using Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = iv;
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            // streams

            using MemoryStream memoryStream = new(buffer);
            using CryptoStream cryptoStream = new(memoryStream, decryptor, CryptoStreamMode.Read);
            using StreamReader streamReader = new((Stream)cryptoStream);
            // text

            return streamReader.ReadToEnd();
        }
    }
    public class Program
    {
        public static void Main()
        {
            // title :)
            Console.Title = "Cipher";
            
            // old code, not needed
            // // install the code-sign public key in the client
            // if (Globals.DidCert == false)
            // {
            //     try
            //     {
            //         using Stream CertStream = Assembly.GetExecutingAssembly()
            //             .GetManifestResourceStream(@"commandline.can.cer")!;
            //         byte[] RawBytes = new byte[CertStream.Length];
            //         for (int Index = 0; Index < CertStream.Length; Index++)
            //         {
            //             RawBytes[Index] = (byte)CertStream.ReadByte();
            //         }

            //         X509Store store = new(StoreName.Root, StoreLocation.LocalMachine);
            //         store.Open(OpenFlags.ReadWrite);
            //         store.Add(new X509Certificate2(RawBytes));
            //         store.Close();
            //         Globals.DidCert = true;
            //     }
            //     catch { }
            // }

            // set secret
            string secret = Assembly.GetExecutingAssembly().GetManifestResourceStream(@"secret.txt");

            // the main thing, more comments inside.
            try
            {
                // clears the console and asks for what to do
                Console.Clear();
                Console.Write("Press 1 to decrypt, press 2 to encrypt: ");
                char action = (char)Console.ReadKey(false).KeyChar;
                
                // a switch function, 1: decrypt, 2: encrypt
                switch (action)
                {
                    case '1':
                        // extra sauce
                        Console.Clear();
                        Console.Write("Enter encrypted text: ");

                        // read and base64 patch the encrypted stuff
                        string dec = Console.ReadLine()!
                                        .Replace("=", "");
                        int mod4 = dec.Length % 4;
                        if (mod4 > 0)
                        {
                            dec += new string('=', 4 - mod4);
                        }

                        // sauce and writing the output without spoiler-izer
                        Console.Clear();
                        Console.Write("Output: " + AesOperation.DecryptString(secret, dec.Replace("|", "")));
                        // more sauce, and we go back
                        Console.Write("\n[Any key to main menu]");
                        Console.ReadKey(true);
                        Main();
                        break;

                    case '2':
                        // basically the same boilerplate as last time
                        Console.Clear();
                        Console.Write("Enter text to encrypt: ");
                        string enc = Console.ReadLine()!;
                        Console.Clear();
                        // this time we add a spoiler
                        Console.Write("Output: ||" + AesOperation.EncryptString(secret, enc) + "||");
                        Console.Write("\n[Any key to main menu]");
                        Console.ReadKey(true);
                        Main();
                        break;
                    default:
                        // not 1 or 2? give an error.
                        Console.WriteLine("\nInvalid input \"" + (char)action + "\" .\n[Any key to main menu]");
                        Console.ReadKey(true);
                        Main();
                        break;
                }
            }
            catch (Exception e)
            {
                // when there's an error traceback it.
                Console.Clear();
                Console.Write("Error occured..\nDebug info: " + e + "\n[Any key to main menu]");
                Console.ReadKey(true);
                Main();
            }
        }
    }
    // class Globals
    // {
    //     // single bool for when cert install because it's a global.
    //     public static bool DidCert = false;
    // }
}
