using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

namespace SecureFileEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== Secure File Encryption Tool ===\n");

            Console.WriteLine("Choose an option:");
            Console.WriteLine("1. Encrypt a file");
            Console.WriteLine("2. Decrypt a file\n");

            Console.Write("Option: ");
            string option = Console.ReadLine();

            if (option == "1")
            {
                EncryptFile();
            }
            else if (option == "2")
            {
                DecryptFile();
            }
            else
            {
                Console.WriteLine("Invalid option selected.");
            }
        }

        static void EncryptFile()
        {
            Console.Write("\nEnter the name of the file to encrypt (without extension): ");
            string fileName = Console.ReadLine();

            Console.Write("Enter the file type to search for (e.g., 'Word', 'Excel', 'All'): ");
            string fileType = Console.ReadLine();

            string[] extensions = GetExtensionsForFileType(fileType);
            if (extensions == null)
            {
                Console.WriteLine("\nUnsupported file type.");
                return;
            }

            string inputFile = FindFile(fileName, extensions);
            if (inputFile == null)
            {
                Console.WriteLine("\nFile not found.");
                return;
            }

            Console.Write("Enter a password: ");
            string password = ReadPassword();

            string outputFile = inputFile + ".enc";

            try
            {
                FileEncrypt(inputFile, outputFile, password);
                Console.WriteLine($"\nFile encrypted successfully!\nEncrypted file: {outputFile}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError: {ex.Message}");
            }
        }

        static void DecryptFile()
        {
            Console.Write("\nEnter the name of the encrypted file to decrypt (without '.enc'): ");
            string fileName = Console.ReadLine();

            // Automatically search for files with '.enc' extension
            string[] extensions = new string[] { "*.enc" };

            string inputFile = FindFile(fileName, extensions);
            if (inputFile == null)
            {
                Console.WriteLine("\nEncrypted file not found.");
                return;
            }

            Console.Write("Enter the password: ");
            string password = ReadPassword();

            string outputFile;
            if (inputFile.EndsWith(".enc"))
            {
                outputFile = inputFile.Substring(0, inputFile.Length - 4);
            }
            else
            {
                outputFile = inputFile + ".dec";
            }

            try
            {
                FileDecrypt(inputFile, outputFile, password);
                Console.WriteLine($"\nFile decrypted successfully!\nDecrypted file: {outputFile}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError: {ex.Message}");
            }
        }

        static string[] GetExtensionsForFileType(string fileType)
        {
            switch (fileType.ToLower())
            {
                case "word":
                    return new string[] { "*.doc", "*.docx" };
                case "excel":
                    return new string[] { "*.xls", "*.xlsx" };
                case "pdf":
                    return new string[] { "*.pdf" };
                case "text":
                    return new string[] { "*.txt" };
                case "all":
                    return new string[] { "*" };
                default:
                    return null;
            }
        }

        static string FindFile(string fileName, string[] extensions)
        {
            Console.WriteLine("\nSearching for the file. Please wait...");
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            List<string> foundFiles = new List<string>();

            try
            {
                foreach (string dir in GetAllAccessibleDirectories(userProfile))
                {
                    foreach (string ext in extensions)
                    {
                        try
                        {
                            string[] files = Directory.GetFiles(dir, fileName + ext, SearchOption.TopDirectoryOnly);
                            foundFiles.AddRange(files);
                        }
                        catch { /* Ignore access denied errors */ }
                    }
                }

                if (foundFiles.Count == 0)
                {
                    Console.WriteLine("\nNo files found with that name and file type.");
                    return null;
                }
                else if (foundFiles.Count == 1)
                {
                    Console.WriteLine($"\nFile found: {foundFiles[0]}");
                    return foundFiles[0];
                }
                else
                {
                    Console.WriteLine("\nMultiple files found:");
                    for (int i = 0; i < foundFiles.Count; i++)
                    {
                        Console.WriteLine($"{i + 1}. {foundFiles[i]}");
                    }
                    Console.Write("\nEnter the number of the correct file: ");
                    if (int.TryParse(Console.ReadLine(), out int choice) && choice > 0 && choice <= foundFiles.Count)
                    {
                        return foundFiles[choice - 1];
                    }
                    else
                    {
                        Console.WriteLine("Invalid selection.");
                        return null;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError during file search: {ex.Message}");
                return null;
            }
        }

        static IEnumerable<string> GetAllAccessibleDirectories(string root)
        {
            Queue<string> queue = new Queue<string>();
            queue.Enqueue(root);

            while (queue.Count > 0)
            {
                string currentDir = queue.Dequeue();
                yield return currentDir;

                try
                {
                    foreach (string subDir in Directory.GetDirectories(currentDir))
                    {
                        queue.Enqueue(subDir);
                    }
                }
                catch { /* Ignore access denied errors */ }
            }
        }

        static void FileEncrypt(string inputFile, string outputFile, string password)
        {
            byte[] salt = GenerateRandomSalt();

            using FileStream fsCrypt = new FileStream(outputFile, FileMode.Create);
            fsCrypt.Write(salt, 0, salt.Length);

            using RijndaelManaged AES = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CFB
            };

            var key = new Rfc2898DeriveBytes(password, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            using CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);
            using FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            byte[] buffer = new byte[1048576]; // 1MB buffer
            int read;
            while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
            {
                cs.Write(buffer, 0, read);
            }
        }

        static void FileDecrypt(string inputFile, string outputFile, string password)
        {
            byte[] salt = new byte[32];

            using FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            using RijndaelManaged AES = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CFB
            };

            var key = new Rfc2898DeriveBytes(password, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            using CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);
            using FileStream fsOut = new FileStream(outputFile, FileMode.Create);

            byte[] buffer = new byte[1048576]; // 1MB buffer
            int read;
            while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
            {
                fsOut.Write(buffer, 0, read);
            }
        }

        static byte[] GenerateRandomSalt()
        {
            byte[] salt = new byte[32];
            using RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(salt);
            return salt;
        }

        static string ReadPassword()
        {
            StringBuilder password = new StringBuilder();
            ConsoleKeyInfo info;
            do
            {
                info = Console.ReadKey(true);
                if (info.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Length--;
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    password.Append(info.KeyChar);
                    Console.Write("*");
                }
            } while (true);
            Console.WriteLine();
            return password.ToString();
        }
    }
}
