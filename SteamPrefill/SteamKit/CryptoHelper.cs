/*
 * This file is subject to the terms and conditions defined in
 * file 'license.txt', which is part of this source code package.
 */



using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SteamPrefill.SteamKit
{

    /// <summary>
    /// Handles encrypting and decrypting using the RSA public key encryption
    /// algorithm.
    /// </summary>
    public class RSACrypto : IDisposable
    {
        RSA rsa;

        /// <summary>
        /// Initializes a new instance of the <see cref="RSACrypto"/> class.
        /// </summary>
        /// <param name="key">The public key to encrypt with.</param>
        public RSACrypto(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            AsnKeyParser keyParser = new AsnKeyParser(key);

            rsa = RSA.Create();
            rsa.ImportParameters(keyParser.ParseRSAPublicKey());
        }

        /// <summary>
        /// Encrypt the specified input.
        /// </summary>
        /// <returns>The encrypted input.</returns>
        /// <param name="input">The input to encrypt.</param>
        public byte[] Encrypt(byte[] input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            return rsa.Encrypt(input, RSAEncryptionPadding.OaepSHA1);
        }

        /// <summary>
        /// Disposes of this class.
        /// </summary>
        public void Dispose()
        {
            ((IDisposable)rsa).Dispose();
        }
    }

    /// <summary>
    /// Provides Crypto functions used in Steam protocols
    /// </summary>
    public static class CryptoHelper
    {
        /// <summary>
        /// Performs an SHA1 hash of an input byte array
        /// </summary>
        public static byte[] SHAHash(byte[] input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            using (var sha = SHA1.Create())
            {
                return sha.ComputeHash(input);
            }
        }

        /// <summary>
        /// Encrypts using AES/CBC/PKCS7 an input byte array with a given key and IV
        /// </summary>
        public static byte[] AESEncrypt(byte[] input, byte[] key, byte[] iv)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (iv == null)
            {
                throw new ArgumentNullException(nameof(iv));
            }

            using (var aes = Aes.Create())
            {
                aes.BlockSize = 128;
                aes.KeySize = 128;

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var aesTransform = aes.CreateEncryptor(key, iv))
                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, aesTransform, CryptoStreamMode.Write))
                {
                    cs.Write(input, 0, input.Length);
                    cs.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
        }

        /// <summary>
        /// Decrypts an input byte array using AES/CBC/PKCS7 with a given key and IV
        /// </summary>
        public static byte[] AESDecrypt(byte[] input, byte[] key, byte[] iv)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (iv == null)
            {
                throw new ArgumentNullException(nameof(iv));
            }

            using (var aes = Aes.Create())
            {
                aes.BlockSize = 128;
                aes.KeySize = 128;

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] plainText = new byte[input.Length];
                int outLen = 0;

                using (var aesTransform = aes.CreateDecryptor(key, iv))
                using (var ms = new MemoryStream(input))
                using (var cs = new CryptoStream(ms, aesTransform, CryptoStreamMode.Read))
                {
                    outLen = cs.ReadAll(plainText);
                }

                byte[] output = new byte[outLen];
                Array.Copy(plainText, 0, output, 0, output.Length);

                return output;
            }
        }
        
        /// <summary>
        /// Decrypts using AES/CBC/PKCS7 with an input byte array and key, using the random IV prepended using AES/ECB/None
        /// </summary>
        public static byte[] SymmetricDecrypt(byte[] input, byte[] key)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return SymmetricDecrypt(input, key, out _);
        }
        
        /// <summary>
        /// Decrypts using AES/CBC/PKCS7 with an input byte array and key, using the random IV prepended using AES/ECB/None
        /// </summary>
        static byte[] SymmetricDecrypt(byte[] input, byte[] key, out byte[] iv)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            DebugLog.Assert(key.Length == 32, "CryptoHelper", "SymmetricDecrypt used with non 32 byte key!");

            using (var aes = Aes.Create())
            {
                aes.BlockSize = 128;
                aes.KeySize = 256;

                // first 16 bytes of input is the ECB encrypted IV
                byte[] cryptedIv = new byte[16];
                iv = new byte[cryptedIv.Length];
                Array.Copy(input, 0, cryptedIv, 0, cryptedIv.Length);

                // the rest is ciphertext
                byte[] cipherText = new byte[input.Length - cryptedIv.Length];
                Array.Copy(input, cryptedIv.Length, cipherText, 0, cipherText.Length);

                // decrypt the IV using ECB
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                using (var aesTransform = aes.CreateDecryptor(key, null))
                {
                    iv = aesTransform.TransformFinalBlock(cryptedIv, 0, cryptedIv.Length);
                }

                // decrypt the remaining ciphertext in cbc with the decrypted IV
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var aesTransform = aes.CreateDecryptor(key, iv))
                using (var ms = new MemoryStream(cipherText))
                using (var cs = new CryptoStream(ms, aesTransform, CryptoStreamMode.Read))
                {
                    // plaintext is never longer than ciphertext
                    byte[] plaintext = new byte[cipherText.Length];

                    int len = cs.ReadAll(plaintext);

                    byte[] output = new byte[len];
                    Array.Copy(plaintext, 0, output, 0, len);

                    return output;
                }
            }
        }

        /// <summary>
        /// Verifies and performs a symmetricdecrypt on the input using the given password as a key
        /// </summary>
        public static byte[] VerifyAndDecryptPassword(byte[] input, string password)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            byte[] key, hash;
            using (var sha256 = SHA256.Create())
            {
                byte[] password_bytes = Encoding.UTF8.GetBytes(password);
                key = sha256.ComputeHash(password_bytes);
            }
            using (HMACSHA1 hmac = new HMACSHA1(key))
            {
                hash = hmac.ComputeHash(input, 0, 32);
            }

            for (int i = 32; i < input.Length; i++)
                if (input[i] != hash[i % 32])
                    return null;

            byte[] encrypted = new byte[32];
            Array.Copy(input, encrypted, encrypted.Length);

            return SymmetricDecrypt(encrypted, key);
        }

        /// <summary>
        /// Decrypts using AES/ECB/PKCS7
        /// </summary>
        public static byte[] SymmetricDecryptECB(byte[] input, byte[] key)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            DebugLog.Assert(key.Length == 32, "CryptoHelper", "SymmetricDecryptECB used with non 32 byte key!");

            using (var aes = Aes.Create())
            {
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;

                using (var aesTransform = aes.CreateDecryptor(key, null))
                {
                    byte[] output = aesTransform.TransformFinalBlock(input, 0, input.Length);

                    return output;
                }
            }
        }

        /// <summary>
        /// Performs CRC32 on an input byte array using the CrcStandard.Crc32Bit parameters
        /// </summary>
        public static byte[] CRCHash(byte[] input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            using (var crc = new Crc32())
            {
                byte[] hash = crc.ComputeHash(input);
                Array.Reverse(hash);

                return hash;
            }
        }

        /// <summary>
        /// Performs an Adler32 on the given input
        /// </summary>
        public static byte[] AdlerHash(byte[] input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            uint a = 0, b = 0;
            for (int i = 0; i < input.Length; i++)
            {
                a = (a + input[i]) % 65521;
                b = (b + a) % 65521;
            }
            return BitConverter.GetBytes(a | b << 16);
        }

        /// <summary>
        /// Generate an array of random bytes given the input length
        /// </summary>
        public static byte[] GenerateRandomBlock(int size)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var block = new byte[size];

                rng.GetBytes(block);

                return block;
            }
        }
    }
}
