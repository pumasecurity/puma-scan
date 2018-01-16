/* 
 * Copyright(c) 2016 - 2018 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System.IO;
using System.Security.Cryptography;

namespace Puma.Security.Rules.Core.Crypto
{
    public class Symmetric
    {
        private static int BLOCK_SIZE = 8192;

        public static long EncryptStream(Stream input, Stream output, byte[] key, byte[] iv)
        {
            var rmCrypto = new RijndaelManaged
            {
                IV = iv,
                Key = key
            };

            using (var encryptor = rmCrypto.CreateEncryptor())
            {
                return ProcessCrypto(input, output, encryptor);
            }
        }

        public static long DecryptStream(Stream input, Stream output, byte[] key, byte[] iv)
        {
            var rmCrypto = new RijndaelManaged
            {
                IV = iv,
                Key = key
            };

            using (var decryptor = rmCrypto.CreateDecryptor())
            {
                return ProcessCrypto(input, output, decryptor);
            }
        }

        private static long ProcessCrypto(Stream input, Stream output, ICryptoTransform cryptoTransform)
        {
            using (var cryptoStream = new CryptoStream(output, cryptoTransform, CryptoStreamMode.Write))
            {
                var buffer = new byte[BLOCK_SIZE];
                var binaryWriter = new BinaryWriter(cryptoStream);

                var readBytes = 0;
                var totalBytes = 0;
                while ((readBytes = input.Read(buffer, 0, BLOCK_SIZE)) > 0)
                {
                    binaryWriter.Write(buffer, 0, readBytes);
                    totalBytes += readBytes;
                }

                return totalBytes;
            }
        }
    }
}