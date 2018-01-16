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

using System;
using System.Security.Cryptography;
using System.Text;

namespace Puma.Security.Rules.Core.Crypto
{
    public class Asymmetric
    {
        private readonly RSACryptoServiceProvider _rsaProvider;

        public Asymmetric()
        {
            _rsaProvider = new RSACryptoServiceProvider(2048);
        }

        public Asymmetric(string key)
        {
            _rsaProvider = new RSACryptoServiceProvider(2048);
            _rsaProvider.ImportCspBlob(Convert.FromBase64String(key));
        }

        public string GetPublicKey()
        {
            return Convert.ToBase64String(_rsaProvider.ExportCspBlob(false));
        }

        public string GetPrivateKey()
        {
            return Convert.ToBase64String(_rsaProvider.ExportCspBlob(true));
        }

        public byte[] Encrypt(string data)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(data);
            return _rsaProvider.Encrypt(plainBytes, false);
        }

        public string Decrypt(byte[] encryptedBytes)
        {
            byte[] plainBytes = _rsaProvider.Decrypt(encryptedBytes, false);

            return Encoding.UTF8.GetString(plainBytes, 0, plainBytes.Length);
        }

        public byte[] SignBytes(byte[] data)
        {
            return _rsaProvider.SignData(data, new SHA1CryptoServiceProvider());
        }

        public bool ValidateSignature(byte[] data, byte[] signature)
        {
            return _rsaProvider.VerifyData(data, new SHA1CryptoServiceProvider(), signature);
        }
    }
}