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

using System.Security.Cryptography;

namespace Puma.Security.Rules.Core.Crypto
{
    public class Hash
    {
        public static int _ITERATIONS = 1;
        public static int _RETURN_BYTES = 32;

        public static byte[] GetBytes(byte[] input, byte[] salt)
        {
            return GetBytes(input, salt, _ITERATIONS, _RETURN_BYTES);
        }

        public static byte[] GetBytes(byte[] input, byte[] salt, int iterations)
        {
            return GetBytes(input, salt, iterations, _RETURN_BYTES);
        }

        public static byte[] GetBytes(byte[] input, byte[] salt, int interations, int returnBytes)
        {
            Rfc2898DeriveBytes pbkdf = new Rfc2898DeriveBytes(input, salt, interations);
            return pbkdf.GetBytes(returnBytes);
        }
    }
}