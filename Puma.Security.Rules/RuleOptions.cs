/* 
 * Copyright(c) 2016 - 2019 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

namespace Puma.Security.Rules
{
    public class RuleOptions
    {
        private static int _sessionExpirationMax = 30;
        private static string _productionBuildConfiguration = "Release";
        //private static string _productionBuildConfiguration = ""; //This will disable transforms
        private static int _maxRequestLengthMax = 204800;
        private static int _passwordComplexityMinPasswordLength = 12;
        private static bool _passwordComplexityRequireNumber = true;
        private static bool _passwordComplexityRequireSpecialCharcter = true;
        private static bool _passwordComplexityRequireLowerCharacter = true;
        private static bool _passwordComplexityRequireUpperCharacter = true;

        public static int SessionExpirationMax
        {
            get
            {
                return _sessionExpirationMax;
            }

            set
            {
                _sessionExpirationMax = value;
            }
        }

        public static string ProductionBuildConfiguration
        {
            get
            {
                return _productionBuildConfiguration;
            }

            set
            {
                _productionBuildConfiguration = value;
            }
        }

        public static int MaxRequestLengthMax
        {
            get
            {
                return _maxRequestLengthMax;
            }

            set
            {
                _maxRequestLengthMax = value;
            }
        }

        public static int PasswordComplexityMinPasswordLength
        {
            get
            {
                return _passwordComplexityMinPasswordLength;
            }

            set
            {
                _passwordComplexityMinPasswordLength = value;
            }
        }

        public static bool PasswordComplexityRequireNumber
        {
            get
            {
                return _passwordComplexityRequireNumber;
            }

            set
            {
                _passwordComplexityRequireNumber = value;
            }
        }

        public static bool PasswordComplexityRequireSpecialCharcter
        {
            get
            {
                return _passwordComplexityRequireSpecialCharcter;
            }

            set
            {
                _passwordComplexityRequireSpecialCharcter = value;
            }
        }

        public static bool PasswordComplexityRequireLowerCharacter
        {
            get
            {
                return _passwordComplexityRequireLowerCharacter;
            }

            set
            {
                _passwordComplexityRequireLowerCharacter = value;
            }
        }

        public static bool PasswordComplexityRequireUpperCharacter
        {
            get
            {
                return _passwordComplexityRequireUpperCharacter;
            }

            set
            {
                _passwordComplexityRequireUpperCharacter = value;
            }
        }
    }
}