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

using System.Text.RegularExpressions;

namespace Puma.Security.Rules.Regex
{
    internal abstract class BaseRegexHelper : IRegexHelper
    {
        private readonly RegexOptions _options;

        protected BaseRegexHelper(RegexOptions options = RegexOptions.None)
        {
            _options = options;
        }

        public bool HasMatch(string source)
        {
            var regex = new System.Text.RegularExpressions.Regex(GetExpression(), _options);

            var hasMatch = regex.Match(source);

            return hasMatch.Success;
        }

        public MatchCollection GetMatches(string source)
        {
            var regex = new System.Text.RegularExpressions.Regex(GetExpression(), _options);

            return regex.Matches(source);
        }

        protected abstract string GetExpression();
    }
}