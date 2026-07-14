/* 
 * Copyright(c) 2016 - 2020 Puma Security, LLC (https://pumasecurity.io)
 * 
 * Project Leads:
 * Eric Johnson (eric.johnson@pumascan.com)
 * Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System.Text.RegularExpressions;

namespace Puma.Security.Rules.Regex.Mvc
{
    internal class HtmlRawRegexHelper : BaseRegexHelper
    {
        private const string Regex = @"\@Html.Raw\(
                                            (
                                                [^()]+         
                                                | (?<Level>\() 
                                                | (?<-Level>\))
                                            )+                 
                                            (?(Level)(?!))     
                                        \)";

        internal HtmlRawRegexHelper() : base(RegexOptions.IgnorePatternWhitespace) { }

        protected override string GetExpression()
        {
            return Regex;
        }
    }
}