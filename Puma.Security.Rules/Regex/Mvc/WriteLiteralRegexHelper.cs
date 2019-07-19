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

namespace Puma.Security.Rules.Regex.Mvc
{
    internal class WriteLiteralRegexHelper : BaseRegexHelper
    {
        //TODO: this one could use some more love. As if two WriteLiteral's exist in one code block it will only fire 1 rule violation. Want to only match on 
        //WriteLiterals within the code block @{}, but not necessarily have the regex expression match the code block. Could have analyzer run two regexes or 
        //just get better at Regex :)
        //private const string Regex = "@{(.|\t|\r|\n)+?(WriteLiteral\\()*(.|\t|\r|\n)+?}"; //Too many false positives, too greedy
        private const string Regex = "WriteLiteral\\((.|\n|\r|\t)+?\\);";

        protected override string GetExpression()
        {
            return Regex;
        }
    }
}