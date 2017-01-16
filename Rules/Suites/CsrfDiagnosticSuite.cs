/* 
 * Copyright(c) 2016 - 2017 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Analyzer.Validation.Csrf;
using Puma.Security.Rules.Base;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Puma.Security.Rules.Suites
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class CsrfDiagnosticSuite : BaseSyntaxDiagnosticSuite
    {
        public CsrfDiagnosticSuite()
        {
            //TODO: could also have this look at attributes. Manually creating list for now 
            Analyzers = new List<ISyntaxNodeAnalyzer>
            {
                new AntiForgeryTokenAnalyzer()
            };
        }
    }
}
