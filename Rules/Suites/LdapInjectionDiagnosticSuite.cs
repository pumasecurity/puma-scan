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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Analyzer.Injection.Ldap;
using Puma.Security.Rules.Core;
using System.Collections.Immutable;

namespace Puma.Security.Rules.Suites
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class LdapInjectionDiagnosticSuite : BaseSyntaxDiagnosticSuite
    {
        public LdapInjectionDiagnosticSuite()
        {
            Analyzers = new ISyntaxAnalyzer[]
            {
               new LdapDirectoryEntryPathAssignmentAnalzyer(),
               new LdapDirectoryEntryPathCreationAnalyzer(),
               new LdapDirectorySearcherAnalyzer(),
            }.ToImmutableArray();
        }
    }
}
