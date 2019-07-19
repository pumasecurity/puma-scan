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

using System.Collections.Generic;
using System.Collections.Immutable;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Core;
using Puma.Security.Rules.Suites.Core;

namespace Puma.Security.Rules.Suites
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class PumaDiagnosticSuite : DiagnosticSuite
    {
        public PumaDiagnosticSuite()
        {
            var factories = GetDefaultAnalyzerSuiteFactories();

            var analyzers = new List<ICompilationAnalyzer>();
            foreach (var factory in factories)
            {
                analyzers.AddRange(factory.Create());
            }

            Analyzers = analyzers.ToImmutableArray();
        }

        private static IAnalyzerSuiteFactory[] GetDefaultAnalyzerSuiteFactories()
        {
            var factories = new IAnalyzerSuiteFactory[]
            {
                new AccessControlAnalyzerSuiteFactory(),
                new CertificateValidationAnalyzerSuiteFactory(),
                new CommandInjectionAnalyzerSuiteFactory(),
                new ConfigurationAnalyzerSuiteFactory(),
                new CookiesConfigurationAnalyzerSuiteFactory(),
                new CryptoAnalyzerSuiteFactory(),
                new CsrfAnalyzerSuiteFactory(),
                new DeserializationAnalyzerSuiteFactory(),
                new FormsConfigurationAnalyzerSuiteFactory(),
                new HttpRuntimeConfigurationAnalyzerSuiteFactory(),
                new IdentityAnalyzerSuiteFactory(),
                new LdapInjectionAnalyzerSuiteFactory(),
                new MvcMarkupAnalyzerSuiteFactory(),
                new PagesConfigurationAnalyzerSuiteFactory(),
                new PathTamperingAnalyzerSuiteFactory(),
                new RequestValidationAnalyzerSuiteFactory(),
                new SessionStateConfigurationAnalyzerSuiteFactory(),
                new SqlInjectionAnalyzerSuiteFactory(),
                new UnvalidatedRedirectAnalyzerSuiteFactory(),
                new WebFormsMarkupAnalyzerSuiteFactory(),
                new WebFormsXssAnalyzerSuiteFactory()
            };
            return factories;
        }
    }
}