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

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text.RegularExpressions;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Diagnostics;

namespace Puma.Security.Rules.Core
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class BaseDiagnosticSuite : DiagnosticAnalyzer
    {
        public IEnumerable<ICompilationAnalyzer> Analyzers;
        protected IDiagnosticFactory DiagnosticFactory;

        public BaseDiagnosticSuite()
        {
            Analyzers = new List<ICompilationAnalyzer>();
            DiagnosticFactory = new DiagnosticFactory();
        }

        public string Name
        {
            get { return System.Text.RegularExpressions.Regex.Matches(GetType().Name.Replace("DiagnosticSuite", string.Empty), "[A-Za-z0-9]+").OfType<Match>().Select(match => match.Value).Aggregate((acc, b) => acc + " " + b).TrimStart(' '); }
        }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            {
                if (Analyzers != null && Analyzers.Any())
                    return Analyzers
                        .Select(p => GetSupportedDiagnosticAttribute(p).GetDescriptor())
                        .ToImmutableArray();

                return ImmutableArray.Create<DiagnosticDescriptor>();
            }
        }

        protected static SupportedDiagnosticAttribute GetSupportedDiagnosticAttribute(ICompilationAnalyzer analyzer)
        {
            var supportedDiagnosticAttribute = analyzer.GetType()
                .GetCustomAttributes(typeof(SupportedDiagnosticAttribute), true)
                .FirstOrDefault() as SupportedDiagnosticAttribute;

            return supportedDiagnosticAttribute;
        }

        public override void Initialize(AnalysisContext context)
        {
            
        }
    }
}