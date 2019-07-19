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

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text.RegularExpressions;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;

namespace Puma.Security.Rules.Core
{
    public class DiagnosticSuite : DiagnosticAnalyzer
    {
        public IEnumerable<ICompilationAnalyzer> Analyzers = new List<ICompilationAnalyzer>();
        private readonly IConfigurationFileAnalyzerRegisterService _configurationFileAnalyzerRegisterService;
        private readonly IAdditionalTextAnalyzerRegisterService _additionalTextAnalyzerRegisterService;
        private readonly ISyntaxNodeAnalyzerRegisterService _syntaxNodeAnalyzerRegisterService;

        public DiagnosticSuite()
        {
            _configurationFileAnalyzerRegisterService = new ConfigurationFileAnalyzerRegisterService();
            _syntaxNodeAnalyzerRegisterService = new SyntaxNodeAnalyzerRegisterService();
            _additionalTextAnalyzerRegisterService = new AdditionalTextAnalyzerRegisterService();
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
                {
                    return Analyzers
                        .Select(p => p.GetDiagnosticDescriptor())
                        .ToImmutableArray();
                }

                return ImmutableArray.Create<DiagnosticDescriptor>();
            }
        }

        public override void Initialize(AnalysisContext context)
        {
            try
            {
                var pumaContext = new PumaAnalysisContext(context);

                //add the analyzers
                foreach (var analyzer in Analyzers)
                {
                    switch (analyzer)
                    {
                        case IConfigurationFileAnalyzer _:
                            _configurationFileAnalyzerRegisterService.Register(context, analyzer);
                            break;
                        case IAdditionalTextAnalyzer _:
                            _additionalTextAnalyzerRegisterService.Register(context, analyzer);
                            break;
                        case ISyntaxAnalyzer _:
                            _syntaxNodeAnalyzerRegisterService.Register(pumaContext, analyzer);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}