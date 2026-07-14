/*
 * Copyright(c) 2016 - 2026 Puma Security, LLC (https://pumasecurity.io)
 *
 * Project Leads:
 * Eric Johnson (eric.johnson@pumascan.com)
 * Eric Mead (eric.mead@pumascan.com)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;

namespace Puma.Security.Rules.Core
{
    internal class SyntaxNodeAnalyzerRegisterService : ISyntaxNodeAnalyzerRegisterService
    {
        private readonly IPumaSyntaxNodeAnalysisContextReporterService _pumaSyntaxNodeAnalysisContextReporterService;

        internal SyntaxNodeAnalyzerRegisterService() : this(new PumaSyntaxNodeAnalysisContextReporterService())
        {

        }

        private SyntaxNodeAnalyzerRegisterService(IPumaSyntaxNodeAnalysisContextReporterService pumaSyntaxNodeAnalysisContextReporterService)
        {
            _pumaSyntaxNodeAnalysisContextReporterService = pumaSyntaxNodeAnalysisContextReporterService;
        }

        public void Register(AnalysisContext context, ICompilationAnalyzer analyzer)
        {
            var syntaxAnalyzer = analyzer as ISyntaxAnalyzer;
            if (syntaxAnalyzer == null)
                return;

            var diagnosticId = syntaxAnalyzer.GetDiagnosticId();

            context.RegisterSyntaxNodeAction(
                c => _pumaSyntaxNodeAnalysisContextReporterService.Report(syntaxAnalyzer, diagnosticId, c),
                syntaxAnalyzer.SinkKind);
        }
    }
}
