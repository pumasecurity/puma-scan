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

using Puma.Security.Rules.Analyzer;

namespace Puma.Security.Rules.Core
{
    internal class SyntaxNodeAnalyzerRegisterService : ISyntaxNodeAnalyzerRegisterService
    {
        private readonly ISyntaxNodeAnalysisReporterService _syntaxNodeAnalysisReporterService;

        internal SyntaxNodeAnalyzerRegisterService() : this(new SyntaxNodeAnalysisReporterService())
        {

        }

        private SyntaxNodeAnalyzerRegisterService(ISyntaxNodeAnalysisReporterService syntaxNodeAnalysisReporterService)
        {
            _syntaxNodeAnalysisReporterService = syntaxNodeAnalysisReporterService;
        }

        public void Register(PumaAnalysisContext pumaContext, ICompilationAnalyzer analyzer)
        {
            var syntaxAnalyzer = analyzer as ISyntaxAnalyzer;
            if (syntaxAnalyzer == null)
                return;

            pumaContext.Context.RegisterSyntaxNodeAction(_syntaxNodeAnalysisReporterService.Report(syntaxAnalyzer, syntaxAnalyzer.GetDiagnosticId()), syntaxAnalyzer.SinkKind);
        }
    }
}