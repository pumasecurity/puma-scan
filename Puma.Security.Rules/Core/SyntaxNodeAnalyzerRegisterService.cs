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

using Puma.Security.Rules.Analyzer;

namespace Puma.Security.Rules.Core
{
    internal class SyntaxNodeAnalyzerRegisterService : ISyntaxNodeAnalyzerRegisterService
    {
        private readonly IPumaSyntaxNodeAnalysisContextReporterService _pumaSyntaxNodeAnalysisContextReporterService;
        private readonly IPumaCompilationAnalysisReporterService _pumaCompilationAnalysisReporterService;

        internal SyntaxNodeAnalyzerRegisterService() : this(new PumaSyntaxNodeAnalysisContextReporterService(), new PumaCompilationAnalysisReporterService())
        {

        }

        private SyntaxNodeAnalyzerRegisterService(IPumaSyntaxNodeAnalysisContextReporterService pumaSyntaxNodeAnalysisContextReporterService, IPumaCompilationAnalysisReporterService pumaCompilationAnalysisReporterService)
        {
            _pumaSyntaxNodeAnalysisContextReporterService = pumaSyntaxNodeAnalysisContextReporterService;
            _pumaCompilationAnalysisReporterService = pumaCompilationAnalysisReporterService;
        }

        public void Register(PumaAnalysisContext pumaContext, ICompilationAnalyzer analyzer)
        {
            var syntaxAnalyzer = analyzer as ISyntaxAnalyzer;
            if (syntaxAnalyzer == null)
                return;

            pumaContext.RegisterCompilationStartAction(RegisterPumaActions(syntaxAnalyzer));
        }

        private Action<PumaCompilationStartAnalysisContext> RegisterPumaActions(ISyntaxAnalyzer syntaxAnalyzer)
        {
            return c =>
            {
                c.RegisterSyntaxNodeAction(_pumaSyntaxNodeAnalysisContextReporterService.Report(syntaxAnalyzer), syntaxAnalyzer.SinkKind, syntaxAnalyzer.GetDiagnosticId());

                c.RegisterCompilationEndAction(_pumaCompilationAnalysisReporterService.Report(syntaxAnalyzer), syntaxAnalyzer.GetDiagnosticId());
            };
        }
    }
}