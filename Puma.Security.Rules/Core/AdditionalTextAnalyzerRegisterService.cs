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

using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Core
{
    internal class AdditionalTextAnalyzerRegisterService : IAdditionalTextAnalyzerRegisterService
    {
        private readonly IDiagnosticFactory _diagnosticFactory;

        internal AdditionalTextAnalyzerRegisterService() : this(new DiagnosticFactory())
        {

        }

        private AdditionalTextAnalyzerRegisterService(IDiagnosticFactory diagnosticFactory)
        {
            _diagnosticFactory = diagnosticFactory;
        }

        public void Register(AnalysisContext context, ICompilationAnalyzer analyzer)
        {
            var additionalTextAnalyzer = analyzer as IAdditionalTextAnalyzer;
            if (additionalTextAnalyzer == null)
                return;

            context.RegisterCompilationAction(c =>
            {
                var pumaContext = new PumaCompilationAnalysisContext(additionalTextAnalyzer.GetDiagnosticId(), c);
                additionalTextAnalyzer.OnCompilationEnd(pumaContext);
                while (!additionalTextAnalyzer.VulnerableAdditionalText.IsEmpty)
                {
                    DiagnosticInfo additionalText;
                    if (!additionalTextAnalyzer.VulnerableAdditionalText.TryPop(out additionalText))
                        continue;

                    var supportedDiagnostic = additionalTextAnalyzer.GetSupportedDiagnosticAttribute();

                    var diagnostic = _diagnosticFactory.Create(supportedDiagnostic.GetDescriptor(), additionalText);

                    c.ReportDiagnostic(diagnostic);
                }
            });
        }
    }
}