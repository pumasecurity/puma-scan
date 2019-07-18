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
using System.Linq;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Core
{
    internal class PumaCompilationAnalysisReporterService : IPumaCompilationAnalysisReporterService
    {
        private readonly DiagnosticFactory _diagnosticFactory;

        internal PumaCompilationAnalysisReporterService() : this(new DiagnosticFactory()) { }

        private PumaCompilationAnalysisReporterService(DiagnosticFactory diagnosticFactory)
        {
            _diagnosticFactory = diagnosticFactory;
        }

        public Action<PumaCompilationAnalysisContext> Report(ISyntaxAnalyzer analyzer)
        {
            return pumaContext =>
            {
                try
                {
                    var context = pumaContext.RosylnContext;
                    analyzer.OnCompilationEnd(pumaContext);
                    while (!analyzer.VulnerableSyntaxNodes.IsEmpty)
                    {
                        VulnerableSyntaxNode vulnerableSyntaxNode;
                        if (!analyzer.VulnerableSyntaxNodes.TryPop(out vulnerableSyntaxNode))
                            continue;

                        if (!context.Compilation.SyntaxTrees.Contains(vulnerableSyntaxNode.Sink.SyntaxTree))
                            continue;

                        if (!vulnerableSyntaxNode.Suppressed)
                        {
                            var supportedDiagnostic = analyzer.GetSupportedDiagnosticAttribute();

                            var diagnosticInfo = new DiagnosticInfo(vulnerableSyntaxNode.Sink.GetLocation(), vulnerableSyntaxNode.MessageArgs);

                            var diagnostic = _diagnosticFactory.Create(supportedDiagnostic.GetDescriptor(), diagnosticInfo);

                            context.ReportDiagnostic(diagnostic);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }
            };
        }
    }
}