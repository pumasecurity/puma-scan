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

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Core
{
    internal class PumaSyntaxNodeAnalysisContextReporterService : IPumaSyntaxNodeAnalysisContextReporterService
    {
        private readonly DiagnosticFactory _diagnosticFactory;

        internal PumaSyntaxNodeAnalysisContextReporterService() : this(new DiagnosticFactory()) { }

        private PumaSyntaxNodeAnalysisContextReporterService(DiagnosticFactory diagnosticFactory)
        {
            _diagnosticFactory = diagnosticFactory;
        }

        public void Report(ISyntaxAnalyzer analyzer, DiagnosticId diagnosticId, SyntaxNodeAnalysisContext context)
        {
            try
            {
                var sinks = new List<VulnerableSyntaxNode>();

                // Analyzer instances are shared across compilations, so the sink
                // stack and the stateful IsVulnerable helpers must not interleave
                // between actions. Holding the lock across GetSinks + drain
                // guarantees this action pops exactly the nodes it pushed.
                lock (analyzer.VulnerableSyntaxNodes)
                {
                    analyzer.GetSinks(context, diagnosticId);

                    while (analyzer.VulnerableSyntaxNodes.TryPop(out var vulnerableSyntaxNode))
                        sinks.Add(vulnerableSyntaxNode);
                }

                foreach (var vulnerableSyntaxNode in sinks)
                {
                    if (analyzer.IsSuppressed(context.SemanticModel, vulnerableSyntaxNode, diagnosticId))
                        continue;

                    var supportedDiagnostic = analyzer.GetSupportedDiagnosticAttribute();

                    var diagnosticInfo = new DiagnosticInfo(vulnerableSyntaxNode.Sink.GetLocation(), vulnerableSyntaxNode.MessageArgs);

                    var diagnostic = _diagnosticFactory.Create(supportedDiagnostic.GetDescriptor(), diagnosticInfo);

                    context.ReportDiagnostic(diagnostic);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
