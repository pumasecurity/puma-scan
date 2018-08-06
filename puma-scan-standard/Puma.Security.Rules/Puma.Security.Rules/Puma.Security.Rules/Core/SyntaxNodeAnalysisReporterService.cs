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

using System;
using System.Linq;

using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Core
{
    internal class SyntaxNodeAnalysisReporterService : ISyntaxNodeAnalysisReporterService
    {
        private readonly DiagnosticFactory _diagnosticFactory;

        internal SyntaxNodeAnalysisReporterService() : this(new DiagnosticFactory()) { }

        private SyntaxNodeAnalysisReporterService(DiagnosticFactory diagnosticFactory)
        {
            _diagnosticFactory = diagnosticFactory;
        }

        public Action<SyntaxNodeAnalysisContext> Report(ISyntaxAnalyzer analyzer, DiagnosticId ruleId)
        {
            return c =>
            {
                var syntaxContext = c;
                analyzer.GetSinks(c, ruleId);
                while (!analyzer.VulnerableSyntaxNodes.IsEmpty)
                {
                    VulnerableSyntaxNode vulnerableSyntaxNode;
                    if (!analyzer.VulnerableSyntaxNodes.TryPop(out vulnerableSyntaxNode))
                        continue;

                    if (!syntaxContext.SemanticModel.Compilation.SyntaxTrees.Contains(vulnerableSyntaxNode.Sink.SyntaxTree))
                        continue;

                    var supportedDiagnostic = analyzer.GetSupportedDiagnosticAttribute();

                    if (!vulnerableSyntaxNode.Suppressed)
                        syntaxContext.ReportDiagnostic(_diagnosticFactory.Create(supportedDiagnostic.GetDescriptor(), new DiagnosticInfo(vulnerableSyntaxNode.Sink.GetLocation(), vulnerableSyntaxNode.MessageArgs)));
                }
            };
        }
    }
}