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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Core
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class BaseSyntaxDiagnosticSuite : BaseDiagnosticSuite
    {
        public override void Initialize(AnalysisContext context)
        {
            base.Initialize(context);

            foreach (var syntaxAnalyzer in Analyzers.OfType<ISyntaxAnalyzer>())
            {
                context.RegisterCompilationStartAction(RegisterPumaActions(syntaxAnalyzer));
            }
        }

        private Action<CompilationStartAnalysisContext> RegisterPumaActions(ISyntaxAnalyzer syntaxAnalyzer)
        {
            return context =>
            {
                context.RegisterSyntaxNodeAction(syntaxAnalyzer.GetSinks, syntaxAnalyzer.SinkKind);

                context.RegisterCompilationEndAction(ReportCompilationAnalysisDiagnostic(syntaxAnalyzer));
            };
        }

        private Action<CompilationAnalysisContext> ReportCompilationAnalysisDiagnostic(ISyntaxAnalyzer analyzer)
        {
            return context =>
            {
                analyzer.OnCompilationEnd(context);
                while (!analyzer.VulnerableSyntaxNodes.IsEmpty)
                {
                    VulnerableSyntaxNode vulnerableSyntaxNode;
                    if (!analyzer.VulnerableSyntaxNodes.TryPop(out vulnerableSyntaxNode))
                        continue;

                    if (!context.Compilation.SyntaxTrees.Contains(vulnerableSyntaxNode.Sink.SyntaxTree))
                        continue;

                    if (!vulnerableSyntaxNode.Suppressed)
                        context.ReportDiagnostic(DiagnosticFactory.Create(GetSupportedDiagnosticAttribute(analyzer).GetDescriptor(), new DiagnosticInfo(vulnerableSyntaxNode.Sink.GetLocation(), vulnerableSyntaxNode.MessageArgs)));
                }
            };
        }
    }
}