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

using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Cmd.Core
{
    internal class ProcessStartInvocationExpressionAnalyzer : IProcessStartInvocationExpressionAnalyzer
    {
        public List<SyntaxNode> Sources { get; set; }

        public ProcessStartInvocationExpressionAnalyzer()
        {
            if (Sources == null) Sources = new List<SyntaxNode>();
        }

        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            //These persist from previous invocations (clear before staring)
            //TODO: Make this lock during execution until we call ToImmutableArray() after this is done
            this.Sources.Clear();

            //Cheap check for class & method name
            if (!syntax.Expression.ToString().Contains("Process.Start")) return false;

            //Verify full namesapce
            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
            if (!symbol.IsMethod("System.Diagnostics.Process", "Start"))
                return false;

            //Bail if no arguments to analyze (this is covered by the ProcessStartInfo analyzer)
            if (syntax.ArgumentList?.Arguments.Count == 0)
                return false;

            //Lots of weird cases here
            //: 1 argument (no)
            //: 2 arguments (string filename, string arguments)
            //: 4 arguments (string filename, no, no, no)
            //: 5 argumnets (string filename, string arguments, no, no, no)

            if (syntax.ArgumentList?.Arguments.Count == 1 || syntax.ArgumentList?.Arguments.Count == 4)
            {
                var fileNameSyntax = syntax.ArgumentList?.Arguments[0].Expression;

                //Custom cheap check, weed out the process start info type
                var fileNameSymbol = model.GetSymbolInfo(fileNameSyntax).Symbol as ILocalSymbol;
                if (string.Compare(fileNameSymbol?.Type.ToString(), "System.Diagnostics.ProcessStartInfo") == 0)
                    return false;

                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(fileNameSyntax);
                if (!expressionAnalyzer.CanIgnore(model, fileNameSyntax)
                    && !expressionAnalyzer.CanSuppress(model, fileNameSyntax, ruleId))
                {
                    this.Sources.Add(fileNameSyntax);
                }

            }
            else if (syntax.ArgumentList?.Arguments.Count == 2 || syntax.ArgumentList?.Arguments.Count == 5)
            {
                var fileNameSyntax = syntax.ArgumentList?.Arguments[0].Expression;
                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(fileNameSyntax);
                if (!expressionAnalyzer.CanIgnore(model, fileNameSyntax)
                    && !expressionAnalyzer.CanSuppress(model, fileNameSyntax, ruleId))
                {
                    this.Sources.Add(fileNameSyntax);
                }

                var argumenetSyntax = syntax.ArgumentList.Arguments[1].Expression;
                expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(argumenetSyntax);
                if (!expressionAnalyzer.CanIgnore(model, argumenetSyntax)
                    && !expressionAnalyzer.CanSuppress(model, argumenetSyntax, ruleId))
                {
                    this.Sources.Add(argumenetSyntax);
                }
            }

            return Sources != null && Sources.Count > 0;
        }
    }
}
