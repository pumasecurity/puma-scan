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

using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Cmd.Core
{
    internal class ProcessStartCreationExpressionAnalyzer : IProcessStartCreationExpressionAnalyzer
    {
        public SyntaxNode Source { get; set; }

        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            //Cheap check for class & method name
            if (!syntax.Expression.ToString().Contains("Process.Start")) return false;

            //Verify full namesapce
            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
            if (!symbol.IsMethod("System.Diagnostics.Process", "Start"))
                return false;

            //Bail if no arguments to analyze (this is covered by the ProcessStartInfo analyzer)
            if (syntax.ArgumentList?.Arguments.Count == 0)
                return false;

            //Argument 1 is the file / script to execute
            foreach(ArgumentSyntax argumentSyntax in syntax.ArgumentList?.Arguments)
            {
                var expressionSyntax = argumentSyntax.Expression;

                //Cheap analysis before passing back to DFA
                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(expressionSyntax);

                //If cannot ignore and cannot suppress, add to the sources list
                if (!expressionAnalyzer.CanIgnore(model, expressionSyntax)
                    && !expressionAnalyzer.CanSuppress(model, expressionSyntax, ruleId))
                {
                    Source = expressionSyntax;
                    return true;
                }
            }

            ////Argument 2 is the "arguments" passed to the file / script to execute
            //if(syntax.ArgumentList?.Arguments.Count > 1)
            //{
            //    var expressionSyntax = syntax.ArgumentList?.Arguments[1].Expression;

            //    //Cheap analysis before passing back to DFA
            //    var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(expressionSyntax);

            //    //If cannot ignore and cannot suppress, add to the sources list
            //    if (!expressionAnalyzer.CanIgnore(model, expressionSyntax)
            //        && !expressionAnalyzer.CanSuppress(model, expressionSyntax, ruleId))
            //    {
            //        addSourceForAnalysis(expressionSyntax);
            //    }
            //}
            
            return false;
        }
    }
}
