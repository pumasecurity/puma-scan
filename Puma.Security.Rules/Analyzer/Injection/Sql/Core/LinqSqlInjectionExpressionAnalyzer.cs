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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    internal class LinqSqlInjectionExpressionAnalyzer : ILinqSqlInjectionExpressionAnalyzer
    {
        public SyntaxNode Source { get; set; }

        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            if (!ContainsLinqExecuteCommands(syntax))
                return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;

            if (!IsSymbolLinqExecuteCommand(symbol)) return false;

            if (syntax.ArgumentList != null && syntax.ArgumentList.Arguments.Any())
            {
                var commandTextArg = syntax.ArgumentList.Arguments[0].Expression;

                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(commandTextArg);

                if (expressionAnalyzer.CanSuppress(model, commandTextArg, ruleId))
                    return false;

                //Set source to analyze and return for further analysis
                Source = commandTextArg;
                return true;
            }
            
            return false;
        }

        private static bool ContainsLinqExecuteCommands(InvocationExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("ExecuteQuery") ||
                   syntax.ToString().Contains("ExecuteCommand");
        }

        private bool IsSymbolLinqExecuteCommand(IMethodSymbol symbol)
        {
            return symbol.IsMethod("System.Data.Linq.DataContext", "ExecuteQuery") ||
                   symbol.IsMethod("System.Data.Linq.DataContext", "ExecuteCommand");
        }
    }
}