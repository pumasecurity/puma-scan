/* 
 * Copyright(c) 2016 Puma Security, LLC (https://www.pumascan.com)
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

using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    public class LinqSqlInjectionExpressionAnalyzer : ILinqSqlInjectionExpressionAnalyzer
    {   
        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax)
        {
            if (!ContainsLinqExecuteCommands(syntax))
                return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;

            if (!IsSymbolLinqExecuteCommand(symbol)) return false;

            if (syntax.ArgumentList.Arguments.Count == 1) //No params passed
            {
                return !(syntax.ArgumentList.Arguments[0].Expression is LiteralExpressionSyntax);
            }

            if (syntax.ArgumentList.Arguments.Count > 1)
                //params passed, code could still be doing some string concatation in first param, passing as safe for now
            {
                return syntax.ArgumentList.Arguments[0].Expression is BinaryExpressionSyntax;
            }

            return true;
        }

        private static bool ContainsLinqExecuteCommands(InvocationExpressionSyntax syntax)
         => syntax.ToString().Contains("ExecuteQuery") ||
            syntax.ToString().Contains("ExecuteCommand");

        private bool IsSymbolLinqExecuteCommand(IMethodSymbol symbol)
            => symbol.IsMethod("System.Data.Linq.DataContext", "ExecuteQuery") ||
               symbol.IsMethod("System.Data.Linq.DataContext", "ExecuteCommand");
    }
}