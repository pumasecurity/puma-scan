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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    internal class EfQueryCommandInjectionExpressionAnalyzer : IEfQueryCommandInjectionExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax)
        {
            if (!ContainsEfRawSqlCommands(syntax)) return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;

            if (!IsSymbolEfRawSqlCommand(symbol)) return false;

            if (syntax.ArgumentList != null && syntax.ArgumentList.Arguments.Any())
            {
                var commandTextArg = syntax.ArgumentList.Arguments[0];

                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(commandTextArg);
                if (expressionAnalyzer.CanSuppress(model, commandTextArg))
                    return false;
            }

            return true;
        }

        private bool IsSymbolEfRawSqlCommand(IMethodSymbol symbol)
        {
            return symbol.IsMethod("System.Data.Entity.Database", "SqlQuery") ||
                   symbol.IsMethod("System.Data.Entity.DbSet<TEntity>", "SqlQuery") ||
                   symbol.IsMethod("System.Data.Entity.Database", "ExecuteSqlCommand") ||
                   symbol.IsMethod("System.Data.Entity.Database", "ExecuteSqlCommandAsync");
        }


        private static bool ContainsEfRawSqlCommands(InvocationExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("SqlQuery") ||
                   syntax.ToString().Contains("ExecuteSqlCommand") ||
                   syntax.ToString().Contains("ExecuteSqlCommandAsync");
        }
    }
}