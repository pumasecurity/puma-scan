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
    internal class EfQueryCommandInjectionExpressionAnalyzer : IEfQueryCommandInjectionExpressionAnalyzer
    {
        public SyntaxNode Source { get; set; }

        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            if (!ContainsEfRawSqlCommands(syntax)) return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;

            if (!IsSymbolEfRawSqlCommand(symbol)) return false;

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

            //Default return false
            return false;
        }

        private bool IsSymbolEfRawSqlCommand(IMethodSymbol symbol)
        {
            return symbol != null && (
                       symbol.IsMethod("System.Data.Entity.Database", "SqlQuery") ||
                       symbol.IsMethod("System.Data.Entity.DbSet<TEntity>", "SqlQuery") ||
                       symbol.IsMethod("Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade", "SqlQuery") ||
                       symbol.IsMethod("System.Data.Entity.Database", "ExecuteSqlCommand") ||
                       symbol.IsMethod("Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade", "ExecuteSqlCommand") ||
                       symbol.IsMethod("System.Data.Entity.Database", "ExecuteSqlCommandAsync") ||
                       symbol.IsMethod("Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade", "ExecuteSqlCommandAsync") ||
                       symbol.OriginalDefinition.IsMethod("System.Linq.IQueryable<TEntity>", "FromSql"));
        }


        private static bool ContainsEfRawSqlCommands(InvocationExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("SqlQuery") ||
                   syntax.ToString().Contains("ExecuteSqlCommand") ||
                   syntax.ToString().Contains("ExecuteSqlCommandAsync") ||
                   syntax.ToString().Contains("FromSql");
        }
    }
}