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

using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    internal class SqlCommandInjectionObjectCreationExpressionAnalyzer : ISqlCommandInjectionObjectCreationExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            if (!ContainsSqlCommand(syntax))
                return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
            if (!IsSymbolSqlCommand(symbol))
                return false;

            if (syntax.ArgumentList != null && syntax.ArgumentList.Arguments.Any())
            {
                var commandTextArg = syntax.ArgumentList.Arguments[0].Expression;

                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(commandTextArg);
                if (expressionAnalyzer.CanIgnore(model, commandTextArg))
                    return false;
                if (expressionAnalyzer.CanSuppress(model, commandTextArg, ruleId))
                    return false;
            }

            var commandTextInitializer =
                syntax.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                    .FirstOrDefault(p =>
                    {
                        var nameSyntax = p.Left as IdentifierNameSyntax;
                        return nameSyntax?.Identifier.ValueText == "CommandText";
                    });

            if (commandTextInitializer != null)
            {
                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(commandTextInitializer);
                if (expressionAnalyzer.CanIgnore(model, commandTextInitializer))
                    return false;
                if (expressionAnalyzer.CanSuppress(model, commandTextInitializer, ruleId))
                    return false;
            }

            return commandTextInitializer != null || (syntax.ArgumentList != null && syntax.ArgumentList.Arguments.Any());
        }

        private bool IsSymbolSqlCommand(IMethodSymbol symbol)
        {
            return  symbol.IsCtorFor("System.Data.SqlClient.SqlCommand") ||
                    symbol.IsCtorFor("Microsoft.Data.Sqlite.SqliteCommand");
        }


        private static bool ContainsSqlCommand(ObjectCreationExpressionSyntax syntax)
        {
            return  syntax.ToString().Contains("SqlCommand") ||
                    syntax.ToString().Contains("SqliteCommand");
        }
    }
}