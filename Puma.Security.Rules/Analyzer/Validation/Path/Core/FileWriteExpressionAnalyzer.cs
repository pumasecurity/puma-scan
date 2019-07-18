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

namespace Puma.Security.Rules.Analyzer.Validation.Path.Core
{
    internal class FileWriteExpressionAnalyzer : IFileWriteExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            if (!ContainsFileWriteCommands(syntax)) return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;

            if (!IsFileWriteCommand(symbol)) return false;

            if (syntax.ArgumentList.Arguments.Count > 0)
            {
                var argSyntax = syntax.ArgumentList.Arguments[0].Expression;
                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(argSyntax);
                if (expressionAnalyzer.CanIgnore(model, argSyntax))
                    return false;
                if (expressionAnalyzer.CanSuppress(model, argSyntax, ruleId))
                    return false;
            }

            return true;
        }

        private static bool ContainsFileWriteCommands(InvocationExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("File.WriteAllText") ||
                   syntax.ToString().Contains("File.WriteAllLines") ||
                   syntax.ToString().Contains("File.WriteAllBytes");
        }

        private bool IsFileWriteCommand(IMethodSymbol symbol)
        {
            return symbol.IsMethod("System.IO.File", "WriteAllText") ||
                   symbol.IsMethod("System.IO.File", "WriteAllLines") ||
                   symbol.IsMethod("System.IO.File", "WriteAllBytes");
        }
    }
}