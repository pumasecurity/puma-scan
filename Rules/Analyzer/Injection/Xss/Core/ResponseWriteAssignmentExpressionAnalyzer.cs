using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Xss.Core
{
    public class ResponseWriteAssignmentExpressionAnalyzer : IResponseWriteAssignmentExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax)
        {
            if (!ContainsResponseWriteCommand(syntax)) return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;

            if (!IsResponseWriteCommand(symbol)) return false;

            if (syntax.ArgumentList.Arguments.Count > 0)
            {
                var argSyntax = syntax.ArgumentList.Arguments[0].Expression;
                var expressionAnalyzer = ExpressionSyntaxAnalyzerFactory.Create(argSyntax);
                if (expressionAnalyzer.CanSuppress(model, argSyntax))
                {
                    return false;
                }

                //TODO: if still vulnerable after eliminating any low hanging fruit - then we need to perform data flow analysis
            }

            return true;
        }

        private static bool ContainsResponseWriteCommand(InvocationExpressionSyntax syntax)
            => syntax.ToString().Contains("Response.Write");


        private bool IsResponseWriteCommand(IMethodSymbol symbol) => symbol.IsMethod("System.Web.HttpResponse", "Write");
    }
}