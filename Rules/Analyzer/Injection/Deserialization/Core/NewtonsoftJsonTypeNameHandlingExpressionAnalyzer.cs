using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Puma.Security.Rules.Analyzer.Injection.Deserialization.Core
{
    public class NewtonsoftJsonTypeNameHandlingExpressionAnalyzer : INewtonsoftJsonTypeNameHandlingExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, AssignmentExpressionSyntax syntax)
        {
            //2 cases here: x.TypeNameHandling or { TypeNameHandling = }
            if (syntax?.Left is MemberAccessExpressionSyntax)
            {
                var leftSyntax = syntax?.Left as MemberAccessExpressionSyntax;
                if (leftSyntax == null || string.Compare(leftSyntax.Name.Identifier.ValueText, "TypeNameHandling", true) != 0)
                    return false;

                var leftSymbol = model.GetSymbolInfo(leftSyntax.Name).Symbol as IPropertySymbol;
                if (leftSymbol == null || string.Compare(leftSymbol.Type.ToString(), "Newtonsoft.Json.TypeNameHandling", true) != 0)
                    return false;

                var rightSyntax = syntax?.Right as MemberAccessExpressionSyntax;
                if (rightSyntax == null || string.Compare(rightSyntax.Name.Identifier.ValueText, "None", true) == 0)
                    return false;

                return true;
            }
            else if(syntax?.Left is IdentifierNameSyntax)
            {
                var leftSyntax = syntax?.Left as IdentifierNameSyntax;
                if (leftSyntax == null || string.Compare(leftSyntax.Identifier.ValueText, "TypeNameHandling", true) != 0)
                    return false;

                var leftSymbol = model.GetSymbolInfo(leftSyntax).Symbol as IPropertySymbol;
                if (leftSymbol == null || string.Compare(leftSymbol.Type.ToString(), "Newtonsoft.Json.TypeNameHandling", true) != 0)
                    return false;

                var rightSyntax = syntax?.Right as MemberAccessExpressionSyntax;
                if (rightSyntax == null || string.Compare(rightSyntax.Name.Identifier.ValueText, "None", true) == 0)
                    return false;

                return true;
            }

            return false;
        }
    }
}
