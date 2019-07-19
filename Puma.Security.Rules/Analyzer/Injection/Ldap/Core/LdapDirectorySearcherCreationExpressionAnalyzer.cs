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

namespace Puma.Security.Rules.Analyzer.Injection.Ldap.Core
{
    internal class LdapDirectorySearcherCreationExpressionAnalyzer : ILdapDirectorySearcherCreationExpressionAnalyzer
    {
        public SyntaxNode Source { get; set; }

        public bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            //Cheap check for class name
            if (!syntax.ToString().Contains("DirectorySearcher")) return false;

            //Verify full namespace
            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
            if (!symbol.IsCtorFor("System.DirectoryServices.DirectorySearcher"))
                return false;

            //Bail if no initializers or arguments to analyze
            if (syntax.Initializer?.Expressions.Count == 0 && syntax.ArgumentList?.Arguments.Count == 0)
                return false;

            //Option 1: Check the initializers for the "Filter" property
            if (syntax.Initializer?.Expressions.Count > 0)
            {
                var filter = syntax.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                   .FirstOrDefault(p => (p.Left as IdentifierNameSyntax)?.Identifier.ValueText == "Filter");

                if (filter != null)
                {
                    var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(filter.Right);
                    if (expressionAnalyzer.CanIgnore(model, filter.Right))
                        return false;
                    if (expressionAnalyzer.CanSuppress(model, filter.Right, ruleId))
                        return false;

                    //Right expression needs more analysis in DFA
                    Source = filter.Right;
                    return true;
                }

                return false;
            }

            //Option 2: Check the argument list for the "filter" parameter
            if (syntax.ArgumentList?.Arguments.Count > 0)
            {
                //This is a bitch because overloads send the "filter" in different parameter positions
                //public DirectorySearcher(string filter)
                //public DirectorySearcher(string filter, string[] propertiesToLoad)
                //public DirectorySearcher(DirectoryEntry searchRoot, string filter, string[] propertiesToLoad)
                //public DirectorySearcher(string filter, string[] propertiesToLoad, SearchScope scope)
                //public DirectorySearcher(DirectoryEntry searchRoot, string filter, string[] propertiesToLoad, SearchScope scope)
                //Solution: Check the 2st parameter first, this is always filter. 
                //If not, check the 1st parm and see if it's a DirectoryEntry object, if not its the filter

                ExpressionSyntax expressionSyntax = null;
                if (syntax.ArgumentList?.Arguments.Count > 1)
                    expressionSyntax = syntax.ArgumentList?.Arguments[1].Expression;
                else
                {
                    expressionSyntax = syntax.ArgumentList?.Arguments[0].Expression;

                    //Quick symbol check to weed out directory entry objects in parm 0 position
                    var expressionSymbol = model.GetSymbolInfo(expressionSyntax).Symbol as ISymbol;

                    //Weed out directory entry objects
                    if (expressionSymbol != null && expressionSymbol.OriginalDefinition != null &&
                        expressionSymbol.OriginalDefinition.ToString().StartsWith("System.DirectoryServices.DirectoryEntry"))
                        expressionSyntax = null;

                    //Weed out local objects that are base directory entry
                    var localExpressionSymbol = expressionSymbol as ILocalSymbol;
                    if (localExpressionSymbol?.Type.ToString() == "System.DirectoryServices.DirectoryEntry")
                        expressionSyntax = null;
                }
                
                //If no string expression syntax type, bail out
                if (expressionSyntax == null)
                    return false;

                //Cheap checks for suppression before registering for DFA
                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(expressionSyntax);
                if (expressionAnalyzer.CanIgnore(model, expressionSyntax))
                    return false;
                if (expressionAnalyzer.CanSuppress(model, expressionSyntax, ruleId))
                    return false;

                //Filter param needs more advanced analysis
                Source = expressionSyntax;
                return true;
            }

            return false;
        }
    }
}