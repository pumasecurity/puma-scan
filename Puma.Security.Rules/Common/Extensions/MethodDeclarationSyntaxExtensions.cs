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

namespace Puma.Security.Rules.Common.Extensions
{
    internal static class MethodDeclarationSyntaxExtensions
    {
        internal static bool ContainsReturnType(this MethodDeclarationSyntax syntax, SemanticModel model, params string[] args)
        {
            foreach (SyntaxNode node in syntax.ReturnType.DescendantNodesAndSelf())
            {
                //Grab the return type symbol and return if it is not a named type
                var symbol = model.GetSymbolInfo(node).Symbol as INamedTypeSymbol;
                if (symbol == null)
                    continue;

                //Check the symbol for the 
                if (symbol.InheritsStartsWith(args))
                    return true;
            }

            return false;
        }
    }
}