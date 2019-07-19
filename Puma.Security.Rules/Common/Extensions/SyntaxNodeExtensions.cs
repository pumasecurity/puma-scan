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
    internal static class SyntaxNodeExtensions
    {
        internal static SyntaxNode TrimTrivia(this SyntaxNode node)
        {
            return node.WithoutLeadingTrivia().WithoutTrailingTrivia();
        }

        internal static ClassDeclarationSyntax GetClassDeclaration(this SyntaxNode syntax)
        {
            while (true)
            {
                //Check the symbol type
                if (syntax is ClassDeclarationSyntax)
                    return syntax as ClassDeclarationSyntax;

                //If no match, walk up the chain to the base type
                if (syntax.Parent != null)
                {
                    syntax = syntax.Parent;
                    continue;
                }

                //Break when the base type hits null
                break;
            }

            return null;
        }
    }
}