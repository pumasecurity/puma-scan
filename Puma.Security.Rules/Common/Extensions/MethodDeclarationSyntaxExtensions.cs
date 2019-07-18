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

using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Common.Extensions
{
    internal static class MethodDeclarationSyntaxExtensions
    {
        internal static IdentifierNameSyntax GetMethodReturnType(this MethodDeclarationSyntax syntax)
        {
            IdentifierNameSyntax returnType = null;

            if (syntax?.ReturnType is GenericNameSyntax)
            {
                var generic = syntax?.ReturnType as GenericNameSyntax;
                if (generic.TypeArgumentList.Arguments.Count > 0)
                    returnType = generic.TypeArgumentList.Arguments[0] as IdentifierNameSyntax;
            }

            if (syntax?.ReturnType is IdentifierNameSyntax)
                returnType = syntax?.ReturnType as IdentifierNameSyntax;

            return returnType;
        }
    }
}