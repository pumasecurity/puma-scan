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

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Text;

namespace Puma.Security.Rules.Common.Extensions
{
    internal static class ExpressionSyntaxExtensions
    {
        internal static bool IsFalse(this ExpressionSyntax syntax)
        {
            return syntax is LiteralExpressionSyntax && syntax?.Kind() == SyntaxKind.FalseLiteralExpression;
        }
    }
}
