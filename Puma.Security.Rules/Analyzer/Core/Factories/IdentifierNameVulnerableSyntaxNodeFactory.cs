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

using System;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Core.Factories
{
    internal class IdentifierNameVulnerableSyntaxNodeFactory : IIdentifierNameVulnerableSyntaxNodeFactory
    {
        public VulnerableSyntaxNode Create(IdentifierNameSyntax syntaxNode, params string[] messageArgs)
        {
            if (syntaxNode == null) throw new ArgumentNullException(nameof(syntaxNode));

            return new VulnerableSyntaxNode(syntaxNode, messageArgs);
        }
    }
}
