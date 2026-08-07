/* 
 * Copyright(c) 2016 - 2026 Puma Security, LLC (https://pumasecurity.io)
 * 
 * Project Leads:
 * Eric Johnson (eric.johnson@pumascan.com)
 * Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System.Collections.Concurrent;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class BaseSemanticAnalyzer
    {
        public ConcurrentStack<VulnerableSyntaxNode> VulnerableSyntaxNodes { get; } =
            new ConcurrentStack<VulnerableSyntaxNode>();

        public virtual void GetSinks(SyntaxNodeAnalysisContext context, DiagnosticId ruleId)
        {

        }

        public virtual bool IsSuppressed(SemanticModel model, VulnerableSyntaxNode vulnerableSyntaxNode, DiagnosticId ruleId)
        {
            return false;
        }
    }
}
