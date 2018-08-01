/* 
 * Copyright(c) 2016 - 2018 Puma Security, LLC (https://www.pumascan.com)
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
using Puma.Security.Rules.Common;
using System.Collections.Generic;

namespace Puma.Security.Rules.Analyzer.Injection.Cmd.Core
{
    internal interface IProcessStartCreationExpressionAnalyzer
    {
        bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax, DiagnosticId ruleId);

        SyntaxNode Source { get; set; }
    }
}
