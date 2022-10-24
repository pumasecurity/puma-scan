/* 
 * Copyright(c) 2016 - 2020 Puma Security, LLC (https://pumasecurity.io)
 * 
 * Project Leads:
 * Eric Johnson (eric.johnson@pumascan.com)
 * Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using Microsoft.CodeAnalysis;

using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class BaseSyntaxNodeAnalyzer<T> : ISyntaxNodeAnalyzer<T>
    {
        public virtual bool CanSuppress(SemanticModel model, SyntaxNode syntax, DiagnosticId ruleId)
        {
            return false;
        }

        public virtual bool CanIgnore(SemanticModel model, SyntaxNode syntax)
        {
            return false;
        }
    }
}