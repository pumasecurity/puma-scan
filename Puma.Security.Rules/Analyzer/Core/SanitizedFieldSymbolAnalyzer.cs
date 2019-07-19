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

using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis;

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Configuration.Core;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class SanitizedFieldSymbolAnalyzer : ISanitizedFieldSymbolAnalyzer
    {
        private readonly ICleansedMethodsProvider _cleansedMethodsProvider;

        internal SanitizedFieldSymbolAnalyzer(ICleansedMethodsProvider cleansedMethodsProvider)
        {
            _cleansedMethodsProvider = cleansedMethodsProvider;
        }

        public bool IsSymbolSanitized(IFieldSymbol fieldSymbol, DiagnosticId ruleId)
        {
            //Filter by namespace
            IEnumerable<CleanseMethod> methods = _cleansedMethodsProvider.GetByRuleId(ruleId).Where(i => string.Compare(i.Namespace, fieldSymbol.ContainingNamespace.ToString()) == 0);
            if (methods.Count() == 0)
                return false;

            //Filter by type: ContainingType (Namespace.Type)
            //exection to rule for "string". ToDisplayName is "string" and not "System.String"
            methods = methods.Where(i => i.Type.Equals("*") || string.Compare(string.Join(".", i.Namespace, i.Type).Replace("System.String", "string"), fieldSymbol.ContainingType.ToDisplayString()) == 0);
            if (methods.Count() == 0)
                return false;

            //Filter by method name
            methods = methods.Where(i => i.Method.Equals("*") || string.Compare(i.Method, fieldSymbol.Name) == 0);
            if (methods.Count() == 0)
                return false;

            //If we hit this, then the cleanse method exists and we can return true
            return true;
        }
    }
}