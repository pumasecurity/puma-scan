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

using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis;

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Configuration.Core;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class SanitizedParameterSymbolAnalyzer : ISanitizedParameterSymbolAnalyzer
    {
        private readonly ICleansedMethodsProvider _cleansedMethodsProvider;
       
        internal SanitizedParameterSymbolAnalyzer(ICleansedMethodsProvider cleansedMethodsProvider)
        {
            _cleansedMethodsProvider = cleansedMethodsProvider;
        }

        public bool IsSymbolSanitized(IParameterSymbol parameterSymbol, DiagnosticId ruleId)
        {
            //Filter by namespace
            IEnumerable<CleanseMethod> methods = _cleansedMethodsProvider.GetByRuleId(ruleId).Where(i => string.Compare(i.Namespace, parameterSymbol.ContainingNamespace.ToString()) == 0);
            if (methods.Count() == 0)
                return false;

            //Filter by type: ContainingType (Namespace.Type)
            methods = methods.Where(i => i.Type.Equals("*") || string.Compare(string.Join(".", i.Namespace, i.Type), parameterSymbol.ContainingType.ToDisplayString()) == 0);
            if (methods.Count() == 0)
                return false;

            //Filter by method name
            methods = methods.Where(i => i.Method.Equals("*") || string.Compare(i.Method, parameterSymbol.Name) == 0);
            if (methods.Count() == 0)
                return false;

            return true;
        }
    }
}