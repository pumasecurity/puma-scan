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
using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class SanitizedSourceAnalyzer : ISanitizedSourceAnalyzer
    {
        private readonly ISanitizedMethodSymbolAnalyzer _methodSymbolAnalyzer;
        private readonly ISanitizedLocalSymbolAnalyzer _localSymbolAnalyzer;
        private readonly ISanitizedFieldSymbolAnalyzer _fieldSymbolAnalyzer;
        private readonly ISanitizedParameterSymbolAnalyzer _parameterSymbolAnalyzer;
        private readonly ISanitizedPropertySymbolAnalyzer _propertySymbolAnalyzer;

        internal SanitizedSourceAnalyzer() : this(new CleansedMethodsProvider()) { }

        internal SanitizedSourceAnalyzer(ICleansedMethodsProvider cleansedMethodsProvider)
            : this(new SanitizedMethodSymbolAnalyzer(cleansedMethodsProvider),
                  new SanitizedLocalSymbolAnalyzer(cleansedMethodsProvider),
                  new SanitizedFieldSymbolAnalyzer(cleansedMethodsProvider),
                  new SanitizedParameterSymbolAnalyzer(cleansedMethodsProvider),
                  new SanitizedPropertySymbolAnalyzer(cleansedMethodsProvider))
        {
        }

        internal SanitizedSourceAnalyzer(ISanitizedMethodSymbolAnalyzer methodSymbolAnalyzer, ISanitizedLocalSymbolAnalyzer localSymbolAnalyzer, ISanitizedFieldSymbolAnalyzer fieldSymbolAnalyzer, ISanitizedParameterSymbolAnalyzer parameterSymbolAnalyzer, ISanitizedPropertySymbolAnalyzer propertySymbolAnalyzer)
        {
            _methodSymbolAnalyzer = methodSymbolAnalyzer;
            _localSymbolAnalyzer = localSymbolAnalyzer;
            _fieldSymbolAnalyzer = fieldSymbolAnalyzer;
            _parameterSymbolAnalyzer = parameterSymbolAnalyzer;
            _propertySymbolAnalyzer = propertySymbolAnalyzer;
        }

        public bool IsSymbolSanitized(SymbolInfo symbolInfo, DiagnosticId ruleId)
        {
            //TODO: create a func factory so it can just be magic
            if (CanMethodSymbolBeSanitized(symbolInfo, ruleId)) return true;

            if (CanLocalSymbolBeSanitized(symbolInfo, ruleId)) return true;

            if (CanFieldSymbolBeSanitized(symbolInfo, ruleId)) return true;

            if (CanParameterSymbolBeSanitized(symbolInfo, ruleId)) return true;

            if (CanPropertySymbolBeSanitized(symbolInfo, ruleId)) return true;

            return false;
        }

        private bool CanMethodSymbolBeSanitized(SymbolInfo symbolInfo, DiagnosticId ruleId)
        {
            var methodSymbol = symbolInfo.Symbol as IMethodSymbol;
            if (methodSymbol == null)
                return false;

            return _methodSymbolAnalyzer.IsSymbolSanitized(methodSymbol, ruleId);
        }

        private bool CanLocalSymbolBeSanitized(SymbolInfo symbolInfo, DiagnosticId ruleId)
        {
            var localSymbol = symbolInfo.Symbol as ILocalSymbol;
            if (localSymbol == null)
                return false;

            return _localSymbolAnalyzer.IsSymbolSanitized(localSymbol, ruleId);
        }

        private bool CanFieldSymbolBeSanitized(SymbolInfo symbolInfo, DiagnosticId ruleId)
        {
            var fieldSymbol = symbolInfo.Symbol as IFieldSymbol;
            if (fieldSymbol == null)
                return false;

            return _fieldSymbolAnalyzer.IsSymbolSanitized(fieldSymbol, ruleId);
        }

        private bool CanParameterSymbolBeSanitized(SymbolInfo symbolInfo, DiagnosticId ruleId)
        {
            var parameterSymbol = symbolInfo.Symbol as IParameterSymbol;
            if (parameterSymbol == null)
                return false;

            return _parameterSymbolAnalyzer.IsSymbolSanitized(parameterSymbol, ruleId);
        }

        public bool CanPropertySymbolBeSanitized(SymbolInfo symbolInfo, DiagnosticId ruleId)
        {
            var propertySymbol = symbolInfo.Symbol as IPropertySymbol;
            if (propertySymbol == null)
                return false;

            return _propertySymbolAnalyzer.IsSymbolSanitized(propertySymbol, ruleId);
        }
    }
}