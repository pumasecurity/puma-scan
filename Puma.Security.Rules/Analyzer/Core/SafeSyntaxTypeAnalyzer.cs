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
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Configuration.Core;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class SafeSyntaxTypeAnalyzer : ISafeSyntaxTypeAnalyzer
    {
        private IEnumerable<CleanseMethod> GetSafeSyntaxTypes()
        {
            var sources = new List<CleanseMethod>();

            sources.Add(new CleanseMethod(TaintFlags.System, typeof(PredefinedTypeSyntax).Name, "System", "Decimal", ""));
            sources.Add(new CleanseMethod(TaintFlags.System, typeof(PredefinedTypeSyntax).Name, "System", "Double", ""));
            sources.Add(new CleanseMethod(TaintFlags.System, typeof(PredefinedTypeSyntax).Name, "System", "DateTime", ""));
            sources.Add(new CleanseMethod(TaintFlags.System, typeof(PredefinedTypeSyntax).Name, "System", "DateTimeOffset", ""));
            sources.Add(new CleanseMethod(TaintFlags.System, typeof(PredefinedTypeSyntax).Name, "System", "Int16", ""));
            sources.Add(new CleanseMethod(TaintFlags.System, typeof(PredefinedTypeSyntax).Name, "System", "Int32", ""));
            sources.Add(new CleanseMethod(TaintFlags.System, typeof(PredefinedTypeSyntax).Name, "System", "Int64", ""));
            sources.Add(new CleanseMethod(TaintFlags.System, typeof(PredefinedTypeSyntax).Name, "System", "Guid", ""));

            return sources;
        }

        public bool IsSafeSyntaxType(SymbolInfo symbolInfo)
        {
            if (IsMethodSymbolSafeType(symbolInfo)) return true;

            if (IsLocalSymbolSafeType(symbolInfo)) return true;

            if (IsFieldSymbolSafeType(symbolInfo)) return true;

            if (IsParameterSymbolSafeType(symbolInfo)) return true;

            if (IsPropertySymbolSafeType(symbolInfo)) return true;

            return false;
        }

        private bool IsPropertySymbolSafeType(SymbolInfo symbolInfo)
        {
            var propertySymbol = symbolInfo.Symbol as IPropertySymbol;
            if (propertySymbol != null)
            {
                if (this.IsSafeSyntaxType(propertySymbol.Type))
                    return true;
            }
            return false;
        }

        private bool IsParameterSymbolSafeType(SymbolInfo symbolInfo)
        {
            var parameterSymbol = symbolInfo.Symbol as IParameterSymbol;
            if (parameterSymbol != null)
            {
                if (this.IsSafeSyntaxType(parameterSymbol.Type))
                    return true;
            }
            return false;
        }

        private bool IsFieldSymbolSafeType(SymbolInfo symbolInfo)
        {
            var fieldSymbol = symbolInfo.Symbol as IFieldSymbol;
            if (fieldSymbol != null)
            {
                if (this.IsSafeSyntaxType(fieldSymbol.Type))
                    return true;
            }
            return false;
        }

        private bool IsLocalSymbolSafeType(SymbolInfo symbolInfo)
        {
            var localSymbol = symbolInfo.Symbol as ILocalSymbol;
            if (localSymbol != null)
            {
                if (this.IsSafeSyntaxType(localSymbol.Type))
                    return true;
            }
            return false;
        }

        private bool IsMethodSymbolSafeType(SymbolInfo symbolInfo)
        {
            var methodSymbol = symbolInfo.Symbol as IMethodSymbol;
            if (methodSymbol != null)
            {
                //TODO: DETERMINE IF WE NEED A SWTICH TO DRIVE RETURN TYPE ONLY VS RECEIVER TYPE ONLY INSTEAD OF RUNNING BOTH
                //Check for return type strong syntax
                if (this.IsSafeSyntaxType(methodSymbol.ReturnType))
                    return true;

                //Check for return type receiver type
                if (this.IsSafeSyntaxType(methodSymbol.ReceiverType))
                    return true;
            }
            return false;
        }

        public bool IsSafeSyntaxType(ISymbol symbol)
        {
            var typeToCheck = symbol;
            if (symbol.Name.ToLower() == "nullable")
            {
                var namedType = symbol as INamedTypeSymbol;
                if (namedType == null)
                    return false;

                var ctor = namedType.Constructors.FirstOrDefault(p => p.Parameters.Length > 0);
                if (ctor != null)
                {
                    typeToCheck = ctor.Parameters[0].Type;
                }
            }

            //Filter by system namespace
            IEnumerable<CleanseMethod> methods = GetSafeSyntaxTypes().Where(i => string.Compare(i.Namespace, typeToCheck.ContainingNamespace?.ToString()) == 0);
            if (methods.Count() == 0)
                return false;

            //Filter by type: NamedType.Name (Int32, etc.)
            methods = methods.Where(i => string.Compare(i.Type, typeToCheck.Name) == 0);
            if (methods.Count() == 0)
                return false;

            return true;
        }
    }
}