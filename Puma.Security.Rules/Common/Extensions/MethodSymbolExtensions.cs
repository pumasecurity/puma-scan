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

namespace Puma.Security.Rules.Common.Extensions
{
    internal static class MethodSymbolExtensions
    {
        internal static bool IsMethod(this IMethodSymbol symbol, string sourceObjectType, string methodName)
        {
            return symbol?.Name == methodName &&
                   (symbol?.ReceiverType.ToString() == sourceObjectType || symbol?.ReceiverType.OriginalDefinition.ToString() == sourceObjectType);
        }

        internal static bool IsMethod(this IMethodSymbol symbol, string sourceObjectType, string methodName, bool checkNamespaceStartsWith)
        {
            return symbol != null &&
                    symbol.Name == methodName &&
                   (symbol.ReceiverType.ToString().StartsWith(sourceObjectType) || symbol.ReceiverType.OriginalDefinition.ToString().StartsWith(sourceObjectType));
        }

        internal static bool DoesMethodContain(this IMethodSymbol symbol, string sourceObjectType, string methodName)
        {
            return symbol != null &&
                    symbol.Name.Contains(methodName) &&
                   (symbol.ReceiverType.ToString() == sourceObjectType || symbol.ReceiverType.OriginalDefinition.ToString() == sourceObjectType);
        }

        internal static bool DoesMethodContain(this IMethodSymbol symbol, string sourceObjectType, string methodName, bool checkNamespaceStartsWith)
        {
            return symbol != null &&
                    symbol.Name.Contains(methodName) &&
                   (symbol.ReceiverType.ToString().StartsWith(sourceObjectType) || symbol.ReceiverType.OriginalDefinition.ToString().StartsWith(sourceObjectType));
        }

        internal static bool IsCtorFor(this IMethodSymbol symbol, string sourceObjectType)
        {
            return symbol?.MethodKind == MethodKind.Constructor &&
                   symbol?.ReceiverType.ToString() == sourceObjectType;
        }
    }
}