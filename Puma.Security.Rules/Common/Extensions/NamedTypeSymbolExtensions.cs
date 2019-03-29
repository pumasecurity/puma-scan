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

using System;

using Microsoft.CodeAnalysis;

namespace Puma.Security.Rules.Common.Extensions
{
    internal static class NamedTypeSymbolExtensions
    {
        internal static bool SymbolInheritsFrom(this INamedTypeSymbol symbol, string baseTypeFullName)
        {
            while (true)
            {
                //Check the symbol type
                if (string.Compare(symbol.ToDisplayString(), baseTypeFullName, StringComparison.Ordinal) == 0)
                    return true;

                //If no match, walk up the chain to the base type
                if (symbol.BaseType != null)
                {
                    symbol = symbol.BaseType;
                    continue;
                }

                //Break when the base type hits null
                break;
            }

            return false;
        }
    }
}