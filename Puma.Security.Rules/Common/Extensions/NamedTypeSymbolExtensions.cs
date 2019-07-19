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

using Microsoft.CodeAnalysis;

namespace Puma.Security.Rules.Common.Extensions
{
    internal static class NamedTypeSymbolExtensions
    {
        internal static bool InheritsFrom(this INamedTypeSymbol symbol, params string[] args)
        {
            foreach (string s in args)
            {
                var tempSymbol = symbol;

                while (true)
                {
                    //Check the symbol type
                    if (string.Compare(tempSymbol.ToDisplayString(), s, StringComparison.Ordinal) == 0)
                        return true;

                    //If no match, walk up the chain to the base type
                    if (tempSymbol.BaseType != null)
                    {
                        tempSymbol = tempSymbol.BaseType;
                        continue;
                    }

                    //Break when the base type hits null
                    break;
                }
            }

            return false;
        }

        internal static bool InheritsStartsWith(this INamedTypeSymbol symbol, params string[] args)
        {
            foreach (string s in args)
            {
                var tempSymbol = symbol;

                while (true)
                {
                    //Check the symbol type
                    if (tempSymbol.ToDisplayString().StartsWith(s))
                        return true;

                    //If no match, walk up the chain to the base type
                    if (tempSymbol.BaseType != null)
                    {
                        tempSymbol = tempSymbol.BaseType;
                        continue;
                    }

                    //Break when the base type hits null
                    break;
                }
            }

            return false;
        }
    }
}