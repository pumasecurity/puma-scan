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
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Deserialization.Core
{
    internal class BinaryFormatterExpressionAnalyzer : IBinaryFormatterExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            if (!ContainsBinaryFormatterCommands(syntax)) return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;

            if (!IsBinaryFormatterCommands(symbol)) return false;

            return true;
        }

        private bool ContainsBinaryFormatterCommands(InvocationExpressionSyntax syntax)
        {
            return ContainsBinaryFormatterDeserializeCommand(syntax) || ContainsBinaryFormatterUnsafeDeserializeCommand(syntax) || ContainsBinaryFormatterUnsafeDeserializeMethodResponseCommand(syntax);
        }

        private bool ContainsBinaryFormatterDeserializeCommand(InvocationExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("Deserialize");
        }

        private bool ContainsBinaryFormatterUnsafeDeserializeCommand(InvocationExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("UnsafeDeserialize");
        }

        private bool ContainsBinaryFormatterUnsafeDeserializeMethodResponseCommand(InvocationExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("UnsafeDeserializeMethodResponse");
        }

        private bool IsBinaryFormatterCommands(IMethodSymbol symbol)
        {
            return IsDeserializeCommand(symbol) || IsUnsafeDeserializeCommand(symbol) || IsUnsafeDeserializeMethodResponseCommand(symbol);
        }

        private bool IsDeserializeCommand(IMethodSymbol symbol)
        {
            return symbol.IsMethod("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter", "Deserialize");
        }

        private bool IsUnsafeDeserializeCommand(IMethodSymbol symbol)
        {
            return symbol.IsMethod("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter", "UnsafeDeserialize");
        }

        private bool IsUnsafeDeserializeMethodResponseCommand(IMethodSymbol symbol)
        {
            return symbol.IsMethod("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter", "UnsafeDeserializeMethodResponse");
        }
    }
}