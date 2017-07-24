using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Puma.Security.Rules.Analyzer.Injection.Deserialization.Core
{
    public class BinaryFormatterExpressionAnalyzer : IBinaryFormatterExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax)
        {
            if (!ContainsBinaryFormatterCommands(syntax)) return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;

            if (!IsBinaryFormatterCommands(symbol)) return false;

            //TODO: CodeBlock analysis to see if the bytes come from a trusted source.
            //For now, flagging as dangerous method.

            return true;
        }

        private bool ContainsBinaryFormatterCommands(InvocationExpressionSyntax syntax)
            => ContainsBinaryFormatterDeserializeCommand(syntax) || ContainsBinaryFormatterUnsafeDeserializeCommand(syntax) || ContainsBinaryFormatterUnsafeDeserializeMethodResponseCommand(syntax);
        private bool ContainsBinaryFormatterDeserializeCommand(InvocationExpressionSyntax syntax)
            => syntax.ToString().Contains("Deserialize");

        private bool ContainsBinaryFormatterUnsafeDeserializeCommand(InvocationExpressionSyntax syntax)
            => syntax.ToString().Contains("UnsafeDeserialize");

        private bool ContainsBinaryFormatterUnsafeDeserializeMethodResponseCommand(InvocationExpressionSyntax syntax)
            => syntax.ToString().Contains("UnsafeDeserializeMethodResponse");

        private bool IsBinaryFormatterCommands(IMethodSymbol symbol)
            => IsDeserializeCommand(symbol) || IsUnsafeDeserializeCommand(symbol) || IsUnsafeDeserializeMethodResponseCommand(symbol);

        private bool IsDeserializeCommand(IMethodSymbol symbol) => symbol.IsMethod("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter", "Deserialize");

        private bool IsUnsafeDeserializeCommand(IMethodSymbol symbol) => symbol.IsMethod("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter", "UnsafeDeserialize");

        private bool IsUnsafeDeserializeMethodResponseCommand(IMethodSymbol symbol) => symbol.IsMethod("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter", "UnsafeDeserializeMethodResponse");
    }
}
