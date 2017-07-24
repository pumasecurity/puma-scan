using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Puma.Security.Rules.Analyzer.Injection.Deserialization.Core
{
    public interface IBinaryFormatterExpressionAnalyzer
    {
        bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax);
    }
}
