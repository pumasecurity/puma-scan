using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

using Autofac;
using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Analyzer.Injection.Deserialization;
using Puma.Security.Rules.Base;

namespace Puma.Security.Rules.Suites
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class DeserializationDiagnosticSuite : BaseSyntaxDiagnosticSuite
    {
        public DeserializationDiagnosticSuite()
        {
            Analyzers = new IAnalyzer[]
            {
                Container.Resolve<NewtonsoftJsonTypeNameHandlingAnalyzer>(),
                Container.Resolve<BinaryFormatterAnalyzer>(),
            }.ToImmutableArray();
        }
    }
}
