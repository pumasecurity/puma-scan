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
using Puma.Security.Rules.Analyzer.Crypto;
using Puma.Security.Rules.Base;

namespace Puma.Security.Rules.Suites
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class CryptoDiagnosticSuite : BaseSyntaxDiagnosticSuite
    {
        public CryptoDiagnosticSuite()
        {
            Analyzers = new IAnalyzer[]
            {
                Container.Resolve<DesDiagnosticAnalyzer>(),
                Container.Resolve<EcbDiagnosticAnalyzer>(),
                Container.Resolve<Md5DiagnosticAnalyzer>(),
                Container.Resolve<Sha1DiagnosticAnalyzer>(),
            }.ToImmutableArray();
        }
    }
}
