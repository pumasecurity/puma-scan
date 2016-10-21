using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

using Autofac;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Diagnostics;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Puma.Security.Rules.Base
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class BaseDiagnosticSuite : DiagnosticAnalyzer
    {
        protected IEnumerable<IAnalyzer> Analyzers;
        protected IContainer Container;
        protected IDiagnosticFactory DiagnosticFactory;

        public BaseDiagnosticSuite()
        {
            Container = PumaApp.Instance.Container;
            Analyzers = new List<IAnalyzer>();
            DiagnosticFactory = new DiagnosticFactory();
        }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            {
                if (Analyzers != null && Analyzers.Any())
                {
                    return Analyzers
                        .Select(p => GetSupportedDiagnosticAttribute(p).GetDescriptor())
                        .ToImmutableArray();
                }

                return ImmutableArray.Create<DiagnosticDescriptor>();
            }
        }

        protected static SupportedDiagnosticAttribute GetSupportedDiagnosticAttribute(IAnalyzer analyzer)
        {
            var supportedDiagnosticAttribute = analyzer.GetType()
                .GetCustomAttributes(typeof(SupportedDiagnosticAttribute), true)
                .FirstOrDefault() as SupportedDiagnosticAttribute;

            return supportedDiagnosticAttribute;
        }


        public override void Initialize(AnalysisContext context)
        {
            
        }
    }
}