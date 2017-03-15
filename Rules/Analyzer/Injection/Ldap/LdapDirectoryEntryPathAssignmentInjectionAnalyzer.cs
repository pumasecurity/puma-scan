using System.Collections.Generic;

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer.Injection.Ldap.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Analyzer.Injection.Ldap
{
    [SupportedDiagnostic(DiagnosticId.SEC0114)]
    public class LdapDirectoryEntryPathAssignmentInjectionAnalyzer : ISyntaxNodeAnalyzer
    {
        private readonly ILdapDirectoryEntryPathAssignmentInjectionExpressionAnalyzer _expressionSyntaxAnalyzer;

        public LdapDirectoryEntryPathAssignmentInjectionAnalyzer(ILdapDirectoryEntryPathAssignmentInjectionExpressionAnalyzer expressionSyntaxAnalyzer)
        {
            _expressionSyntaxAnalyzer = expressionSyntaxAnalyzer;
        }

        public SyntaxKind Kind => SyntaxKind.SimpleAssignmentExpression;

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(SyntaxNodeAnalysisContext context)
        {
            var result = new List<DiagnosticInfo>();
            var syntax = context.Node as AssignmentExpressionSyntax;

            if (!_expressionSyntaxAnalyzer.IsVulnerable(context.SemanticModel, syntax))
                return result;

            result.Add(new DiagnosticInfo(syntax.GetLocation()));

            return result;
        }
    }
}