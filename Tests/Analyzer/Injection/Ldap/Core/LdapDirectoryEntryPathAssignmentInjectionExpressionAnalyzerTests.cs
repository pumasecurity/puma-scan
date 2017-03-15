using System;
using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Security.Application;

using NUnit.Framework;

using Puma.Security.Rules.Analyzer.Injection.Ldap.Core;
using Puma.Security.Rules.Test.Helpers;

namespace Puma.Security.Rules.Test.Analyzer.Injection.Ldap.Core
{
    [TestFixture]
    public class LdapDirectoryEntryPathAssignmentInjectionExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new LdapDirectoryEntryPathAssignmentInjectionExpressionAnalyzer();
        }

        private ILdapDirectoryEntryPathAssignmentInjectionExpressionAnalyzer _analyzer;

        private static readonly MetadataReference DirectoryServicesReferences =
           MetadataReference.CreateFromFile(typeof(System.DirectoryServices.DirectoryEntry).Assembly.Location);

        private const string DefaultUsing = @"using System;
                                                    using System.DirectoryServices;";

        private const string LdapDirectoryEntryPathAssignmentToLiteralExpress = @"public class MockObject
                    {
                       public object GetDomainResources2(string domain)
                        {
                            DirectoryEntry entry = new DirectoryEntry();
                            entry.Path = ""LDAP://DC=FOO, DC=COM/"";

                            return entry.Children;
                        }
                    }";

        private static AssignmentExpressionSyntax GetSyntax(TestCode testCode)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().Where(p => p is AssignmentExpressionSyntax).ToList();

            return result.FirstOrDefault(p =>
            {
                var assignementSyntax = p as AssignmentExpressionSyntax;
                var left = assignementSyntax?.Left as MemberAccessExpressionSyntax;
                if (left == null) return false;

                var methodSymbol = testCode.SemanticModel.GetSymbolInfo(left).Symbol as IPropertySymbol;
                return methodSymbol?.ContainingType.Name == "DirectoryEntry" && methodSymbol.Name == "Path";

            }) as AssignmentExpressionSyntax;
        }

        [TestCase(LdapDirectoryEntryPathAssignmentToLiteralExpress, false)]
        public void TestIsVulnerable(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, DirectoryServicesReferences);

            var rightSyntax = GetSyntax(testCode);

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, rightSyntax);

            Assert.AreEqual(expectedResult, result);
        }
        
    }
}