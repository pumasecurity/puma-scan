/* 
 * Copyright(c) 2016 - 2017 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System.Linq;

using Puma.Security.Rules.Test.Helpers;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using NUnit.Framework;

using Puma.Security.Rules.Analyzer.Injection.Ldap.Core;

namespace Puma.Security.Rules.Test.Analyzer.Injection.Ldap.Core
{
    [TestFixture]
    public class LdapDirectorySearcherInjectionExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new LdapDirectorySearcherInjectionExpressionAnalyzer();
        }

        private LdapDirectorySearcherInjectionExpressionAnalyzer _analyzer;

        private static readonly MetadataReference DirectoryServicesReferences =
            MetadataReference.CreateFromFile(typeof(System.DirectoryServices.DirectoryEntry).Assembly.Location);

        private const string DefaultUsing = @"using System;
                                                    using System.DirectoryServices;";


        private const string LdapFindAllFilterExpressionAssignmentWithVulnerableBinaryExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");

                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.SearchScope = SearchScope.Subtree;

                searcher.Filter = "" (|(type="" + types[0] + "" ) (type="" + types[1] + ""))"";

                resultCollection = searcher.FindAll();

                return resultCollection;
            }    
        }";

        private const string LdapFindAllFilterExpressionAssignmentWithLiteralExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");

                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.SearchScope = SearchScope.Subtree;

                searcher.Filter = "" (|(type=printer) (type=scanner))"";

                resultCollection = searcher.FindAll();

                return resultCollection;
            }    
        }";

        private const string LdapFindAllFilterConstructorParamWithVulnerableExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");

                DirectorySearcher searcher = new DirectorySearcher(entry, "" (| (type = "" + types[0] + "")(type = "" + types[1] + ""))"");
                searcher.SearchScope = SearchScope.Subtree;

                searcher.Filter = "" (|(type=printer) (type=scanner))"";

                resultCollection = searcher.FindAll();

                return resultCollection;
            }    
        }";

        private const string LdapFindAllFilterConstructorParamWithLiteralExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectorySearcher searcher = new DirectorySearcher(new DirectoryEntry(""LDAP://DC=FOO, DC=COM/""), "" (|(type=printer) (type=scanner))"");
                searcher.SearchScope = SearchScope.Subtree;

                searcher.Filter = "" (|(type=printer) (type=scanner))"";

                resultCollection = searcher.FindAll();

                return resultCollection;
            }    
        }";

        private const string LdapFindAllFilterConstructorParamWithLiteralExpressionV2 = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression, DirectoryEntry entry)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectorySearcher searcher = new DirectorySearcher(entry, "" (|(type=printer) (type=scanner))"");
                searcher.SearchScope = SearchScope.Subtree;

                searcher.Filter = "" (|(type=printer) (type=scanner))"";

                resultCollection = searcher.FindAll();

                return resultCollection;
            }    
        }";

        private const string LdapFindAllFilterObjectInitializerWithVulnerableExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");

                DirectorySearcher searcher = new DirectorySearcher(entry)
                {
                    Filter = ""(|(type="" + types[0] + "" ) (type="" + types[1] + ""))""
                };

                searcher.SearchScope = SearchScope.Subtree;

                resultCollection = searcher.FindAll();

                return resultCollection;
            }    
        }";

        private const string LdapFindAllFilterObjectInitializerWithLiteralExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");

                DirectorySearcher searcher = new DirectorySearcher(entry)
                {
                    Filter = "" (|(type=printer) (type=scanner))""
                };

                searcher.SearchScope = SearchScope.Subtree;

                resultCollection = searcher.FindAll();

                return resultCollection;
            }    
        }";

        private const string LdapFindOneFilterExpressionAssignmentWithVulnerableBinaryExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");

                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.SearchScope = SearchScope.Subtree;

                searcher.Filter = "" (|(type="" + types[0] + "" ) (type="" + types[1] + ""))"";

                resultCollection = searcher.FindOne();

                return resultCollection;
            }    
        }";

        private const string LdapFindOneFilterExpressionAssignmentWithLiteralExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");

                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.SearchScope = SearchScope.Subtree;

                searcher.Filter = "" (|(type=printer) (type=scanner))"";

                resultCollection = searcher.FindOne();

                return resultCollection;
            }    
        }";

        private const string LdapFindOneFilterConstructorParamWithVulnerableExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");

                DirectorySearcher searcher = new DirectorySearcher(entry, "" (| (type = "" + types[0] + "")(type = "" + types[1] + ""))"");
                searcher.SearchScope = SearchScope.Subtree;

                searcher.Filter = "" (|(type=printer) (type=scanner))"";

                resultCollection = searcher.FindOne();

                return resultCollection;
            }    
        }";

        private const string LdapFindOneFilterConstructorParamWithLiteralExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectorySearcher searcher = new DirectorySearcher(new DirectoryEntry(""LDAP://DC=FOO, DC=COM/""), "" (|(type=printer) (type=scanner))"");
                searcher.SearchScope = SearchScope.Subtree;

                searcher.Filter = "" (|(type=printer) (type=scanner))"";

                resultCollection = searcher.FindOne();

                return resultCollection;
            }    
        }";

        private const string LdapFindOneFilterConstructorParamWithLiteralExpressionV2 = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression, DirectoryEntry entry)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectorySearcher searcher = new DirectorySearcher(entry, "" (|(type=printer) (type=scanner))"");
                searcher.SearchScope = SearchScope.Subtree;

                searcher.Filter = "" (|(type=printer) (type=scanner))"";

                resultCollection = searcher.FindOne();

                return resultCollection;
            }    
        }";

        private const string LdapFindOneFilterObjectInitializerWithVulnerableExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");

                DirectorySearcher searcher = new DirectorySearcher(entry)
                {
                    Filter = ""(|(type="" + types[0] + "" ) (type="" + types[1] + ""))""
                };

                searcher.SearchScope = SearchScope.Subtree;

                resultCollection = searcher.FindOne();

                return resultCollection;
            }    
        }";

        private const string LdapFindOneFilterObjectInitializerWithLiteralExpression = @"public class LdapSearch 
        {   
            public object SearchByType(string searchExpression)
            {
                string[] types = searchExpression.Split('|');

                SearchResultCollection resultCollection = null;

                DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");

                DirectorySearcher searcher = new DirectorySearcher(entry)
                {
                    Filter = "" (|(type=printer) (type=scanner))""
                };

                searcher.SearchScope = SearchScope.Subtree;

                resultCollection = searcher.FindOne();

                return resultCollection;
            }    
        }";

        private static InvocationExpressionSyntax GetSyntax(TestCode testCode, string name)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().Where(p => p is InvocationExpressionSyntax).ToList();

            return result.FirstOrDefault(p =>
            {
                var symbol = testCode.SemanticModel.GetSymbolInfo(p).Symbol as IMethodSymbol;
                return symbol?.Name == name &&
                       symbol?.ReceiverType.ToString() == "System.DirectoryServices.DirectorySearcher";
            }) as InvocationExpressionSyntax;
        }

        [TestCase(LdapFindAllFilterExpressionAssignmentWithVulnerableBinaryExpression, true)]
        [TestCase(LdapFindAllFilterExpressionAssignmentWithLiteralExpression, false)]
        [TestCase(LdapFindAllFilterConstructorParamWithVulnerableExpression, true)]
        [TestCase(LdapFindAllFilterConstructorParamWithLiteralExpression, false)]
        [TestCase(LdapFindAllFilterConstructorParamWithLiteralExpressionV2, false)]
        [TestCase(LdapFindAllFilterObjectInitializerWithVulnerableExpression, true)]
        [TestCase(LdapFindAllFilterObjectInitializerWithLiteralExpression, false)]
        public void TestFindAll(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, DirectoryServicesReferences);

            var syntax = GetSyntax(testCode, "FindAll");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(expectedResult, result);
        }

        [TestCase(LdapFindOneFilterExpressionAssignmentWithVulnerableBinaryExpression, true)]
        [TestCase(LdapFindOneFilterExpressionAssignmentWithLiteralExpression, false)]
        [TestCase(LdapFindOneFilterConstructorParamWithVulnerableExpression, true)]
        [TestCase(LdapFindOneFilterConstructorParamWithLiteralExpression, false)]
        [TestCase(LdapFindOneFilterConstructorParamWithLiteralExpressionV2, false)]
        [TestCase(LdapFindOneFilterObjectInitializerWithVulnerableExpression, true)]
        [TestCase(LdapFindOneFilterObjectInitializerWithLiteralExpression, false)]
        public void TestFindOne(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, DirectoryServicesReferences);

            var syntax = GetSyntax(testCode, "FindOne");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(expectedResult, result);
        }
    }
}