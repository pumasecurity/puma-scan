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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using NUnit.Framework;

using Puma.Security.Rules.Analyzer.Injection.Ldap.Core;
using Puma.Security.Rules.Test.Helpers;

namespace Puma.Security.Rules.Test.Analyzer.Injection.Ldap.Core
{
    [TestFixture]
    public class LdapDirectoryEntryPathInjectionExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new LdapDirectoryEntryPathInjectionExpressionAnalyzer();
        }

        private LdapDirectoryEntryPathInjectionExpressionAnalyzer _analyzer;

        private static readonly MetadataReference DirectoryServicesReferences =
            MetadataReference.CreateFromFile(typeof(System.DirectoryServices.DirectoryEntry).Assembly.Location);

        private const string DefaultUsing = @"using System;
                                                    using System.DirectoryServices;";


        private static ObjectCreationExpressionSyntax GetSyntax(TestCode testCode)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().Where(p => p is ObjectCreationExpressionSyntax).ToList();

            return result.FirstOrDefault(p =>
            {
                var symbol = testCode.SemanticModel.GetSymbolInfo(p).Symbol as IMethodSymbol;
                return symbol?.Name == ".ctor" &&
                       symbol?.ReceiverType.ToString() == "System.DirectoryServices.DirectoryEntry";
            }) as ObjectCreationExpressionSyntax;
        }

        private const string LdapDirectoryCtorWithVulnerableBinaryExpression = @"public class LdapSearch 
        {   
            public object GetDirectoryChildren(string domain)
            {
                 DirectoryEntry entry = new DirectoryEntry(""LDAP://DC="" + domain + "", DC=COM/"");
            
                 return entry.Children;
            }    
        }";

        //TODO: add endcoder and whitelist
        private const string LdapDirectoryCtorWithSafeBinaryExpression = @"public class LdapSearch 
        {   
            public object GetDirectoryChildren(string domain)
            {
                 DirectoryEntry entry = new DirectoryEntry(""LDAP://DC="" + domain + "", DC=COM/"");
            
                 return entry.Children;
            }    
        }";

        private const string LdapDirectoryCtorWithLiteralExpression = @"public class LdapSearch 
        {   
            public object GetDirectoryChildren(string domain)
            {
                 DirectoryEntry entry = new DirectoryEntry(""LDAP://DC=FOO, DC=COM/"");
            
                 return entry.Children;
            }    
        }";

        [TestCase(LdapDirectoryCtorWithVulnerableBinaryExpression, true)]
      //  [TestCase(LdapDirectoryCtorWithLiteralExpression, false)]
        //[TestCase(LdapDirectoryCtorWithSafeBinaryExpression, false, Ignore = "Pending whitelist check for encoder")]
        public void TestCtor(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, DirectoryServicesReferences);

            var syntax = GetSyntax(testCode);

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(expectedResult, result);
        }

    }
}