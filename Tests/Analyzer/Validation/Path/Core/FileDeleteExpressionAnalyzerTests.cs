/* 
 * Copyright(c) 2016 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System.IO;
using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using NUnit.Framework;

using Puma.Security.Rules.Analyzer.Validation.Path.Core;
using Puma.Security.Rules.Test.Helpers;

namespace Puma.Security.Rules.Test.Analyzer.Validation.Path.Core
{
    [TestFixture]
    public class FileDeleteExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new FileDeleteExpressionAnalyzer();
        }

        private FileDeleteExpressionAnalyzer _analyzer;

        private static readonly MetadataReference IOReference =
            MetadataReference.CreateFromFile(typeof(File).Assembly.Location);

        private const string DefaultUsing = @"using System;using System.IO;";

        private const string FileDeleteWithUserControlledValue = @"public static class FileHelper
    {
         public static void Delete(string path)
        {
            File.Delete(path);
        }
    }";

        private const string FileDeleteWithStaticValue = @"public static class FileHelper
    {
        public static void Delete()
        {
            File.Delete(""C:\hardcoded\path.txt"");
        }
    }";

        private static InvocationExpressionSyntax GetFileSyntax(TestCode testCode, string methodName)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().Where(p => p is InvocationExpressionSyntax).ToList();

            return result.FirstOrDefault(p =>
            {
                var symbol = testCode.SemanticModel.GetSymbolInfo(p).Symbol as IMethodSymbol;
                return symbol?.Name == methodName &&
                       symbol?.ReceiverType.ToString() == "System.IO.File";
            }) as InvocationExpressionSyntax;
        }

        [TestCase(FileDeleteWithUserControlledValue, true)]
        [TestCase(FileDeleteWithStaticValue, false)]
        public void TestFileOpen(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "Delete");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
    }

    public static class FileHelper3
    {
        public static void Delete(string path)
        {
            File.Delete(path);
        }
    }
}