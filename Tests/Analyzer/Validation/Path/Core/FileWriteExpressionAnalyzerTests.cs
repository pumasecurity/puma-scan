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
    public class FileWriteExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new FileWriteExpressionAnalyzer();
        }

        private FileWriteExpressionAnalyzer _analyzer;

        private static readonly MetadataReference IOReference =
            MetadataReference.CreateFromFile(typeof(File).Assembly.Location);

        private const string DefaultUsing = @"using System;using System.IO;";

        private const string FileWriteAllTextWithUserControlledValue = @"public static class FileHelper
    {
        public static void Write(string path, string text)
        {
            File.WriteAllText(path, text);
        }
    }";
        private const string FileWriteAllTextWithStaticValue = @"public static class FileHelper
    {
        public static void Write(string text)
        {
            File.WriteAllText(""C:\hardcoded\path.txt"", text);
        }
    }";
        private const string FileWriteAllLinesWithUserControlledValue = @"public static class FileHelper
    {
          public static void Write(string path, string[] lines)
        {
            File.WriteAllLines(path, lines);
        }
    }";
        private const string FileWriteAllLinesWithStaticValue = @"public static class FileHelper
    {
          public static void Write(string[] lines)
        {
            File.WriteAllLines(""C:\hardcoded\path.txt"", lines);
        }
    }";
        private const string FileWriteAllBytesWithUserControlledValue = @"public static class FileHelper
    {
        public static void Write(string path, byte[] bytes)
        {
            File.WriteAllBytes(path, bytes);
        }
    }";
        private const string FileWriteAllBytesWithStaticValue = @"public static class FileHelper
    {
                public static void Write(byte[] bytes)
        {
            File.WriteAllBytes(""C:\hardcoded\path.txt"", bytes);
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

        [TestCase(FileWriteAllTextWithUserControlledValue, true)]
        [TestCase(FileWriteAllTextWithStaticValue, false)]
        public void TestFileWriteAllText(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "WriteAllText");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        [TestCase(FileWriteAllLinesWithUserControlledValue, true)]
        [TestCase(FileWriteAllLinesWithStaticValue, false)]
        public void TestFileWriteAllLines(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "WriteAllLines");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        [TestCase(FileWriteAllBytesWithUserControlledValue, true)]
        [TestCase(FileWriteAllBytesWithStaticValue, false)]
        public void TestFileWriteAllBytes(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "WriteAllBytes");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
    }
}