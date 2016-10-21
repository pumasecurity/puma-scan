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

using System.Collections;
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
    public class FileReadExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new FileReadExpressionAnalyzer();
        }

        private FileReadExpressionAnalyzer _analyzer;

        private static readonly MetadataReference IOReference =
            MetadataReference.CreateFromFile(typeof(File).Assembly.Location);

        private const string DefaultUsing = @"using System;using System.IO;";

        private const string FileReadAllTextWithUserControlledValue = @"public static class FileHelper
    {
        public static string Read(string path)
        {
            return File.ReadAllText(path);
        }
    }";
        private const string FileReadAllTextWithStaticValue = @"public static class FileHelper
    {
        public static string Read()
        {
            return File.ReadAllText(""X:\shares\publicInfo.txt"");
        }
    }";
        private const string FileReadAllLinesWithUserControlledValue = @"public static class FileHelper
    {
         public static string[] Read(string path)
        {
            return File.ReadAllLines(path);
        }
    }";
        private const string FileReadAllLinesWithStaticValue = @"public static class FileHelper
    {
        public static string[] Read()
        {
            return File.ReadAllLines(""X:\shares\publicInfo.txt"");
        }
    }";
        private const string FileReadAllBytesWithUserControlledValue = @"public static class FileHelper
    {
         public static byte[] Read(string path)
        {
            return File.ReadAllBytes(path);
        }
    }";
        private const string FileReadAllBytesWithStaticValue = @"public static class FileHelper
    {
                 public static byte[] Read(string path)
        {
            return File.ReadAllBytes(""X:\shares\publicInfo.txt"");
        }
    }";    private const string FileReadLinesWithUserControlledValue = @"public static class FileHelper
    {
          public static IEnumerable Read(string path)
        {
            return File.ReadLines(path);
        }
    }";
        private const string FileReadLinesWithStaticValue = @"public static class FileHelper
    {
                  public static IEnumerable Read()
        {
            return File.ReadLines(""X:\shares\publicInfo.txt"");
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

        [TestCase(FileReadAllTextWithUserControlledValue, true)]
        [TestCase(FileReadAllTextWithStaticValue, false)]
        public void TestFileReadAllText(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "ReadAllText");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        [TestCase(FileReadAllLinesWithUserControlledValue, true)]
        [TestCase(FileReadAllLinesWithStaticValue, false)]
        public void TestFileReadAllLines(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "ReadAllLines");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        [TestCase(FileReadAllBytesWithUserControlledValue, true)]
        [TestCase(FileReadAllBytesWithStaticValue, false)]
        public void TestFileReadAllBytes(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "ReadAllBytes");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        [TestCase(FileReadLinesWithUserControlledValue, true)]
        [TestCase(FileReadLinesWithStaticValue, false)]
        public void TestFileReadLines(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "ReadLines");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
    }

    public static class FileHelper
    {
        public static IEnumerable Read(string path)
        {
            return File.ReadLines(path);
        }
    }
}