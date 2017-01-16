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
    public class FileOpenExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new FileOpenExpressionAnalyzer();
        }

        private FileOpenExpressionAnalyzer _analyzer;

        private static readonly MetadataReference IOReference =
            MetadataReference.CreateFromFile(typeof(File).Assembly.Location);

        private const string DefaultUsing = @"using System;using System.IO;";

        private const string FileOpenWithUserControlledValue = @"public static class FileHelper
    {
         public static FileStream Open(string path)
        {
            return File.Open(path, FileMode.OpenOrCreate);
        }
    }";

        private const string FileOpenWithStaticValue = @"public static class FileHelper
    {
         public static FileStream Open()
        {
            return File.Open(""C:\hardcoded\path.txt"", FileMode.OpenOrCreate);
        }
    }";

        private const string FileOpenReadWithUserControlledValue = @"public static class FileHelper
    {
         public static FileStream Open(string path)
        {
            return File.OpenRead(path);
        }
    }";

        private const string FileOpenReadWithStaticValue = @"public static class FileHelper
    {
         public static FileStream Open()
        {
            return File.OpenRead(""C:\hardcoded\path.txt"");
        }
    }";


        private const string FileOpenWriteWithUserControlledValue = @"public static class FileHelper
    {
         public static FileStream Open(string path)
        {
            return File.OpenWrite(path);
        }
    }";

        private const string FileOpenWriteWithStaticValue = @"public static class FileHelper
    {
         public static FileStream Open()
        {
            return File.OpenWrite(""C:\hardcoded\path.txt"");
        }
    }";

        private const string FileOpenTextWithUserControlledValue = @"public static class FileHelper
    {
         public static StreamReader Open(string path)
        {
            return File.OpenText(path);
        }
    }";

        private const string FileOpenTextWithStaticValue = @"public static class FileHelper
    {
         public static StreamReader Open()
        {
            return File.OpenText(""C:\hardcoded\path.txt"");
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

        [TestCase(FileOpenWithUserControlledValue, true)]
        [TestCase(FileOpenWithStaticValue, false)]
        public void TestFileOpen(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "Open");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        [TestCase(FileOpenReadWithUserControlledValue, true)]
        [TestCase(FileOpenReadWithStaticValue, false)]
        public void TestFileOpenRead(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "OpenRead");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        [TestCase(FileOpenWriteWithUserControlledValue, true)]
        [TestCase(FileOpenWriteWithStaticValue, false)]
        public void TestFileOpenWrite(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "OpenWrite");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        [TestCase(FileOpenTextWithUserControlledValue, true)]
        [TestCase(FileOpenTextWithStaticValue, false)]
        public void TestFileOpenText(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileSyntax(testCode, "OpenText");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
    }

    public static class FileHelper2
    {
        public static StreamReader Open(string path)
        {
            return File.OpenText(path);
        }
    }

    //File.OpenText()
}