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

using System.Linq;
using System.Web.Mvc;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using NUnit.Framework;

using Puma.Security.Rules.Analyzer.Validation.Path.Core;
using Puma.Security.Rules.Test.Helpers;

namespace Puma.Security.Rules.Test.Analyzer.Validation.Path.Core
{
    [TestFixture]
    public class FilePathResultExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new FilePathResultExpressionAnalyzer();
        }

        private static readonly MetadataReference MvcReference =
            MetadataReference.CreateFromFile(typeof(Controller).Assembly.Location);

        private FilePathResultExpressionAnalyzer _analyzer;

        private const string DefaultUsing = @"using System;using System.Web.Mvc;";

        private const string FilePathResultWithUserControlledValue = @"public class FilePathResultController : Controller
    {
        public FilePathResultController()
        {
        }

         [HttpPost]
        [ValidateInput(false)]
        public FileResult Download(string path)
        {
            return new FilePathResult(path, ""application/octet-stream"");
        }
}";

        private const string FilePathResultWithStaticValue = @"public class FilePathResultController : Controller
    {
        public FilePathResultController()
        {
        }

         [HttpPost]
        [ValidateInput(false)]
        public FileResult Download()
        {
            return new FilePathResult(""H:\trivialInformationFile.txt"", ""application/octet-stream"");
        }
}";

        private static ObjectCreationExpressionSyntax GetFilePathResultSyntax(TestCode testCode)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().Where(p => p is ObjectCreationExpressionSyntax).ToList();

            return result.FirstOrDefault(p =>
            {
                var symbol = testCode.SemanticModel.GetSymbolInfo(p).Symbol as IMethodSymbol;
                return symbol?.MethodKind == MethodKind.Constructor &&
                        symbol?.ReceiverType.ToString() == "System.Web.Mvc.FilePathResult";

            }) as ObjectCreationExpressionSyntax;
        }

        [TestCase(FilePathResultWithUserControlledValue, true)]
        [TestCase(FilePathResultWithStaticValue, false)]
        public void TestFilePathResult(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, MvcReference);

            var syntax = GetFilePathResultSyntax(testCode);

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
    }

    //public class FilePathResultController : Controller
    //{
    //    [HttpPost]
    //    [ValidateInput(false)]
    //    public FileResult Download(string path)
    //    {
    //        return new FilePathResult(path, "application/octet-stream");
    //    }
    //}
}