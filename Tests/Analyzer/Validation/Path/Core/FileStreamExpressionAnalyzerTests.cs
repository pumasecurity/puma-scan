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
using System.Web;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using NUnit.Framework;

using Puma.Security.Rules.Analyzer.Validation.Path.Core;
using Puma.Security.Rules.Test.Helpers;

namespace Puma.Security.Rules.Test.Analyzer.Validation.Path.Core
{
    [TestFixture]
    public class FileStreamExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new FileStreamExpressionAnalyzer();
        }

        private FileStreamExpressionAnalyzer _analyzer;

        private static readonly MetadataReference IOReference =
            MetadataReference.CreateFromFile(typeof(File).Assembly.Location);

        private static readonly MetadataReference WebReference =
            MetadataReference.CreateFromFile(typeof(IHttpHandler).Assembly.Location);

        private const string DefaultUsing = @"using System;using System.IO;";

        private const string FileStreamWithUserControlledValue = @"public class FileHelper
    {
        private FileStream _fs;

        public FileHelper(string path)
        {
            _fs = new FileStream(path, FileMode.Open);
        }
    }";
        private const string FileStreamWithStaticValue = @"public class FileHelper
    {
        private FileStream _fs;

        public FileHelper()
        {
            _fs = new FileStream(""C:\hardcoded\path.txt"", FileMode.Open);
        }
    }";
        private const string FileStreamWithMapPathAndStaticValue = @"public class DownloadHandler : IHttpHandler
    {
        private const int _BUFFER_SIZE = 2048;

        public bool IsReusable
        {
            get { return true; }
        }

        public void ProcessRequest(HttpContext context)
        {
            //Add code here to authorize the user and make sure they are in the admin role

            //Set the response headers to download the file in a secure manner
            context.Response.ContentType = ""application/pdf"";
            context.Response.AddHeader(""content-disposition"", ""attachment; filename=Widget10000.pdf"");
            context.Response.AddHeader(""cache-control"", ""no-transform"");
            context.Response.AddHeader(""X-Content-Type-Options"", ""nosniff"");

            //Download the file
            using (FileStream stream = new FileStream(context.Request.MapPath(""~/Marketing/Widget10000.pdf""), FileMode.Open, FileAccess.Read))
            {
                byte[] bytes = new byte[_BUFFER_SIZE];
                int read = 0;

                while ((read = stream.Read(bytes, 0, _BUFFER_SIZE)) > 0)
                {
                    context.Response.BinaryWrite(bytes);
                }
            }
        }
    }";

        private static ObjectCreationExpressionSyntax GetFileStreamSyntax(TestCode testCode)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().Where(p => p is ObjectCreationExpressionSyntax).ToList();

            return result.FirstOrDefault(p =>
            {
                var symbol = testCode.SemanticModel.GetSymbolInfo(p).Symbol as IMethodSymbol;
                return symbol?.MethodKind == MethodKind.Constructor &&
                       symbol?.ReceiverType.ToString() == "System.IO.FileStream";
            }) as ObjectCreationExpressionSyntax;
        }

        [TestCase(FileStreamWithUserControlledValue, true)]
        [TestCase(FileStreamWithStaticValue, false)]
        public void TestFileStream(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, IOReference);

            var syntax = GetFileStreamSyntax(testCode);

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
        
        [TestCase(FileStreamWithMapPathAndStaticValue, false)]
        public void TestFileStreamMapPath(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + "using System.Web;" + code, IOReference, WebReference);

            var syntax = GetFileStreamSyntax(testCode);

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
    }

    public class DownloadHandler : IHttpHandler
    {
        private const int _BUFFER_SIZE = 2048;

        public bool IsReusable
        {
            get { return true; }
        }

        public void ProcessRequest(HttpContext context)
        {
            //Add code here to authorize the user and make sure they are in the admin role

            //Set the response headers to download the file in a secure manner
            context.Response.ContentType = "application/pdf";
            context.Response.AddHeader("content-disposition", "attachment; filename=Widget10000.pdf");
            context.Response.AddHeader("cache-control", "no-transform");
            context.Response.AddHeader("X-Content-Type-Options", "nosniff");

            //Download the file
            using (FileStream stream = new FileStream(context.Request.MapPath("~/Marketing/Widget10000.pdf"), FileMode.Open, FileAccess.Read))
            {
                byte[] bytes = new byte[_BUFFER_SIZE];
                int read = 0;

                while ((read = stream.Read(bytes, 0, _BUFFER_SIZE)) > 0)
                {
                    context.Response.BinaryWrite(bytes);
                }
            }
        }
    }
}