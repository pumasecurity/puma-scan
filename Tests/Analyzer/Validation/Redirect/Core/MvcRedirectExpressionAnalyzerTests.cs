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

using Puma.Security.Rules.Analyzer.Validation.Redirect.Core;
using Puma.Security.Rules.Test.Helpers;

namespace Puma.Security.Rules.Test.Analyzer.Validation.Redirect.Core
{
    [TestFixture]
    public class MvcRedirectExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new MvcRedirectExpressionAnalyzer();
        }

        private static readonly MetadataReference MvcReference =
            MetadataReference.CreateFromFile(typeof(Controller).Assembly.Location);

        private MvcRedirectExpressionAnalyzer _analyzer;

        private const string DefaultUsing = @"using System;using System.Web.Mvc;";

        private const string RedirectWithUserControlledValue = @"public class RedirectController : Controller
    {
        public RedirectController()
        {
        }

        public ActionResult DoRedirect(string returnUrl)
        {
            return this.Redirect(returnUrl);
        }
    }";

        private const string RedirectWithStaticValue = @"public class RedirectController : Controller
    {
        public RedirectController()
        {
        }

        public ActionResult DoRedirect()
        {
            return this.Redirect(""http://www.google.com"");
        }
    }";

        private static InvocationExpressionSyntax GetRedirectSyntax(TestCode testCode)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().Where(p => p is InvocationExpressionSyntax).ToList();

            return result.FirstOrDefault(p =>
            {
                var symbol = testCode.SemanticModel.GetSymbolInfo(p).Symbol as IMethodSymbol;
                return symbol?.Name == "Redirect" &&
                       symbol?.ReceiverType.ToString() == "System.Web.Mvc.Controller";
            }) as InvocationExpressionSyntax;
        }

        [TestCase(RedirectWithUserControlledValue, true)]
        [TestCase(RedirectWithStaticValue, false)]
        public void TestResponse(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, MvcReference);

            var syntax = GetRedirectSyntax(testCode);

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
    }

    //public class RedirectController : Controller
    //{
    //    public ActionResult DoRedirect(string returnUrl)
    //    {
    //        return Redirect(returnUrl);
    //    }
    //}
}