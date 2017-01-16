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
using System.Web.UI;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using NUnit.Framework;

using Puma.Security.Rules.Analyzer.Validation.Redirect.Core;
using Puma.Security.Rules.Test.Helpers;

namespace Puma.Security.Rules.Test.Analyzer.Validation.Redirect.Core
{
    [TestFixture]
    public class ResponseRedirectExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new ResponseRedirectExpressionAnalyzer();
        }

        private ResponseRedirectExpressionAnalyzer _analyzer;

        private static readonly MetadataReference PageReference =
            MetadataReference.CreateFromFile(typeof(Page).Assembly.Location);

        private const string DefaultUsing = @"using System;using System.Web.UI;";

        private const string RedirectWithUserControlledValue = @"public partial class Register : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            var url = Request.QueryString[0];
            Redirect(url);
        }

        private void Redirect(string url)
        {  
            Response.Redirect(url);
        }
    }";

        private const string RedirectWithStaticValue = @"public partial class Register : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {            
            Redirect();
        }

        private void Redirect(string url)
        {              
            Response.Redirect(""http://www.google.com"");
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
                       symbol?.ReceiverType.ToString() == "System.Web.HttpResponse";
            }) as InvocationExpressionSyntax;
        }

        [TestCase(RedirectWithUserControlledValue, true)]
        [TestCase(RedirectWithStaticValue, false)]
        public void TestResponseRedirect(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, PageReference);

            var syntax = GetRedirectSyntax(testCode);

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
    }

    //public partial class Register : Page
    //{
    //    protected void Page_Load(object sender, EventArgs e)
    //    {

    //    }

    //    protected void RegisterUser_CreatedUser(object sender, EventArgs e)
    //    {  
    //        Response.Redirect("http://www.google.com");
    //    }
    //}
}