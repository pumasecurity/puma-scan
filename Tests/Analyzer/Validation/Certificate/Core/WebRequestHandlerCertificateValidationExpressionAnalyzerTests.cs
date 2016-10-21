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
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using NUnit.Framework;

using Puma.Security.Rules.Analyzer.Validation.Certificate.Core;
using Puma.Security.Rules.Test.Helpers;

namespace Puma.Security.Rules.Test.Analyzer.Validation.Certificate.Core
{
    [TestFixture]
    public class WebRequestHandlerCertificateValidationExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new WebRequestHandlerCertificateValidationExpressionAnalyzer();
        }

        private WebRequestHandlerCertificateValidationExpressionAnalyzer _analyzer;

        private static readonly MetadataReference NetReference =
            MetadataReference.CreateFromFile(typeof(ServicePointManager).Assembly.Location);

        private static readonly MetadataReference NetSecurityReference =
            MetadataReference.CreateFromFile(typeof(SslPolicyErrors).Assembly.Location);

        private static readonly MetadataReference HttpClientReference =
            MetadataReference.CreateFromFile(typeof(HttpClient).Assembly.Location);

        private static readonly MetadataReference WebRequestHandlerReference =
            MetadataReference.CreateFromFile(typeof(WebRequestHandler).Assembly.Location);

        private static readonly MetadataReference CertReference =
            MetadataReference.CreateFromFile(typeof(X509Certificate).Assembly.Location);

        private const string DefaultUsing =
            @"using System;using System.Net;using System.Net.Http;using System.Net.Security;using System.Security.Cryptography.X509Certificates;";

        private const string ServerCertificateValidationCallbackAsMethod = @" public class WebRequestHelper
    {
        public void Post(HttpContent httpContent)
        {
            using (var handler = new WebRequestHandler())
            {
                handler.ServerCertificateValidationCallback += ServerCertificateValidationCallback;
                using (var httpClient = new HttpClient())
                {
                    httpClient.PostAsync(""someendpoint"", httpContent);
                }
            }
        }

        private bool ServerCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }";
        private const string ServerCertificateValidationCallbackAsLambda = @"public class WebRequestHelper
    {
        public void Post(HttpContent httpContent)
        {
            using (var handler = new WebRequestHandler())
            {
                handler.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
                using (var httpClient = new HttpClient(handler))
                {
                    httpClient.PostAsync(""someendpoint"", httpContent);
                }
            }
        }
    }";
        private const string ServerCertificateValidationCallbackAsDelgate = @"public class WebRequestHelper
    {
        public void Post(HttpContent httpContent)
        {
            using (var handler = new WebRequestHandler())
            {
                handler.ServerCertificateValidationCallback += delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
                {
                    return true;
                };

                using (var httpClient = new HttpClient())
                {
                    httpClient.PostAsync(""someendpoint"", httpContent);
                }
            }
        }
    }";

        private static AssignmentExpressionSyntax GetServicePointManagerSyntax(TestCode testCode)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().OfType<AssignmentExpressionSyntax>().ToList();

            return result.FirstOrDefault(p =>
            {
                var symbol = testCode.SemanticModel.GetSymbolInfo(p.Left).Symbol as IPropertySymbol;

                return symbol?.Name == "ServerCertificateValidationCallback"
                       && symbol.ContainingType.Name == "WebRequestHandler";
            });
        }

        [TestCase(ServerCertificateValidationCallbackAsMethod, true)]
        [TestCase(ServerCertificateValidationCallbackAsLambda, true)]
        [TestCase(ServerCertificateValidationCallbackAsDelgate, true)]
        public void TestWebRequestHandler(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, NetReference, HttpClientReference,
                WebRequestHandlerReference, NetSecurityReference,
                CertReference);

            var syntax = GetServicePointManagerSyntax(testCode);
            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
    }

    public class WebRequestHelper
    {
        public void Post(HttpContent httpContent)
        {
            using (var handler = new WebRequestHandler())
            {
                handler.ServerCertificateValidationCallback += delegate { return true; };

                using (var httpClient = new HttpClient())
                {
                    httpClient.PostAsync("someendpoint", httpContent);
                }
            }
        }
    }
}