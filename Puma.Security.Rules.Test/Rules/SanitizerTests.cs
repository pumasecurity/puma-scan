/*
 * Copyright(c) 2016 - 2026 Puma Security, LLC (https://pumasecurity.io)
 *
 * Project Leads:
 * Eric Johnson (eric.johnson@pumascan.com)
 * Eric Mead (eric.mead@pumascan.com)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

using System.Threading.Tasks;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using Puma.Security.Rules.Test.Verifiers;

namespace Puma.Security.Rules.Test.Rules
{
    [TestClass]
    public class SanitizerTests
    {
        // Exercises the modern encoder entries in CleansedMethodsProvider through
        // the SEC0024 Response.Write sink.
        private const string Stubs = @"
namespace System.Web
{
    public class HttpResponse
    {
        public void Write(string s) { }
    }
}

namespace System.Text.Encodings.Web
{
    public class HtmlEncoder
    {
        public static HtmlEncoder Default { get; }
        public string Encode(string value) { return value; }
    }
}
";

        [TestMethod]
        public async Task ResponseWriteWithTaintedValueFlagsSEC0024()
        {
            var test = Stubs + @"
public class Page
{
    public void Render(System.Web.HttpResponse Response, string input)
    {
        {|SEC0024:Response.Write(input)|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task ResponseWriteWithHtmlEncoderEncodedValueDoesNotFlag()
        {
            var test = Stubs + @"
public class Page
{
    public void Render(System.Web.HttpResponse Response, string input)
    {
        Response.Write(System.Text.Encodings.Web.HtmlEncoder.Default.Encode(input));
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }
    }
}
