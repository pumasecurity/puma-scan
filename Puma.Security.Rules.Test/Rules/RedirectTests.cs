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
    public class RedirectTests
    {
        private const string Stubs = @"
namespace Microsoft.AspNetCore.Mvc
{
    public class RedirectResult { }

    public class ControllerBase
    {
        public RedirectResult Redirect(string url) { return null; }
        public RedirectResult RedirectPermanent(string url) { return null; }
    }
}

namespace Microsoft.AspNetCore.Http
{
    public class HttpResponse
    {
        public void Redirect(string location) { }
    }
}
";

        [TestMethod]
        public async Task AspNetCoreControllerRedirectWithTaintedUrlFlagsSEC0109()
        {
            var test = Stubs + @"
public class AccountController : Microsoft.AspNetCore.Mvc.ControllerBase
{
    public object Login(string returnUrl)
    {
        return {|SEC0109:Redirect(returnUrl)|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task AspNetCoreHttpResponseRedirectWithTaintedUrlFlagsSEC0110()
        {
            var test = Stubs + @"
public class Middleware
{
    public void Handle(Microsoft.AspNetCore.Http.HttpResponse response, string returnUrl)
    {
        {|SEC0110:response.Redirect(returnUrl)|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task AspNetCoreControllerRedirectWithConstantUrlDoesNotFlag()
        {
            var test = Stubs + @"
public class AccountController : Microsoft.AspNetCore.Mvc.ControllerBase
{
    public object Login()
    {
        return Redirect(""/home"");
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }
    }
}
