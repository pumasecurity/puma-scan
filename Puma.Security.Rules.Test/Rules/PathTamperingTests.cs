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
    public class PathTamperingTests
    {
        private const string Stubs = @"
namespace Microsoft.AspNetCore.Mvc
{
    public class PhysicalFileResult
    {
        public PhysicalFileResult(string fileName, string contentType) { }
    }

    public class VirtualFileResult
    {
        public VirtualFileResult(string fileName, string contentType) { }
    }
}
";

        [TestMethod]
        public async Task PhysicalFileResultWithTaintedPathFlagsSEC0111()
        {
            var test = Stubs + @"
public class DownloadController
{
    public object Download(string fileName)
    {
        return {|SEC0111:new Microsoft.AspNetCore.Mvc.PhysicalFileResult(fileName, ""application/octet-stream"")|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task VirtualFileResultWithTaintedPathFlagsSEC0111()
        {
            var test = Stubs + @"
public class DownloadController
{
    public object Download(string fileName)
    {
        return {|SEC0111:new Microsoft.AspNetCore.Mvc.VirtualFileResult(fileName, ""application/octet-stream"")|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task PhysicalFileResultWithConstantPathDoesNotFlag()
        {
            var test = Stubs + @"
public class DownloadController
{
    public object Download()
    {
        return new Microsoft.AspNetCore.Mvc.PhysicalFileResult(""C:\\reports\\summary.pdf"", ""application/pdf"");
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }
    }
}
