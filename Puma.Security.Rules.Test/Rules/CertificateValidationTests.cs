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
    public class CertificateValidationTests
    {
        // SEC0113 matches on the property and containing type names, so stub types
        // stand in for the real BCL networking types.
        private const string Stubs = @"
namespace System.Net.Http
{
    public class HttpClientHandler
    {
        public System.Func<object, object, object, object, bool> ServerCertificateCustomValidationCallback { get; set; }

        public static System.Func<object, object, object, object, bool> DangerousAcceptAnyServerCertificateValidator { get; }
    }
}

namespace System.Net.Security
{
    public class SslClientAuthenticationOptions
    {
        public System.Func<object, object, object, object, bool> RemoteCertificateValidationCallback { get; set; }
    }
}

namespace System.Net
{
    public static class ServicePointManager
    {
        public static System.Func<object, object, object, object, bool> ServerCertificateValidationCallback { get; set; }
    }
}
";

        [TestMethod]
        public async Task HttpClientHandlerCallbackReturningTrueFlagsSEC0113()
        {
            var test = Stubs + @"
public class Client
{
    public void Configure(System.Net.Http.HttpClientHandler handler)
    {
        {|SEC0113:handler.ServerCertificateCustomValidationCallback|} = (message, cert, chain, errors) => true;
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task HttpClientHandlerDangerousAcceptAnyValidatorFlagsSEC0113()
        {
            var test = Stubs + @"
public class Client
{
    public void Configure(System.Net.Http.HttpClientHandler handler)
    {
        {|SEC0113:handler.ServerCertificateCustomValidationCallback|} = System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task SslClientAuthenticationOptionsCallbackReturningTrueFlagsSEC0113()
        {
            var test = Stubs + @"
public class Client
{
    public void Configure(System.Net.Security.SslClientAuthenticationOptions options)
    {
        {|SEC0113:options.RemoteCertificateValidationCallback|} = (sender, cert, chain, errors) => true;
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task ServicePointManagerSimpleAssignmentReturningTrueFlagsSEC0113()
        {
            var test = Stubs + @"
public class Client
{
    public void Configure()
    {
        {|SEC0113:System.Net.ServicePointManager.ServerCertificateValidationCallback|} = (sender, cert, chain, errors) => true;
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task ServicePointManagerAddAssignmentReturningTrueStillFlagsSEC0113()
        {
            var test = Stubs + @"
public class Client
{
    public void Configure()
    {
        {|SEC0113:System.Net.ServicePointManager.ServerCertificateValidationCallback|} += (sender, cert, chain, errors) => true;
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task HttpClientHandlerCallbackWithRealValidationDoesNotFlag()
        {
            var test = Stubs + @"
public class Client
{
    public void Configure(System.Net.Http.HttpClientHandler handler)
    {
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => errors == null;
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }
    }
}
