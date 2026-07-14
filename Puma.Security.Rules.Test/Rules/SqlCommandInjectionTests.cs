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
    public class SqlCommandInjectionTests
    {
        // SEC0107 matches on the fully-qualified receiver type name, so stub types
        // with the right namespaces stand in for the real ADO.NET packages.
        private const string Stubs = @"
namespace System.Data.SqlClient
{
    public class SqlCommand
    {
        public SqlCommand() { }
        public SqlCommand(string commandText) { }
        public string CommandText { get; set; }
    }
}

namespace Microsoft.Data.SqlClient
{
    public class SqlCommand
    {
        public SqlCommand() { }
        public SqlCommand(string commandText) { }
        public string CommandText { get; set; }
    }
}
";

        [TestMethod]
        public async Task MicrosoftDataSqlClientCtorWithTaintedArgumentFlagsSEC0107()
        {
            var test = Stubs + @"
public class Db
{
    public void Execute(string input)
    {
        var cmd = {|SEC0107:new Microsoft.Data.SqlClient.SqlCommand(""SELECT * FROM Users WHERE Name = '"" + input + ""'"")|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task MicrosoftDataSqlClientCommandTextAssignmentWithTaintedValueFlagsSEC0107()
        {
            var test = Stubs + @"
public class Db
{
    public void Execute(string input)
    {
        var cmd = new Microsoft.Data.SqlClient.SqlCommand();
        {|SEC0107:cmd.CommandText|} = ""SELECT * FROM Users WHERE Name = '"" + input + ""'"";
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task SystemDataSqlClientCtorWithTaintedArgumentStillFlagsSEC0107()
        {
            var test = Stubs + @"
public class Db
{
    public void Execute(string input)
    {
        var cmd = {|SEC0107:new System.Data.SqlClient.SqlCommand(""SELECT * FROM Users WHERE Name = '"" + input + ""'"")|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task MicrosoftDataSqlClientCtorWithConstantCommandDoesNotFlag()
        {
            var test = Stubs + @"
public class Db
{
    public void Execute()
    {
        var cmd = new Microsoft.Data.SqlClient.SqlCommand(""SELECT * FROM Users"");
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }
    }
}
