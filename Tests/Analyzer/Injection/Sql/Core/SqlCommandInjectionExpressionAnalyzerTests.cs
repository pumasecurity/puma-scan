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

using System.Data.SqlClient;
using System.Linq;

using Puma.Security.Rules.Analyzer.Injection.Sql.Core;
using Puma.Security.Rules.Test.Helpers;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using NUnit.Framework;

namespace Puma.Security.Rules.Test.Analyzer.Injection.Sql.Core
{
    [TestFixture]
    public class SqlCommandInjectionExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new SqlCommandInjectionExpressionAnalyzer();
        }

        private SqlCommandInjectionExpressionAnalyzer _analyzer;

        private static readonly MetadataReference LinqReference =
            MetadataReference.CreateFromFile(typeof(Queryable).Assembly.Location);

        private static readonly MetadataReference SqlDataReference =
            MetadataReference.CreateFromFile(typeof(SqlCommand).Assembly.Location);


        private const string DefaultUsing = @"using System;
                                              using System.Data.SqlClient;
                                              using System.Linq;";

        private static InvocationExpressionSyntax GetSyntax(TestCode testCode, string name)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().Where(p => p is InvocationExpressionSyntax).ToList();

            return result.FirstOrDefault(p =>
            {
                var symbol = testCode.SemanticModel.GetSymbolInfo(p).Symbol as IMethodSymbol;
                return symbol?.Name == name &&
                       symbol?.ReceiverType.ToString() == "System.Data.SqlClient.SqlCommand";
            }) as InvocationExpressionSyntax;
        }

        private const string ExecuteReaderVulnerableCommandTextSuppliedInContructor =
            @"public class MockSqlInjectionClass
                        {
                            public MockSqlInjectionClass(string contestId)
                            {
                                using (SqlConnection cn = new SqlConnection(""connectionString""))
                                {
                                    cn.Open();
                                    var sb = new StringBuilder(""Test"");
                                    SqlCommand cmdOther = new SqlCommand();
                                    SqlCommand cmd = new SqlCommand(""select id from Contests where ID ="" + contestId, cn);
                                    SqlDataReader cName = cmd.ExecuteReader();

                                    cName.Close();
                                }
                            }
                        }";

        private const string ExecuteReaderVulnerableCommandTextSuppliedViaObjectInit =
            @"public class MockSqlInjectionClass
    {
        public MockSqlInjectionClass(string contestId)
        {
            using (SqlConnection cn = new SqlConnection(""connectionString""))
            {
                cn.Open();
                var sb = new StringBuilder(""Test"");
                SqlCommand cmdOther = new SqlCommand();
                SqlCommand cmd = new SqlCommand
                {
                    CommandText = ""select id from Contests where ID = "" + contestId,
                    Connection = cn
                };
                SqlDataReader cName = cmd.ExecuteReader();

                cName.Close();
            }
        }
    }";

        private const string ExecuteReaderVulnerableCommandTextSuppliedViaCommandText =
            @"public class MockSqlInjectionClass
    {
        public MockSqlInjectionClass(string contestId)
        {
            using (SqlConnection cn = new SqlConnection(""connectionString""))
            {
                cn.Open();
                SqlCommand cmd = new SqlCommand();
                cmd.Connection = cn;
                cmd.CommandText = ""select id from Contests where ID = "" + contestId;
                SqlDataReader cName = cmd.ExecuteReader();

                cName.Close();
            }
        }
    }";

        [TestCase(ExecuteReaderVulnerableCommandTextSuppliedInContructor, true)]
        [TestCase(ExecuteReaderVulnerableCommandTextSuppliedViaCommandText, true)]
        [TestCase(ExecuteReaderVulnerableCommandTextSuppliedViaObjectInit, true)]
        //TODO: assigned via local var thru ctor, cmdText or obj init
        //TODO: method supplies cmdTxt to ctor, cmText or obj init
        public void TestExecuteReader(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code, SqlDataReference, LinqReference);

            var syntax = GetSyntax(testCode, "ExecuteReader");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(expectedResult, result);
        }

        public void TestExecuteNonQuery(string code, bool expectedResult)
        {
            //var testCode = new TestCode(DefaultUsing + code, SqlDataReference, LinqReference);

            //var syntax = GetExecuteReaderSyntax(testCode);

            //var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            //Assert.That(result, Is.False);
        }

        public void TestExecuteScalar(string code, bool expectedResult)
        {
            //var testCode = new TestCode(DefaultUsing + code, SqlDataReference, LinqReference);

            //var syntax = GetExecuteReaderSyntax(testCode);

            //var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            //Assert.That(result, Is.False);
        }
    }


    //public class MockSqlInjectionClass
    //{
    //    public MockSqlInjectionClass(string contestId)
    //    {
    //        using (SqlConnection cn = new SqlConnection("connectionString"))
    //        {
    //            cn.Open();
    //            SqlCommand cmd = new SqlCommand();
    //            cmd.Connection = cn;
    //            cmd.CommandText = "select id from Contests where ID = " + contestId;
    //            SqlDataReader cName = cmd.ExecuteReader();

    //            cName.Close();
    //        }
    //    }
    //}

    //string newEntry = "Insert Into ContestEntries (ContestID, Name, Address, PostalCode, City, Province, PhoneNumber, EmailAddress, TermsAgreement) ";
    //newEntry += "values (" + contestId + ", '" + model.Name + "', '" + model.Address + "', '" + model.PostalCode + "', '"
    //                    + model.City + "', '" + stateAbbreviation + "', '" + model.Phone + "', '" + model.Email + "', 1)";

    //cmd.CommandText = newEntry;
    //cmd.ExecuteNonQuery();
    //cn.Close();
}