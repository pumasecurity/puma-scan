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

using System.Data;
using System.Data.Linq;
using System.Linq;

using Puma.Security.Rules.Analyzer.Injection.Sql.Core;
using Puma.Security.Rules.Test.Helpers;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using NUnit.Framework;

namespace Puma.Security.Rules.Test.Analyzer.Injection.Sql.Core
{
    [TestFixture]
    public class LinqSqlInjectionExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new LinqSqlInjectionExpressionAnalyzer();
        }

        private LinqSqlInjectionExpressionAnalyzer _analyzer;

        private static readonly MetadataReference LinqReference =
            MetadataReference.CreateFromFile(typeof(Queryable).Assembly.Location);

        private static readonly MetadataReference DataLinqReference =
            MetadataReference.CreateFromFile(typeof(DataContext).Assembly.Location);

        private static readonly MetadataReference DataReference =
            MetadataReference.CreateFromFile(typeof(DataColumn).Assembly.Location);


        private const string DefaultUsing = @"using System;
                                                using System.Data;
                                                using System.Linq;
                                                using System.Data.Linq;
                                                using System.Data.Linq.Mapping;";

        private const string MockDbContext = @"public partial class MockDbContext : System.Data.Linq.DataContext {
                            public MockDbContext(string fileOrServerOrConnection) : base(fileOrServerOrConnection)
                            {
                            }

                            public MockDbContext(string fileOrServerOrConnection, MappingSource mapping) : base(fileOrServerOrConnection, mapping)
                            {
                            }

                            public MockDbContext(IDbConnection connection) : base(connection)
                            {
                            }

                            public MockDbContext(IDbConnection connection, MappingSource mapping) : base(connection, mapping)
                            {
                            }
                        }";

        private const string ExecuteQueryWhereQuerySuppliedFromMethod = @" public class MockLinqTestClass
                        {
                            private string Destination;
                            private MockDbContext dbContext = new MockDbContext(""connectionString"");
                            
                            public string GetQuery() 
                            {
                                int productId = 1;
                                string q = ""Select ProductName from Products where ID = "" + productId;
                                return q;
                            }

                            public MockLinqTestClass()
                            {   
                                Destination = dbContext.ExecuteQuery<string>(GetQuery()).SingleOrDefault().ToString();
                                }
                            }";

        private const string ExecuteQueryWhereQuerySuppliedFromBinaryExpressionWithoutParamArg =
            @" public class MockLinqTestClass
                        {
                            private string Destination;
                            private MockDbContext dbContext = new MockDbContext(""connectionString"");
                            public MockLinqTestClass()
                            {
                                int productId = 1;
                                Destination = dbContext.ExecuteQuery<string>(""Select ProductName from Products where ID = "" + productId).SingleOrDefault().ToString();
                                }
                            }";

        private const string ExecuteQueryWhereQuerySuppliedFromLiteralWithParamArg = @"public class MockLinqTestClass
                        {
                            private string Destination;
                            private MockDbContext dbContext = new MockDbContext(""connectionString"");
                            public MockLinqTestClass()
                            {
                                int productId = 1;
                                string q = ""Select ProductName from Products where ID = {0}"";
                                Destination = dbContext.ExecuteQuery<string>(q, productId).SingleOrDefault().ToString();
                                }
                            }";

        private const string ExecuteQueryWhereQuerySuppliedFromVar = @"
                        public class MockLinqTestClass
                        {
                            private string Destination;
                            private MockDbContext dbContext = new MockDbContext(""connectionString"");
                            public MockLinqTestClass()
                            {
                                int productId = 1;
                                string q = ""Select ProductName from Products where ID = "" + productId;
                                Destination = dbContext.ExecuteQuery<string>(q).SingleOrDefault().ToString();
                                }
                            }";
        
        private const string ExecuteCommandWhereQuerySuppliedFromLiteralWithParamArg = @"public class MockLinqTestClass
    {
        private MockDbContext dbContext = new MockDbContext("""");
        public MockLinqTestClass(string productName)
        {   
            dbContext.ExecuteCommand(""insert into dbo.Products (Name) Values({0})"", productName);
        }
    }";

        private const string ExecuteCommandWhereQuerySuppliedFromBinaryExpressionWithoutParamArg = @"public class MockLinqTestClass
    {
        private MockDbContext dbContext = new MockDbContext("""");
        public MockLinqTestClass(string productName)
        {
            dbContext.ExecuteCommand(""insert into dbo.Products (Name) Values("" + productName+ "")"");
        }
    }";


        private static InvocationExpressionSyntax GetExecuteQuerySyntax(TestCode testCode, string methodName)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().Where(p => p is InvocationExpressionSyntax).ToList();

            return result.FirstOrDefault(p =>
            {
                var symbol = testCode.SemanticModel.GetSymbolInfo(p).Symbol as IMethodSymbol;
                return symbol?.Name == methodName &&
                       symbol?.ReceiverType.ToString() == "System.Data.Linq.DataContext";
            }) as InvocationExpressionSyntax;
        }

        [TestCase(ExecuteQueryWhereQuerySuppliedFromVar, true, Ignore = "Dataflow scenario")]
        [TestCase(ExecuteQueryWhereQuerySuppliedFromMethod, true, Ignore = "Dataflow scenario")]
        [TestCase(ExecuteQueryWhereQuerySuppliedFromLiteralWithParamArg, false)]
        [TestCase(ExecuteQueryWhereQuerySuppliedFromBinaryExpressionWithoutParamArg, true)]
        public void TestExecuteReader(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + MockDbContext + code, DataReference, LinqReference,
                DataLinqReference);

            var syntax = GetExecuteQuerySyntax(testCode, "ExecuteQuery");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        
        [TestCase(ExecuteCommandWhereQuerySuppliedFromLiteralWithParamArg, false)]
        [TestCase(ExecuteCommandWhereQuerySuppliedFromBinaryExpressionWithoutParamArg, true)]
        public void TestExecuteCommand(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + MockDbContext + code, DataReference, LinqReference,
                DataLinqReference);

            var syntax = GetExecuteQuerySyntax(testCode, "ExecuteCommand");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }
    }

    //public partial class MockDbContext : System.Data.Linq.DataContext
    //{
    //    public MockDbContext(string fileOrServerOrConnection) : base(fileOrServerOrConnection)
    //    {
    //    }

    //    public MockDbContext(string fileOrServerOrConnection, MappingSource mapping) : base(fileOrServerOrConnection, mapping)
    //    {
    //    }

    //    public MockDbContext(IDbConnection connection) : base(connection)
    //    {
    //    }

    //    public MockDbContext(IDbConnection connection, MappingSource mapping) : base(connection, mapping)
    //    {
    //    }
    //}

    //public class MockLinqTestClass
    //{
    //    private MockDbContext dbContext = new MockDbContext("");
    //    public MockLinqTestClass(string productName)
    //    {
            
    //        string q = "insert into dbo.Products (Name)" +
    //                   "Values(" + productName+ ")";
    //        dbContext.ExecuteCommand(q);
    //    }
    //}
}