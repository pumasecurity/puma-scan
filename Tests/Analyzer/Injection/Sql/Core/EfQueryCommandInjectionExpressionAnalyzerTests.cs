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

using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity;
using System.Data.Entity.ModelConfiguration.Conventions;
using System.Linq;

using Puma.Security.Rules.Analyzer.Injection.Sql.Core;
using Puma.Security.Rules.Test.Helpers;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using NUnit.Framework;

namespace Puma.Security.Rules.Test.Analyzer.Injection.Sql.Core
{
    [TestFixture]
    public class EfQueryCommandInjectionExpressionAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new EfQueryCommandInjectionExpressionAnalyzer();
        }

        private EfQueryCommandInjectionExpressionAnalyzer _analyzer;

        private static readonly MetadataReference ComponentModelReference =
            MetadataReference.CreateFromFile(typeof(Container).Assembly.Location);

        private static readonly MetadataReference LinqReference =
            MetadataReference.CreateFromFile(typeof(Queryable).Assembly.Location);

        private static readonly MetadataReference DataAnnotationsSchemaDataReference =
            MetadataReference.CreateFromFile(typeof(ColumnAttribute).Assembly.Location);

        private static readonly MetadataReference DataAnnotationsDataReference =
            MetadataReference.CreateFromFile(typeof(DataTypeAttribute).Assembly.Location);

        private static readonly MetadataReference EntityFrameworkDataReference =
            MetadataReference.CreateFromFile(typeof(Database).Assembly.Location);

        private static readonly MetadataReference EntityFrameworkModelConfigurationDataReference =
            MetadataReference.CreateFromFile(typeof(ColumnAttributeConvention).Assembly.Location);


        private const string DefaultUsing = @"using System;
                                                using System.ComponentModel;
                                                using System.ComponentModel.DataAnnotations;
                                                using System.ComponentModel.DataAnnotations.Schema;
                                                using System.Data.Entity;
                                                using System.Data.Entity.ModelConfiguration.Conventions;
                                                using System.Linq;";

        private static InvocationExpressionSyntax GetSyntax(TestCode testCode, string name)
        {
            var result =
                testCode.SyntaxTree.GetRoot().DescendantNodes().Where(p => p is InvocationExpressionSyntax).ToList();

            return result.FirstOrDefault(p =>
            {
                var symbol = testCode.SemanticModel.GetSymbolInfo(p).Symbol as IMethodSymbol;
                return symbol?.Name == name &&
                       (symbol?.ReceiverType.OriginalDefinition.ToString() == "System.Data.Entity.DbSet<TEntity>" ||
                        symbol?.ReceiverType.OriginalDefinition.ToString() == "System.Data.Entity.Database");
            }) as InvocationExpressionSyntax;
        }

        private const string SqlQueryOnEfDatabase = @" public class MockEfClass
    {
        public MockEfClass(string name)
        {
            using (var context = new MockContext())
            {
                var things = context.Database.SqlQuery<string>(""SELECT * FROM dbo.MockEntities Where Name = "" + name).ToList();
            }
        }
    }";

        private const string ExecuteSqlCommandOnEfDatabase = @" public class MockEfClass
    {
        public MockEfClass(string name)
        {
            using (var context = new MockContext())
            {
                context.Database.ExecuteSqlCommand(""update dbo.MockEntities Set Name = "" + name);
            }
}
    }";

        private const string ExecuteSqlCommandAsyncOnEfDatabase = @" public class MockEfClass
    {
        public MockEfClass(string name)
        {
            using (var context = new MockContext())
            {
                context.Database.ExecuteSqlCommandAsync(""update dbo.MockEntities Set Name = "" + name);
            }
}
    }";

        private const string SqlQueryOnEfEntity =
            @" public class MockEfClass
    {
        public MockEfClass(string name)
        {
            using (var context = new MockContext())
            {
                var things = context.MockEntities.SqlQuery(""SELECT * FROM dbo.MockEntities Where Name = "" + name).ToList();
            }
        }
    }";

        [TestCase(SqlQueryOnEfEntity, true)]
        [TestCase(SqlQueryOnEfDatabase, true)]
        public void TestSqlQuery(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + MockEntityCode + code,
                LinqReference,
                ComponentModelReference,
                EntityFrameworkDataReference,
                EntityFrameworkModelConfigurationDataReference,
                DataAnnotationsDataReference,
                DataAnnotationsSchemaDataReference);

            var syntax = GetSyntax(testCode, "SqlQuery");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        [TestCase(ExecuteSqlCommandOnEfDatabase, true)]
        public void TestExecuteSqlCommand(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + MockEntityCode + code, LinqReference,
                EntityFrameworkDataReference,
                EntityFrameworkModelConfigurationDataReference, DataAnnotationsDataReference,
                DataAnnotationsSchemaDataReference);

            var syntax = GetSyntax(testCode, "ExecuteSqlCommand");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        [TestCase(ExecuteSqlCommandAsyncOnEfDatabase, true)]
        public void TestExecuteSqlCommandAsync(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + MockEntityCode + code, LinqReference,
                EntityFrameworkDataReference,
                EntityFrameworkModelConfigurationDataReference, DataAnnotationsDataReference,
                DataAnnotationsSchemaDataReference);

            var syntax = GetSyntax(testCode, "ExecuteSqlCommandAsync");

            var result = _analyzer.IsVulnerable(testCode.SemanticModel, syntax);

            Assert.AreEqual(result, expectedResult);
        }

        private const string MockEntityCode = @"[Serializable]
    [Table(""MockEntity"")]
    public partial class MockEntity
    {
        public MockEntity() { }

        public MockEntity(string Name)
        {
            this.Name = Name;
        }

        [Required, MaxLength(512)]
        public virtual string Name { get; set; }
    }

    public partial class MockContext : DbContext
    {
        static MockContext()
        {
            Database.SetInitializer<MockContext>(null);
        }

        public MockContext()
            : base(""Name=MockContext"") { }


        public DbSet<MockEntity> MockEntities { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Conventions.Remove<OneToManyCascadeDeleteConvention>();
        }

        public bool HasChanges
        {
            get
            {
                return this.ChangeTracker.Entries().Any(e => e.State == EntityState.Added || e.State == EntityState.Modified || e.State == EntityState.Deleted);
            }
        }
    }";
    }

    [Serializable]
    [Table("MockEntity")]
    public class MockEntity
    {
        public MockEntity()
        {
        }

        public MockEntity(string Name)
        {
            this.Name = Name;
        }

        [Required, MaxLength(512)]
        public virtual string Name { get; set; }
    }

    public class MockContext : DbContext
    {
        static MockContext()
        {
            Database.SetInitializer<MockContext>(null);
        }

        public MockContext()
            : base("Name=MockContext")
        {
        }


        public DbSet<MockEntity> MockEntities { get; set; }

        public bool HasChanges
        {
            get
            {
                return
                    ChangeTracker.Entries()
                        .Any(
                            e =>
                                e.State == EntityState.Added || e.State == EntityState.Modified ||
                                e.State == EntityState.Deleted);
            }
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Conventions.Remove<OneToManyCascadeDeleteConvention>();
        }
    }

    public class MockEfClass
    {
        public MockEfClass(string name)
        {
            using (var context = new MockContext())
            {
                context.Database.ExecuteSqlCommandAsync("update dbo.MockEntities Set Name = " + name);
            }
        }
    }
}