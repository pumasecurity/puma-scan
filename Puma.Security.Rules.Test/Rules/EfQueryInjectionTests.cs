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
    public class EfQueryInjectionTests
    {
        // SEC0108 matches on the fully-qualified receiver type name, so stub types
        // with the EF Core namespaces stand in for the real packages.
        private const string Stubs = @"
namespace Microsoft.EntityFrameworkCore.Infrastructure
{
    public class DatabaseFacade
    {
        public int ExecuteSqlCommand(string sql) { return 0; }
        public int ExecuteSqlRaw(string sql) { return 0; }
        public System.Threading.Tasks.Task<int> ExecuteSqlRawAsync(string sql) { return null; }
        public int ExecuteSqlInterpolated(System.FormattableString sql) { return 0; }
    }
}

namespace Microsoft.EntityFrameworkCore
{
    public class DbSet<TEntity>
    {
        public System.Linq.IQueryable<TEntity> FromSqlRaw(string sql) { return null; }
        public System.Linq.IQueryable<TEntity> FromSqlInterpolated(System.FormattableString sql) { return null; }
    }
}

public class User { }

public class AppDbContext
{
    public Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade Database { get; } =
        new Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade();

    public Microsoft.EntityFrameworkCore.DbSet<User> Users { get; } =
        new Microsoft.EntityFrameworkCore.DbSet<User>();
}
";

        [TestMethod]
        public async Task ExecuteSqlRawWithTaintedArgumentFlagsSEC0108()
        {
            var test = Stubs + @"
public class Repo
{
    public void Execute(AppDbContext db, string input)
    {
        {|SEC0108:db.Database.ExecuteSqlRaw(""SELECT * FROM Users WHERE Name = '"" + input + ""'"")|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task ExecuteSqlRawAsyncWithTaintedArgumentFlagsSEC0108()
        {
            var test = Stubs + @"
public class Repo
{
    public async System.Threading.Tasks.Task Execute(AppDbContext db, string input)
    {
        await {|SEC0108:db.Database.ExecuteSqlRawAsync(""SELECT * FROM Users WHERE Name = '"" + input + ""'"")|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task FromSqlRawWithTaintedArgumentFlagsSEC0108()
        {
            var test = Stubs + @"
public class Repo
{
    public void Execute(AppDbContext db, string input)
    {
        var users = {|SEC0108:db.Users.FromSqlRaw(""SELECT * FROM Users WHERE Name = '"" + input + ""'"")|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task LegacyExecuteSqlCommandWithTaintedArgumentStillFlagsSEC0108()
        {
            var test = Stubs + @"
public class Repo
{
    public void Execute(AppDbContext db, string input)
    {
        {|SEC0108:db.Database.ExecuteSqlCommand(""SELECT * FROM Users WHERE Name = '"" + input + ""'"")|};
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task ExecuteSqlInterpolatedDoesNotFlag()
        {
            var test = Stubs + @"
public class Repo
{
    public void Execute(AppDbContext db, string input)
    {
        db.Database.ExecuteSqlInterpolated($""SELECT * FROM Users WHERE Name = {input}"");
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }

        [TestMethod]
        public async Task ExecuteSqlRawWithConstantCommandDoesNotFlag()
        {
            var test = Stubs + @"
public class Repo
{
    public void Execute(AppDbContext db)
    {
        db.Database.ExecuteSqlRaw(""SELECT * FROM Users"");
    }
}
";
            await PumaVerifier.VerifyAnalyzerAsync(test);
        }
    }
}
