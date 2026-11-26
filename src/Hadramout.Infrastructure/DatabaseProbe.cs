using System.Runtime.Versioning;
using Hadramout.Core;
using Microsoft.EntityFrameworkCore;

namespace Hadramout.Infrastructure;

// Disposable on-disk test of actual migrations, native provider and reopen.
// Never opens user data.
public static class DatabaseProbe
{
    public static bool Verify()
    {
        var directory = Directory.CreateTempSubdirectory("hadramout-probe-");
        var path = Path.Combine(directory.FullName, "probe.db");
        try
        {
            var site = new Site { Name = "compatibility-probe" };
            using (var connection = DatabaseStore.Open(path))
            using (var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>()
                .UseSqlite(connection).Options))
            {
                db.Sites.Add(site);
                db.SaveChanges();
            }

            using var reopened = DatabaseStore.Open(path);
            using var readDb = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>()
                .UseSqlite(reopened).Options);
            return readDb.Sites.Single().Id == site.Id;
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [SupportedOSPlatform("windows")]
    public static bool VerifyManagedStartup()
    {
        var directory = Directory.CreateTempSubdirectory("hadramout-managed-startup-");
        try
        {
            Guid id;
            using (var session = ManagedDatabase.OpenApplicationSessionAt(directory.FullName))
            {
                id = session.Generation;
                using var c = DatabaseStore.OpenExisting(session.DatabasePath);
                using var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>()
                    .UseSqlite(c).Options);
                db.Sites.Add(new Site { Name = "managed-startup-probe" });
                db.SaveChanges();
            }
            using var reopened = ManagedDatabase.OpenApplicationSessionAt(directory.FullName);
            using var connection = DatabaseStore.OpenExisting(reopened.DatabasePath);
            using var read = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>()
                .UseSqlite(connection).Options);
            return id == reopened.Generation && read.Sites.Single().Name == "managed-startup-probe";
        }
        finally { directory.Delete(recursive: true); }
    }
}
