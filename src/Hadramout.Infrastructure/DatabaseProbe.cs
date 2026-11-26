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
}
