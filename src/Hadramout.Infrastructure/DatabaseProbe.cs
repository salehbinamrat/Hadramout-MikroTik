using Hadramout.Core;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Hadramout.Infrastructure;

// Only a disposable, in-memory compatibility check. Never opens user data.
public static class DatabaseProbe
{
    public static bool Verify()
    {
        using var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True;Pooling=False");
        connection.Open();
        var options = new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(connection).Options;
        using var db = new NetworkDbContext(options);
        db.Database.EnsureCreated();
        var site = new Site { Name = "compatibility-probe" };
        db.Sites.Add(site);
        db.SaveChanges();
        db.ChangeTracker.Clear();
        return db.Sites.Single().Id == site.Id;
    }
}
