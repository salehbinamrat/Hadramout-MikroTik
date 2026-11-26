using System.Runtime.Versioning;
using Hadramout.Core;
using Microsoft.EntityFrameworkCore;

namespace Hadramout.Infrastructure;

[SupportedOSPlatform("windows")]
public static class CredentialProbe
{
    // Disposable synthetic data only, executed by both published Windows architectures.
    public static bool Verify()
    {
        var directory = Directory.CreateTempSubdirectory("hadramout-credential-probe-");
        var path = Path.Combine(directory.FullName, "probe.db");
        try
        {
            var site = new Site { Name = "probe" };
            var router = new Router { SiteId = site.Id, Name = "probe" };
            using (var c = DatabaseStore.Open(path))
            using (var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c).Options))
            {
                db.AddRange(site, router);
                db.SaveChanges();
            }
            var store = new RouterCredentialStore(path);
            store.Save(router.Id, "test-user"u8, "test-password"u8);
            using var lease = store.Load(router.Id);
            return lease is not null && lease.Username.SequenceEqual("test-user"u8)
                && lease.Password.SequenceEqual("test-password"u8);
        }
        finally { directory.Delete(recursive: true); }
    }
}
