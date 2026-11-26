using System.Runtime.Versioning;
using Hadramout.Core;
using Microsoft.EntityFrameworkCore;

namespace Hadramout.Infrastructure;

[SupportedOSPlatform("windows")]
public static class RestoreCredentialProbe
{
    public static bool Verify()
    {
        var directory = Directory.CreateTempSubdirectory("hadramout-restore-credential-probe-");
        try
        {
            string source = Path.Combine(directory.FullName, "source.db");
            string encrypted = Path.Combine(directory.FullName, "backup.hmk");
            string candidate = Path.Combine(directory.FullName, "candidate.db");
            var site = new Site { Name = "probe" };
            var first = new Router { SiteId = site.Id, Name = "first" };
            var second = new Router { SiteId = site.Id, Name = "second" };
            using (var c = DatabaseStore.Open(source))
            using (var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c).Options))
            {
                db.AddRange(site, first, second);
                db.SaveChanges();
            }
            new RouterCredentialStore(source).Save(first.Id, "probe-user"u8, "probe-password"u8);
            EncryptedDatabaseBackup.Create(source, encrypted, "synthetic-probe-password"u8);
            EncryptedDatabaseBackup.PrepareRestore(encrypted, candidate, "synthetic-probe-password"u8);
            var statuses = RestoreCredentialInspector.Inspect(candidate);
            if (statuses.Count != 2 ||
                statuses.Single(x => x.RouterId == first.Id).State != RestoreCredentialState.AvailableLocally ||
                statuses.Single(x => x.RouterId == second.Id).State != RestoreCredentialState.Missing)
                return false;

            // Synthetic invalid envelope models a local decryption failure, not a real second account.
            using (var c = DatabaseStore.Open(candidate))
            using (var cmd = c.CreateCommand())
            {
                cmd.CommandText = "UPDATE router_credentials SET PasswordEnvelope=X'01';";
                cmd.ExecuteNonQuery();
            }
            if (RestoreCredentialInspector.Inspect(candidate).Single(x => x.RouterId == first.Id).State
                != RestoreCredentialState.Unavailable) return false;
            new RouterCredentialStore(candidate).ReenterUnavailable(first.Id, "new-user"u8, "new-password"u8);
            return RestoreCredentialInspector.Inspect(candidate).Single(x => x.RouterId == first.Id).State
                == RestoreCredentialState.AvailableLocally;
        }
        finally { directory.Delete(recursive: true); }
    }
}
