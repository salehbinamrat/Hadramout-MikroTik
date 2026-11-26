using Hadramout.Core;
using Microsoft.EntityFrameworkCore;

namespace Hadramout.Infrastructure;

public static class BackupProbe
{
    public static bool Verify()
    {
        var directory = Directory.CreateTempSubdirectory("hadramout-backup-probe-");
        try
        {
            string source = Path.Combine(directory.FullName, "source.db");
            string backup = Path.Combine(directory.FullName, "backup.db");
            string candidate = Path.Combine(directory.FullName, "candidate.db");
            using (var c = DatabaseStore.Open(source))
            using (var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c).Options))
            {
                db.Sites.Add(new Site { Name = "backup-probe" });
                db.SaveChanges();
                var receipt = DatabaseBackup.Create(source, backup);
                DatabaseBackup.PrepareRestore(backup, candidate, receipt.Sha256);
            }
            using var restored = DatabaseStore.Open(candidate);
            using var read = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(restored).Options);
            return read.Sites.Single().Name == "backup-probe"
                && AuditStore.ReadRecent(candidate).Count == 2;
        }
        finally { directory.Delete(recursive: true); }
    }
}
