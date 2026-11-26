using Hadramout.Core;
using Microsoft.EntityFrameworkCore;

namespace Hadramout.Infrastructure;

public static class EncryptedBackupProbe
{
    public static bool Verify()
    {
        var directory = Directory.CreateTempSubdirectory("hadramout-encrypted-probe-");
        try
        {
            string source = Path.Combine(directory.FullName, "source.db");
            string encrypted = Path.Combine(directory.FullName, "backup.hmk");
            string candidate = Path.Combine(directory.FullName, "candidate.db");
            using (var c = DatabaseStore.Open(source))
            using (var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c).Options))
            {
                db.Sites.Add(new Site { Name = "encrypted-probe" });
                db.SaveChanges();
            }
            EncryptedDatabaseBackup.Create(source, encrypted, "synthetic-probe-password"u8);
            EncryptedDatabaseBackup.PrepareRestore(encrypted, candidate, "synthetic-probe-password"u8);
            using var connection = DatabaseStore.Open(candidate);
            using var restored = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>()
                .UseSqlite(connection).Options);
            return restored.Sites.Single().Name == "encrypted-probe";
        }
        finally { directory.Delete(recursive: true); }
    }
}
