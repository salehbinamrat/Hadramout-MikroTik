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
                using var cmd = c.CreateCommand();
                cmd.CommandText = "CREATE TABLE test_payload(Data BLOB NOT NULL); INSERT INTO test_payload VALUES(zeroblob(3145728));";
                cmd.ExecuteNonQuery();
            }
            EncryptedDatabaseBackup.Create(source, encrypted, "synthetic-probe-password"u8);
            string precaution = Path.Combine(directory.FullName, "precaution.hmk");
            EncryptedDatabaseBackup.PrepareWithPrecaution(source, encrypted, candidate, precaution,
                "synthetic-probe-password"u8, "synthetic-precaution-password"u8);
            using var connection = DatabaseStore.Open(candidate);
            using var restored = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>()
                .UseSqlite(connection).Options);
            using var check = connection.CreateCommand();
            check.CommandText = "SELECT length(Data) FROM test_payload;";
            return restored.Sites.Single().Name == "encrypted-probe" && (long)check.ExecuteScalar()! == 3145728;
        }
        finally { directory.Delete(recursive: true); }
    }
}
