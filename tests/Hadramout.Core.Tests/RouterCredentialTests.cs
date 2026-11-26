using System.Runtime.Versioning;
using System.Security.Cryptography;
using Hadramout.Core;
using Hadramout.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Hadramout.Core.Tests;

[SupportedOSPlatform("windows")]
public sealed class RouterCredentialTests
{
    [Fact]
    public void PublishedProbeContract() => Assert.True(CredentialProbe.Verify());

    [Fact]
    public void SaveLoadUpdateRemoveAndEmptyPassword()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Path);
        Assert.Null(store.Load(f.First));
        store.Save(f.First, "first-user"u8, "first-password"u8);
        using (var lease = new RouterCredentialStore(f.Path).Load(f.First))
        {
            Assert.NotNull(lease);
            Assert.True(lease.Username.SequenceEqual("first-user"u8));
            Assert.True(lease.Password.SequenceEqual("first-password"u8));
        }
        store.Save(f.First, "changed-user"u8, ReadOnlySpan<byte>.Empty);
        using (var lease = store.Load(f.First))
        {
            Assert.NotNull(lease);
            Assert.True(lease.Username.SequenceEqual("changed-user"u8));
            Assert.True(lease.Password.IsEmpty);
        }
        Assert.True(store.Remove(f.First));
        Assert.False(store.Remove(f.First));
        Assert.Null(store.Load(f.First));
    }

    [Fact]
    public void OnlyEncryptedBlobsArePersisted()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Path);
        store.Save(f.First, "synthetic-username-123"u8, "synthetic-password-456"u8);
        using var c = DatabaseStore.Open(f.Path);
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT UsernameEnvelope, PasswordEnvelope FROM router_credentials;";
        using var reader = cmd.ExecuteReader();
        Assert.True(reader.Read());
        byte[] user = reader.GetFieldValue<byte[]>(0);
        byte[] pass = reader.GetFieldValue<byte[]>(1);
        Assert.Equal(-1, user.AsSpan().IndexOf("synthetic-username-123"u8));
        Assert.Equal(-1, pass.AsSpan().IndexOf("synthetic-password-456"u8));
    }

    [Fact]
    public void RepeatedSavesUseDifferentEnvelopes()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Path);
        store.Save(f.First, "user"u8, "password"u8);
        byte[] before = f.PasswordBlob();
        store.Save(f.First, "user"u8, "password"u8);
        Assert.False(before.AsSpan().SequenceEqual(f.PasswordBlob()));
    }

    [Fact]
    public void TamperedCiphertextFailsClosed()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Path);
        store.Save(f.First, "user"u8, "password"u8);
        byte[] blob = f.PasswordBlob();
        blob[^1] ^= 1;
        using (var c = DatabaseStore.Open(f.Path))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "UPDATE router_credentials SET PasswordEnvelope=$blob;";
            cmd.Parameters.Add("$blob", SqliteType.Blob).Value = blob;
            cmd.ExecuteNonQuery();
        }
        Assert.Throws<CryptographicException>(() => store.Load(f.First));
    }

    [Fact]
    public void TransplantedRouterCredentialsFailClosed()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Path);
        store.Save(f.First, "user"u8, "password"u8);
        using (var c = DatabaseStore.Open(f.Path))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = """
                INSERT INTO router_credentials
                SELECT $target, UsernameEnvelope, PasswordEnvelope FROM router_credentials WHERE RouterId=$source;
                """;
            cmd.Parameters.AddWithValue("$target", f.Second);
            cmd.Parameters.AddWithValue("$source", f.First);
            cmd.ExecuteNonQuery();
        }
        Assert.Throws<CryptographicException>(() => store.Load(f.Second));
    }

    [Fact]
    public void SwappedFieldsFailClosed()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Path);
        store.Save(f.First, "user"u8, "password"u8);
        using (var c = DatabaseStore.Open(f.Path))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "UPDATE router_credentials SET UsernameEnvelope=PasswordEnvelope;";
            cmd.ExecuteNonQuery();
        }
        Assert.Throws<CryptographicException>(() => store.Load(f.First));
    }

    [Fact]
    public void MissingRouterAndInvalidInputsAreRejected()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Path);
        Assert.Throws<ArgumentException>(() => store.Save(Guid.Empty, "user"u8, "password"u8));
        Assert.Throws<ArgumentException>(() => store.Save(f.First, ReadOnlySpan<byte>.Empty, "password"u8));
        Assert.Throws<ArgumentException>(() => store.Save(f.First, "user"u8, new byte[4097]));
        Assert.Throws<SqliteException>(() => store.Save(Guid.NewGuid(), "user"u8, "password"u8));
    }

    [Fact]
    public void DisposedLeaseCannotBeRead()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Path);
        store.Save(f.First, "user"u8, "password"u8);
        using var lease = store.Load(f.First);
        Assert.NotNull(lease);
        lease.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { _ = lease.Username.Length; });
        Assert.Throws<ObjectDisposedException>(() => { _ = lease.Password.Length; });
    }

    [Fact]
    public void VersionTwoMigratesWithoutLosingRouter()
    {
        using var f = new Fixture();
        using (var c = DatabaseStore.Open(f.Path))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "DROP TABLE audit_events; DROP TABLE router_credentials; PRAGMA user_version=2;";
            cmd.ExecuteNonQuery();
        }
        var store = new RouterCredentialStore(f.Path);
        Assert.Null(store.Load(f.First));
        store.Save(f.First, "user"u8, "pass"u8);
        using var lease = store.Load(f.First);
        Assert.NotNull(lease);
        Assert.True(lease.Password.SequenceEqual("pass"u8));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("hadramout-credentials-");
        public string Path => System.IO.Path.Combine(directory.FullName, "test.db");
        public Guid First { get; }
        public Guid Second { get; }
        public Fixture()
        {
            using var c = DatabaseStore.Open(Path);
            using var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c).Options);
            var site = new Site { Name = "site" };
            var first = new Router { SiteId = site.Id, Name = "first" };
            var second = new Router { SiteId = site.Id, Name = "second" };
            db.AddRange(site, first, second);
            db.SaveChanges();
            First = first.Id;
            Second = second.Id;
        }
        public byte[] PasswordBlob()
        {
            using var c = DatabaseStore.Open(Path);
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT PasswordEnvelope FROM router_credentials;";
            return (byte[])cmd.ExecuteScalar()!;
        }
        public void Dispose() => directory.Delete(recursive: true);
    }
}
