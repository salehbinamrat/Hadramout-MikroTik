using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Hadramout.Infrastructure;

// A fresh AES-256-GCM key for each envelope, protected by Windows DPAPI CurrentUser.
// The version, router identity and field purpose are authenticated together.
[SupportedOSPlatform("windows")]
internal static class RouterCredentialProtector
{
    private const byte Version = 1;
    private const int Header = 5;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    internal const int MaxSecretLength = 4096;
    private const int MaxWrappedKey = 16384;

    internal static byte[] Protect(Guid routerId, string purpose, ReadOnlySpan<byte> secret)
    {
        if (secret.Length > MaxSecretLength)
            throw new ArgumentException("Credential exceeds the supported length.");
        byte[] context = Context(routerId, purpose);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        try
        {
            byte[] wrapped = ProtectedData.Protect(key, context, DataProtectionScope.CurrentUser);
            if (wrapped.Length is < 1 or > MaxWrappedKey)
                throw new CryptographicException("Credential protection failed.");
            byte[] result = new byte[Header + wrapped.Length + NonceSize + TagSize + secret.Length];
            result[0] = Version;
            BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(1, 4), wrapped.Length);
            wrapped.CopyTo(result, Header);
            int offset = Header + wrapped.Length;
            Span<byte> nonce = result.AsSpan(offset, NonceSize);
            RandomNumberGenerator.Fill(nonce);
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, secret, result.AsSpan(offset + NonceSize + TagSize),
                result.AsSpan(offset + NonceSize, TagSize), context);
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal static byte[] Unprotect(Guid routerId, string purpose, byte[] envelope)
    {
        if (envelope.Length < Header + NonceSize + TagSize + 1 || envelope[0] != Version)
            throw Failure();
        int wrappedLength = BinaryPrimitives.ReadInt32LittleEndian(envelope.AsSpan(1, 4));
        if (wrappedLength is < 1 or > MaxWrappedKey ||
            envelope.Length < Header + wrappedLength + NonceSize + TagSize)
            throw Failure();
        int offset = Header + wrappedLength;
        int length = envelope.Length - offset - NonceSize - TagSize;
        if (length > MaxSecretLength) throw Failure();

        byte[] context = Context(routerId, purpose);
        byte[]? key = null;
        byte[] clear = new byte[length];
        bool success = false;
        try
        {
            key = ProtectedData.Unprotect(envelope.AsSpan(Header, wrappedLength).ToArray(),
                context, DataProtectionScope.CurrentUser);
            if (key.Length != 32) throw Failure();
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(envelope.AsSpan(offset, NonceSize),
                envelope.AsSpan(offset + NonceSize + TagSize),
                envelope.AsSpan(offset + NonceSize, TagSize), clear, context);
            success = true;
            return clear;
        }
        catch (CryptographicException) { throw Failure(); }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (!success) CryptographicOperations.ZeroMemory(clear);
        }
    }

    private static byte[] Context(Guid id, string purpose) =>
        Encoding.UTF8.GetBytes($"HadramoutMikroTik/credential/v1/{id:D}/{purpose}");
    private static CryptographicException Failure() => new("Stored router credential is unavailable or invalid.");
}
