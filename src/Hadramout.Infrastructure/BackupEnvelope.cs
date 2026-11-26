using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Hadramout.Infrastructure;

// Frozen formats. v1 remains readable; v2 is the only writer.
internal static class BackupEnvelope
{
    private const int ChunkSize = 1024 * 1024;
    private const int SaltSize = 16;
    private const int TagSize = 16;
    private const int Iterations = 600_000;
    private const int HeaderSize = 40;
    private const int LegacyLimit = 64 * 1024 * 1024;
    private static ReadOnlySpan<byte> MagicV1 => "HMKBACK1"u8;
    private static ReadOnlySpan<byte> MagicV2 => "HMKBACK2"u8;

    internal static void Write(Stream input, Stream output, ReadOnlySpan<byte> password)
    {
        long length = input.Length;
        if (length is < 1 or > EncryptedDatabaseBackup.MaximumSnapshotBytes)
            throw InvalidFormat();
        byte[] header = new byte[HeaderSize];
        MagicV2.CopyTo(header);
        RandomNumberGenerator.Fill(header.AsSpan(8, SaltSize + 8));
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(32), length);
        byte[] key = Derive(password, header);
        byte[] clear = new byte[ChunkSize];
        byte[] cipher = new byte[ChunkSize];
        byte[] nonce = new byte[12];
        byte[] aad = new byte[HeaderSize + 4];
        byte[] tag = new byte[TagSize];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            output.Write(header);
            header.CopyTo(aad, 0);
            header.AsSpan(24, 8).CopyTo(nonce);
            for (uint index = 0; length > 0; index++)
            {
                int size = (int)Math.Min(length, ChunkSize);
                input.ReadExactly(clear.AsSpan(0, size));
                SetIndex(index, nonce, aad);
                aes.Encrypt(nonce, clear.AsSpan(0, size), cipher.AsSpan(0, size), tag, aad);
                output.Write(cipher.AsSpan(0, size));
                output.Write(tag);
                CryptographicOperations.ZeroMemory(clear.AsSpan(0, size));
                length -= size;
            }
            if (input.ReadByte() != -1) throw InvalidFormat();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(clear);
        }
    }

    internal static void Read(Stream input, Stream output, ReadOnlySpan<byte> password)
    {
        try
        {
            byte[] header = new byte[HeaderSize];
            input.ReadExactly(header);
            if (header.AsSpan(0, 8).SequenceEqual(MagicV2))
                ReadV2(input, output, password, header);
            else if (header.AsSpan(0, 8).SequenceEqual(MagicV1))
                ReadV1(input, output, password, header);
            else throw InvalidFormat();
        }
        catch (EndOfStreamException) { throw InvalidFormat(); }
        catch (CryptographicException) { throw new CryptographicException("Backup authentication failed."); }
    }

    private static void ReadV2(Stream input, Stream output, ReadOnlySpan<byte> password, byte[] header)
    {
        long length = BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(32));
        if (length is < 1 or > EncryptedDatabaseBackup.MaximumSnapshotBytes)
            throw InvalidFormat();
        long chunks = (length + ChunkSize - 1) / ChunkSize;
        if (input.Length != HeaderSize + length + chunks * TagSize)
            throw InvalidFormat();

        byte[] key = Derive(password, header);
        byte[] clear = new byte[ChunkSize];
        byte[] cipher = new byte[ChunkSize];
        byte[] nonce = new byte[12];
        byte[] aad = new byte[HeaderSize + 4];
        byte[] tag = new byte[TagSize];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            header.CopyTo(aad, 0);
            header.AsSpan(24, 8).CopyTo(nonce);
            for (uint index = 0; length > 0; index++)
            {
                int size = (int)Math.Min(length, ChunkSize);
                input.ReadExactly(cipher.AsSpan(0, size));
                input.ReadExactly(tag);
                SetIndex(index, nonce, aad);
                aes.Decrypt(nonce, cipher.AsSpan(0, size), tag, clear.AsSpan(0, size), aad);
                output.Write(clear.AsSpan(0, size));
                CryptographicOperations.ZeroMemory(clear.AsSpan(0, size));
                length -= size;
            }
            if (input.ReadByte() != -1) throw InvalidFormat();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(clear);
        }
    }

    private static void ReadV1(Stream input, Stream output, ReadOnlySpan<byte> password, byte[] header)
    {
        int length = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(36));
        if (length is < 1 or > LegacyLimit || input.Length != HeaderSize + (long)length + TagSize)
            throw InvalidFormat();
        byte[] cipher = new byte[length];
        byte[] tag = new byte[TagSize];
        input.ReadExactly(cipher);
        input.ReadExactly(tag);
        if (input.ReadByte() != -1) throw InvalidFormat();
        byte[] clear = new byte[length];
        byte[] key = Derive(password, header);
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(header.AsSpan(24, 12), cipher, tag, clear, header);
            output.Write(clear);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(clear);
        }
    }

    private static byte[] Derive(ReadOnlySpan<byte> password, byte[] header) =>
        Rfc2898DeriveBytes.Pbkdf2(password, header.AsSpan(8, SaltSize), Iterations, HashAlgorithmName.SHA256, 32);

    private static void SetIndex(uint index, byte[] nonce, byte[] aad)
    {
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8), index);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(HeaderSize), index);
    }

    private static InvalidDataException InvalidFormat() => new("Unsupported or malformed encrypted backup.");
}
