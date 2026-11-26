using System.Buffers.Binary;

namespace Hadramout.Infrastructure;

// Byte-preserving RouterOS API framing. No network, authentication, or retry policy here.
// A framing error, cancellation or incomplete write invalidates the owning connection.
internal static class RouterOsWireCodec
{
    internal const int MaxWordBytes = 1024 * 1024;
    internal const int MaxSentenceBytes = 4 * 1024 * 1024;
    internal const int MaxWords = 1024;

    // Encode the full protocol length range for independent boundary tests.
    internal static int EncodeLength(uint length, Span<byte> buffer)
    {
        if (buffer.Length < 5) throw new ArgumentException("Length buffer requires five bytes.", nameof(buffer));
        if (length <= 0x7F)
        {
            buffer[0] = (byte)length;
            return 1;
        }
        if (length <= 0x3FFF)
        {
            BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)(length | 0x8000));
            return 2;
        }
        if (length <= 0x1FFFFF)
        {
            buffer[0] = (byte)((length >> 16) | 0xC0);
            BinaryPrimitives.WriteUInt16BigEndian(buffer[1..], (ushort)(length & 0xFFFF));
            return 3;
        }
        if (length <= 0x0FFFFFFF)
        {
            BinaryPrimitives.WriteUInt32BigEndian(buffer, length | 0xE0000000);
            return 4;
        }
        buffer[0] = 0xF0;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[1..], length);
        return 5;
    }

    internal static async ValueTask<uint> ReadLengthAsync(Stream stream, Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        if (buffer.Length < 5) throw new ArgumentException("Length buffer requires five bytes.", nameof(buffer));
        await stream.ReadExactlyAsync(buffer[..1], cancellationToken).ConfigureAwait(false);
        byte first = buffer.Span[0];
        int extra;
        uint value;
        uint minimum;
        if (first < 0x80) return first;
        if (first < 0xC0) { extra = 1; value = (uint)(first & 0x3F); minimum = 0x80; }
        else if (first < 0xE0) { extra = 2; value = (uint)(first & 0x1F); minimum = 0x4000; }
        else if (first < 0xF0) { extra = 3; value = (uint)(first & 0x0F); minimum = 0x200000; }
        else if (first == 0xF0) { extra = 4; value = 0; minimum = 0x10000000; }
        else throw new InvalidDataException("Unsupported RouterOS length or control byte.");
        await stream.ReadExactlyAsync(buffer.Slice(1, extra), cancellationToken).ConfigureAwait(false);
        for (int i = 1; i <= extra; i++)
            value = (value << 8) | buffer.Span[i];
        if (value < minimum) throw new InvalidDataException("Noncanonical RouterOS length.");
        return value;
    }

    internal static async ValueTask<byte[][]> ReadSentenceAsync(Stream stream, CancellationToken cancellationToken)
    {
        var words = new List<byte[]>();
        byte[] prefix = new byte[5];
        int total = 0;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                uint length = await ReadLengthAsync(stream, prefix, cancellationToken).ConfigureAwait(false);
                if (length == 0) return words.ToArray();
                if (length > MaxWordBytes || words.Count >= MaxWords ||
                    length > MaxSentenceBytes - total)
                    throw new InvalidDataException("RouterOS sentence exceeds configured bounds.");
                var word = new byte[(int)length];
                words.Add(word);
                await stream.ReadExactlyAsync(word, cancellationToken).ConfigureAwait(false);
                total += word.Length;
            }
        }
        catch
        {
            foreach (byte[] word in words)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(word);
            throw;
        }
    }

    internal static async ValueTask WriteSentenceAsync(Stream stream, IReadOnlyList<ReadOnlyMemory<byte>> words,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(words);
        // Validate the complete outgoing sentence before writing any bytes.
        if (words.Count is < 1 or > MaxWords)
            throw new ArgumentException("Invalid RouterOS sentence word count.", nameof(words));
        var stable = new ReadOnlyMemory<byte>[words.Count];
        int total = 0;
        for (int i = 0; i < stable.Length; i++)
        {
            var word = words[i];
            if (word.Length is < 1 or > MaxWordBytes || word.Length > MaxSentenceBytes - total)
                throw new ArgumentException("RouterOS sentence exceeds configured bounds.", nameof(words));
            total += word.Length;
            stable[i] = word;
        }

        byte[] prefix = new byte[5];
        foreach (var word in stable)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int count = EncodeLength((uint)word.Length, prefix);
            await stream.WriteAsync(prefix.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(word, cancellationToken).ConfigureAwait(false);
        }
        prefix[0] = 0;
        await stream.WriteAsync(prefix.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
