using System.Text;
using Hadramout.Infrastructure;
using Xunit;

namespace Hadramout.Core.Tests;

public sealed class RouterOsWireCodecTests
{
    [Theory]
    [InlineData(0u, "00")]
    [InlineData(127u, "7F")]
    [InlineData(128u, "8080")]
    [InlineData(16383u, "BFFF")]
    [InlineData(16384u, "C04000")]
    [InlineData(2097151u, "DFFFFF")]
    [InlineData(2097152u, "E0200000")]
    [InlineData(268435455u, "EFFFFFFF")]
    [InlineData(268435456u, "F010000000")]
    [InlineData(uint.MaxValue, "F0FFFFFFFF")]
    public async Task LengthEncodingMatchesProtocolBoundaries(uint length, string expected)
    {
        byte[] prefix = new byte[5];
        int count = RouterOsWireCodec.EncodeLength(length, prefix);
        Assert.Equal(expected, Convert.ToHexString(prefix.AsSpan(0, count)));
        using var stream = new FragmentedStream(Convert.FromHexString(expected));
        Assert.Equal(length, await RouterOsWireCodec.ReadLengthAsync(stream, new byte[5], CancellationToken.None));
    }

    [Theory]
    [InlineData("F1")]
    [InlineData("F8")]
    [InlineData("FF")]
    [InlineData("8000")]
    [InlineData("C00080")]
    [InlineData("E0004000")]
    [InlineData("F000000001")]
    public async Task ReservedAndNoncanonicalLengthsRejected(string hex)
    {
        using var stream = new MemoryStream(Convert.FromHexString(hex));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await RouterOsWireCodec.ReadSentenceAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task RoundTripPreservesArabicBinaryAndEquals()
    {
        ReadOnlyMemory<byte>[] words = [
            "/ip/hotspot/user/print"u8.ToArray(),
            Encoding.UTF8.GetBytes("=comment=حضرموت=اختبار"),
            new byte[] { 0x3D, 0xFF, 0x00, 0x80 }
        ];
        using var output = new MemoryStream();
        await RouterOsWireCodec.WriteSentenceAsync(output, words, CancellationToken.None);
        using var input = new FragmentedStream(output.ToArray());
        byte[][] decoded = await RouterOsWireCodec.ReadSentenceAsync(input, CancellationToken.None);
        Assert.Equal(words.Length, decoded.Length);
        for (int i = 0; i < words.Length; i++) Assert.True(words[i].Span.SequenceEqual(decoded[i]));
        Assert.Equal(input.Length, input.Position);
    }

    [Fact]
    public async Task MultipleSentencesStaySeparateIncludingEmptySentence()
    {
        using var stream = new MemoryStream();
        await RouterOsWireCodec.WriteSentenceAsync(stream, ["!empty"u8.ToArray()], CancellationToken.None);
        await stream.WriteAsync(new byte[] { 0 });
        await RouterOsWireCodec.WriteSentenceAsync(stream, ["!done"u8.ToArray()], CancellationToken.None);
        stream.Position = 0;
        Assert.Equal("!empty", Encoding.ASCII.GetString(Assert.Single(
            await RouterOsWireCodec.ReadSentenceAsync(stream, CancellationToken.None))));
        Assert.Empty(await RouterOsWireCodec.ReadSentenceAsync(stream, CancellationToken.None));
        Assert.Equal("!done", Encoding.ASCII.GetString(Assert.Single(
            await RouterOsWireCodec.ReadSentenceAsync(stream, CancellationToken.None))));
    }

    [Theory]
    [InlineData("")]
    [InlineData("80")]
    [InlineData("036162")]
    [InlineData("0161")]
    public async Task IncompleteFrameRejected(string hex)
    {
        using var stream = new MemoryStream(Convert.FromHexString(hex));
        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await RouterOsWireCodec.ReadSentenceAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task OversizedWordRejectedBeforePayloadAllocation()
    {
        byte[] bytes = new byte[5];
        int count = RouterOsWireCodec.EncodeLength((uint)RouterOsWireCodec.MaxWordBytes + 1, bytes);
        using var stream = new MemoryStream(bytes.AsSpan(0, count).ToArray());
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await RouterOsWireCodec.ReadSentenceAsync(stream, CancellationToken.None));
        Assert.Equal((long)count, stream.Position);
    }

    [Fact]
    public async Task ExcessWordCountRejected()
    {
        using var stream = new MemoryStream();
        for (int i = 0; i <= RouterOsWireCodec.MaxWords; i++) stream.Write(new byte[] { 1, 65 });
        stream.WriteByte(0);
        stream.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await RouterOsWireCodec.ReadSentenceAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task ExcessTotalPayloadRejectedBeforeReadingNextPayload()
    {
        using var stream = new MemoryStream();
        var prefix = new byte[5];
        int count = RouterOsWireCodec.EncodeLength(RouterOsWireCodec.MaxWordBytes, prefix);
        for (int i = 0; i < 4; i++)
        {
            stream.Write(prefix, 0, count);
            stream.Write(new byte[RouterOsWireCodec.MaxWordBytes]);
        }
        stream.WriteByte(1);
        stream.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await RouterOsWireCodec.ReadSentenceAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task OutgoingInvalidWordRejectedBeforeAnyWrite()
    {
        using var stream = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await RouterOsWireCodec.WriteSentenceAsync(stream,
                ["/login"u8.ToArray(), ReadOnlyMemory<byte>.Empty], CancellationToken.None));
        Assert.Equal(0L, stream.Length);
    }

    [Fact]
    public async Task CancellationDoesNotWriteOrReturnPartialSentence()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        using var stream = new MemoryStream();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await RouterOsWireCodec.WriteSentenceAsync(stream, ["/login"u8.ToArray()], cts.Token));
        Assert.Equal(0L, stream.Length);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await RouterOsWireCodec.ReadSentenceAsync(stream, cts.Token));
    }

    private sealed class FragmentedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(1, buffer.Length)], cancellationToken);
    }
}
