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

    [Fact]
    public async Task ReplyReaderReturnsRowsOnlyAfterCompletion()
    {
        using var stream = new MemoryStream();
        await ReplyAsync(stream, "!re", "=name=user-manager", "=version=6.49.19");
        await ReplyAsync(stream, "!re", "=name=system", "=version=6.49.19");
        await ReplyAsync(stream, "!done");
        stream.Position = 0;
        var result = await RouterOsReplyReader.ReadAsync(stream,
            words => Encoding.ASCII.GetString(words[1]), 2, CancellationToken.None);
        Assert.Equal(RouterOsReplyOutcome.Completed, result.Outcome);
        Assert.Equal(new[] { "=name=user-manager", "=name=system" }, result.Rows);
        Assert.Null(result.TrapCategory);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReplyReaderRecognizesLegacyAndModernEmptyResults(bool explicitEmpty)
    {
        using var stream = new MemoryStream();
        if (explicitEmpty) await ReplyAsync(stream, "!empty");
        await ReplyAsync(stream, "!done");
        stream.Position = 0;
        var result = await RouterOsReplyReader.ReadAsync(stream, _ => "unexpected", 2, CancellationToken.None);
        Assert.Equal(RouterOsReplyOutcome.Completed, result.Outcome);
        Assert.Empty(result.Rows);
    }

    [Theory]
    [InlineData("!trap", "=category=2", 2)]
    [InlineData("!trap", "=category=9", null)]
    [InlineData("!fatal", "=message=connection-closed", null)]
    public async Task FailedReplyDiscardsPartialRows(string kind, string attribute, int? category)
    {
        using var stream = new MemoryStream();
        await ReplyAsync(stream, "!re", "=name=partial");
        await ReplyAsync(stream, kind, attribute);
        await ReplyAsync(stream, "!done");
        stream.Position = 0;
        var result = await RouterOsReplyReader.ReadAsync(stream, _ => "partial", 2, CancellationToken.None);
        Assert.Equal(kind == "!trap" ? RouterOsReplyOutcome.Rejected : RouterOsReplyOutcome.Fatal, result.Outcome);
        Assert.Empty(result.Rows);
        Assert.Equal(category, result.TrapCategory);
        // The caller must close, not accidentally use the pending completion as another command's reply.
        Assert.True(stream.Position < stream.Length);
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("tagged")]
    [InlineData("duplicate")]
    [InlineData("invalid-attribute")]
    [InlineData("done-data")]
    [InlineData("empty-then-row")]
    [InlineData("row-then-empty")]
    [InlineData("double-empty")]
    [InlineData("row-limit")]
    [InlineData("bare-row")]
    [InlineData("zero-frame")]
    public async Task MalformedReplyCannotBeReportedAsSuccessful(string scenario)
    {
        using var stream = new MemoryStream();
        switch (scenario)
        {
            case "unknown": await ReplyAsync(stream, "!other"); break;
            case "tagged": await ReplyAsync(stream, "!re", ".tag=unrelated", "=name=x"); break;
            case "duplicate": await ReplyAsync(stream, "!re", "=name=x", "=name=y"); break;
            case "invalid-attribute": await ReplyAsync(stream, "!re", "=invalid"); break;
            case "done-data": await ReplyAsync(stream, "!done", "=ret=unexpected"); break;
            case "empty-then-row": await ReplyAsync(stream, "!empty"); await ReplyAsync(stream, "!re", "=name=x"); break;
            case "row-then-empty": await ReplyAsync(stream, "!re", "=name=x"); await ReplyAsync(stream, "!empty"); break;
            case "double-empty": await ReplyAsync(stream, "!empty"); await ReplyAsync(stream, "!empty"); break;
            case "row-limit": await ReplyAsync(stream, "!re", "=name=x"); await ReplyAsync(stream, "!re", "=name=y"); break;
            case "bare-row": await ReplyAsync(stream, "!re"); break;
            case "zero-frame": stream.WriteByte(0); break;
        }
        await ReplyAsync(stream, "!done");
        stream.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await RouterOsReplyReader.ReadAsync(stream, _ => "row", 1, CancellationToken.None));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingCompletionIsNeverSuccess(bool explicitEmpty)
    {
        using var stream = new MemoryStream();
        if (explicitEmpty) await ReplyAsync(stream, "!empty");
        else await ReplyAsync(stream, "!re", "=name=partial");
        stream.Position = 0;
        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await RouterOsReplyReader.ReadAsync(stream, _ => "partial", 2, CancellationToken.None));
    }

    [Fact]
    public async Task AggregateReplyLimitRejectsIndividuallyValidSentences()
    {
        using var stream = new MemoryStream();
        byte[] field = new byte[RouterOsWireCodec.MaxWordBytes];
        "=name="u8.CopyTo(field);
        for (int i = 0; i < 16; i++)
            await RouterOsWireCodec.WriteSentenceAsync(stream,
                ["!re"u8.ToArray(), field], CancellationToken.None);
        await ReplyAsync(stream, "!done");
        stream.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await RouterOsReplyReader.ReadAsync(stream, _ => "row", 20, CancellationToken.None));
    }

    [Fact]
    public async Task RawReplyWordsAreClearedAfterProjection()
    {
        using var stream = new MemoryStream();
        await ReplyAsync(stream, "!re", "=name=synthetic");
        await ReplyAsync(stream, "!done");
        stream.Position = 0;
        byte[][]? captured = null;
        var result = await RouterOsReplyReader.ReadAsync(stream, words =>
        {
            captured = words; // test-only inspection of buffer cleanup
            return Encoding.ASCII.GetString(words[1]);
        }, 1, CancellationToken.None);
        Assert.Equal("=name=synthetic", Assert.Single(result.Rows));
        Assert.NotNull(captured);
        Assert.All(captured, word => Assert.All(word, value => Assert.Equal((byte)0, value)));
    }

    private static ValueTask ReplyAsync(Stream stream, params string[] words) =>
        RouterOsWireCodec.WriteSentenceAsync(stream,
            words.Select(word => (ReadOnlyMemory<byte>)Encoding.ASCII.GetBytes(word)).ToArray(),
            CancellationToken.None);

    [Theory]
    [InlineData("6.49.19 (long-term)", 1)]
    [InlineData("6.49.11", 1)]
    [InlineData("7.18 (stable)", 2)]
    [InlineData("7.21.1 (stable)", 2)]
    [InlineData("6.48.7", 0)]
    [InlineData("8.0", 0)]
    [InlineData("7.22beta1 (testing)", 0)]
    [InlineData("7.21.1 (testing)", 0)]
    [InlineData("07.21.1", 0)]
    [InlineData("7", 0)]
    [InlineData("7.21.1.2", 0)]
    public void VersionClassificationIsConservative(string version, int expected) =>
        Assert.Equal((RouterOsFamily)expected, RouterOsInventory.ClassifyVersion(version));

    [Theory]
    [InlineData("7.21.1", "false", "", 3)]
    [InlineData("7.21.1", "no", null, 3)]
    [InlineData("", "true", "", 2)]
    [InlineData("7.21.1", "yes", "", 2)]
    [InlineData("7.21.1", null, "", 0)]
    [InlineData("7.20", "false", "", 0)]
    [InlineData("7.21.1", "false", "disable", 0)]
    [InlineData("", "false", "", 0)]
    public void PackageEvidenceCannotBeConfusedWithServiceAvailability(
        string version, string? disabled, string? scheduled, int expected)
    {
        var fields = new List<string> { "!re", "=name=user-manager", "=version=" + version };
        if (disabled is not null) fields.Add("=disabled=" + disabled);
        if (scheduled is not null) fields.Add("=scheduled=" + scheduled);
        var package = RouterOsInventory.ParsePackage(fields.Select(Encoding.ASCII.GetBytes).ToArray());
        var inventory = RouterOsInventory.Classify("7.21.1 (stable)", [package], inventoryRead: true);
        Assert.Equal((UserManagerPackageState)expected, inventory.UserManagerPackage);
        Assert.Equal(RouterOsFamily.V7, inventory.Family);
    }

    [Fact]
    public void MissingPackageAndUnreadInventoryAreDistinct()
    {
        Assert.Equal(UserManagerPackageState.NotListed,
            RouterOsInventory.Classify("6.49.19", [], true).UserManagerPackage);
        Assert.Equal(UserManagerPackageState.Unknown,
            RouterOsInventory.Classify("6.49.19", [], false).UserManagerPackage);
    }

    [Fact]
    public void DuplicatePackageNamesAreRejected()
    {
        var package = new RouterOsPackage("user-manager", "6.49.19", false, null);
        Assert.Throws<InvalidDataException>(() =>
            RouterOsInventory.Classify("6.49.19", [package, package], true));
    }

    [Theory]
    [InlineData("=name=", "=disabled=no")]
    [InlineData("=name=user-manager", "=disabled=maybe")]
    [InlineData("=name=user manager", "=disabled=false")]
    public void MalformedPackageRowsFailClosed(string name, string disabled)
    {
        Assert.Throws<InvalidDataException>(() => RouterOsInventory.ParsePackage(
            ["!re"u8.ToArray(), Encoding.ASCII.GetBytes(name), Encoding.ASCII.GetBytes(disabled)]));
    }

    [Theory]
    [InlineData("0", 0L)]
    [InlineData("15000", 15000L)]
    [InlineData("9223372036854775807", long.MaxValue)]
    public async Task CountOnlyAcceptsExplicitNonnegativeCompletion(string value, long expected)
    {
        using var stream = new MemoryStream();
        await ReplyAsync(stream, "!done", "=ret=" + value);
        stream.Position = 0;
        var result = await RouterOsReplyReader.ReadAsync(stream, _ => 0, 1, CancellationToken.None, countOnly: true);
        Assert.Equal(RouterOsReplyOutcome.Completed, result.Outcome);
        Assert.Equal(expected, result.CompletionCount);
        Assert.Empty(result.Rows);
    }

    [Theory]
    [InlineData("")]
    [InlineData("-1")]
    [InlineData("+1")]
    [InlineData(" 1")]
    [InlineData("1.0")]
    [InlineData("9223372036854775808")]
    public async Task CountOnlyRejectsInvalidReturnValue(string value)
    {
        using var stream = new MemoryStream();
        await ReplyAsync(stream, "!done", "=ret=" + value);
        stream.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await RouterOsReplyReader.ReadAsync(stream, _ => 0, 1, CancellationToken.None, countOnly: true));
    }

    [Theory]
    [InlineData("bare-done")]
    [InlineData("row")]
    [InlineData("wrong-attribute")]
    [InlineData("empty-nonzero")]
    [InlineData("duplicate-ret")]
    public async Task CountOnlyCannotInferSuccessFromUnrelatedReplies(string condition)
    {
        using var stream = new MemoryStream();
        switch (condition)
        {
            case "bare-done": await ReplyAsync(stream, "!done"); break;
            case "row": await ReplyAsync(stream, "!re", "=name=synthetic"); break;
            case "wrong-attribute": await ReplyAsync(stream, "!done", "=count=0"); break;
            case "empty-nonzero": await ReplyAsync(stream, "!empty"); await ReplyAsync(stream, "!done", "=ret=1"); break;
            case "duplicate-ret": await ReplyAsync(stream, "!done", "=ret=1", "=ret=2"); break;
        }
        stream.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await RouterOsReplyReader.ReadAsync(stream, _ => 0, 1, CancellationToken.None, countOnly: true));
    }

    [Fact]
    public async Task ExplicitEmptyCountRequiresZeroCompletion()
    {
        using var stream = new MemoryStream();
        await ReplyAsync(stream, "!empty");
        await ReplyAsync(stream, "!done", "=ret=0");
        stream.Position = 0;
        var result = await RouterOsReplyReader.ReadAsync(stream, _ => 0, 1, CancellationToken.None, countOnly: true);
        Assert.Equal(0L, result.CompletionCount);
        Assert.Equal(RouterOsReplyOutcome.Completed, result.Outcome);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(" card")]
    [InlineData("card ")]
    [InlineData("card\nnext")]
    [InlineData("card\0next")]
    public void UserManager6RejectsInvalidLookupIdentity(string value) =>
        Assert.Throws<ArgumentException>(() => UserManager6Records.ValidateKey(value, "username"));

    [Fact]
    public void UserManager6LookupIdentityUsesByteLimitNotJustCharacterCount()
    {
        UserManager6Records.ValidateKey(new string('ع', 64), "name");
        Assert.Throws<ArgumentException>(() => UserManager6Records.ValidateKey(new string('ع', 65), "name"));
    }

    [Fact]
    public void UserManager6RejectsInvalidUtf8AndUnknownDisabledFlag()
    {
        Assert.Throws<InvalidDataException>(() => UserManager6Records.ParseAccount(
            ["!re"u8.ToArray(), "=customer=admin"u8.ToArray(), "=username=123"u8.ToArray(),
                "=disabled=maybe"u8.ToArray()], "admin", "123"));
        Assert.Throws<InvalidDataException>(() => UserManager6Records.ParseAccount(
            ["!re"u8.ToArray(), "=customer=admin"u8.ToArray(), "=username=123"u8.ToArray(),
                [0x3D, 0x61, 0x63, 0x74, 0x75, 0x61, 0x6C, 0x2D, 0x70, 0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x3D, 0xFF]],
            "admin", "123"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("1.5MiB")]
    [InlineData("2G")]
    [InlineData("-1")]
    [InlineData("+1")]
    [InlineData(" 0")]
    [InlineData("18446744073709551616")]
    [InlineData("B")]
    public void Um6ByteValuesNeverTurnUnknownIntoZero(string? raw)
    {
        var value = UserManager6ByteValue.FromRaw(raw);
        Assert.Equal(raw, value.Raw);
        Assert.Null(value.Bytes);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("0B")]
    [InlineData("4294967296")]
    [InlineData("18446744073709551615B")]
    public void Um6ByteValuesPreserveExactUnsignedCounters(string raw)
    {
        var value = UserManager6ByteValue.FromRaw(raw);
        Assert.Equal(raw, value.Raw);
        Assert.Equal(ulong.Parse(raw.TrimEnd('B'), System.Globalization.CultureInfo.InvariantCulture), value.Bytes);
    }

    [Fact]
    public void Um6ObservedTransferCannotOverflowOrInferMissingCounter()
    {
        var maximum = UserManager6ByteValue.FromRaw("18446744073709551615");
        var one = UserManager6ByteValue.FromRaw("1");
        var zero = UserManager6ByteValue.FromRaw("0");
        var missing = UserManager6ByteValue.FromRaw(null);
        Assert.Null(new UserManager6Usage(maximum, one, null).ObservedTransferBytes);
        Assert.Null(new UserManager6Usage(one, missing, null).ObservedTransferBytes);
        Assert.Equal(ulong.MaxValue, new UserManager6Usage(maximum, zero, null).ObservedTransferBytes);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" quota")]
    [InlineData("quota ")]
    public void Um6ProfileLinkRejectsMalformedLimitationIdentity(string limitation)
    {
        Assert.Throws<InvalidDataException>(() => UserManager6Records.ParseProfileLink(
            ["!re"u8.ToArray(), "=profile=day"u8.ToArray(), Encoding.UTF8.GetBytes("=limitation=" + limitation)], "day"));
    }

    [Fact]
    public async Task Um6ProfileMappingRejectsMoreThanThirtyTwoRows()
    {
        using var stream = new MemoryStream();
        for (int i = 0; i < 33; i++)
            await ReplyAsync(stream, "!re", "=profile=day", "=limitation=quota");
        await ReplyAsync(stream, "!done");
        stream.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await RouterOsReplyReader.ReadAsync(stream, words => UserManager6Records.ParseProfileLink(words, "day"),
                32, CancellationToken.None));
    }

    private sealed class FragmentedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(1, buffer.Length)], cancellationToken);
    }
}
