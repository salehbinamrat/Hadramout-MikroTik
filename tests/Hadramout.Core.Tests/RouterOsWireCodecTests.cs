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

    [Theory]
    [InlineData("0s", 0UL)]
    [InlineData("18m20s", 1100UL)]
    [InlineData("1d2h", 93600UL)]
    [InlineData("1w2d3h4m5s", 788645UL)]
    [InlineData("18446744073709551615s", ulong.MaxValue)]
    public void Um6UptimeDecodesOnlyExactUnitComponents(string raw, ulong expected) =>
        Assert.Equal(expected, UserManager6Records.ParseUptimeSeconds(raw));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("00:00:00")]
    [InlineData("unlimited")]
    [InlineData("1.5h")]
    [InlineData("-1s")]
    [InlineData("1h2h")]
    [InlineData("1s1m")]
    [InlineData("1h 2m")]
    [InlineData("1")]
    [InlineData("18446744073709551616s")]
    [InlineData("18446744073709551615m")]
    [InlineData("1m18446744073709551615s")]
    public void Um6UptimeUnknownOrOverflowNeverBecomesZero(string? raw) =>
        Assert.Null(UserManager6Records.ParseUptimeSeconds(raw));

    [Theory]
    [InlineData(null, null, null, 0, 0)]
    [InlineData("no", "", "never", 1, 1)]
    [InlineData("yes", "day", "never", 2, 1)]
    [InlineData("no", "day", "nov/26/2026 18:00:00", 2, 2)]
    [InlineData(null, " ", "", 0, 0)]
    public void Um6AccountKeepsAdministrativeProfileAndActivityObservationsIndependent(
        string? disabled, string? profile, string? lastSeen, int profileObservation, int lastSeenObservation)
    {
        var words = new List<byte[]> { "!re"u8.ToArray(), "=customer=admin"u8.ToArray(), "=username=123"u8.ToArray() };
        if (disabled is not null) words.Add(Encoding.UTF8.GetBytes("=disabled=" + disabled));
        if (profile is not null) words.Add(Encoding.UTF8.GetBytes("=actual-profile=" + profile));
        if (lastSeen is not null) words.Add(Encoding.UTF8.GetBytes("=last-seen=" + lastSeen));
        words.Add("=download-used=0"u8.ToArray());
        words.Add("=upload-used=0"u8.ToArray());
        words.Add("=active-sessions=0"u8.ToArray());
        var account = UserManager6Records.ParseAccount(words.ToArray(), "admin", "123");
        Assert.Equal(disabled == "yes" ? true : disabled == "no" ? false : (bool?)null, account.Disabled);
        Assert.Equal((UserManager6ProfileObservation)profileObservation, account.ProfileObservation);
        Assert.Equal((UserManager6LastSeenObservation)lastSeenObservation, account.Activity.LastSeenObservation);
        Assert.Equal(profile, account.ActualProfile);
        Assert.Equal(lastSeen, account.Activity.LastSeen);
        Assert.Equal("0", account.Activity.ActiveSessions);
        Assert.Null(account.Activity.Active);
        Assert.Null(account.Activity.Incomplete);
        Assert.Equal(0UL, account.Usage.ObservedTransferBytes);
        Assert.Null(account.Usage.ObservedUptimeSeconds);
    }

    [Fact]
    public void Um6ActivityEvidenceRejectsOversizedSessionReferenceField()
    {
        Assert.Throws<InvalidDataException>(() => UserManager6Records.ParseAccount(
            ["!re"u8.ToArray(), "=customer=admin"u8.ToArray(), "=username=123"u8.ToArray(),
                Encoding.ASCII.GetBytes("=active-sessions=" + new string('x', 4097))], "admin", "123"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Um6CreateWireEncodesOnlyOneDisabledAccountWithUniqueMarker(bool empty)
    {
        using var reply = new MemoryStream();
        await ReplyAsync(reply, "!done", "=ret=*1A");
        using var wire = new CreateExchangeStream(reply.ToArray());
        var exchange = new UserManager6CreateWire(wire);
        Guid id = Guid.Parse("aabbccdd-1122-3344-5566-778899aabbcc");
        byte[] password = empty ? [] : Encoding.UTF8.GetBytes("synthetic=كرت");
        var result = await exchange.CreateDisabledOnceAsync(id, "admin", "001", password, CancellationToken.None);
        Assert.Equal(UserManager6CreateWireOutcome.Acknowledged, result.Outcome);
        Assert.Equal("*1A", result.ReturnedId);
        using var sent = new MemoryStream(wire.ToArray());
        byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(sent, CancellationToken.None);
        Assert.Equal(new[] { "/tool/user-manager/user/add", "=customer=admin", "=username=001",
            "=password=" + Encoding.UTF8.GetString(password), "=disabled=yes",
            "=comment=hmk-create:aabbccdd112233445566778899aabbcc" },
            words.Select(word => Encoding.UTF8.GetString(word)).ToArray());
        Assert.Equal(sent.Length, sent.Position);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            exchange.CreateDisabledOnceAsync(id, "admin", "001", password, CancellationToken.None));
        Assert.Equal(sent.Length, wire.Length);
    }

    [Theory]
    [InlineData("bare", true)]
    [InlineData("trap", false)]
    [InlineData("fatal", false)]
    [InlineData("data", false)]
    [InlineData("unknown", false)]
    [InlineData("missing", false)]
    [InlineData("truncated", false)]
    [InlineData("malformed-id", false)]
    [InlineData("extra-attribute", false)]
    [InlineData("duplicate-ret", false)]
    [InlineData("empty", false)]
    public async Task Um6CreateWireNeverTreatsUncertainReplyAsAcknowledged(string kind, bool acknowledged)
    {
        using var reply = new MemoryStream();
        switch (kind)
        {
            case "bare": await ReplyAsync(reply, "!done"); break;
            case "trap": await ReplyAsync(reply, "!trap", "=message=synthetic"); await ReplyAsync(reply, "!done"); break;
            case "fatal": await ReplyAsync(reply, "!fatal"); break;
            case "data": await ReplyAsync(reply, "!re", "=.id=*1"); await ReplyAsync(reply, "!done"); break;
            case "unknown": await ReplyAsync(reply, "!unknown"); break;
            case "truncated": reply.Write(new byte[] { 5, (byte)'!' }); break;
            case "malformed-id": await ReplyAsync(reply, "!done", "=ret=not-an-id"); break;
            case "extra-attribute": await ReplyAsync(reply, "!done", "=ret=*1", "=other=1"); break;
            case "duplicate-ret": await ReplyAsync(reply, "!done", "=ret=*1", "=ret=*2"); break;
            case "empty": await ReplyAsync(reply, "!empty"); await ReplyAsync(reply, "!done"); break;
        }
        using var wire = new CreateExchangeStream(reply.ToArray());
        var exchange = new UserManager6CreateWire(wire);
        Guid id = Guid.NewGuid();
        var result = await exchange.CreateDisabledOnceAsync(id, "admin", "001", "synthetic"u8.ToArray(), CancellationToken.None);
        Assert.Equal(acknowledged ? UserManager6CreateWireOutcome.Acknowledged : UserManager6CreateWireOutcome.Indeterminate, result.Outcome);
        Assert.Null(result.ReturnedId);
        long length = wire.Length;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            exchange.CreateDisabledOnceAsync(id, "admin", "001", "synthetic"u8.ToArray(), CancellationToken.None));
        Assert.Equal(length, wire.Length);
    }

    [Theory]
    [InlineData("invalid-utf8")]
    [InlineData("control")]
    [InlineData("too-long")]
    [InlineData("empty-id")]
    [InlineData("invalid-user")]
    public async Task Um6CreateWireRejectsInvalidInputBeforeWriting(string kind)
    {
        using var wire = new CreateExchangeStream([]);
        var exchange = new UserManager6CreateWire(wire);
        byte[] password = kind switch
        {
            "invalid-utf8" => [0xff], "control" => [0], "too-long" => new byte[4097], _ => []
        };
        await Assert.ThrowsAnyAsync<ArgumentException>(() => exchange.CreateDisabledOnceAsync(
            kind == "empty-id" ? Guid.Empty : Guid.NewGuid(), "admin",
            kind == "invalid-user" ? " 001" : "001", password, CancellationToken.None));
        Assert.Equal(0L, wire.Length);
    }

    [Fact]
    public async Task Um6CreateWirePartialWriteIsIndeterminateAndCannotRepeat()
    {
        using var wire = new CreateExchangeStream([], failAfterFirstWrite: true);
        var exchange = new UserManager6CreateWire(wire);
        Guid id = Guid.NewGuid();
        var receipt = await exchange.CreateDisabledOnceAsync(id, "admin", "001", ReadOnlyMemory<byte>.Empty, CancellationToken.None);
        Assert.Equal(UserManager6CreateWireOutcome.Indeterminate, receipt.Outcome);
        Assert.True(wire.Length > 0);
        long length = wire.Length;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            exchange.CreateDisabledOnceAsync(id, "admin", "001", ReadOnlyMemory<byte>.Empty, CancellationToken.None));
        Assert.Equal(length, wire.Length);
    }

    [Fact]
    public async Task Um6CreateWirePreCancelledDoesNotWrite()
    {
        using var wire = new CreateExchangeStream([]);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new UserManager6CreateWire(wire).CreateDisabledOnceAsync(Guid.NewGuid(), "admin", "001",
                ReadOnlyMemory<byte>.Empty, cts.Token));
        Assert.Equal(0L, wire.Length);
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("zero")]
    [InlineData("missing-counters")]
    [InlineData("scaled")]
    [InlineData("overflow")]
    [InlineData("empty")]
    [InlineData("wrong-id")]
    [InlineData("wrong-name")]
    [InlineData("missing-id")]
    [InlineData("missing-name")]
    [InlineData("duplicate-row")]
    [InlineData("duplicate-field")]
    [InlineData("trap")]
    [InlineData("partial")]
    public async Task Um7TotalUsageQualificationRequiresCompleteIdentityBoundReply(string condition)
    {
        using var wire = new MemoryStream();
        if (condition != "empty" && condition != "trap")
        {
            var row = new List<ReadOnlyMemory<byte>> { "!re"u8.ToArray() };
            if (condition != "missing-id")
                row.Add(condition == "wrong-id" ? "=.id=*2"u8.ToArray() : "=.id=*1"u8.ToArray());
            if (condition != "missing-name")
                row.Add(condition == "wrong-name" ? "=name=002"u8.ToArray() : "=name=001"u8.ToArray());
            if (condition != "missing-counters")
            {
                row.Add(Encoding.ASCII.GetBytes("=total-download=" + (condition switch
                {
                    "zero" => "0", "scaled" => "4.7GiB", "overflow" => "18446744073709551615", _ => "4294967296"
                })));
                row.Add(condition == "zero" ? "=total-upload=0"u8.ToArray() : "=total-upload=128"u8.ToArray());
                row.Add(condition == "zero" ? "=total-uptime=0s"u8.ToArray() : "=total-uptime=1d2h"u8.ToArray());
            }
            row.Add("=active-sessions=0"u8.ToArray());
            row.Add("=actual-profile=day"u8.ToArray());
            if (condition == "duplicate-field") row.Add("=total-download=1"u8.ToArray());
            await RouterOsWireCodec.WriteSentenceAsync(wire, row, CancellationToken.None);
            if (condition == "duplicate-row")
                await RouterOsWireCodec.WriteSentenceAsync(wire, row, CancellationToken.None);
        }
        if (condition == "trap")
            await RouterOsWireCodec.WriteSentenceAsync(wire, ["!trap"u8.ToArray()], CancellationToken.None);
        else if (condition != "partial")
            await RouterOsWireCodec.WriteSentenceAsync(wire, ["!done"u8.ToArray()], CancellationToken.None);
        using var input = new MemoryStream(wire.ToArray(), writable: false);
        var account = new UserManager7Account("*1", "001", false, null, null);
        Task<UserManager7TotalUsageSample?> Read() =>
            UserManager7Records.ReadQualifiedTotalUsageReplyAsync(input, account, CancellationToken.None);
        if (condition == "partial")
            await Assert.ThrowsAsync<EndOfStreamException>(Read);
        else if (condition == "empty")
            Assert.Null(await Read());
        else if (condition is "valid" or "zero" or "missing-counters" or "scaled" or "overflow")
        {
            var sample = await Read();
            Assert.NotNull(sample);
            Assert.Equal("*1", sample.RemoteId);
            Assert.Equal("001", sample.Username);
            Assert.Equal("0", sample.ActiveSessionsRaw);
            Assert.Equal("day", sample.ActualProfileRaw);
            Assert.Equal(condition switch
            {
                "valid" => 4294967424UL, "zero" => 0UL, _ => (ulong?)null
            }, sample.Usage.ObservedTransferBytes);
            Assert.Equal(condition switch
            {
                "zero" => 0UL, "missing-counters" => (ulong?)null, _ => 93600UL
            }, sample.Usage.ObservedUptimeSeconds);
            if (condition == "scaled") Assert.Equal("4.7GiB", sample.Usage.DownloadUsed.Raw);
        }
        else await Assert.ThrowsAsync<InvalidDataException>(Read);
    }

    // Separate in/out buffers model the duplex exchange without a real router.
    private sealed class CreateExchangeStream(byte[] response, bool failAfterFirstWrite = false) : MemoryStream
    {
        private readonly MemoryStream input = new(response);
        private int writes;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            input.ReadAsync(buffer, cancellationToken);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (failAfterFirstWrite && ++writes > 1) return ValueTask.FromException(new IOException("Synthetic write failure."));
            return base.WriteAsync(buffer, cancellationToken);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) input.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed class FragmentedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(1, buffer.Length)], cancellationToken);
    }
}
