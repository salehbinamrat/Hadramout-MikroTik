using System.Text;
using System.Globalization;

namespace Hadramout.Infrastructure;

// Remote observations only, not authoritative entitlement/expiry or write permission.
internal sealed record UserManager6ByteValue(string? Raw, ulong? Bytes)
{
    // Retain unknown formats; never interpret absent, scaled or malformed values as zero.
    internal static UserManager6ByteValue FromRaw(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return new(raw, null);
        ReadOnlySpan<char> number = raw.AsSpan();
        if (number[^1] == 'B') number = number[..^1];
        if (number.IsEmpty) return new(raw, null);
        foreach (char ch in number)
            if (!char.IsAsciiDigit(ch)) return new(raw, null);
        return new(raw, ulong.TryParse(number, NumberStyles.None, CultureInfo.InvariantCulture,
            out ulong bytes) ? bytes : null);
    }
}

internal sealed record UserManager6Usage(UserManager6ByteValue DownloadUsed,
    UserManager6ByteValue UploadUsed, string? UptimeUsed)
{
    internal ulong? ObservedTransferBytes =>
        DownloadUsed.Bytes is ulong download && UploadUsed.Bytes is ulong upload &&
        download <= ulong.MaxValue - upload ? download + upload : null;

    internal ulong? ObservedUptimeSeconds => UserManager6Records.ParseUptimeSeconds(UptimeUsed);
}

// Independent observations, deliberately not an entitlement/expiry classification.
internal enum UserManager6ProfileObservation { Unknown, EmptyNameReported, NameReported }
internal enum UserManager6LastSeenObservation { Unknown, NeverReported, OtherValueReported }

internal sealed record UserManager6ActivityEvidence(string? Active, string? Incomplete,
    string? LastSeen, string? ActiveSessions)
{
    internal UserManager6LastSeenObservation LastSeenObservation =>
        string.IsNullOrWhiteSpace(LastSeen) ? UserManager6LastSeenObservation.Unknown :
        LastSeen == "never" ? UserManager6LastSeenObservation.NeverReported :
        UserManager6LastSeenObservation.OtherValueReported;
}

internal sealed record UserManager6Account(string Customer, string Username, bool? Disabled,
    string? ActualProfile, UserManager6Usage Usage, UserManager6ActivityEvidence Activity)
{
    internal UserManager6ProfileObservation ProfileObservation =>
        ActualProfile == "" ? UserManager6ProfileObservation.EmptyNameReported :
        string.IsNullOrWhiteSpace(ActualProfile) ? UserManager6ProfileObservation.Unknown :
        UserManager6ProfileObservation.NameReported;
}

internal sealed record UserManager6Limitation(string Owner, string Name,
    UserManager6ByteValue DownloadLimit, UserManager6ByteValue UploadLimit,
    UserManager6ByteValue TransferLimit, string? UptimeLimit,
    string? RateLimitRx, string? RateLimitTx);
internal sealed record UserManager6Profile(string Owner, string Name, string? Validity, string? StartsAt);

// Legacy profile-limitation rows do not expose an owner in the documented field set.
// A name match is evidence only; it is not an authoritative owner-scoped binding.
internal sealed record UserManager6ProfileLink(string Profile, string Limitation,
    string? FromTime, string? TillTime, string? Weekdays);

internal sealed record UserManager6ProfileMappingEvidence(UserManager6Profile Profile,
    IReadOnlyList<UserManager6ProfileLink> VisibleNameMatches);

internal enum UserManager6PreflightState { ProfileNotVisible, UsernameAlreadyVisible, NoVisibleUsernameMatch }
internal sealed record UserManager6PreflightEvidence(UserManager6PreflightState State,
    UserManager6Profile? Profile, string? ExistingCustomer);

// Observation only: not a persisted confirmation, entitlement or permission to print.
internal sealed record UserManager6DisabledCreationObservation(string RemoteId, bool ReturnedIdMatched);

internal static class UserManager6Records
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static void ValidateKey(string value, string parameter)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || value != value.Trim() ||
            value.Any(char.IsControl))
            throw new ArgumentException("A bounded nonblank User Manager identity is required.", parameter);
        try
        {
            if (Utf8.GetByteCount(value) > 128)
                throw new ArgumentException("User Manager identity exceeds the byte limit.", parameter);
        }
        catch (EncoderFallbackException)
        {
            throw new ArgumentException("Invalid User Manager identity encoding.", parameter);
        }
    }

    internal static byte[] Query(string field, string value) => Utf8.GetBytes("?" + field + "=" + value);

    internal static UserManager6Account ParseAccount(byte[][] words, string customer, string username)
    {
        string actualCustomer = RequiredMatch(words, "customer", customer);
        string actualUsername = RequiredMatch(words, "username", username);
        bool? disabled = ReadText(words, "disabled", 8) switch
        {
            "yes" or "true" => true,
            "no" or "false" => false,
            null or "" => null,
            _ => throw new InvalidDataException("Invalid User Manager disabled flag.")
        };
        return new(actualCustomer, actualUsername, disabled, ReadText(words, "actual-profile", 512),
            new UserManager6Usage(ReadBytes(words, "download-used"), ReadBytes(words, "upload-used"),
                ReadText(words, "uptime-used", 128)),
            new UserManager6ActivityEvidence(ReadText(words, "active", 128),
                ReadText(words, "incomplete", 128), ReadText(words, "last-seen", 128),
                ReadText(words, "active-sessions", 4096)));
    }

    internal static string ParseVisibleUsernameCustomer(byte[][] words, string username)
    {
        RequiredMatch(words, "username", username);
        string? customer = ReadText(words, "customer", 128);
        if (customer is null) throw new InvalidDataException("User Manager account has no customer identity.");
        try { ValidateKey(customer, nameof(customer)); }
        catch (ArgumentException) { throw new InvalidDataException("Invalid User Manager customer identity."); }
        return customer;
    }

    internal static bool IsOpaqueRemoteId(string? value) =>
        value is { Length: >= 2 and <= 33 } && value[0] == '*' &&
        value.Skip(1).All(char.IsAsciiHexDigit);

    internal static UserManager6DisabledCreationObservation ParseDisabledCreationObservation(
        byte[][] words, Guid reservationId, string customer, string username, string? returnedId)
    {
        RequiredMatch(words, "customer", customer);
        RequiredMatch(words, "username", username);
        RequiredMatch(words, "comment", "hmk-create:" + reservationId.ToString("N"));
        if (ReadText(words, "disabled", 8) is not ("yes" or "true"))
            throw new InvalidDataException("User Manager readback did not prove disabled state.");
        string? id = ReadText(words, ".id", 33);
        if (!IsOpaqueRemoteId(id) ||
            (returnedId is not null && !string.Equals(id, returnedId, StringComparison.Ordinal)))
            throw new InvalidDataException("User Manager readback identity does not match.");
        return new(id!, returnedId is not null);
    }

    // An empty actual-profile field is only a visible observation. It cannot prove
    // the absence of hidden, queued or inactive assignments on legacy RouterOS.
    internal static (UserManager6DisabledCreationObservation Account, string? ActualProfile) ParseProfileLinkAccount(
        byte[][] words, Guid reservationId, string customer, string username, string expectedId)
    {
        if (!IsOpaqueRemoteId(expectedId)) throw new ArgumentException("Expected identity required.", nameof(expectedId));
        var account = ParseDisabledCreationObservation(words, reservationId, customer, username, expectedId);
        return (account, ReadText(words, "actual-profile", 512));
    }

    internal static UserManager6Profile ParseProfile(byte[][] words, string owner, string name) =>
        new(RequiredMatch(words, "owner", owner), RequiredMatch(words, "name", name),
            ReadText(words, "validity", 128), ReadText(words, "starts-at", 128));

    internal static UserManager6Limitation ParseLimitation(byte[][] words, string owner, string name) =>
        new(RequiredMatch(words, "owner", owner), RequiredMatch(words, "name", name),
            ReadBytes(words, "download-limit"), ReadBytes(words, "upload-limit"),
            ReadBytes(words, "transfer-limit"), ReadText(words, "uptime-limit", 128),
            ReadText(words, "rate-limit-rx", 128), ReadText(words, "rate-limit-tx", 128));

    internal static UserManager6ProfileLink ParseProfileLink(byte[][] words, string profile)
    {
        string actualProfile = RequiredMatch(words, "profile", profile);
        string? limitation = ReadText(words, "limitation", 128);
        if (limitation is null)
            throw new InvalidDataException("User Manager profile link has no limitation identity.");
        try { ValidateKey(limitation, nameof(limitation)); }
        catch (ArgumentException) { throw new InvalidDataException("Invalid User Manager limitation identity."); }
        return new(actualProfile, limitation, ReadText(words, "from-time", 128),
            ReadText(words, "till-time", 128), ReadText(words, "weekdays", 128));
    }

    // Decode only exact descending w/d/h/m/s components; unknown formats stay raw.
    // No calendar conversion, wall-clock expiry, or subtraction from a profile limit.
    internal static ulong? ParseUptimeSeconds(string? raw)
    {
        if (string.IsNullOrEmpty(raw) || raw.Length > 128) return null;
        ReadOnlySpan<char> remaining = raw.AsSpan();
        int previousRank = 6;
        ulong total = 0;
        while (!remaining.IsEmpty)
        {
            int i = 0;
            while (i < remaining.Length && char.IsAsciiDigit(remaining[i])) i++;
            if (i == 0 || i == remaining.Length ||
                !ulong.TryParse(remaining[..i], NumberStyles.None, CultureInfo.InvariantCulture, out ulong amount))
                return null;
            (int rank, ulong factor) = remaining[i] switch
            {
                'w' => (5, 604800UL),
                'd' => (4, 86400UL),
                'h' => (3, 3600UL),
                'm' => (2, 60UL),
                's' => (1, 1UL),
                _ => (0, 0UL)
            };
            if (rank == 0 || rank >= previousRank || amount > (ulong.MaxValue - total) / factor)
                return null;
            total += amount * factor;
            previousRank = rank;
            remaining = remaining[(i + 1)..];
        }
        return total;
    }

    private static UserManager6ByteValue ReadBytes(byte[][] words, string field) =>
        UserManager6ByteValue.FromRaw(ReadText(words, field, 64));

    private static string RequiredMatch(byte[][] words, string field, string expected)
    {
        string? value = ReadText(words, field, 128);
        if (!string.Equals(value, expected, StringComparison.Ordinal))
            throw new InvalidDataException("User Manager reply does not match the requested identity.");
        return value!;
    }

    internal static string? ReadText(byte[][] words, string field, int maxBytes)
    {
        byte[] prefix = Encoding.ASCII.GetBytes("=" + field + "=");
        string? result = null;
        foreach (byte[] word in words.Skip(1))
        {
            if (!word.AsSpan().StartsWith(prefix)) continue;
            if (result is not null || word.Length - prefix.Length > maxBytes)
                throw new InvalidDataException("Invalid User Manager field length or duplicate.");
            try { result = Utf8.GetString(word, prefix.Length, word.Length - prefix.Length); }
            catch (DecoderFallbackException) { throw new InvalidDataException("Invalid User Manager text encoding."); }
            if (result.Any(char.IsControl)) throw new InvalidDataException("Invalid User Manager text field.");
        }
        return result;
    }
}
