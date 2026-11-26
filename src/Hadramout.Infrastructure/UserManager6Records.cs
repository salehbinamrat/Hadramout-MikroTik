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
}

internal sealed record UserManager6Account(string Customer, string Username, bool? Disabled,
    string? ActualProfile, UserManager6Usage Usage);

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
                ReadText(words, "uptime-used", 128)));
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

    private static UserManager6ByteValue ReadBytes(byte[][] words, string field) =>
        UserManager6ByteValue.FromRaw(ReadText(words, field, 64));

    private static string RequiredMatch(byte[][] words, string field, string expected)
    {
        string? value = ReadText(words, field, 128);
        if (!string.Equals(value, expected, StringComparison.Ordinal))
            throw new InvalidDataException("User Manager reply does not match the requested identity.");
        return value!;
    }

    private static string? ReadText(byte[][] words, string field, int maxBytes)
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
