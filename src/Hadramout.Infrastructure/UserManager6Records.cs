using System.Text;

namespace Hadramout.Infrastructure;

// Remote observations only, not authoritative entitlement/expiry or write permission.
internal sealed record UserManager6Account(string Customer, string Username, bool? Disabled, string? ActualProfile);
internal sealed record UserManager6Profile(string Owner, string Name, string? Validity, string? StartsAt);

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
        return new(actualCustomer, actualUsername, disabled, ReadText(words, "actual-profile", 512));
    }

    internal static UserManager6Profile ParseProfile(byte[][] words, string owner, string name) =>
        new(RequiredMatch(words, "owner", owner), RequiredMatch(words, "name", name),
            ReadText(words, "validity", 128), ReadText(words, "starts-at", 128));

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
