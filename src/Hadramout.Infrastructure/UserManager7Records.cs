namespace Hadramout.Infrastructure;

// Observation only, not an entitlement, expiry or authorization decision.
internal sealed record UserManager7Account(string RemoteId, string Username, bool? Disabled,
    string? Group, string? SharedUsersRaw);

internal static class UserManager7Records
{
    internal static UserManager7Account ParseAccount(byte[][] words, string username)
    {
        UserManager6Records.ValidateKey(username, nameof(username));
        string? name = UserManager6Records.ReadText(words, "name", 128);
        if (!string.Equals(name, username, StringComparison.Ordinal))
            throw new InvalidDataException("User Manager v7 account identity does not match.");
        string? id = UserManager6Records.ReadText(words, ".id", 33);
        if (!UserManager6Records.IsOpaqueRemoteId(id))
            throw new InvalidDataException("Invalid User Manager v7 remote identity.");
        bool? disabled = UserManager6Records.ReadText(words, "disabled", 8) switch
        {
            "yes" or "true" => true,
            "no" or "false" => false,
            null or "" => null,
            _ => throw new InvalidDataException("Invalid User Manager v7 disabled flag.")
        };
        return new(id!, name!, disabled, UserManager6Records.ReadText(words, "group", 128),
            UserManager6Records.ReadText(words, "shared-users", 64));
    }
}
