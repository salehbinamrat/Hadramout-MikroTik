namespace Hadramout.Infrastructure;

// Observation only, not an entitlement, expiry or authorization decision.
internal sealed record UserManager7Account(string RemoteId, string Username, bool? Disabled,
    string? Group, string? SharedUsersRaw);

internal enum UserManager7AssignmentState { Unknown, ActiveReported, ReadyReported, UsedReported }
internal sealed record UserManager7Assignment(string RemoteId, string Username, string ProfileName,
    string? StateRaw, string? EndTimeRaw)
{
    internal UserManager7AssignmentState State => StateRaw switch
    {
        "running active" => UserManager7AssignmentState.ActiveReported,
        "running" => UserManager7AssignmentState.ReadyReported,
        "used" => UserManager7AssignmentState.UsedReported,
        _ => UserManager7AssignmentState.Unknown
    };
}

// Visibility is permission-dependent; even a completed empty list is not an
// entitlement, expiration or absence-of-assignment proof.
internal sealed record UserManager7AssignmentEvidence(UserManager7Account Account,
    IReadOnlyList<UserManager7Assignment> VisibleAssignments)
{
    internal bool ConflictingActiveReports =>
        VisibleAssignments.Count(row => row.State == UserManager7AssignmentState.ActiveReported) > 1;
}

internal sealed record UserManager7Profile(string RemoteId, string Name, string? ValidityRaw,
    string? StartsWhenRaw, string? OverrideSharedUsersRaw);
internal sealed record UserManager7ProfileLink(string RemoteId, string ProfileName, string LimitationName,
    string? FromTimeRaw, string? TillTimeRaw, string? WeekdaysRaw);
internal sealed record UserManager7ProfileMappingEvidence(UserManager7Profile Profile,
    IReadOnlyList<UserManager7ProfileLink> VisibleLinks);
internal sealed record UserManager7Limitation(string RemoteId, string Name,
    string? DownloadLimitRaw, string? UploadLimitRaw, string? TransferLimitRaw,
    string? UptimeLimitRaw, string? RateLimitRxRaw, string? RateLimitTxRaw,
    string? ResetIntervalRaw, string? ResetStartRaw);

internal static class UserManager7Records
{
    private static string ExactKey(byte[][] words, string field, string? expected = null)
    {
        string? value = UserManager6Records.ReadText(words, field, 128);
        if (value is null || (expected is not null && value != expected))
            throw new InvalidDataException("User Manager v7 definition identity does not match.");
        try { UserManager6Records.ValidateKey(value, field); }
        catch (ArgumentException) { throw new InvalidDataException("Invalid User Manager v7 definition identity."); }
        return value;
    }

    private static string RemoteId(byte[][] words)
    {
        string? id = UserManager6Records.ReadText(words, ".id", 33);
        if (!UserManager6Records.IsOpaqueRemoteId(id))
            throw new InvalidDataException("Invalid User Manager v7 definition remote identity.");
        return id!;
    }

    internal static UserManager7Profile ParseProfile(byte[][] words, string name) =>
        new(RemoteId(words), ExactKey(words, "name", name),
            UserManager6Records.ReadText(words, "validity", 128),
            UserManager6Records.ReadText(words, "starts-when", 64),
            UserManager6Records.ReadText(words, "override-shared-users", 64));

    internal static UserManager7ProfileLink ParseProfileLink(byte[][] words, string name) =>
        new(RemoteId(words), ExactKey(words, "profile", name), ExactKey(words, "limitation"),
            UserManager6Records.ReadText(words, "from-time", 128),
            UserManager6Records.ReadText(words, "till-time", 128),
            UserManager6Records.ReadText(words, "weekdays", 128));

    // Keep zero, missing, unlimited and unrecognized formats distinct. Never
    // calculate effective allowances or reverse RX/TX based on guesses.
    internal static UserManager7Limitation ParseLimitation(byte[][] words, string name) =>
        new(RemoteId(words), ExactKey(words, "name", name),
            UserManager6Records.ReadText(words, "download-limit", 64),
            UserManager6Records.ReadText(words, "upload-limit", 64),
            UserManager6Records.ReadText(words, "transfer-limit", 64),
            UserManager6Records.ReadText(words, "uptime-limit", 128),
            UserManager6Records.ReadText(words, "rate-limit-rx", 128),
            UserManager6Records.ReadText(words, "rate-limit-tx", 128),
            UserManager6Records.ReadText(words, "reset-counters-interval", 64),
            UserManager6Records.ReadText(words, "reset-counters-start-time", 128));

    internal static UserManager7Assignment ParseAssignment(byte[][] words, string username)
    {
        string? user = UserManager6Records.ReadText(words, "user", 128);
        if (!string.Equals(user, username, StringComparison.Ordinal))
            throw new InvalidDataException("User Manager v7 assignment user does not match.");
        string? id = UserManager6Records.ReadText(words, ".id", 33);
        if (!UserManager6Records.IsOpaqueRemoteId(id))
            throw new InvalidDataException("Invalid User Manager v7 assignment identity.");
        string? profile = UserManager6Records.ReadText(words, "profile", 128);
        if (profile is null) throw new InvalidDataException("Missing User Manager v7 assignment profile.");
        try { UserManager6Records.ValidateKey(profile, nameof(profile)); }
        catch (ArgumentException) { throw new InvalidDataException("Invalid User Manager v7 assignment profile."); }
        return new(id!, user!, profile, UserManager6Records.ReadText(words, "state", 64),
            UserManager6Records.ReadText(words, "end-time", 128));
    }

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
