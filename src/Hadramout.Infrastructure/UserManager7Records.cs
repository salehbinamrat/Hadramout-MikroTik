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

internal static class UserManager7Records
{
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
