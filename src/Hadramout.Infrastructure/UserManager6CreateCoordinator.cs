using System.Runtime.Versioning;

namespace Hadramout.Infrastructure;

internal enum UserManager6CoordinationOutcome
{
    ProfileNotVisible, UsernameAlreadyVisible, ClaimUnavailable, Acknowledged, Indeterminate
}

// Qualification-only orchestration, with no production socket/session entry point.
// The stream is owned by the caller, must be exclusive and independently authenticated.
// Future production integration must enforce the enrolled target pin, exact version,
// authorization and configuration quiescence; this component cannot establish those.
[SupportedOSPlatform("windows")]
internal static class UserManager6CreateCoordinator
{
    internal static async Task<UserManager6CoordinationOutcome> ExecuteForQualificationAsync(
        string databasePath, Guid reservationId, Stream stream, TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        TimeSpan limit = timeout ?? TimeSpan.FromSeconds(15);
        if (limit <= TimeSpan.Zero || limit > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(limit);

        var journal = new UserManager6CreateJournal(databasePath);
        var scope = journal.ReadPreparedPreflightScope(reservationId);
        UserManager6Records.ValidateKey(scope.Customer, nameof(scope.Customer));
        var evidence = await RouterOsSession.ReadUm6PreflightCoreAsync(stream,
            scope.ProfileOwner, scope.ProfileName, scope.Username, deadline.Token).ConfigureAwait(false);
        if (evidence.State == UserManager6PreflightState.ProfileNotVisible)
            return UserManager6CoordinationOutcome.ProfileNotVisible;
        if (evidence.State == UserManager6PreflightState.UsernameAlreadyVisible)
            return UserManager6CoordinationOutcome.UsernameAlreadyVisible;
        if (evidence.State != UserManager6PreflightState.NoVisibleUsernameMatch)
            throw new InvalidDataException("Unexpected creation preflight evidence.");

        deadline.Token.ThrowIfCancellationRequested();
        using var secret = journal.TryClaimBoundSecret(reservationId);
        if (secret is null) return UserManager6CoordinationOutcome.ClaimUnavailable;

        // From here onward a crash or exception must leave a non-rearmable claim.
        // Never invoke the read recovery/reconnect wrapper around this exchange.
        var receipt = await new UserManager6CreateWire(stream).CreateDisabledOnceAsync(
            reservationId, scope.Customer, scope.Username, secret.Password, deadline.Token).ConfigureAwait(false);
        bool acknowledged = receipt.Outcome == UserManager6CreateWireOutcome.Acknowledged;
        // No cancellation token for local result persistence. If persistence fails,
        // the previously committed DispatchStarted state is still non-rearmable.
        bool recorded = acknowledged ? journal.TryMarkAcknowledged(reservationId) :
            journal.TryMarkIndeterminate(reservationId);
        if (!recorded) throw new InvalidOperationException("Creation result could not be recorded; review required.");
        return acknowledged ? UserManager6CoordinationOutcome.Acknowledged : UserManager6CoordinationOutcome.Indeterminate;
    }
}
