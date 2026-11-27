namespace Hadramout.Infrastructure;

internal enum UserManager7CreateWireOutcome { Acknowledged, Indeterminate }
internal sealed record UserManager7CreateWireReceipt(UserManager7CreateWireOutcome Outcome, string? ReturnedId);

// Qualification-only wire primitive. The caller must supply an authenticated,
// exclusively held, qualified stream and committed durable claim. No retry,
// profile assignment or activation; caller closes the stream on uncertainty.
internal sealed class UserManager7CreateWire(Stream stream)
{
    private readonly UserManagerCreateExchange exchange = new(stream);

    internal async Task<UserManager7CreateWireReceipt> CreateDisabledOnceAsync(Guid reservationId,
        string groupName, string username, ReadOnlyMemory<byte> password, CancellationToken cancellationToken)
    {
        UserManager6Records.ValidateKey(groupName, nameof(groupName));
        var receipt = await exchange.ExecuteOnceAsync(true, reservationId, groupName, username, password,
            cancellationToken).ConfigureAwait(false);
        return new(receipt.Acknowledged ? UserManager7CreateWireOutcome.Acknowledged :
            UserManager7CreateWireOutcome.Indeterminate, receipt.ReturnedId);
    }
}
