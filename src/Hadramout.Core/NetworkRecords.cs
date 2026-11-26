namespace Hadramout.Core;

public enum BackendKind
{
    Hotspot = 1,
    UserManager6 = 2,
    UserManager7 = 3,
    Pppoe = 4
}

public sealed class Site
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required string Name { get; init; }
}

public sealed class Router
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required Guid SiteId { get; init; }
    public required string Name { get; init; }
}

public sealed class Backend
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required Guid RouterId { get; init; }
    public required BackendKind Kind { get; init; }
}

public sealed class Plan
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required Guid BackendId { get; init; }
    public required string Name { get; init; }
}

public sealed class VoucherBatch
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required Guid BackendId { get; init; }
    public required Guid PlanId { get; init; }
}

public sealed class VoucherReservation
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required Guid BackendId { get; init; }
    public required Guid BatchId { get; init; }
    public required string Username { get; init; }
}
