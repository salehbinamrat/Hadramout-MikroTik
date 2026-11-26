using Hadramout.Core;
using Microsoft.EntityFrameworkCore;

namespace Hadramout.Infrastructure;

public sealed class NetworkDbContext(DbContextOptions<NetworkDbContext> options) : DbContext(options)
{
    public DbSet<Site> Sites => Set<Site>();
    public DbSet<Router> Routers => Set<Router>();
    public DbSet<Backend> Backends => Set<Backend>();
    public DbSet<Plan> Plans => Set<Plan>();
    public DbSet<VoucherBatch> Batches => Set<VoucherBatch>();
    public DbSet<VoucherReservation> Reservations => Set<VoucherReservation>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<Site>(b =>
        {
            b.ToTable("sites", t => t.HasCheckConstraint("ck_site_name", "length(trim(Name)) BETWEEN 1 AND 128"));
            b.HasKey(x => x.Id);
            b.Property(x => x.Name).UseCollation("BINARY").IsRequired();
            b.HasIndex(x => x.Name).IsUnique();
        });
        model.Entity<Router>(b =>
        {
            b.ToTable("routers", t => t.HasCheckConstraint("ck_router_name", "length(trim(Name)) BETWEEN 1 AND 128"));
            b.HasKey(x => x.Id);
            b.Property(x => x.Name).UseCollation("BINARY").IsRequired();
            b.HasIndex(x => new { x.SiteId, x.Name }).IsUnique();
            b.HasOne<Site>().WithMany().HasForeignKey(x => x.SiteId).OnDelete(DeleteBehavior.Restrict);
        });
        model.Entity<Backend>(b =>
        {
            b.ToTable("backends", t => t.HasCheckConstraint("ck_backend_kind", "Kind IN (1,2,3,4)"));
            b.HasKey(x => x.Id);
            b.HasIndex(x => new { x.RouterId, x.Kind }).IsUnique();
            b.HasOne<Router>().WithMany().HasForeignKey(x => x.RouterId).OnDelete(DeleteBehavior.Restrict);
        });
        model.Entity<Plan>(b =>
        {
            b.ToTable("plans", t => t.HasCheckConstraint("ck_plan_name", "length(trim(Name)) BETWEEN 1 AND 128"));
            b.HasKey(x => x.Id);
            b.HasAlternateKey(x => new { x.BackendId, x.Id });
            b.Property(x => x.Name).UseCollation("BINARY").IsRequired();
            b.HasIndex(x => new { x.BackendId, x.Name }).IsUnique();
            b.HasOne<Backend>().WithMany().HasForeignKey(x => x.BackendId).OnDelete(DeleteBehavior.Restrict);
        });
        model.Entity<VoucherBatch>(b =>
        {
            b.ToTable("voucher_batches");
            b.HasKey(x => x.Id);
            b.HasAlternateKey(x => new { x.BackendId, x.Id });
            b.HasOne<Plan>().WithMany().HasForeignKey(x => new { x.BackendId, x.PlanId })
                .HasPrincipalKey(x => new { x.BackendId, x.Id }).OnDelete(DeleteBehavior.Restrict);
        });
        model.Entity<VoucherReservation>(b =>
        {
            b.ToTable("voucher_reservations", t => t.HasCheckConstraint("ck_voucher_username", "length(Username) BETWEEN 1 AND 128 AND Username = trim(Username)"));
            b.HasKey(x => x.Id);
            b.Property(x => x.Username).UseCollation("BINARY").IsRequired();
            b.HasIndex(x => new { x.BackendId, x.Username }).IsUnique();
            b.HasOne<VoucherBatch>().WithMany().HasForeignKey(x => new { x.BackendId, x.BatchId })
                .HasPrincipalKey(x => new { x.BackendId, x.Id }).OnDelete(DeleteBehavior.Restrict);
        });
    }
}
