using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hadramout.Infrastructure;
using Xunit;

namespace Hadramout.Core.Tests;

public sealed class RouterOsTlsTransportTests
{
    [Fact]
    public async Task TrustedPrivateCaAuthenticatesAndExchangesFramedData()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf);
        Task serve = server.RunAsync(reply: true);
        using var transport = await RouterOsTlsTransport.ConnectAsync("127.0.0.1", "router.test",
            server.Port, trustedRootDer: certificates.Root.RawData);
        Assert.True(transport.Stream.IsEncrypted);
        Assert.Equal(SslProtocols.Tls12, transport.Stream.SslProtocol);
        await RouterOsWireCodec.WriteSentenceAsync(transport.Stream, ["/system/resource/print"u8.ToArray()],
            CancellationToken.None);
        byte[][] reply = await RouterOsWireCodec.ReadSentenceAsync(transport.Stream, CancellationToken.None);
        Assert.True(Assert.Single(reply).AsSpan().SequenceEqual("!done"u8));
        await serve;
    }

    [Theory]
    [InlineData("wrong-name")]
    [InlineData("untrusted-ca")]
    [InlineData("expired-leaf")]
    [InlineData("system-trust")]
    public async Task InvalidPeerCannotEstablishAuthenticatedTransport(string condition)
    {
        using var certificates = new Certificates(expired: condition == "expired-leaf");
        using var other = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf);
        Task serve = server.RunAsync(reply: false);
        string name = condition == "wrong-name" ? "other.test" : "router.test";
        byte[] trust = condition switch
        {
            "untrusted-ca" => other.Root.RawData,
            "system-trust" => [],
            _ => certificates.Root.RawData
        };
        try
        {
            await Assert.ThrowsAnyAsync<AuthenticationException>(() =>
                RouterOsTlsTransport.ConnectAsync("127.0.0.1", name, server.Port, trustedRootDer: trust));
        }
        finally { await serve; }
    }

    [Fact]
    public async Task HandshakeDeadlineStopsSilentPeer()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var certificates = new Certificates();
        await Assert.ThrowsAsync<TimeoutException>(() => RouterOsTlsTransport.ConnectAsync(
            "127.0.0.1", "router.test", port, TimeSpan.FromSeconds(1), certificates.Root.RawData));
    }

    [Fact]
    public async Task PrecancelledRequestNeverConnects()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            RouterOsTlsTransport.ConnectAsync("127.0.0.1", "router.test", cancellationToken: cts.Token));
    }

    [Fact]
    public async Task ExplicitCancellationDuringHandshakeIsNotReportedAsTimeout()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource();
        Task<RouterOsTlsTransport> connect = RouterOsTlsTransport.ConnectAsync("127.0.0.1", "router.test",
            port, TimeSpan.FromSeconds(10), cancellationToken: cts.Token);
        using var acceptDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var peer = await listener.AcceptTcpClientAsync(acceptDeadline.Token);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await connect);
    }

    [Fact]
    public async Task LeafCannotBeConfiguredAsPrivateCa()
    {
        using var certificates = new Certificates();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            RouterOsTlsTransport.ConnectAsync("127.0.0.1", "router.test", trustedRootDer: certificates.Leaf.RawData));
    }

    [Theory]
    [InlineData("https://router.test", "router.test", 8729)]
    [InlineData("127.0.0.1", " ", 8729)]
    [InlineData("127.0.0.1", "router.test", 0)]
    public async Task InvalidEndpointsFailBeforeConnecting(string host, string name, int port)
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(() => RouterOsTlsTransport.ConnectAsync(host, name, port));
    }

    private sealed class Certificates : IDisposable
    {
        private readonly RSA rootKey = RSA.Create(2048);
        private readonly RSA leafKey = RSA.Create(2048);
        public X509Certificate2 Root { get; }
        public X509Certificate2 Leaf { get; }

        public Certificates(bool expired = false)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var rootRequest = new CertificateRequest("CN=Hadramout isolated test CA", rootKey,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign |
                X509KeyUsageFlags.CrlSign, true));
            rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            Root = rootRequest.CreateSelfSigned(now.AddDays(-30), now.AddDays(30));

            var request = new CertificateRequest("CN=router.test", leafKey, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.KeyEncipherment, true));
            var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("router.test");
            request.CertificateExtensions.Add(san.Build());
            using var issued = request.Create(Root, now.AddDays(-10), expired ? now.AddDays(-1) : now.AddDays(10),
                RandomNumberGenerator.GetBytes(16));
            Leaf = issued.CopyWithPrivateKey(leafKey);
        }

        public void Dispose()
        {
            Leaf.Dispose();
            Root.Dispose();
            leafKey.Dispose();
            rootKey.Dispose();
        }
    }

    private sealed class LoopbackServer : IDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly X509Certificate2 certificate;
        private readonly CancellationTokenSource deadline = new(TimeSpan.FromSeconds(20));
        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

        public LoopbackServer(X509Certificate2 certificate)
        {
            this.certificate = certificate;
            listener.Start();
        }

        public async Task RunAsync(bool reply)
        {
            using var peer = await listener.AcceptTcpClientAsync(deadline.Token);
            using var tls = new SslStream(peer.GetStream(), leaveInnerStreamOpen: false);
            try
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                    EnabledSslProtocols = SslProtocols.Tls12
                }, deadline.Token);
                if (reply)
                {
                    byte[][] command = await RouterOsWireCodec.ReadSentenceAsync(tls, deadline.Token);
                    Assert.True(Assert.Single(command).AsSpan().SequenceEqual("/system/resource/print"u8));
                    await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], deadline.Token);
                }
            }
            catch (AuthenticationException) when (!reply) { }
            catch (IOException) when (!reply) { }
        }

        public void Dispose()
        {
            deadline.Cancel();
            listener.Stop();
            deadline.Dispose();
        }
    }
}
