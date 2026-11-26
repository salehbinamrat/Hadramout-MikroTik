using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hadramout.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace Hadramout.Core.Tests;

public sealed class RouterOsTlsTransportTests(ITestOutputHelper output)
{
    [Fact]
    public async Task TrustedPrivateCaAuthenticatesAndExchangesFramedData()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true);
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            using var transport = await RouterOsTlsTransport.ConnectAsync("127.0.0.1", "router.test",
                server.Port, trustedRootDer: certificates.Root.RawData, cancellationToken: deadline.Token);
            Assert.True(transport.Stream.IsEncrypted);
            Assert.Equal(SslProtocols.Tls12, transport.Stream.SslProtocol);
            await RouterOsWireCodec.WriteSentenceAsync(transport.Stream, ["/system/resource/print"u8.ToArray()],
                deadline.Token);
            byte[][] reply = await RouterOsWireCodec.ReadSentenceAsync(transport.Stream, deadline.Token);
            Assert.True(Assert.Single(reply).AsSpan().SequenceEqual("!done"u8));
        }
        finally
        {
            // Always observe the server task, even if the client reports EOF during TLS.
            await serve;
        }
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
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
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
            using var withKey = issued.CopyWithPrivateKey(leafKey);
            // Schannel requires a usable on-disk key container. Import a short-lived PFX
            // into the user key set rather than retaining CopyWithPrivateKey's key handle.
            // Do not specify PersistKeySet; disposal releases the imported temporary key.
            string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            byte[] pfx = withKey.Export(X509ContentType.Pkcs12, password);
            try
            {
                Leaf = X509CertificateLoader.LoadPkcs12(pfx, password,
                    OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
            }
            finally { CryptographicOperations.ZeroMemory(pfx); }
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
        private readonly SslStreamCertificateContext context;
        private readonly ITestOutputHelper output;
        private readonly CancellationTokenSource deadline = new(TimeSpan.FromSeconds(20));
        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

        public LoopbackServer(X509Certificate2 certificate, X509Certificate2 root, ITestOutputHelper output)
        {
            this.output = output;
            context = SslStreamCertificateContext.Create(certificate,
                new X509Certificate2Collection(root), offline: true);
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
                    ServerCertificateContext = context,
                    EnabledSslProtocols = SslProtocols.Tls12
                }, deadline.Token);
                if (reply)
                {
                    byte[][] command = await RouterOsWireCodec.ReadSentenceAsync(tls, deadline.Token);
                    Assert.True(Assert.Single(command).AsSpan().SequenceEqual("/system/resource/print"u8));
                    await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], deadline.Token);
                }
                else
                {
                    // Keep the peer alive until the client accepts or rejects the handshake.
                    // No application data is allowed in negative authentication cases.
                    byte[] buffer = new byte[1];
                    int read = await tls.ReadAsync(buffer, deadline.Token);
                    Assert.Equal(0, read);
                }
            }
            catch (Exception ex)
            {
                output.WriteLine("Loopback TLS server: " + ex);
                if (reply || ex is not (AuthenticationException or IOException)) throw;
            }
        }

        public void Dispose()
        {
            deadline.Cancel();
            listener.Stop();
            deadline.Dispose();
        }
    }
}
