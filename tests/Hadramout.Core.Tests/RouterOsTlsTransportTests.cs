using System.Net;
using System.Runtime.Versioning;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hadramout.Infrastructure;
using Hadramout.Core;
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

    [Theory]
    [InlineData("6.49.19 (long-term)")]
    [InlineData("7.21.1 (stable)")]
    public async Task SessionAuthenticatesAndReadsVersion(string version)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertVersionRequestAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls,
                ["!re"u8.ToArray(), Encoding.ASCII.GetBytes("=version=" + version)], token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            Assert.Equal(version, await session.ReadVersionAsync());
        }
        finally { await serve; }
    }

    [Theory]
    [InlineData("trap")]
    [InlineData("fatal")]
    [InlineData("challenge")]
    [InlineData("unexpected-data")]
    public async Task LoginRejectsAnythingOtherThanBareCompletion(string condition)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            ReadOnlyMemory<byte>[] reply = condition switch
            {
                "trap" => ["!trap"u8.ToArray(), "=message=synthetic-private-password"u8.ToArray()],
                "fatal" => ["!fatal"u8.ToArray()],
                "challenge" => ["!done"u8.ToArray(), "=ret=0123456789abcdef"u8.ToArray()],
                _ => ["!re"u8.ToArray()]
            };
            await RouterOsWireCodec.WriteSentenceAsync(tls, reply, token);
        });
        try
        {
            var ex = await Assert.ThrowsAsync<AuthenticationException>(() => ConnectSessionAsync(server, certificates));
            Assert.DoesNotContain("synthetic-private-password", ex.Message, StringComparison.Ordinal);
        }
        finally { await serve; }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PinnedSessionRequiresExactCertificateAndAuthenticatesBeforeRead(bool lowerCase)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        string pin = Convert.ToHexString(SHA256.HashData(certificates.Leaf.RawData));
        if (lowerCase) pin = pin.ToLowerInvariant();
        Task serve = server.RunAsync(reply: true, handler: (tls, token) =>
            PrepareProbePeerAsync(tls, token, "6.49.19"));
        try
        {
            using var session = await RouterOsSession.ConnectPinnedAsync("127.0.0.1", "router.test", pin,
                "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
                trustedRootDer: certificates.Root.RawData);
            Assert.Equal("6.49.19", await session.ReadVersionAsync());
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Theory]
    [InlineData("wrong-pin")]
    [InlineData("wrong-name")]
    [InlineData("wrong-ca")]
    [InlineData("expired")]
    public async Task PinnedSessionCannotBypassTrustOrSendLoginOnMismatch(string condition)
    {
        using var certificates = new Certificates(expired: condition == "expired");
        using var other = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        string pin = Convert.ToHexString(SHA256.HashData(
            condition == "wrong-pin" ? other.Leaf.RawData : certificates.Leaf.RawData));
        string name = condition == "wrong-name" ? "other.test" : "router.test";
        byte[] trust = condition == "wrong-ca" ? other.Root.RawData : certificates.Root.RawData;
        // For a valid chain with the wrong pin, TLS succeeds but absolutely no
        // application data may reach the peer. Observe this assertion strictly.
        Task serve = condition == "wrong-pin"
            ? server.RunAsync(reply: true, handler: async (tls, token) =>
                Assert.Equal(0, await tls.ReadAsync(new byte[1], token)))
            : server.RunAsync(reply: false);
        try
        {
            var error = await Assert.ThrowsAnyAsync<AuthenticationException>(() =>
                RouterOsSession.ConnectPinnedAsync("127.0.0.1", name, pin,
                    "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(),
                    server.Port, trustedRootDer: trust));
            Assert.DoesNotContain("synthetic-private-password", error.Message, StringComparison.Ordinal);
            if (condition == "wrong-pin")
                Assert.Equal("RouterOS certificate does not match the configured target.", error.Message);
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("ab")]
    [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    public async Task InvalidLeafPinCannotOpenSocket(string pin)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await Assert.ThrowsAnyAsync<ArgumentException>(() =>
            RouterOsSession.ConnectPinnedAsync("127.0.0.1", "router.test", pin,
                "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), port));
        Assert.False(listener.Pending());
    }

    [Fact]
    public async Task InvalidCertificatePreventsLoginCredentialsFromBeingSent()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        // Existing negative TLS fixture checks that no application data is sent.
        Task serve = server.RunAsync(reply: false);
        try
        {
            await Assert.ThrowsAnyAsync<AuthenticationException>(() => RouterOsSession.ConnectAsync(
                "127.0.0.1", "wrong.test", "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(),
                server.Port, trustedRootDer: certificates.Root.RawData));
        }
        finally { await serve; }
    }

    [Theory]
    [InlineData("premature-done")]
    [InlineData("duplicate-version")]
    [InlineData("trap")]
    [InlineData("fatal")]
    [InlineData("tagged")]
    [InlineData("missing-version")]
    public async Task InvalidVersionResponseClosesSession(string condition)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertVersionRequestAsync(tls, token);
            ReadOnlyMemory<byte>[] reply = condition switch
            {
                "premature-done" => ["!done"u8.ToArray()],
                "duplicate-version" => ["!re"u8.ToArray(), "=version=6.49.19"u8.ToArray(), "=version=7.21.1"u8.ToArray()],
                "trap" => ["!trap"u8.ToArray()],
                "fatal" => ["!fatal"u8.ToArray(), "=message=connection-closed"u8.ToArray()],
                "tagged" => ["!re"u8.ToArray(), "=version=6.49.19"u8.ToArray(), ".tag=unknown"u8.ToArray()],
                _ => ["!re"u8.ToArray(), "=architecture-name=arm"u8.ToArray()]
            };
            await RouterOsWireCodec.WriteSentenceAsync(tls, reply, token);
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            await Assert.ThrowsAsync<InvalidDataException>(() => session.ReadVersionAsync());
            await Assert.ThrowsAsync<ObjectDisposedException>(() => session.ReadVersionAsync());
        }
        finally { await serve; }
    }

    [Fact]
    public async Task PendingVersionCommandRejectsConcurrentCommandAndCancellationClosesSession()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var requestReceived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertVersionRequestAsync(tls, token);
            requestReceived.SetResult();
            await release.Task.WaitAsync(token);
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            using var cts = new CancellationTokenSource();
            Task<string> pending = session.ReadVersionAsync(cancellationToken: cts.Token);
            try
            {
                await requestReceived.Task.WaitAsync(TimeSpan.FromSeconds(10));
                await Assert.ThrowsAsync<InvalidOperationException>(() => session.ReadVersionAsync());
            }
            finally { cts.Cancel(); }
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
            await Assert.ThrowsAsync<ObjectDisposedException>(() => session.ReadVersionAsync());
        }
        finally
        {
            release.TrySetResult();
            await serve;
        }
    }

    [Fact]
    public async Task SilentVersionPeerTimesOutAndClosesSession()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertVersionRequestAsync(tls, token);
            await release.Task.WaitAsync(token);
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            await Assert.ThrowsAsync<TimeoutException>(() => session.ReadVersionAsync(TimeSpan.FromSeconds(2)));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => session.ReadVersionAsync());
        }
        finally
        {
            release.TrySetResult();
            await serve;
        }
    }

    [Theory]
    [InlineData("6.49.19 (long-term)", "6.49.19", "no", 1, 3)]
    [InlineData("7.21.1 (stable)", "7.21.1", "false", 2, 3)]
    [InlineData("7.21.1 (stable)", "", "true", 2, 2)]
    public async Task DiscoveryReadsVersionAndPackageEvidenceWithoutMutation(
        string version, string packageVersion, string disabled, int family, int expected)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertVersionRequestAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls,
                ["!re"u8.ToArray(), Encoding.ASCII.GetBytes("=version=" + version)], token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertPackageRequestAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls,
                ["!re"u8.ToArray(), "=name=user-manager"u8.ToArray(),
                    Encoding.ASCII.GetBytes("=version=" + packageVersion),
                    Encoding.ASCII.GetBytes("=disabled=" + disabled)], token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            var result = await session.DiscoverAsync();
            Assert.Equal((RouterOsFamily)family, result.Family);
            Assert.Equal((UserManagerPackageState)expected, result.UserManagerPackage);
            Assert.Equal("user-manager", Assert.Single(result.Packages).Name);
        }
        finally { await serve; }
    }

    [Fact]
    public async Task UnsupportedVersionDoesNotQueryPackages()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertVersionRequestAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls,
                ["!re"u8.ToArray(), "=version=8.0"u8.ToArray()], token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            byte[] buffer = new byte[1];
            Assert.Equal(0, await tls.ReadAsync(buffer, token));
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            var result = await session.DiscoverAsync();
            Assert.Equal(RouterOsFamily.Unsupported, result.Family);
            Assert.Equal(UserManagerPackageState.Unknown, result.UserManagerPackage);
        }
        finally { await serve; }
    }

    [Fact]
    public async Task RejectedPackageReadNeverReportsPackageAbsent()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertVersionRequestAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls,
                ["!re"u8.ToArray(), "=version=6.49.19"u8.ToArray()], token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertPackageRequestAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!trap"u8.ToArray(), "=category=0"u8.ToArray()], token);
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            await Assert.ThrowsAsync<InvalidDataException>(() => session.DiscoverAsync());
            await Assert.ThrowsAsync<ObjectDisposedException>(() => session.ReadVersionAsync());
        }
        finally { await serve; }
    }

    [Theory]
    [InlineData("6.49.19", 2, "/tool/user-manager/user/print", 0L)]
    [InlineData("7.21.1", 3, "/user-manager/user/print", 15000L)]
    [InlineData("6.49.19", 1, "/ip/hotspot/user/print", 24L)]
    [InlineData("7.21.1", 4, "/ppp/secret/print", 12L)]
    public async Task ServiceProbeUsesCorrectReadOnlyMenuAndCount(string version, int kind, string path, long count)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, version);
            byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
            string[] expected = kind == 4
                ? [path, "=count-only=", "?service=pppoe", "?service=any", "?#|"]
                : [path, "=count-only="];
            Assert.Equal(expected, words.Select(word => Encoding.ASCII.GetString(word)).ToArray());
            await RouterOsWireCodec.WriteSentenceAsync(tls,
                ["!done"u8.ToArray(), Encoding.ASCII.GetBytes("=ret=" + count.ToString(System.Globalization.CultureInfo.InvariantCulture))], token);
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            var result = await session.ProbeServiceAsync((BackendKind)kind);
            Assert.Equal(RouterOsServiceProbeState.Readable, result.State);
            Assert.Equal((BackendKind)kind, result.Backend);
            Assert.Equal(count, result.AccountCount);
        }
        finally { await serve; }
    }

    [Theory]
    [InlineData("6.49.19", 3)]
    [InlineData("7.21.1", 2)]
    [InlineData("8.0", 1)]
    public async Task IncompatibleServiceNeverSendsMenuCommand(string version, int kind)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, version);
            Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            var result = await session.ProbeServiceAsync((BackendKind)kind);
            Assert.Equal(RouterOsServiceProbeState.NotApplicable, result.State);
            Assert.Null(result.AccountCount);
        }
        finally { await serve; }
    }

    [Theory]
    [InlineData("!trap", 2)]
    [InlineData("!fatal", 3)]
    public async Task RejectedOrFatalServiceProbeIsNotAnEmptyAccountList(string kind, int state)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, "6.49.19");
            await RouterOsWireCodec.ReadSentenceAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls,
                [Encoding.ASCII.GetBytes(kind), "=message=synthetic-rejection"u8.ToArray()], token);
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            var result = await session.ProbeServiceAsync(BackendKind.UserManager6);
            Assert.Equal((RouterOsServiceProbeState)state, result.State);
            Assert.Null(result.AccountCount);
            await Assert.ThrowsAsync<ObjectDisposedException>(() => session.ReadVersionAsync());
        }
        finally { await serve; }
    }

    [Fact]
    public async Task MalformedCountProbeClosesSessionWithoutReturningZero()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, "7.21.1");
            await RouterOsWireCodec.ReadSentenceAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
        });
        try
        {
            using var session = await ConnectSessionAsync(server, certificates);
            await Assert.ThrowsAsync<InvalidDataException>(() => session.ProbeServiceAsync(BackendKind.UserManager7));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => session.ReadVersionAsync());
        }
        finally { await serve; }
    }

    [Fact]
    public async Task ReadRecoveryDiscardsIncompleteVersionAndUsesNewAuthenticatedSession()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = ServeRecoveryAsync();
        async Task ServeRecoveryAsync()
        {
            await server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await AssertLoginAsync(tls, token);
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                await AssertVersionRequestAsync(tls, token);
                await RouterOsWireCodec.WriteSentenceAsync(tls,
                    ["!re"u8.ToArray(), "=version=6.49.19"u8.ToArray()], token);
                // Graceful TLS shutdown before !done produces EOF at the frame reader.
                await tls.ShutdownAsync();
            });
            await server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "7.21.1");
            });
        }
        try
        {
            string version = await RouterOsReadRecovery.ReadVersionAsync("127.0.0.1", "router.test",
                "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
                trustedRootDer: certificates.Root.RawData);
            Assert.Equal("7.21.1", version);
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Fact]
    public async Task RecoveryStopsAfterSecondIncompleteRead()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = ServeTwiceAsync();
        async Task ServeTwiceAsync()
        {
            for (int i = 0; i < 2; i++)
                await server.RunAsync(reply: true, handler: async (tls, token) =>
                {
                    await AssertLoginAsync(tls, token);
                    await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                    await AssertVersionRequestAsync(tls, token);
                    await tls.ShutdownAsync();
                });
        }
        try
        {
            await Assert.ThrowsAsync<EndOfStreamException>(() =>
                RouterOsReadRecovery.ReadVersionAsync("127.0.0.1", "router.test",
                    "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
                    trustedRootDer: certificates.Root.RawData));
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Theory]
    [InlineData("login")]
    [InlineData("trap")]
    [InlineData("malformed")]
    public async Task RecoveryNeverRetriesAuthenticationOrProtocolRejection(string condition)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            if (condition == "login")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!trap"u8.ToArray()], token);
                return;
            }
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertVersionRequestAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls,
                [Encoding.ASCII.GetBytes(condition == "trap" ? "!trap" : "!unknown")], token);
        });
        try
        {
            Task<string> read = RouterOsReadRecovery.ReadVersionAsync("127.0.0.1", "router.test",
                "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
                trustedRootDer: certificates.Root.RawData);
            if (condition == "login")
                await Assert.ThrowsAsync<AuthenticationException>(() => read);
            else
                await Assert.ThrowsAsync<InvalidDataException>(() => read);
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Fact]
    public async Task RecoveryDeadlineDoesNotStartAnotherConnection()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertVersionRequestAsync(tls, token);
            await release.Task.WaitAsync(token);
        });
        try
        {
            await Assert.ThrowsAsync<TimeoutException>(() =>
                RouterOsReadRecovery.ReadVersionAsync("127.0.0.1", "router.test",
                    "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
                    timeout: TimeSpan.FromSeconds(4), trustedRootDer: certificates.Root.RawData));
        }
        finally
        {
            release.TrySetResult();
            await serve;
        }
        Assert.False(server.HasPendingConnection);
    }

    [Fact]
    public async Task PrecancelledRecoveryNeverConnects()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            RouterOsReadRecovery.ReadVersionAsync("127.0.0.1", "router.test",
                "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(),
                ((IPEndPoint)listener.LocalEndpoint).Port, cancellationToken: cts.Token));
        Assert.False(listener.Pending());
    }

    [Theory]
    [InlineData(SocketError.ConnectionReset, true)]
    [InlineData(SocketError.ConnectionAborted, true)]
    [InlineData(SocketError.NetworkReset, true)]
    [InlineData(SocketError.Shutdown, true)]
    [InlineData(SocketError.ConnectionRefused, false)]
    [InlineData(SocketError.TimedOut, false)]
    [InlineData(SocketError.AccessDenied, false)]
    public void RecoveryClassifiesOnlyExplicitTransientSocketDisconnects(SocketError code, bool expected)
    {
        var socket = new SocketException((int)code);
        Assert.Equal(expected, RouterOsReadRecovery.IsTransientReadDisconnect(socket));
        Assert.Equal(expected, RouterOsReadRecovery.IsTransientReadDisconnect(new IOException("transport", socket)));
    }

    [Fact]
    public void RecoveryDoesNotTreatGenericIoOrSecurityFailuresAsTransient()
    {
        Assert.True(RouterOsReadRecovery.IsTransientReadDisconnect(new EndOfStreamException()));
        Assert.False(RouterOsReadRecovery.IsTransientReadDisconnect(new IOException("ambiguous TLS failure")));
        Assert.False(RouterOsReadRecovery.IsTransientReadDisconnect(new AuthenticationException()));
        Assert.False(RouterOsReadRecovery.IsTransientReadDisconnect(new InvalidDataException()));
        Assert.False(RouterOsReadRecovery.IsTransientReadDisconnect(new TimeoutException()));
    }

    [Fact]
    public void AdmissionLimitsConcurrentEndpointsWithoutQueuing()
    {
        var admission = new RouterOsReadAdmission(2);
        using var first = admission.Acquire("router-a.test", 8729);
        using var second = admission.Acquire("router-b.test", 8729);
        var busy = Assert.Throws<RouterOsReadBusyException>(() => admission.Acquire("router-c.test", 8729));
        Assert.Equal(RouterOsReadBusyReason.CapacityReached, busy.Reason);
        first.Dispose();
        using var third = admission.Acquire("router-c.test", 8729);
    }

    [Theory]
    [InlineData("Router.TEST", "router.test.")]
    [InlineData("127.0.0.1", "::ffff:127.0.0.1")]
    [InlineData("2001:db8::1", "2001:0db8:0:0:0:0:0:1")]
    public void AdmissionNormalizesEquivalentEndpointSpellings(string firstHost, string secondHost)
    {
        var admission = new RouterOsReadAdmission(2);
        using var first = admission.Acquire(firstHost, 8729);
        var busy = Assert.Throws<RouterOsReadBusyException>(() => admission.Acquire(secondHost, 8729));
        Assert.Equal(RouterOsReadBusyReason.EndpointBusy, busy.Reason);
        using var differentPort = admission.Acquire(secondHost, 9872);
    }

    [Fact]
    public void DisposingOldLeaseAgainCannotReleaseNewLease()
    {
        var admission = new RouterOsReadAdmission(1);
        using var first = admission.Acquire("router.test", 8729);
        first.Dispose();
        using var second = admission.Acquire("router.test", 8729);
        first.Dispose();
        var busy = Assert.Throws<RouterOsReadBusyException>(() => admission.Acquire("router.test", 8729));
        Assert.Equal(RouterOsReadBusyReason.EndpointBusy, busy.Reason);
    }

    [Fact]
    public void PrecancelledAdmissionDoesNotConsumeCapacity()
    {
        var admission = new RouterOsReadAdmission(1);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => admission.Acquire("router.test", 8729, cancellation.Token));
        using var lease = admission.Acquire("router.test", 8729);
    }

    [Fact]
    public void ParallelAdmissionAllowsExactlyOneLeaseForEndpoint()
    {
        var admission = new RouterOsReadAdmission(8);
        var leases = new System.Collections.Concurrent.ConcurrentBag<IDisposable>();
        int rejected = 0;
        try
        {
            Parallel.For(0, 16, _ =>
            {
                try { leases.Add(admission.Acquire("router.test", 8729)); }
                catch (RouterOsReadBusyException ex) when (ex.Reason == RouterOsReadBusyReason.EndpointBusy)
                { Interlocked.Increment(ref rejected); }
            });
            Assert.Single(leases);
            Assert.Equal(15, rejected);
        }
        finally
        {
            foreach (var lease in leases) lease.Dispose();
        }
        using var next = admission.Acquire("router.test", 8729);
    }

    [Fact]
    public async Task BusyRecoveryDoesNotOpenSecondConnectionAndCancellationReleasesAdmission()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await AssertLoginAsync(tls, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            await AssertVersionRequestAsync(tls, token);
            reached.SetResult();
            await release.Task.WaitAsync(token);
        });
        Task<string> first = RouterOsReadRecovery.ReadVersionAsync("127.0.0.1", "router.test",
            "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
            trustedRootDer: certificates.Root.RawData, cancellationToken: cancellation.Token);
        try
        {
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
            // Different certificate identity/credentials must not bypass the endpoint limit.
            var busy = await Assert.ThrowsAsync<RouterOsReadBusyException>(() =>
                RouterOsReadRecovery.ReadVersionAsync("127.0.0.1", "different.test",
                    "other-user"u8.ToArray(), "other-password"u8.ToArray(), server.Port,
                    trustedRootDer: certificates.Root.RawData));
            Assert.Equal(RouterOsReadBusyReason.EndpointBusy, busy.Reason);
            Assert.False(server.HasPendingConnection);
        }
        finally
        {
            cancellation.Cancel();
            release.TrySetResult();
            try { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first); }
            finally { await serve; }
        }

        Task next = server.RunAsync(reply: true, handler: (tls, token) => PrepareProbePeerAsync(tls, token, "6.49.19"));
        try
        {
            Assert.Equal("6.49.19", await RouterOsReadRecovery.ReadVersionAsync("127.0.0.1", "router.test",
                "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
                trustedRootDer: certificates.Root.RawData));
        }
        finally { await next; }
    }

    // P15: exercise the actual recovery facade, not just individual protocol components.
    [Theory]
    [InlineData("6.49.19 (long-term)", "6.49.19", 1, 2, "/tool/user-manager/user/print")]
    [InlineData("7.21.1 (stable)", "7.21.1", 2, 3, "/user-manager/user/print")]
    public async Task CompatibilityMatrixUsesCorrectBackendAcrossCompleteAuthenticatedReads(
        string version, string packageVersion, int family, int umBackend, string umPath)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task inventoryPeer = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, version);
            await AssertPackageRequestAsync(tls, token);
            await WritePackageAsync(tls, token, "user-manager", packageVersion);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
        });
        try
        {
            var inventory = await RouterOsReadRecovery.DiscoverAsync("127.0.0.1", "router.test",
                "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
                trustedRootDer: certificates.Root.RawData);
            Assert.Equal((RouterOsFamily)family, inventory.Family);
            Assert.Equal(UserManagerPackageState.InstalledEnabled, inventory.UserManagerPackage);
            Assert.Equal(packageVersion, Assert.Single(inventory.Packages).Version);
        }
        finally { await inventoryPeer; }

        (BackendKind Kind, string[] Words, long Count)[] probes =
        [
            ((BackendKind)umBackend, [umPath, "=count-only="], 15000L),
            (BackendKind.Hotspot, ["/ip/hotspot/user/print", "=count-only="], 0L),
            (BackendKind.Pppoe, ["/ppp/secret/print", "=count-only=", "?service=pppoe", "?service=any", "?#|"], 100000L)
        ];
        foreach (var probe in probes)
        {
            Task peer = server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, version);
                byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                Assert.Equal(probe.Words, words.Select(word => Encoding.ASCII.GetString(word)).ToArray());
                if (family == 2 && probe.Count == 0)
                    await RouterOsWireCodec.WriteSentenceAsync(tls, ["!empty"u8.ToArray()], token);
                await RouterOsWireCodec.WriteSentenceAsync(tls,
                    ["!done"u8.ToArray(), Encoding.ASCII.GetBytes("=ret=" +
                        probe.Count.ToString(System.Globalization.CultureInfo.InvariantCulture))], token);
            });
            try
            {
                var result = await RouterOsReadRecovery.ProbeServiceAsync(probe.Kind, "127.0.0.1", "router.test",
                    "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
                    trustedRootDer: certificates.Root.RawData);
                Assert.Equal((RouterOsFamily)family, result.Family);
                Assert.Equal(probe.Kind, result.Backend);
                Assert.Equal(RouterOsServiceProbeState.Readable, result.State);
                Assert.Equal(probe.Count, result.AccountCount);
            }
            finally { await peer; }
        }
        Assert.False(server.HasPendingConnection);
    }

    [Fact]
    public async Task DiscoveryRecoveryNeverCombinesPackagesFromDifferentConnections()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = ServeAsync();
        async Task ServeAsync()
        {
            await server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "6.49.19");
                await AssertPackageRequestAsync(tls, token);
                await WritePackageAsync(tls, token, "user-manager", "6.49.19");
                await tls.ShutdownAsync();
            });
            await server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "7.21.1");
                await AssertPackageRequestAsync(tls, token);
                await WritePackageAsync(tls, token, "routeros", "7.21.1");
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            });
        }
        try
        {
            var inventory = await RouterOsReadRecovery.DiscoverAsync("127.0.0.1", "router.test",
                "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
                trustedRootDer: certificates.Root.RawData);
            Assert.Equal("7.21.1", inventory.Version);
            Assert.Equal(RouterOsFamily.V7, inventory.Family);
            Assert.Equal(UserManagerPackageState.NotListed, inventory.UserManagerPackage);
            Assert.Equal("routeros", Assert.Single(inventory.Packages).Name);
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Fact]
    public async Task ServiceRecoveryRechecksFamilyBeforeSendingBackendCommand()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = ServeAsync();
        async Task ServeAsync()
        {
            await server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "6.49.19");
                byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                Assert.Equal(new[] { "/tool/user-manager/user/print", "=count-only=" },
                    words.Select(word => Encoding.ASCII.GetString(word)).ToArray());
                await tls.ShutdownAsync();
            });
            await server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "7.21.1");
                Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
            });
        }
        try
        {
            var result = await RouterOsReadRecovery.ProbeServiceAsync(BackendKind.UserManager6,
                "127.0.0.1", "router.test", "synthetic-user"u8.ToArray(),
                "synthetic-private-password"u8.ToArray(), server.Port, trustedRootDer: certificates.Root.RawData);
            Assert.Equal(RouterOsFamily.V7, result.Family);
            Assert.Equal(RouterOsServiceProbeState.NotApplicable, result.State);
            Assert.Null(result.AccountCount);
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Theory]
    [InlineData("!trap", 2)]
    [InlineData("!fatal", 3)]
    public async Task RecoveryFacadeDoesNotReplayExplicitServiceFailure(string replyKind, int state)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, "7.21.1");
            byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
            Assert.Equal(new[] { "/user-manager/user/print", "=count-only=" },
                words.Select(word => Encoding.ASCII.GetString(word)).ToArray());
            await RouterOsWireCodec.WriteSentenceAsync(tls,
                [Encoding.ASCII.GetBytes(replyKind), "=message=synthetic-rejection"u8.ToArray()], token);
        });
        try
        {
            var result = await RouterOsReadRecovery.ProbeServiceAsync(BackendKind.UserManager7,
                "127.0.0.1", "router.test", "synthetic-user"u8.ToArray(),
                "synthetic-private-password"u8.ToArray(), server.Port, trustedRootDer: certificates.Root.RawData);
            Assert.Equal((RouterOsServiceProbeState)state, result.State);
            Assert.Null(result.AccountCount);
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    private static ValueTask WritePackageAsync(SslStream tls, CancellationToken token, string name, string version) =>
        RouterOsWireCodec.WriteSentenceAsync(tls,
            ["!re"u8.ToArray(), Encoding.ASCII.GetBytes("=name=" + name),
                Encoding.ASCII.GetBytes("=version=" + version), "=disabled=false"u8.ToArray()], token);

    [Theory]
    [InlineData("yes", "", true)]
    [InlineData("no", "باقة=يوم", false)]
    [InlineData("", null, null)]
    public async Task UserManager6ReadsExactAccountWithoutInferringExpiry(string disabled, string? profile, bool? expected)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, "6.49.19");
            await AssertUm6AccountRequestAsync(tls, token);
            var reply = new List<ReadOnlyMemory<byte>>
            {
                "!re"u8.ToArray(), "=customer=admin"u8.ToArray(), "=username=123456"u8.ToArray(),
                Encoding.UTF8.GetBytes("=disabled=" + disabled)
            };
            if (profile is not null) reply.Add(Encoding.UTF8.GetBytes("=actual-profile=" + profile));
            reply.Add("=download-used=4294967296"u8.ToArray());
            reply.Add("=upload-used=128B"u8.ToArray());
            reply.Add("=uptime-used=1d2h"u8.ToArray());
            reply.Add("=active=yes"u8.ToArray());
            reply.Add("=incomplete=no"u8.ToArray());
            reply.Add("=last-seen=nov/26/2026 18:00:00"u8.ToArray());
            reply.Add("=active-sessions=*1,*2"u8.ToArray());
            await RouterOsWireCodec.WriteSentenceAsync(tls, reply, token);
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
        });
        try
        {
            var account = await FindUm6AccountAsync(server, certificates);
            Assert.NotNull(account);
            Assert.Equal("admin", account.Customer);
            Assert.Equal("123456", account.Username);
            Assert.Equal(expected, account.Disabled);
            Assert.Equal(profile, account.ActualProfile);
            Assert.Equal(4294967296UL, account.Usage.DownloadUsed.Bytes);
            Assert.Equal(128UL, account.Usage.UploadUsed.Bytes);
            Assert.Equal(4294967424UL, account.Usage.ObservedTransferBytes);
            Assert.Equal("1d2h", account.Usage.UptimeUsed);
            Assert.Equal(93600UL, account.Usage.ObservedUptimeSeconds);
            Assert.Equal(profile switch
            {
                null => UserManager6ProfileObservation.Unknown,
                "" => UserManager6ProfileObservation.EmptyNameReported,
                _ => UserManager6ProfileObservation.NameReported
            }, account.ProfileObservation);
            Assert.Equal("yes", account.Activity.Active);
            Assert.Equal("no", account.Activity.Incomplete);
            Assert.Equal("nov/26/2026 18:00:00", account.Activity.LastSeen);
            Assert.Equal("*1,*2", account.Activity.ActiveSessions);
            Assert.Equal(UserManager6LastSeenObservation.OtherValueReported, account.Activity.LastSeenObservation);
        }
        finally { await serve; }
    }

    [Theory]
    [InlineData("absent")]
    [InlineData("wrong-customer")]
    [InlineData("wrong-user")]
    [InlineData("duplicate")]
    [InlineData("legacy-name-only")]
    [InlineData("trap")]
    public async Task UserManager6AccountLookupDistinguishesAbsenceFromInvalidOrRejectedRead(string condition)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, "6.49.19");
            await AssertUm6AccountRequestAsync(tls, token);
            if (condition == "trap")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!trap"u8.ToArray()], token);
                return;
            }
            if (condition != "absent")
            {
                ReadOnlyMemory<byte>[] row =
                [
                    "!re"u8.ToArray(),
                    Encoding.ASCII.GetBytes(condition == "wrong-customer" ? "=customer=other" : "=customer=admin"),
                    Encoding.ASCII.GetBytes(condition == "legacy-name-only" ? "=name=123456" :
                        condition == "wrong-user" ? "=username=123457" : "=username=123456")
                ];
                await RouterOsWireCodec.WriteSentenceAsync(tls, row, token);
                if (condition == "duplicate")
                    await RouterOsWireCodec.WriteSentenceAsync(tls, row, token);
                // Invalid rows are rejected immediately; do not race a closed client by writing again.
                return;
            }
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
        });
        try
        {
            if (condition == "absent") Assert.Null(await FindUm6AccountAsync(server, certificates));
            else await Assert.ThrowsAsync<InvalidDataException>(() => FindUm6AccountAsync(server, certificates));
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UserManager6ProfileLookupVerifiesOwnerAndPreservesRawValidity(bool wrongOwner)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, "6.49.19");
            byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
            Assert.Equal(new[] { "/tool/user-manager/profile/print", "=.proplist=owner,name,validity,starts-at",
                "?owner=admin", "?name=باقة=يوم" }, words.Select(word => Encoding.UTF8.GetString(word)).ToArray());
            await RouterOsWireCodec.WriteSentenceAsync(tls,
                ["!re"u8.ToArray(), Encoding.ASCII.GetBytes(wrongOwner ? "=owner=other" : "=owner=admin"),
                    Encoding.UTF8.GetBytes("=name=باقة=يوم"), "=validity=0s"u8.ToArray(), "=starts-at=logon"u8.ToArray()], token);
            if (!wrongOwner) await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
        });
        Task<UserManager6Profile?> Find() => RouterOsReadRecovery.FindUserManager6ProfileAsync("admin", "باقة=يوم",
            "127.0.0.1", "router.test", "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(),
            server.Port, trustedRootDer: certificates.Root.RawData);
        try
        {
            if (wrongOwner) await Assert.ThrowsAsync<InvalidDataException>(Find);
            else
            {
                var profile = await Find();
                Assert.NotNull(profile);
                Assert.Equal("admin", profile.Owner);
                Assert.Equal("باقة=يوم", profile.Name);
                Assert.Equal("0s", profile.Validity);
                Assert.Equal("logon", profile.StartsAt);
            }
        }
        finally { await serve; }
    }

    [Theory]
    [InlineData("present")]
    [InlineData("disabled")]
    [InlineData("missing-flag")]
    [InlineData("absent")]
    [InlineData("wrong-name")]
    [InlineData("legacy-username")]
    [InlineData("wrong-id")]
    [InlineData("duplicate")]
    [InlineData("duplicate-field")]
    [InlineData("invalid-flag")]
    [InlineData("trap")]
    [InlineData("v6")]
    public async Task UserManager7AccountLookupUsesOnlyVersionCorrectBoundedProjection(string condition)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, condition == "v6" ? "6.49.19" : "7.21.1");
            if (condition == "v6")
            {
                Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
                return;
            }
            byte[][] request = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
            Assert.Equal(new[] { "/user-manager/user/print",
                "=.proplist=.id,name,disabled,group,shared-users", "?name=كرت=001" },
                request.Select(word => Encoding.UTF8.GetString(word)).ToArray());
            if (condition == "trap")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!trap"u8.ToArray()], token);
                return;
            }
            if (condition != "absent")
            {
                var row = new List<ReadOnlyMemory<byte>>
                {
                    "!re"u8.ToArray(), Encoding.ASCII.GetBytes(condition == "wrong-id" ? "=.id=1" : "=.id=*1"),
                    Encoding.UTF8.GetBytes(condition switch
                    {
                        "wrong-name" => "=name=other",
                        "legacy-username" => "=username=كرت=001",
                        _ => "=name=كرت=001"
                    }),
                    "=group=default"u8.ToArray(), "=shared-users=unlimited"u8.ToArray()
                };
                if (condition != "missing-flag")
                    row.Add(Encoding.ASCII.GetBytes("=disabled=" + (condition switch
                    {
                        "disabled" => "yes", "invalid-flag" => "maybe", _ => "no"
                    })));
                if (condition == "duplicate-field") row.Add("=disabled=yes"u8.ToArray());
                await RouterOsWireCodec.WriteSentenceAsync(tls, row.ToArray(), token);
                if (condition == "duplicate")
                    await RouterOsWireCodec.WriteSentenceAsync(tls, row.ToArray(), token);
                if (condition is "wrong-name" or "legacy-username" or "wrong-id" or "duplicate" or "duplicate-field" or "invalid-flag")
                    return;
            }
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
        });
        Task<UserManager7Account?> Find() => RouterOsReadRecovery.FindUserManager7AccountAsync("كرت=001",
            "127.0.0.1", "router.test", "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(),
            server.Port, trustedRootDer: certificates.Root.RawData);
        try
        {
            if (condition == "v6") await Assert.ThrowsAsync<NotSupportedException>(Find);
            else if (condition is "present" or "disabled" or "missing-flag")
            {
                var account = await Find();
                Assert.NotNull(account);
                Assert.Equal("*1", account.RemoteId);
                Assert.Equal("كرت=001", account.Username);
                Assert.Equal(condition == "missing-flag" ? (bool?)null : condition == "disabled", account.Disabled);
                Assert.Equal("default", account.Group);
                Assert.Equal("unlimited", account.SharedUsersRaw);
            }
            else if (condition == "absent") Assert.Null(await Find());
            else await Assert.ThrowsAsync<InvalidDataException>(Find);
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Fact]
    public async Task UserManager6LookupNeverSendsLegacyMenuToV7()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, "7.21.1");
            Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
        });
        try { await Assert.ThrowsAsync<NotSupportedException>(() => FindUm6AccountAsync(server, certificates)); }
        finally { await serve; }
    }

    [Theory]
    [InlineData("present")]
    [InlineData("absent")]
    [InlineData("wrong-owner")]
    [InlineData("trap")]
    public async Task Um6LimitationReadKeepsScopeAndZeroDistinctFromMissing(string condition)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, "6.49.19");
            byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
            Assert.Equal(new[] { "/tool/user-manager/profile/limitation/print",
                "=.proplist=owner,name,download-limit,upload-limit,transfer-limit,uptime-limit,rate-limit-rx,rate-limit-tx",
                "?owner=admin", "?name=day" }, words.Select(word => Encoding.UTF8.GetString(word)).ToArray());
            if (condition == "trap")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!trap"u8.ToArray()], token);
                return;
            }
            if (condition != "absent")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls,
                    ["!re"u8.ToArray(), Encoding.ASCII.GetBytes(condition == "wrong-owner" ? "=owner=other" : "=owner=admin"),
                        "=name=day"u8.ToArray(), "=download-limit=0B"u8.ToArray(), "=transfer-limit=5368709120B"u8.ToArray(),
                        "=uptime-limit=2h"u8.ToArray(), "=rate-limit-rx=512k"u8.ToArray()], token);
                if (condition == "wrong-owner") return;
            }
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
        });
        Task<UserManager6Limitation?> Find() => RouterOsReadRecovery.FindUserManager6LimitationAsync("admin", "day",
            "127.0.0.1", "router.test", "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(),
            server.Port, trustedRootDer: certificates.Root.RawData);
        try
        {
            if (condition == "wrong-owner" || condition == "trap")
                await Assert.ThrowsAsync<InvalidDataException>(Find);
            else if (condition == "absent") Assert.Null(await Find());
            else
            {
                var limit = await Find();
                Assert.NotNull(limit);
                Assert.Equal("admin", limit.Owner);
                Assert.Equal("day", limit.Name);
                Assert.Equal(0UL, limit.DownloadLimit.Bytes);
                Assert.Null(limit.UploadLimit.Bytes);
                Assert.Null(limit.UploadLimit.Raw);
                Assert.Equal(5368709120UL, limit.TransferLimit.Bytes);
                Assert.Equal("2h", limit.UptimeLimit);
                Assert.Equal("512k", limit.RateLimitRx);
                Assert.Null(limit.RateLimitTx);
            }
        }
        finally { await serve; }
    }

    [Theory]
    [InlineData("multiple")]
    [InlineData("empty")]
    [InlineData("absent-profile")]
    [InlineData("wrong-owner")]
    [InlineData("duplicate-profile")]
    [InlineData("wrong-link")]
    [InlineData("missing-limitation")]
    [InlineData("rejected")]
    public async Task Um6ProfileMappingRequiresCompleteUniqueProfileAndMatchingLinks(string condition)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
        {
            await PrepareProbePeerAsync(tls, token, "6.49.19");
            byte[][] profileRequest = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
            Assert.Equal(new[] { "/tool/user-manager/profile/print",
                "=.proplist=owner,name,validity,starts-at", "?name=day" },
                profileRequest.Select(word => Encoding.UTF8.GetString(word)).ToArray());
            if (condition == "absent-profile")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
                return;
            }
            ReadOnlyMemory<byte>[] row = ["!re"u8.ToArray(),
                Encoding.ASCII.GetBytes(condition == "wrong-owner" ? "=owner=other" : "=owner=admin"),
                "=name=day"u8.ToArray(), "=validity=1d"u8.ToArray()];
            await RouterOsWireCodec.WriteSentenceAsync(tls, row, token);
            if (condition == "wrong-owner") return;
            if (condition == "duplicate-profile")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls,
                    ["!re"u8.ToArray(), "=owner=other"u8.ToArray(), "=name=day"u8.ToArray()], token);
                return;
            }
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            byte[][] linkRequest = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
            Assert.Equal(new[] { "/tool/user-manager/profile/profile-limitation/print",
                "=.proplist=profile,limitation,from-time,till-time,weekdays", "?profile=day" },
                linkRequest.Select(word => Encoding.UTF8.GetString(word)).ToArray());
            if (condition == "rejected")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!trap"u8.ToArray()], token);
                return;
            }
            if (condition == "wrong-link")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls,
                    ["!re"u8.ToArray(), "=profile=other"u8.ToArray(), "=limitation=quota"u8.ToArray()], token);
                return;
            }
            if (condition == "missing-limitation")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls,
                    ["!re"u8.ToArray(), "=profile=day"u8.ToArray()], token);
                return;
            }
            if (condition == "multiple")
            {
                await RouterOsWireCodec.WriteSentenceAsync(tls,
                    ["!re"u8.ToArray(), "=profile=day"u8.ToArray(), "=limitation=quota"u8.ToArray(),
                        "=from-time=0s"u8.ToArray(), "=till-time=23h59m59s"u8.ToArray(),
                        "=weekdays=sunday,monday"u8.ToArray()], token);
                await RouterOsWireCodec.WriteSentenceAsync(tls,
                    ["!re"u8.ToArray(), "=profile=day"u8.ToArray(), "=limitation=quota"u8.ToArray(),
                        "=from-time=12h"u8.ToArray(), "=weekdays=friday"u8.ToArray()], token);
                await RouterOsWireCodec.WriteSentenceAsync(tls,
                    ["!re"u8.ToArray(), "=profile=day"u8.ToArray(), "=limitation=speed"u8.ToArray()], token);
            }
            await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
        });
        Task<UserManager6ProfileMappingEvidence?> Find() =>
            RouterOsReadRecovery.ReadUserManager6ProfileMappingAsync("admin", "day",
                "127.0.0.1", "router.test", "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(),
                server.Port, trustedRootDer: certificates.Root.RawData);
        try
        {
            if (condition is "wrong-owner" or "duplicate-profile" or "wrong-link" or "missing-limitation" or "rejected")
                await Assert.ThrowsAsync<InvalidDataException>(Find);
            else if (condition == "absent-profile")
                Assert.Null(await Find());
            else
            {
                var evidence = await Find();
                Assert.NotNull(evidence);
                Assert.Equal("admin", evidence.Profile.Owner);
                Assert.Equal("day", evidence.Profile.Name);
                if (condition == "empty") Assert.Empty(evidence.VisibleNameMatches);
                else Assert.Collection(evidence.VisibleNameMatches,
                    link =>
                    {
                        Assert.Equal("quota", link.Limitation);
                        Assert.Equal("0s", link.FromTime);
                        Assert.Equal("23h59m59s", link.TillTime);
                        Assert.Equal("sunday,monday", link.Weekdays);
                    },
                    link =>
                    {
                        Assert.Equal("quota", link.Limitation);
                        Assert.Equal("12h", link.FromTime);
                        Assert.Null(link.TillTime);
                        Assert.Equal("friday", link.Weekdays);
                    },
                    link =>
                    {
                        Assert.Equal("speed", link.Limitation);
                        Assert.Null(link.Weekdays);
                    });
            }
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Fact]
    public async Task Um6MappingRetryDoesNotMergeOldPartialLinksWithNewRows()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        Task serve = ServeAsync();
        async Task ServeAsync()
        {
            for (int i = 0; i < 2; i++)
            {
                bool first = i == 0;
                await server.RunAsync(reply: true, handler: async (tls, token) =>
                {
                    await PrepareProbePeerAsync(tls, token, "6.49.19");
                    byte[][] profile = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                    Assert.Equal(new[] { "/tool/user-manager/profile/print",
                        "=.proplist=owner,name,validity,starts-at", "?name=day" },
                        profile.Select(word => Encoding.UTF8.GetString(word)).ToArray());
                    await RouterOsWireCodec.WriteSentenceAsync(tls,
                        ["!re"u8.ToArray(), "=owner=admin"u8.ToArray(), "=name=day"u8.ToArray()], token);
                    await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                    byte[][] links = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                    Assert.Equal(new[] { "/tool/user-manager/profile/profile-limitation/print",
                        "=.proplist=profile,limitation,from-time,till-time,weekdays", "?profile=day" },
                        links.Select(word => Encoding.UTF8.GetString(word)).ToArray());
                    await RouterOsWireCodec.WriteSentenceAsync(tls,
                        ["!re"u8.ToArray(), "=profile=day"u8.ToArray(),
                            Encoding.ASCII.GetBytes(first ? "=limitation=old" : "=limitation=new")], token);
                    if (first) await tls.ShutdownAsync();
                    else await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                });
            }
        }
        try
        {
            var evidence = await RouterOsReadRecovery.ReadUserManager6ProfileMappingAsync("admin", "day",
                "127.0.0.1", "router.test", "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(),
                server.Port, trustedRootDer: certificates.Root.RawData);
            Assert.NotNull(evidence);
            Assert.Equal("new", Assert.Single(evidence.VisibleNameMatches).Limitation);
        }
        finally { await serve; }
        Assert.False(server.HasPendingConnection);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task BoundAccountReadUsesStoredTargetAndCredentials()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var directory = Directory.CreateTempSubdirectory("hadramout-bound-test-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = SeedBoundRouter(path);
            EnrollBoundRouter(path, id, server.Port, certificates);
            new RouterCredentialStore(path).Save(id, "synthetic-user"u8, "synthetic-private-password"u8);
            Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "6.49.19");
                await AssertUm6AccountRequestAsync(tls, token);
                await RouterOsWireCodec.WriteSentenceAsync(tls,
                    ["!re"u8.ToArray(), "=customer=admin"u8.ToArray(), "=username=123456"u8.ToArray()], token);
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
            });
            try
            {
                var account = await RouterOsReadRecovery.FindBoundUserManager6AccountAsync(path, id, "admin", "123456");
                Assert.NotNull(account);
                Assert.Equal("123456", account.Username);
                Assert.Equal("admin", account.Customer);
            }
            finally { await serve; }
            Assert.False(server.HasPendingConnection);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task BoundReadRetainsPinAndCredentialsAcrossOneReadReconnect()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var directory = Directory.CreateTempSubdirectory("hadramout-bound-retry-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = SeedBoundRouter(path);
            EnrollBoundRouter(path, id, server.Port, certificates);
            new RouterCredentialStore(path).Save(id, "synthetic-user"u8, "synthetic-private-password"u8);
            Task serve = ServeAsync();
            async Task ServeAsync()
            {
                for (int i = 0; i < 2; i++)
                {
                    bool first = i == 0;
                    await server.RunAsync(reply: true, handler: async (tls, token) =>
                    {
                        await AssertLoginAsync(tls, token);
                        await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                        await AssertVersionRequestAsync(tls, token);
                        await RouterOsWireCodec.WriteSentenceAsync(tls,
                            ["!re"u8.ToArray(), Encoding.ASCII.GetBytes(first ? "=version=6.49.19" : "=version=6.49.18")], token);
                        if (first) await tls.ShutdownAsync();
                        else await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                    });
                }
            }
            try { Assert.Equal("6.49.18", await RouterOsReadRecovery.ReadBoundVersionAsync(path, id)); }
            finally { await serve; }
            Assert.False(server.HasPendingConnection);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task BoundReadRejectsWrongPinBeforeSendingStoredCredentials()
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var directory = Directory.CreateTempSubdirectory("hadramout-bound-pin-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = SeedBoundRouter(path);
            new RouterTargetStore(path).Enroll(id, "127.0.0.1", server.Port, "router.test",
                new string('0', 64), certificates.Root.RawData);
            new RouterCredentialStore(path).Save(id, "synthetic-user"u8, "synthetic-private-password"u8);
            Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
                Assert.Equal(0, await tls.ReadAsync(new byte[1], token)));
            try
            {
                await Assert.ThrowsAsync<AuthenticationException>(() =>
                    RouterOsReadRecovery.ReadBoundVersionAsync(path, id));
            }
            finally { await serve; }
            Assert.False(server.HasPendingConnection);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("no-target")]
    [InlineData("no-credentials")]
    [InlineData("corrupt")]
    [InlineData("cancelled")]
    [SupportedOSPlatform("windows")]
    public async Task BoundReadFailsLocallyWithoutOpeningSocket(string condition)
    {
        using var certificates = new Certificates();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var directory = Directory.CreateTempSubdirectory("hadramout-bound-local-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = SeedBoundRouter(path);
            if (condition != "no-target") EnrollBoundRouter(path, id, port, certificates);
            if (condition != "no-credentials")
                new RouterCredentialStore(path).Save(id, "synthetic-user"u8, "synthetic-private-password"u8);
            if (condition == "corrupt")
            {
                using var db = DatabaseStore.OpenExisting(path);
                using var cmd = db.CreateCommand();
                cmd.CommandText = "UPDATE router_credentials SET PasswordEnvelope=X'01';";
                cmd.ExecuteNonQuery();
            }
            using var cancellation = new CancellationTokenSource();
            if (condition == "cancelled") cancellation.Cancel();
            Task<string> Read() => RouterOsReadRecovery.ReadBoundVersionAsync(path, id,
                cancellationToken: cancellation.Token);
            if (condition == "cancelled") await Assert.ThrowsAnyAsync<OperationCanceledException>(Read);
            else if (condition == "corrupt") await Assert.ThrowsAsync<CryptographicException>(Read);
            else await Assert.ThrowsAsync<InvalidOperationException>(Read);
            Assert.False(listener.Pending());
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("clear")]
    [InlineData("existing")]
    [InlineData("other-customer")]
    [InlineData("missing-profile")]
    [InlineData("wrong-owner")]
    [InlineData("duplicate-profile")]
    [InlineData("account-trap")]
    [InlineData("wrong-username")]
    [InlineData("duplicate-account")]
    [SupportedOSPlatform("windows")]
    public async Task PreparedCreationPreflightUsesOnlyScopedReadsAndNeverClaims(string condition)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var directory = Directory.CreateTempSubdirectory("hadramout-preflight-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = PreparePreflightFixture(path, server.Port, certificates, true);
            Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "6.49.19");
                byte[][] request = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                Assert.Equal(new[] { "/tool/user-manager/profile/print", "=.proplist=owner,name,validity,starts-at",
                    "?name=remote-day" }, request.Select(word => Encoding.UTF8.GetString(word)).ToArray());
                if (condition == "missing-profile")
                {
                    await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                    return;
                }
                ReadOnlyMemory<byte>[] profile = ["!re"u8.ToArray(),
                    condition == "wrong-owner" ? "=owner=other"u8.ToArray() : "=owner=owner"u8.ToArray(),
                    "=name=remote-day"u8.ToArray()];
                await RouterOsWireCodec.WriteSentenceAsync(tls, profile, token);
                if (condition == "wrong-owner") return;
                if (condition == "duplicate-profile")
                {
                    await RouterOsWireCodec.WriteSentenceAsync(tls, profile, token);
                    return;
                }
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                request = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                Assert.Equal(new[] { "/tool/user-manager/user/print", "=.proplist=customer,username", "?username=001" },
                    request.Select(word => Encoding.UTF8.GetString(word)).ToArray());
                if (condition == "account-trap")
                {
                    await RouterOsWireCodec.WriteSentenceAsync(tls, ["!trap"u8.ToArray()], token);
                    return;
                }
                if (condition != "clear")
                {
                    ReadOnlyMemory<byte>[] row = ["!re"u8.ToArray(),
                        condition == "other-customer" ? "=customer=other"u8.ToArray() : "=customer=admin"u8.ToArray(),
                        condition == "wrong-username" ? "=username=002"u8.ToArray() : "=username=001"u8.ToArray()];
                    await RouterOsWireCodec.WriteSentenceAsync(tls, row, token);
                    if (condition == "wrong-username") return;
                    if (condition == "duplicate-account")
                    {
                        await RouterOsWireCodec.WriteSentenceAsync(tls, row, token);
                        return;
                    }
                }
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
            });
            try
            {
                if (condition is "wrong-owner" or "duplicate-profile" or "account-trap" or "wrong-username" or "duplicate-account")
                    await Assert.ThrowsAsync<InvalidDataException>(() => RouterOsReadRecovery.ReadPreparedUm6PreflightAsync(path, id));
                else
                {
                    var evidence = await RouterOsReadRecovery.ReadPreparedUm6PreflightAsync(path, id);
                    Assert.Equal(condition switch
                    {
                        "clear" => UserManager6PreflightState.NoVisibleUsernameMatch,
                        "missing-profile" => UserManager6PreflightState.ProfileNotVisible,
                        _ => UserManager6PreflightState.UsernameAlreadyVisible
                    }, evidence.State);
                    Assert.Equal(condition switch { "existing" => "admin", "other-customer" => "other", _ => null },
                        evidence.ExistingCustomer);
                }
                Assert.Equal(UserManager6CreateState.Prepared, new UserManager6CreateJournal(path).Read(id)!.State);
            }
            finally { await serve; }
            Assert.False(server.HasPendingConnection);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("missing-secret")]
    [InlineData("changed-plan")]
    [InlineData("already-claimed")]
    [SupportedOSPlatform("windows")]
    public async Task PreparedPreflightRejectsLocalFailureBeforeConnecting(string condition)
    {
        using var certificates = new Certificates();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var directory = Directory.CreateTempSubdirectory("hadramout-preflight-local-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = PreparePreflightFixture(path, port, certificates, condition != "missing-secret");
            var journal = new UserManager6CreateJournal(path);
            if (condition == "already-claimed") Assert.True(journal.TryBeginBoundDispatch(id));
            if (condition == "changed-plan")
            {
                using var db = DatabaseStore.OpenExisting(path);
                using var cmd = db.CreateCommand();
                cmd.CommandText = "UPDATE plans SET Name='changed';";
                cmd.ExecuteNonQuery();
            }
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await RouterOsReadRecovery.ReadPreparedUm6PreflightAsync(path, id));
            Assert.False(listener.Pending());
            Assert.Equal(condition == "already-claimed" ? UserManager6CreateState.DispatchStarted :
                UserManager6CreateState.Prepared, journal.Read(id)!.State);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("started")]
    [InlineData("indeterminate")]
    [InlineData("legacy-ack")]
    [InlineData("ack")]
    [InlineData("bare-observed")]
    [InlineData("absent")]
    [InlineData("mismatch")]
    [InlineData("wrong-marker")]
    [InlineData("enabled")]
    [InlineData("local-change")]
    [SupportedOSPlatform("windows")]
    public async Task BoundCreationRecoveryReadsExactDisabledIdentityWithoutChangingJournal(string condition)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var directory = Directory.CreateTempSubdirectory("hadramout-recovery-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = PreparePreflightFixture(path, server.Port, certificates, true);
            var journal = new UserManager6CreateJournal(path);
            Assert.True(journal.TryBeginBoundDispatch(id));
            if (condition == "indeterminate") Assert.True(journal.TryMarkIndeterminate(id));
            else if (condition == "legacy-ack") Assert.True(journal.TryMarkAcknowledged(id));
            else if (condition != "started")
            {
                Assert.True(journal.TryRecordAcknowledgement(id, new(UserManager6CreateWireOutcome.Acknowledged,
                    condition == "bare-observed" ? null : "*1")));
                if (condition == "bare-observed") journal.RecordDisabledObservation(id, new("*1", false));
            }
            var prior = journal.ReadBoundRecoveryScope(id);
            Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "6.49.19");
                byte[][] request = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                Assert.Equal(new[] { "/tool/user-manager/user/print",
                    "=.proplist=.id,customer,username,disabled,comment", "?username=001" },
                    request.Select(word => Encoding.UTF8.GetString(word)).ToArray());
                if (condition != "absent")
                {
                    ReadOnlyMemory<byte>[] row = ["!re"u8.ToArray(),
                        condition == "mismatch" ? "=.id=*2"u8.ToArray() : "=.id=*1"u8.ToArray(),
                        "=customer=admin"u8.ToArray(), "=username=001"u8.ToArray(),
                        condition == "enabled" ? "=disabled=no"u8.ToArray() : "=disabled=yes"u8.ToArray(),
                        Encoding.UTF8.GetBytes("=comment=" + (condition == "wrong-marker" ? "different" : "hmk-create:" + id.ToString("N")))];
                    await RouterOsWireCodec.WriteSentenceAsync(tls, row, token);
                    if (condition is "mismatch" or "wrong-marker" or "enabled") return;
                }
                if (condition == "local-change") journal.RecordDisabledObservation(id, new("*1", true));
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
            });
            try
            {
                if (condition is "mismatch" or "wrong-marker" or "enabled")
                    await Assert.ThrowsAsync<InvalidDataException>(() => RouterOsReadRecovery.ReadBoundUm6RecoveryAsync(path, id));
                else if (condition == "local-change")
                    await Assert.ThrowsAsync<InvalidOperationException>(() => RouterOsReadRecovery.ReadBoundUm6RecoveryAsync(path, id));
                else
                {
                    var result = await RouterOsReadRecovery.ReadBoundUm6RecoveryAsync(path, id);
                    Assert.Equal(prior, result.Scope);
                    if (condition == "absent") Assert.Null(result.VisibleDisabledAccount);
                    else
                    {
                        Assert.NotNull(result.VisibleDisabledAccount);
                        Assert.Equal("*1", result.VisibleDisabledAccount.RemoteId);
                        Assert.Equal(prior.ExpectedRemoteId is not null, result.VisibleDisabledAccount.ReturnedIdMatched);
                    }
                }
                if (condition != "local-change") Assert.Equal(prior, journal.ReadBoundRecoveryScope(id));
                Assert.Equal(prior.State, journal.Read(id)!.State);
                Assert.False(journal.TryBeginBoundDispatch(id));
            }
            finally { await serve; }
            Assert.False(server.HasPendingConnection);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("prepared")]
    [InlineData("changed-plan")]
    [InlineData("unbound")]
    [SupportedOSPlatform("windows")]
    public async Task BoundCreationRecoveryRejectsIneligibleLocalScopeBeforeConnecting(string condition)
    {
        using var certificates = new Certificates();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var directory = Directory.CreateTempSubdirectory("hadramout-recovery-local-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            var journal = new UserManager6CreateJournal(path);
            Guid id;
            if (condition == "unbound")
            {
                id = DatabaseDurabilityTests.SeedReservation(path, BackendKind.UserManager6);
                journal.Prepare(id, "admin");
                Assert.True(journal.TryBeginDispatch(id));
            }
            else
            {
                id = PreparePreflightFixture(path, port, certificates, true);
                if (condition == "changed-plan")
                {
                    Assert.True(journal.TryBeginBoundDispatch(id));
                    using var db = DatabaseStore.OpenExisting(path);
                    using var cmd = db.CreateCommand();
                    cmd.CommandText = "UPDATE plans SET Name='changed';";
                    cmd.ExecuteNonQuery();
                }
            }
            var prior = journal.Read(id);
            await Assert.ThrowsAsync<InvalidOperationException>(() => RouterOsReadRecovery.ReadBoundUm6RecoveryAsync(path, id));
            Assert.False(listener.Pending());
            Assert.Equal(prior, journal.Read(id));
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [SupportedOSPlatform("windows")]
    public async Task BoundRecoveryPersistsOnlyPositiveExactEvidence(bool visible)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var directory = Directory.CreateTempSubdirectory("hadramout-recovery-store-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = PreparePreflightFixture(path, server.Port, certificates, true);
            var journal = new UserManager6CreateJournal(path);
            Assert.True(journal.TryBeginBoundDispatch(id));
            Assert.True(journal.TryMarkIndeterminate(id));
            Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "6.49.19");
                byte[][] request = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                Assert.Equal(new[] { "/tool/user-manager/user/print",
                    "=.proplist=.id,customer,username,disabled,comment", "?username=001" },
                    request.Select(word => Encoding.UTF8.GetString(word)).ToArray());
                if (visible)
                    await RouterOsWireCodec.WriteSentenceAsync(tls, ["!re"u8.ToArray(), "=.id=*1"u8.ToArray(),
                        "=customer=admin"u8.ToArray(), "=username=001"u8.ToArray(), "=disabled=yes"u8.ToArray(),
                        Encoding.UTF8.GetBytes("=comment=hmk-create:" + id.ToString("N"))], token);
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
            });
            try
            {
                Assert.Equal(visible, await RouterOsReadRecovery.RecordBoundUm6RecoveryAsync(path, id));
                Assert.Equal(visible ? "*1" : null, journal.ReadBoundRecoveryScope(id).Recovery?.RemoteId);
                Assert.Equal(UserManager6CreateState.Indeterminate, journal.Read(id)!.State);
                Assert.Null(journal.ReadCreationEvidence(id));
            }
            finally { await serve; }
            Assert.False(server.HasPendingConnection);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("both")]
    [InlineData("account-absent")]
    [InlineData("profile-absent")]
    [InlineData("account-mismatch")]
    [InlineData("wrong-owner")]
    [InlineData("duplicate-profile")]
    [InlineData("scope-drift")]
    [InlineData("profile-unknown")]
    [InlineData("profile-whitespace")]
    [InlineData("profile-intended")]
    [InlineData("profile-other")]
    [InlineData("profile-duplicate")]
    [SupportedOSPlatform("windows")]
    public async Task BoundProfileLinkPreflightUsesRetainedIdentityAndExactProfile(string condition)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var directory = Directory.CreateTempSubdirectory("hadramout-profile-link-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = PreparePreflightFixture(path, server.Port, certificates, true);
            var journal = new UserManager6CreateJournal(path);
            Assert.True(journal.TryBeginBoundDispatch(id));
            Assert.True(journal.TryMarkIndeterminate(id));
            Assert.True(journal.TryRecordRecoveryObservation(new(journal.ReadBoundRecoveryScope(id), new("*1", false))));
            var prior = journal.ReadProfileLinkScope(id);
            Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "6.49.19");
                byte[][] request = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                Assert.Equal(new[] { "/tool/user-manager/user/print",
                    "=.proplist=.id,customer,username,disabled,comment,actual-profile", "?username=001" },
                    request.Select(word => Encoding.UTF8.GetString(word)).ToArray());
                if (condition != "account-absent")
                {
                    var words = new List<ReadOnlyMemory<byte>>
                    {
                        "!re"u8.ToArray(), condition == "account-mismatch" ? "=.id=*2"u8.ToArray() : "=.id=*1"u8.ToArray(),
                        "=customer=admin"u8.ToArray(), "=username=001"u8.ToArray(), "=disabled=yes"u8.ToArray(),
                        Encoding.UTF8.GetBytes("=comment=hmk-create:" + id.ToString("N"))
                    };
                    if (condition != "profile-unknown")
                        words.Add(Encoding.UTF8.GetBytes("=actual-profile=" + (condition switch
                        {
                            "profile-whitespace" => " ",
                            "profile-intended" => "remote-day",
                            "profile-other" => "other-day",
                            _ => ""
                        })));
                    if (condition == "profile-duplicate") words.Add("=actual-profile=other-day"u8.ToArray());
                    await RouterOsWireCodec.WriteSentenceAsync(tls, words.ToArray(), token);
                    if (condition is "account-mismatch" or "profile-duplicate") return;
                }
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                if (condition is not ("account-absent" or "profile-unknown" or "profile-whitespace" or "profile-intended" or "profile-other"))
                {
                    request = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                    Assert.Equal(new[] { "/tool/user-manager/profile/print",
                        "=.proplist=owner,name,validity,starts-at", "?name=remote-day" },
                        request.Select(word => Encoding.UTF8.GetString(word)).ToArray());
                    if (condition != "profile-absent")
                    {
                        ReadOnlyMemory<byte>[] profile = ["!re"u8.ToArray(),
                            condition == "wrong-owner" ? "=owner=other"u8.ToArray() : "=owner=owner"u8.ToArray(),
                            "=name=remote-day"u8.ToArray()];
                        await RouterOsWireCodec.WriteSentenceAsync(tls, profile, token);
                        if (condition == "wrong-owner") return;
                        if (condition == "duplicate-profile")
                        {
                            await RouterOsWireCodec.WriteSentenceAsync(tls, profile, token);
                            return;
                        }
                    }
                    if (condition == "scope-drift")
                    {
                        using var db = DatabaseStore.OpenExisting(path);
                        using var cmd = db.CreateCommand();
                        cmd.CommandText = "UPDATE plans SET Name='changed';";
                        cmd.ExecuteNonQuery();
                    }
                    await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                }
                Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
            });
            try
            {
                if (condition is "account-mismatch" or "wrong-owner" or "duplicate-profile" or "profile-duplicate")
                    await Assert.ThrowsAsync<InvalidDataException>(() => RouterOsReadRecovery.ReadBoundUm6ProfileLinkPreflightAsync(path, id));
                else if (condition == "scope-drift")
                    await Assert.ThrowsAsync<InvalidOperationException>(() => RouterOsReadRecovery.ReadBoundUm6ProfileLinkPreflightAsync(path, id));
                else
                {
                    var evidence = await RouterOsReadRecovery.ReadBoundUm6ProfileLinkPreflightAsync(path, id);
                    Assert.Equal(condition switch
                    {
                        "account-absent" => UserManager6ProfileLinkReadState.AccountNotVisible,
                        "profile-absent" => UserManager6ProfileLinkReadState.ProfileNotVisible,
                        "profile-unknown" or "profile-whitespace" => UserManager6ProfileLinkReadState.AccountProfileUnknown,
                        "profile-intended" or "profile-other" => UserManager6ProfileLinkReadState.AccountProfileAlreadyVisible,
                        _ => UserManager6ProfileLinkReadState.BothVisible
                    }, evidence.State);
                    Assert.Equal(condition == "account-absent" ? null : "*1", evidence.Account?.RemoteId);
                    Assert.Equal(condition == "both" ? "remote-day" : null, evidence.Profile?.Name);
                    Assert.Equal(condition switch
                    {
                        "account-absent" or "profile-unknown" => null,
                        "profile-whitespace" => " ",
                        "profile-intended" => "remote-day",
                        "profile-other" => "other-day",
                        _ => ""
                    }, evidence.ActualProfile);
                    if (condition != "both")
                    {
                        Assert.Throws<InvalidOperationException>(() => journal.TryClaimProfileLink(prior, evidence));
                        Assert.Null(journal.ReadProfileLinkEntry(id));
                    }
                }
                if (condition != "scope-drift") Assert.Equal(prior, journal.ReadProfileLinkScope(id));
                Assert.Equal(UserManager6CreateState.Indeterminate, journal.Read(id)!.State);
                Assert.Null(journal.ReadCreationEvidence(id));
            }
            finally { await serve; }
            Assert.False(server.HasPendingConnection);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [SupportedOSPlatform("windows")]
    public async Task ProfileLinkPreflightRequiresPositiveHistoricalObservationBeforeConnecting(bool acknowledged)
    {
        using var certificates = new Certificates();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var directory = Directory.CreateTempSubdirectory("hadramout-profile-link-local-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = PreparePreflightFixture(path, port, certificates, true);
            var journal = new UserManager6CreateJournal(path);
            Assert.True(journal.TryBeginBoundDispatch(id));
            if (acknowledged)
                Assert.True(journal.TryRecordAcknowledgement(id, new(UserManager6CreateWireOutcome.Acknowledged, "*1")));
            var prior = journal.ReadBoundRecoveryScope(id);
            await Assert.ThrowsAsync<InvalidOperationException>(() => RouterOsReadRecovery.ReadBoundUm6ProfileLinkPreflightAsync(path, id));
            Assert.False(listener.Pending());
            Assert.Equal(prior, journal.ReadBoundRecoveryScope(id));
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("match", 2)]
    [InlineData("match", 3)]
    [InlineData("match", 4)]
    [InlineData("absent", 3)]
    [InlineData("empty", 3)]
    [InlineData("unknown", 3)]
    [InlineData("other", 3)]
    [InlineData("missing-profile", 4)]
    [InlineData("wrong-owner", 4)]
    [InlineData("enabled", 4)]
    [InlineData("state-drift", 2)]
    [SupportedOSPlatform("windows")]
    public async Task BoundProfileLinkReviewPreservesClaimAndReadsOnly(string condition, int linkState)
    {
        using var certificates = new Certificates();
        using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
        var directory = Directory.CreateTempSubdirectory("hadramout-profile-review-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = PreparePreflightFixture(path, server.Port, certificates, true);
            var journal = new UserManager6CreateJournal(path);
            Assert.True(journal.TryBeginBoundDispatch(id));
            Assert.True(journal.TryMarkIndeterminate(id));
            Assert.True(journal.TryRecordRecoveryObservation(new(journal.ReadBoundRecoveryScope(id), new("*1", false))));
            var intent = journal.ReadProfileLinkScope(id);
            var preflight = new UserManager6ProfileLinkReadEvidence(UserManager6ProfileLinkReadState.BothVisible,
                new("*1", true), new(intent.ProfileOwner, intent.ProfileName, null, null), "");
            Assert.True(journal.TryClaimProfileLink(intent, preflight));
            if (linkState != 2)
                Assert.True(journal.TryRecordProfileLinkResult(id, (UserManager6ProfileLinkState)linkState));
            var prior = journal.ReadProfileLinkReviewScope(id);
            Task serve = server.RunAsync(reply: true, handler: async (tls, token) =>
            {
                await PrepareProbePeerAsync(tls, token, "6.49.19");
                byte[][] request = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                Assert.Equal(new[] { "/tool/user-manager/user/print",
                    "=.proplist=.id,customer,username,disabled,comment,actual-profile", "?username=001" },
                    request.Select(word => Encoding.UTF8.GetString(word)).ToArray());
                if (condition != "absent")
                {
                    var words = new List<ReadOnlyMemory<byte>>
                    {
                        "!re"u8.ToArray(), "=.id=*1"u8.ToArray(), "=customer=admin"u8.ToArray(),
                        "=username=001"u8.ToArray(), condition == "enabled" ? "=disabled=no"u8.ToArray() : "=disabled=yes"u8.ToArray(),
                        Encoding.UTF8.GetBytes("=comment=hmk-create:" + id.ToString("N"))
                    };
                    if (condition != "unknown")
                        words.Add(Encoding.UTF8.GetBytes("=actual-profile=" + (condition switch
                        {
                            "empty" => "", "other" => "other-day", _ => "remote-day"
                        })));
                    await RouterOsWireCodec.WriteSentenceAsync(tls, words.ToArray(), token);
                    if (condition == "enabled") return;
                }
                await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                if (condition is "match" or "missing-profile" or "wrong-owner" or "state-drift")
                {
                    request = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
                    Assert.Equal(new[] { "/tool/user-manager/profile/print",
                        "=.proplist=owner,name,validity,starts-at", "?name=remote-day" },
                        request.Select(word => Encoding.UTF8.GetString(word)).ToArray());
                    if (condition != "missing-profile")
                    {
                        await RouterOsWireCodec.WriteSentenceAsync(tls, ["!re"u8.ToArray(),
                            condition == "wrong-owner" ? "=owner=other"u8.ToArray() : "=owner=owner"u8.ToArray(),
                            "=name=remote-day"u8.ToArray()], token);
                        if (condition == "wrong-owner") return;
                    }
                    if (condition == "state-drift")
                        Assert.True(journal.TryRecordProfileLinkResult(id, UserManager6ProfileLinkState.Indeterminate));
                    await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
                }
                Assert.Equal(0, await tls.ReadAsync(new byte[1], token));
            });
            try
            {
                if (condition is "wrong-owner" or "enabled")
                    await Assert.ThrowsAsync<InvalidDataException>(() => RouterOsReadRecovery.ReadBoundUm6ProfileLinkReviewAsync(path, id));
                else if (condition == "state-drift")
                    await Assert.ThrowsAsync<InvalidOperationException>(() => RouterOsReadRecovery.ReadBoundUm6ProfileLinkReviewAsync(path, id));
                else
                {
                    var evidence = await RouterOsReadRecovery.ReadBoundUm6ProfileLinkReviewAsync(path, id);
                    Assert.Equal(prior, evidence.Scope);
                    Assert.Equal(condition switch
                    {
                        "absent" => UserManager6ProfileLinkReviewState.AccountNotVisible,
                        "empty" => UserManager6ProfileLinkReviewState.EmptyProfileReported,
                        "unknown" => UserManager6ProfileLinkReviewState.ActualProfileUnknown,
                        "other" => UserManager6ProfileLinkReviewState.OtherProfileReported,
                        "missing-profile" => UserManager6ProfileLinkReviewState.IntendedNameProfileNotVisible,
                        _ => UserManager6ProfileLinkReviewState.IntendedNameAndOwnerVisible
                    }, evidence.State);
                    Assert.Equal(condition == "absent" ? null : "*1", evidence.Account?.RemoteId);
                    Assert.Equal(condition == "match" ? "remote-day" : null, evidence.Profile?.Name);
                }
                Assert.Equal(condition == "state-drift" ? UserManager6ProfileLinkState.Indeterminate : prior.Entry.State,
                    journal.ReadProfileLinkEntry(id)!.State);
                Assert.Equal(intent, journal.ReadProfileLinkScope(id));
                Assert.False(journal.TryClaimProfileLink(intent, preflight));
                Assert.Null(journal.ReadCreationEvidence(id));
            }
            finally { await serve; }
            Assert.False(server.HasPendingConnection);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task ProfileLinkReviewWithoutClaimRejectsBeforeConnection()
    {
        using var certificates = new Certificates();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var directory = Directory.CreateTempSubdirectory("hadramout-profile-review-local-");
        try
        {
            string path = Path.Combine(directory.FullName, "test.db");
            Guid id = PreparePreflightFixture(path, port, certificates, true);
            var journal = new UserManager6CreateJournal(path);
            Assert.True(journal.TryBeginBoundDispatch(id));
            Assert.True(journal.TryMarkIndeterminate(id));
            Assert.True(journal.TryRecordRecoveryObservation(new(journal.ReadBoundRecoveryScope(id), new("*1", false))));
            await Assert.ThrowsAsync<InvalidOperationException>(() => RouterOsReadRecovery.ReadBoundUm6ProfileLinkReviewAsync(path, id));
            Assert.False(listener.Pending());
            Assert.Null(journal.ReadProfileLinkEntry(id));
        }
        finally { directory.Delete(recursive: true); }
    }

    [SupportedOSPlatform("windows")]
    private static Guid PreparePreflightFixture(string path, int port, Certificates certificates, bool saveSecret)
    {
        Guid id = DatabaseDurabilityTests.SeedReservation(path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(path);
        var entry = journal.Prepare(id, "admin");
        EnrollBoundRouter(path, entry.RouterId, port, certificates);
        new RouterCredentialStore(path).Save(entry.RouterId, "synthetic-user"u8, "synthetic-private-password"u8);
        journal.PrepareBoundIntent(id, "owner", "remote-day");
        if (saveSecret) new UserManager6VoucherSecretStore(path).Save(id, "synthetic-voucher"u8);
        return id;
    }

    private static Guid SeedBoundRouter(string path)
    {
        Guid reservation = DatabaseDurabilityTests.SeedReservation(path, BackendKind.UserManager6);
        return new UserManager6CreateJournal(path).Prepare(reservation, "admin").RouterId;
    }

    private static void EnrollBoundRouter(string path, Guid id, int port, Certificates certificates) =>
        new RouterTargetStore(path).Enroll(id, "127.0.0.1", port, "router.test",
            Convert.ToHexString(SHA256.HashData(certificates.Leaf.RawData)), certificates.Root.RawData);

    private static Task<UserManager6Account?> FindUm6AccountAsync(LoopbackServer server, Certificates certificates) =>
        RouterOsReadRecovery.FindUserManager6AccountAsync("admin", "123456", "127.0.0.1", "router.test",
            "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
            trustedRootDer: certificates.Root.RawData);

    private static async Task AssertUm6AccountRequestAsync(SslStream tls, CancellationToken token)
    {
        byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
        Assert.Equal(new[] { "/tool/user-manager/user/print", "=.proplist=customer,username,disabled,actual-profile,download-used,upload-used,uptime-used,active,incomplete,last-seen,active-sessions",
            "?customer=admin", "?username=123456" }, words.Select(word => Encoding.UTF8.GetString(word)).ToArray());
    }

    private static async Task PrepareProbePeerAsync(SslStream tls, CancellationToken token, string version)
    {
        await AssertLoginAsync(tls, token);
        await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
        await AssertVersionRequestAsync(tls, token);
        await RouterOsWireCodec.WriteSentenceAsync(tls,
            ["!re"u8.ToArray(), Encoding.ASCII.GetBytes("=version=" + version)], token);
        await RouterOsWireCodec.WriteSentenceAsync(tls, ["!done"u8.ToArray()], token);
    }

    private static async Task AssertPackageRequestAsync(SslStream tls, CancellationToken token)
    {
        byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
        Assert.Collection(words,
            word => Assert.True(word.AsSpan().SequenceEqual("/system/package/print"u8)),
            word => Assert.True(word.AsSpan().SequenceEqual("=.proplist=name,version,disabled,scheduled"u8)));
    }

    private static Task<RouterOsSession> ConnectSessionAsync(LoopbackServer server, Certificates certificates) =>
        RouterOsSession.ConnectAsync("127.0.0.1", "router.test", "synthetic-user"u8.ToArray(),
            "synthetic-private-password"u8.ToArray(), server.Port, trustedRootDer: certificates.Root.RawData);

    private static async Task AssertLoginAsync(SslStream tls, CancellationToken token)
    {
        byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
        Assert.Collection(words,
            word => Assert.True(word.AsSpan().SequenceEqual("/login"u8)),
            word => Assert.True(word.AsSpan().SequenceEqual("=name=synthetic-user"u8)),
            word => Assert.True(word.AsSpan().SequenceEqual("=password=synthetic-private-password"u8)));
    }

    private static async Task AssertVersionRequestAsync(SslStream tls, CancellationToken token)
    {
        byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
        Assert.Collection(words,
            word => Assert.True(word.AsSpan().SequenceEqual("/system/resource/print"u8)),
            word => Assert.True(word.AsSpan().SequenceEqual("=.proplist=version"u8)));
    }

    [Fact]
    public void IndependentCertificateFixturesHaveUniqueIssuersAndBuildServerContexts()
    {
        var issuers = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < 12; i++)
        {
            using var certificates = new Certificates();
            Assert.True(issuers.Add(certificates.Root.Subject));
            Assert.Equal(certificates.Root.Subject, certificates.Leaf.Issuer);
            Assert.NotNull(certificates.Leaf.Extensions["2.5.29.35"]);
            using var server = new LoopbackServer(certificates.Leaf, certificates.Root, output);
            Assert.True(server.Port > 0);
        }
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
            // Distinct issuer names prevent ambiguity in Windows chain-building caches.
            var rootRequest = new CertificateRequest($"CN=Hadramout test CA {Guid.NewGuid():N}", rootKey,
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
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                Root, includeKeyIdentifier: true, includeIssuerAndSerial: true));
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
        public bool HasPendingConnection => listener.Pending();

        public LoopbackServer(X509Certificate2 certificate, X509Certificate2 root, ITestOutputHelper output)
        {
            this.output = output;
            try
            {
                // Supply only the public issuer certificate, not the CA private key.
                using var publicRoot = X509CertificateLoader.LoadCertificate(root.RawData);
                context = SslStreamCertificateContext.Create(certificate,
                    new X509Certificate2Collection(publicRoot), offline: true);
                listener.Start();
            }
            catch (Exception ex)
            {
                output.WriteLine($"TLS fixture setup failed: HResult=0x{ex.HResult:X8}; " +
                    $"issuer={certificate.Issuer}; leaf={certificate.Thumbprint}; CA={root.Thumbprint}; " +
                    $"runtime={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}; " +
                    $"OS={System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
                deadline.Dispose();
                listener.Stop();
                throw;
            }
        }

        public async Task RunAsync(bool reply, Func<SslStream, CancellationToken, Task>? handler = null)
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
                if (handler is not null)
                    await handler(tls, deadline.Token);
                else if (reply)
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
