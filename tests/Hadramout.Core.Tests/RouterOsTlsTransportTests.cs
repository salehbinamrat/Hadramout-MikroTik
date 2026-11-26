using System.Net;
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

    private static Task<UserManager6Account?> FindUm6AccountAsync(LoopbackServer server, Certificates certificates) =>
        RouterOsReadRecovery.FindUserManager6AccountAsync("admin", "123456", "127.0.0.1", "router.test",
            "synthetic-user"u8.ToArray(), "synthetic-private-password"u8.ToArray(), server.Port,
            trustedRootDer: certificates.Root.RawData);

    private static async Task AssertUm6AccountRequestAsync(SslStream tls, CancellationToken token)
    {
        byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(tls, token);
        Assert.Equal(new[] { "/tool/user-manager/user/print", "=.proplist=customer,username,disabled,actual-profile,download-used,upload-used,uptime-used",
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
