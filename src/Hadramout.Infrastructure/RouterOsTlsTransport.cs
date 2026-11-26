using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Hadramout.Infrastructure;

// Owns a single certificate-authenticated connection. No plaintext fallback, login or retry.
internal sealed class RouterOsTlsTransport : IDisposable
{
    private readonly TcpClient client;
    internal SslStream Stream { get; }

    private RouterOsTlsTransport(TcpClient client, SslStream stream)
    {
        this.client = client;
        Stream = stream;
    }

    internal static async Task<RouterOsTlsTransport> ConnectAsync(string host, string certificateName,
        int port = 8729, TimeSpan? timeout = null, ReadOnlyMemory<byte> trustedRootDer = default,
        CancellationToken cancellationToken = default)
    {
        ValidateHost(host, nameof(host));
        ValidateHost(certificateName, nameof(certificateName));
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        TimeSpan limit = timeout ?? TimeSpan.FromSeconds(15);
        if (limit <= TimeSpan.Zero || limit > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        if (trustedRootDer.Length > 65536)
            throw new ArgumentException("Trusted CA certificate exceeds the size limit.", nameof(trustedRootDer));
        cancellationToken.ThrowIfCancellationRequested();

        // Explicitly configured private CA, never a certificate learned from the peer.
        using X509Certificate2? root = trustedRootDer.IsEmpty ? null :
            X509CertificateLoader.LoadCertificate(trustedRootDer.Span);
        if (root is not null && !root.Extensions.OfType<X509BasicConstraintsExtension>()
            .Any(extension => extension.CertificateAuthority))
            throw new ArgumentException("The configured trust anchor must be a CA certificate.", nameof(trustedRootDer));

        var policy = new X509ChainPolicy
        {
            VerificationFlags = X509VerificationFlags.NoFlag,
            DisableCertificateDownloads = true,
            RevocationMode = root is null ? X509RevocationMode.Online : X509RevocationMode.NoCheck,
            RevocationFlag = X509RevocationFlag.ExcludeRoot,
            UrlRetrievalTimeout = limit
        };
        policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1")); // TLS server authentication
        if (root is not null)
        {
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            policy.CustomTrustStore.Add(root);
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(limit);
        var client = new TcpClient();
        SslStream? tls = null;
        try
        {
            await client.ConnectAsync(host, port, deadline.Token).ConfigureAwait(false);
            client.NoDelay = true;
            tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = certificateName,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                AllowRenegotiation = false,
                CertificateChainPolicy = policy
            }, deadline.Token).ConfigureAwait(false);
            if (!tls.IsAuthenticated || !tls.IsEncrypted || !tls.IsSigned || tls.RemoteCertificate is null)
                throw new AuthenticationException("RouterOS TLS peer is not authenticated.");
            deadline.Token.ThrowIfCancellationRequested();
            return new RouterOsTlsTransport(client, tls);
        }
        catch (Exception ex)
        {
            try { tls?.Dispose(); }
            finally { client.Dispose(); }
            if (deadline.IsCancellationRequested)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new TimeoutException("RouterOS TLS connection deadline exceeded.", ex);
            }
            throw;
        }
    }

    private static void ValidateHost(string host, string parameter)
    {
        if (string.IsNullOrWhiteSpace(host) || host != host.Trim() ||
            Uri.CheckHostName(host) == UriHostNameType.Unknown)
            throw new ArgumentException("A DNS name or IP address is required.", parameter);
    }

    public void Dispose()
    {
        try { Stream.Dispose(); }
        finally { client.Dispose(); }
    }
}
