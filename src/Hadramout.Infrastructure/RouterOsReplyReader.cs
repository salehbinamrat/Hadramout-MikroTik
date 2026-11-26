using System.Security.Cryptography;
using System.Globalization;

namespace Hadramout.Infrastructure;

internal enum RouterOsReplyOutcome { Completed, Rejected, Fatal }

internal sealed record RouterOsReadResult<T>(RouterOsReplyOutcome Outcome, IReadOnlyList<T> Rows, int? TrapCategory, long? CompletionCount = null);

// Read-only untagged reply sequence. A rejection/fatal result or exception requires the
// owner to close the connection: a following !done may still be pending. No retry here.
internal static class RouterOsReplyReader
{
    internal const int MaxRows = 4096;
    internal const int MaxReplyBytes = 16 * 1024 * 1024;

    // The row projector must return only bounded, explicitly selected values.
    // It must not retain references to the raw words or perform side effects.
    internal static async ValueTask<RouterOsReadResult<T>> ReadAsync<T>(Stream stream,
        Func<byte[][], T> project, int maxRows, CancellationToken cancellationToken, bool countOnly = false)
    {
        ArgumentNullException.ThrowIfNull(project);
        if (maxRows is < 1 or > MaxRows) throw new ArgumentOutOfRangeException(nameof(maxRows));

        var rows = new List<T>();
        bool empty = false;
        int total = 0;
        // Count all sentences as well as payload; even zero-length frames cannot spin forever.
        for (int sentence = 0; sentence < maxRows + 2; sentence++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(stream, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                foreach (byte[] word in words)
                {
                    if (word.Length > MaxReplyBytes - total)
                        throw new InvalidDataException("RouterOS reply exceeds configured byte limit.");
                    total += word.Length;
                }
                if (words.Length == 0)
                    throw new InvalidDataException("Unexpected empty RouterOS frame.");

                // No commands in this slice use tags. Reject tagged/unstructured attributes
                // rather than accidentally accepting a reply to a different command.
                var attributes = new HashSet<string>(StringComparer.Ordinal);
                foreach (byte[] word in words.Skip(1))
                {
                    int separator = word.AsSpan(1).IndexOf((byte)'=') + 1;
                    if (word[0] != (byte)'=' || separator < 2 || separator > 129)
                        throw new InvalidDataException("Invalid untagged RouterOS reply attribute.");
                    for (int i = 1; i < separator; i++)
                        if (word[i] is < 0x21 or > 0x7E)
                            throw new InvalidDataException("Invalid RouterOS reply attribute name.");
                    string name = System.Text.Encoding.ASCII.GetString(word, 1, separator - 1);
                    if (!attributes.Add(name))
                        throw new InvalidDataException("Duplicate RouterOS reply attribute.");
                }

                ReadOnlySpan<byte> kind = words[0];
                if (kind.SequenceEqual("!done"u8))
                {
                    long? count = null;
                    if (countOnly)
                    {
                        if (words.Length != 2 || !words[1].AsSpan().StartsWith("=ret="u8))
                            throw new InvalidDataException("RouterOS count completion requires a numeric return value.");
                        string value = RouterOsInventory.ReadAscii(words, "ret", 19, required: true)!;
                        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) ||
                            parsed < 0 || (empty && parsed != 0))
                            throw new InvalidDataException("Invalid RouterOS count result.");
                        count = parsed;
                    }
                    else if (words.Length != 1)
                        throw new InvalidDataException("Unexpected RouterOS completion attributes.");
                    cancellationToken.ThrowIfCancellationRequested();
                    return new(RouterOsReplyOutcome.Completed, rows.AsReadOnly(), null, count);
                }
                if (kind.SequenceEqual("!trap"u8))
                {
                    int? category = null;
                    foreach (byte[] word in words.Skip(1))
                    {
                        if (!word.AsSpan().StartsWith("=category="u8)) continue;
                        if (word.Length == 11 && word[10] is >= (byte)'0' and <= (byte)'7')
                            category = word[10] - (byte)'0';
                        // An unknown category is intentionally not guessed or logged.
                    }
                    return new(RouterOsReplyOutcome.Rejected, Array.Empty<T>(), category);
                }
                if (kind.SequenceEqual("!fatal"u8))
                    return new(RouterOsReplyOutcome.Fatal, Array.Empty<T>(), null);
                if (kind.SequenceEqual("!empty"u8))
                {
                    if (empty || rows.Count != 0 || words.Length != 1)
                        throw new InvalidDataException("Invalid RouterOS empty result.");
                    empty = true;
                    continue;
                }
                if (countOnly || !kind.SequenceEqual("!re"u8) || empty || rows.Count >= maxRows || words.Length == 1)
                    throw new InvalidDataException("Unexpected RouterOS data reply or row limit exceeded.");

                rows.Add(project(words));
            }
            finally
            {
                foreach (byte[] word in words) CryptographicOperations.ZeroMemory(word);
            }
        }
        throw new InvalidDataException("RouterOS reply did not complete within the sentence limit.");
    }
}
