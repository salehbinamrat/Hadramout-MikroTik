using System.Text;
using Hadramout.Core;

namespace Hadramout.Infrastructure;

internal enum RouterOsFamily { Unsupported, V6, V7 }
internal enum UserManagerPackageState { Unknown, NotListed, DisabledOrAvailable, InstalledEnabled }
internal sealed record RouterOsPackage(string Name, string? Version, bool? Disabled, string? Scheduled);

internal enum RouterOsServiceProbeState { NotApplicable, Readable, Rejected, ConnectionTerminated }
internal sealed record RouterOsServiceProbe(BackendKind Backend, RouterOsFamily Family,
    RouterOsServiceProbeState State, long? AccountCount = null, int? TrapCategory = null);

// Package evidence is not proof of service availability, license or command permissions.
internal sealed record RouterOsInventory(string Version, RouterOsFamily Family,
    IReadOnlyList<RouterOsPackage> Packages, UserManagerPackageState UserManagerPackage)
{
    internal static RouterOsFamily ClassifyVersion(string version)
    {
        if (!TryReleaseVersion(version, out var parsed)) return RouterOsFamily.Unsupported;
        return parsed.Major switch
        {
            6 when parsed.Minor == 49 => RouterOsFamily.V6,
            7 => RouterOsFamily.V7,
            _ => RouterOsFamily.Unsupported
        };
    }

    internal static RouterOsInventory Classify(string version, IReadOnlyList<RouterOsPackage> packages,
        bool inventoryRead)
    {
        var family = ClassifyVersion(version);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var package in packages)
            if (!names.Add(package.Name))
                throw new InvalidDataException("Duplicate RouterOS package name.");

        var state = UserManagerPackageState.Unknown;
        if (family != RouterOsFamily.Unsupported && inventoryRead)
        {
            var um = packages.FirstOrDefault(p => p.Name == "user-manager");
            if (um is null) state = UserManagerPackageState.NotListed;
            else if (um.Disabled == true) state = UserManagerPackageState.DisabledOrAvailable;
            else if (um.Disabled == false && string.IsNullOrEmpty(um.Scheduled) &&
                TryReleaseVersion(version, out var systemVersion) &&
                TryReleaseVersion(um.Version, out var packageVersion) &&
                systemVersion.Equals(packageVersion))
                state = UserManagerPackageState.InstalledEnabled;
        }
        return new(version, family, Array.AsReadOnly(packages.ToArray()), state);
    }

    internal static RouterOsPackage ParsePackage(byte[][] words)
    {
        string name = ReadAscii(words, "name", 128, required: true)!;
        if (name.Length == 0 || name.Any(ch => !(char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_')))
            throw new InvalidDataException("Invalid RouterOS package name.");
        string? version = ReadAscii(words, "version", 128, required: false);
        string? disabled = ReadAscii(words, "disabled", 8, required: false);
        bool? isDisabled = disabled switch
        {
            "true" or "yes" => true,
            "false" or "no" => false,
            null or "" => null,
            _ => throw new InvalidDataException("Invalid RouterOS package disabled flag.")
        };
        return new(name, version, isDisabled, ReadAscii(words, "scheduled", 128, required: false));
    }

    internal static string? ReadAscii(byte[][] words, string name, int maxBytes, bool required)
    {
        byte[] prefix = Encoding.ASCII.GetBytes("=" + name + "=");
        string? value = null;
        foreach (byte[] word in words.Skip(1))
        {
            if (!word.AsSpan().StartsWith(prefix)) continue;
            if (value is not null || word.Length - prefix.Length > maxBytes)
                throw new InvalidDataException("Invalid RouterOS field length or duplicate.");
            for (int i = prefix.Length; i < word.Length; i++)
                if (word[i] is < 0x20 or > 0x7E)
                    throw new InvalidDataException("Invalid RouterOS field encoding.");
            value = Encoding.ASCII.GetString(word, prefix.Length, word.Length - prefix.Length);
        }
        if (required && string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException("Required RouterOS field missing.");
        return value;
    }

    private static bool TryReleaseVersion(string? text, out System.Version version)
    {
        version = new System.Version(0, 0, 0);
        if (string.IsNullOrEmpty(text) || text.Length > 128 || text != text.Trim())
            return false;
        int separator = text.IndexOf(' ');
        string number = separator < 0 ? text : text[..separator];
        if (separator >= 0 && text[separator..] is not (" (stable)" or " (long-term)"))
            return false;
        string[] parts = number.Split('.');
        if (parts.Length is < 2 or > 3 || parts.Any(part => part.Length is < 1 or > 5 ||
            part.Any(ch => !char.IsAsciiDigit(ch)) || (part.Length > 1 && part[0] == '0')))
            return false;
        if (!System.Version.TryParse(number, out var parsed)) return false;
        version = new System.Version(parsed.Major, parsed.Minor, Math.Max(0, parsed.Build));
        return true;
    }
}
