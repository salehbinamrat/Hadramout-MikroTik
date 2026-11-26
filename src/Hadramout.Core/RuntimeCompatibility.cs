using System.Runtime.InteropServices;
namespace Hadramout.Core;
public static class RuntimeCompatibility
{
    public static bool MatchesArchitecture(string expected, Architecture actual) =>
        (expected, actual) switch
        {
            ("x86", Architecture.X86) => true,
            ("x64", Architecture.X64) => true,
            _ => false
        };
}
