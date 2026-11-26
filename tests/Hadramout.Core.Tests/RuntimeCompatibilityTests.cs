using System.Runtime.InteropServices;
using Hadramout.Core;
using Xunit;
namespace Hadramout.Core.Tests;
public sealed class RuntimeCompatibilityTests
{
    [Theory]
    [InlineData("x86", Architecture.X86, true)]
    [InlineData("x64", Architecture.X64, true)]
    [InlineData("x86", Architecture.X64, false)]
    [InlineData("x64", Architecture.X86, false)]
    [InlineData("x64", Architecture.Arm64, false)]
    [InlineData("unknown", Architecture.X64, false)]
    public void DetectsExactArchitecture(string expected, Architecture actual, bool matches) =>
        Assert.Equal(matches, RuntimeCompatibility.MatchesArchitecture(expected, actual));
}
