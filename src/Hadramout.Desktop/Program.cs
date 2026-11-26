using System.Runtime.InteropServices;
using System.Windows;
using Hadramout.Core;
using Hadramout.Infrastructure;
namespace Hadramout.Desktop;
internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var app = new Application();
        var window = new MainWindow();
        if (args is ["--smoke-test", var expected])
            return RuntimeCompatibility.MatchesArchitecture(expected, RuntimeInformation.ProcessArchitecture)
                && window.FlowDirection == FlowDirection.RightToLeft && window.Content is not null
                && DatabaseProbe.Verify() && CredentialProbe.Verify() ? 0 : 1;
        if (args.Length != 0) return 2;
        return app.Run(window);
    }
}
