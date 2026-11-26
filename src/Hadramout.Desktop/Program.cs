using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Data.Sqlite;
using System.Windows;
using Hadramout.Core;
using Hadramout.Infrastructure;
namespace Hadramout.Desktop;
internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        // Diagnostic mode is dispatched before WPF initialization; non-shell probes
        // must not create a window or enter the application's normal data directory.
        if (args is ["--smoke-stage", var expected, var stage, var evidence])
            return RunSmokeStage(expected, stage, evidence);
        if (args is ["--smoke-test", var legacyExpected])
            return RuntimeCompatibility.MatchesArchitecture(legacyExpected, RuntimeInformation.ProcessArchitecture)
                && VerifyShell() && DatabaseProbe.Verify() && CredentialProbe.Verify() && BackupProbe.Verify()
                && EncryptedBackupProbe.Verify() && RestoreCredentialProbe.Verify()
                && DatabaseProbe.VerifyManagedStartup() ? 0 : 1;
        if (args.Length != 0) return 2;
        var app = new Application();
        var window = new MainWindow();
        // A normal launch holds the managed session for the full WPF lifetime.
        // Smoke tests above use isolated fixtures and never touch the user's database.
        ManagedDatabaseSession session;
        try
        {
            session = ManagedDatabase.OpenApplicationSession();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException
            or InvalidOperationException or SqliteException)
        {
            MessageBox.Show("تعذر فتح قاعدة البيانات بأمان. تأكد من إغلاق النسخة الأخرى ومن سلامة مجلد البيانات. لم يتم استبدال قاعدة البيانات.",
                "حضرموت مايكروتيك", MessageBoxButton.OK, MessageBoxImage.Error);
            return 3;
        }
        using (session)
            return app.Run(window);
    }

    private static bool VerifyShell()
    {
        var app = new Application();
        var window = new MainWindow();
        return window.FlowDirection == FlowDirection.RightToLeft && window.Content is not null;
    }

    // Fixed allowlist, synthetic fixtures only. Record progress durably enough for
    // a killed test process to reveal which probe began. No credential values.
    private static int RunSmokeStage(string expected, string stage, string evidence)
    {
        Func<bool>? probe = stage switch
        {
            "shell" => VerifyShell,
            "database" => DatabaseProbe.Verify,
            "credential" => CredentialProbe.Verify,
            "backup" => BackupProbe.Verify,
            "encrypted-backup" => EncryptedBackupProbe.Verify,
            "restore-credential" => RestoreCredentialProbe.Verify,
            "managed-startup" => DatabaseProbe.VerifyManagedStartup,
            _ => null
        };
        if (probe is null || !Path.IsPathFullyQualified(evidence)) return 2;
        var timer = Stopwatch.StartNew();
        try
        {
            File.WriteAllText(evidence, $"START {stage} {RuntimeInformation.ProcessArchitecture}{Environment.NewLine}");
            if (!RuntimeCompatibility.MatchesArchitecture(expected, RuntimeInformation.ProcessArchitecture))
            {
                File.AppendAllText(evidence, $"FAIL {stage} architecture mismatch{Environment.NewLine}");
                return 1;
            }
            bool passed = probe();
            File.AppendAllText(evidence, $"{(passed ? "PASS" : "FAIL")} {stage} {timer.ElapsedMilliseconds}ms{Environment.NewLine}");
            return passed ? 0 : 1;
        }
        catch (Exception ex)
        {
            // Only type and HRESULT: do not accidentally include secrets or paths
            // from exception messages in an uploaded diagnostic.
            try
            {
                File.AppendAllText(evidence, $"ERROR {stage} {timer.ElapsedMilliseconds}ms {ex.GetType().FullName} 0x{ex.HResult:X8}{Environment.NewLine}");
            }
            catch (Exception logError) when (logError is IOException or UnauthorizedAccessException) { }
            return 1;
        }
    }
}
