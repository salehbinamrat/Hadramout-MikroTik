using System.IO;
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
        var app = new Application();
        var window = new MainWindow();
        if (args is ["--smoke-test", var expected])
            return RuntimeCompatibility.MatchesArchitecture(expected, RuntimeInformation.ProcessArchitecture)
                && window.FlowDirection == FlowDirection.RightToLeft && window.Content is not null
                && DatabaseProbe.Verify() && CredentialProbe.Verify() && BackupProbe.Verify() && EncryptedBackupProbe.Verify() && RestoreCredentialProbe.Verify() && DatabaseProbe.VerifyManagedStartup() ? 0 : 1;
        if (args.Length != 0) return 2;
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
}
