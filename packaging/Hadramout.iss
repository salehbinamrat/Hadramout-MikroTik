#ifndef Arch
#error Arch required
#endif
#ifndef Payload
#error Payload required
#endif
#ifndef OutputPath
#error OutputPath required
#endif
[Setup]
AppId=HadramoutMikroTik-{#Arch}
AppName=Hadramout MikroTik ({#Arch})
AppVersion=0.1.0
DefaultDirName={localappdata}\Programs\Hadramout MikroTik {#Arch}
DefaultGroupName=Hadramout MikroTik {#Arch}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputPath}
OutputBaseFilename=HadramoutMikroTik-{#Arch}-Setup
Compression=lzma2
SolidCompression=yes
Uninstallable=yes
#if Arch == "x64"
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#else
ArchitecturesAllowed=x86compatible
#endif
[Files]
Source: "{#Payload}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{group}\Hadramout MikroTik"; Filename: "{app}\HadramoutMikroTik.exe"
