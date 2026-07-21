[Setup]
AppName=Aegis ICS Edge
AppVersion=2.2.1
DefaultDirName={autopf}\AegisICS
DefaultGroupName=Aegis ICS
UninstallDisplayIcon={app}\AegisICS.exe
Compression=lzma2
SolidCompression=yes
OutputDir=dist
OutputBaseFilename=Aegis_ICS_Setup_v2.2.1
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "dist\AegisICS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Aegis ICS Edge"; Filename: "{app}\AegisICS.exe"
Name: "{autodesktop}\Aegis ICS Edge"; Filename: "{app}\AegisICS.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"
