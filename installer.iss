; Inno Setup script - tao bo cai dat SentinelX_Setup.exe
; Bien dich bang Inno Setup 6:  iscc installer.iss
#define AppName    "SentinelX Antivirus"
#define AppVersion "2.0"

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=SentinelX Labs
DefaultDirName={autopf}\SentinelX
DefaultGroupName=SentinelX
OutputBaseFilename=SentinelX_Setup
SetupIconFile=assets\sentinelx.ico
Compression=lzma2/max
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern

[Languages]
Name: "vi"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "dist\SentinelX.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "data\signatures.json"; DestDir: "{app}\data"; Flags: onlyifdoesntexist
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SentinelX Antivirus"; Filename: "{app}\SentinelX.exe"
Name: "{autodesktop}\SentinelX Antivirus"; Filename: "{app}\SentinelX.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Tao bieu tuong tren Desktop"; GroupDescription: "Tuy chon:"
Name: "startup";     Description: "Khoi dong cung Windows (bao ve thoi gian thuc)"; GroupDescription: "Tuy chon:"

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; \
  ValueName: "SentinelX"; ValueData: """{app}\SentinelX.exe"""; Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "{app}\SentinelX.exe"; Description: "Khoi chay SentinelX ngay"; Flags: nowait postinstall skipifsilent
