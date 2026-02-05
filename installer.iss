; OPSIS Agent Installer - Inno Setup Script
; Bundles Node.js runtime - no external dependencies required

#define AppName "OPSIS Agent"
#define AppVersion "1.0.0"
#define AppPublisher "OPSIS"
#define AppURL "https://opsis.io"
#define ServiceName "OPSIS Agent Service"

[Setup]
AppId={{A7B3C4D5-E6F7-4A5B-9C8D-1E2F3A4B5C6D}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\OPSIS Agent
DefaultGroupName={#AppName}
AllowNoIcons=yes
LicenseFile=LICENSE.txt
OutputDir=installer-output
OutputBaseFilename=OPSIS-Agent-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
DisableProgramGroupPage=yes
; Icon files (if available)
#ifexist "assets\icon.ico"
UninstallDisplayIcon={app}\assets\icon.ico
SetupIconFile=assets\icon.ico
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "Start Control Panel on Windows startup"; GroupDescription: "Startup Options:"

[Files]
; Application files
Source: "dist\*"; DestDir: "{app}\dist"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "node_modules\*"; DestDir: "{app}\node_modules"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "package.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "scripts\install-service.js"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "scripts\uninstall-service.js"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

; Runbooks (required at runtime)
Source: "runbooks\*"; DestDir: "{app}\runbooks"; Flags: ignoreversion recursesubdirs createallsubdirs

; Assets (optional - only if folder exists)
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

; Config template
Source: "config\agent.config.json"; DestDir: "{app}\config"; Flags: ignoreversion skipifsourcedoesntexist

; Bundled Node.js runtime
Source: "nodejs\node.exe"; DestDir: "{app}\nodejs"; Flags: ignoreversion

[Dirs]
Name: "{app}\data"
Name: "{app}\logs"
Name: "{app}\certs"

[Icons]
Name: "{group}\OPSIS Control Panel"; Filename: "{app}\node_modules\electron\dist\electron.exe"; Parameters: """{app}\dist\gui\electron-main.js"""; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"
Name: "{autodesktop}\OPSIS Control Panel"; Filename: "{app}\node_modules\electron\dist\electron.exe"; Parameters: """{app}\dist\gui\electron-main.js"""; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"; Tasks: desktopicon

[Run]
; Install Windows Service (using bundled Node.js)
Filename: "{app}\nodejs\node.exe"; Parameters: """{app}\scripts\install-service.js"""; WorkingDir: "{app}"; StatusMsg: "Installing OPSIS Agent Service..."; Flags: runhidden waituntilterminated

; Offer to launch GUI
Filename: "{app}\node_modules\electron\dist\electron.exe"; Parameters: """{app}\dist\gui\electron-main.js"""; WorkingDir: "{app}"; Description: "Launch OPSIS Control Panel"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop and uninstall service (using bundled Node.js)
Filename: "{app}\nodejs\node.exe"; Parameters: """{app}\scripts\uninstall-service.js"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated

[Registry]
; Add to startup (if selected)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "OPSIS Agent"; ValueData: """{app}\node_modules\electron\dist\electron.exe"" ""{app}\dist\gui\electron-main.js"""; Tasks: autostart

[Code]
var
  ServerURLPage: TInputQueryWizardPage;

function InitializeSetup(): Boolean;
begin
  // Node.js is bundled - no external dependency check needed
  Result := True;
end;

procedure InitializeWizard;
begin
  // Create custom page for server URL and API key
  ServerURLPage := CreateInputQueryPage(wpSelectDir,
    'OPSIS Server Configuration',
    'Enter your OPSIS server connection details',
    'Enter the server URL and API key provided by your OPSIS administrator.');

  ServerURLPage.Add('Server URL (e.g., ws://opsis.yourdomain.com:8000):', False);
  ServerURLPage.Add('API Key (e.g., opsis_xxxxxxxxxxxx):', False);
  ServerURLPage.Values[0] := '';
  ServerURLPage.Values[1] := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigFile: string;
  ConfigContent: string;
begin
  if CurStep = ssPostInstall then
  begin
    // Create agent.config.json with server URL if provided
    ConfigFile := ExpandConstant('{app}\data\agent.config.json');
    
    ConfigContent := '{' + #13#10;
    
    if ServerURLPage.Values[0] <> '' then
      ConfigContent := ConfigContent + '  "serverUrl": "' + ServerURLPage.Values[0] + '",' + #13#10
    else
      ConfigContent := ConfigContent + '  "serverUrl": null,' + #13#10;

    if ServerURLPage.Values[1] <> '' then
      ConfigContent := ConfigContent + '  "apiKey": "' + ServerURLPage.Values[1] + '",' + #13#10
    else
      ConfigContent := ConfigContent + '  "apiKey": "",' + #13#10;

    ConfigContent := ConfigContent + '  "autoConnect": true,' + #13#10;
    ConfigContent := ConfigContent + '  "autoRemediation": true,' + #13#10;
    ConfigContent := ConfigContent + '  "autoUpdate": false,' + #13#10;
    ConfigContent := ConfigContent + '  "confidenceThreshold": 75,' + #13#10;
    ConfigContent := ConfigContent + '  "updateCheckInterval": 60' + #13#10;
    ConfigContent := ConfigContent + '}';
    
    SaveStringToFile(ConfigFile, ConfigContent, False);
  end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if MsgBox('Do you want to keep your logs and configuration data?', mbConfirmation, MB_YESNO) = IDNO then
    begin
      DelTree(ExpandConstant('{app}\data'), True, True, True);
      DelTree(ExpandConstant('{app}\logs'), True, True, True);
    end;
  end;
end;
