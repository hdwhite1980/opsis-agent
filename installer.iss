; OPSIS Agent Installer - Inno Setup Script (Simplified)
; Uses system Node.js instead of bundling it

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
Source: "dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "node_modules\*"; DestDir: "{app}\node_modules"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "package.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "scripts\*"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

; Assets (optional - only if folder exists)
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Dirs]
Name: "{app}\data"
Name: "{app}\logs"
Name: "{app}\certs"

[Icons]
Name: "{group}\OPSIS Control Panel"; Filename: "node"; Parameters: """{app}\node_modules\electron\dist\electron.exe"" ""{app}\dist\gui\electron-main.js"""; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"
Name: "{autodesktop}\OPSIS Control Panel"; Filename: "node"; Parameters: """{app}\node_modules\electron\dist\electron.exe"" ""{app}\dist\gui\electron-main.js"""; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"; Tasks: desktopicon

[Run]
; Install Windows Service
Filename: "node"; Parameters: """{app}\scripts\install-service.js"""; WorkingDir: "{app}"; StatusMsg: "Installing OPSIS Agent Service..."; Flags: runhidden waituntilterminated

; Offer to launch GUI
Filename: "node"; Parameters: """{app}\node_modules\electron\dist\electron.exe"" ""{app}\dist\gui\electron-main.js"""; WorkingDir: "{app}"; Description: "Launch OPSIS Control Panel"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop and uninstall service
Filename: "node"; Parameters: """{app}\scripts\uninstall-service.js"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated

[Registry]
; Add to startup (if selected)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "OPSIS Agent"; ValueData: "node ""{app}\node_modules\electron\dist\electron.exe"" ""{app}\dist\gui\electron-main.js"""; Tasks: autostart

[Code]
var
  ServerURLPage: TInputQueryWizardPage;
  NodeJSInstalled: Boolean;

function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  // Check if Node.js is installed
  NodeJSInstalled := Exec('node', '--version', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
  
  if not NodeJSInstalled then
  begin
    MsgBox('Node.js is not installed!' + #13#10 + #13#10 + 
           'OPSIS Agent requires Node.js to run.' + #13#10 + #13#10 +
           'Please install Node.js from:' + #13#10 +
           'https://nodejs.org/' + #13#10 + #13#10 +
           'Then run this installer again.', 
           mbError, MB_OK);
    Result := False;
  end
  else
  begin
    Result := True;
  end;
end;

procedure InitializeWizard;
begin
  // Create custom page for server URL
  ServerURLPage := CreateInputQueryPage(wpSelectDir,
    'OPSIS Server Configuration', 
    'Enter your OPSIS server details',
    'If you have a central OPSIS server, enter the URL below. Leave blank for standalone mode.');
  
  ServerURLPage.Add('Server URL (e.g., https://opsis.yourdomain.com):', False);
  ServerURLPage.Values[0] := '';
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
    
    ConfigContent := ConfigContent + '  "autoConnect": true,' + #13#10;
    ConfigContent := ConfigContent + '  "autoUpdate": true,' + #13#10;
    ConfigContent := ConfigContent + '  "localAI": true,' + #13#10;
    ConfigContent := ConfigContent + '  "autoRemediation": true,' + #13#10;
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
