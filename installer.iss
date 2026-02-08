; OPSIS Agent Installer - Inno Setup Script
; Service: compiled standalone exe (pkg). GUI: Tauri native binary (no Electron).

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
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
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
; Compiled service executable (standalone - no Node.js needed)
Source: "dist\opsis-agent-service.exe"; DestDir: "{app}\dist"; Flags: ignoreversion

; WinSW service wrapper
Source: "node_modules\node-windows\bin\winsw\winsw.exe"; DestDir: "{app}\service"; DestName: "OpsisAgentService.exe"; Flags: ignoreversion
Source: "node_modules\node-windows\bin\winsw\winsw.exe.config"; DestDir: "{app}\service"; DestName: "OpsisAgentService.exe.config"; Flags: ignoreversion

; GUI executable (Tauri - single native binary, no Electron needed)
Source: "src-tauri\target\release\opsis-agent-gui.exe"; DestDir: "{app}"; Flags: ignoreversion

; Runbooks (required at runtime)
Source: "runbooks\*"; DestDir: "{app}\runbooks"; Flags: ignoreversion recursesubdirs createallsubdirs

; Self-service portal
Source: "dist\portal\portal.html"; DestDir: "{app}\dist\portal"; Flags: ignoreversion

; GUI launcher batch file
Source: "start-opsis-gui.bat"; DestDir: "{app}"; Flags: ignoreversion

; Assets
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

; Config template
Source: "config\agent.config.json"; DestDir: "{app}\config"; Flags: ignoreversion skipifsourcedoesntexist
Source: "config\exclusions.json"; DestDir: "{app}\config"; Flags: ignoreversion

; License
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\config"
Name: "{app}\data"
Name: "{app}\logs"
Name: "{app}\certs"
Name: "{app}\service"
Name: "{app}\dist\portal"

[Icons]
Name: "{group}\OPSIS Control Panel"; Filename: "{app}\opsis-agent-gui.exe"; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"
Name: "{autodesktop}\OPSIS Control Panel"; Filename: "{app}\opsis-agent-gui.exe"; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"; Tasks: desktopicon

[Run]
; === SECURITY HARDENING ===

; 1. Set PowerShell execution policy (required for agent monitoring commands)
Filename: "powershell.exe"; Parameters: "-Command ""Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"""; StatusMsg: "Configuring PowerShell execution policy..."; Flags: runhidden waituntilterminated shellexec

; 2. Add Defender exclusions for install directory and service exe
Filename: "powershell.exe"; Parameters: "-Command ""Add-MpPreference -ExclusionPath '{app}'; Add-MpPreference -ExclusionProcess '{app}\dist\opsis-agent-service.exe'"""; StatusMsg: "Adding Defender exclusions..."; Flags: runhidden waituntilterminated shellexec

; 3. Lock down NTFS permissions: SYSTEM + Administrators full control, Users read+execute only
Filename: "powershell.exe"; Parameters: "-Command ""$path = '{app}'; icacls $path /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'BUILTIN\Users:(OI)(CI)RX' /T /Q"""; StatusMsg: "Setting directory permissions..."; Flags: runhidden waituntilterminated shellexec

; 4. Lock down data directory: SYSTEM + Administrators only (contains API key, tickets)
Filename: "powershell.exe"; Parameters: "-Command ""$path = '{app}\data'; icacls $path /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' /T /Q"""; StatusMsg: "Securing data directory..."; Flags: runhidden waituntilterminated shellexec

; 5. Lock down logs directory: SYSTEM + Administrators only
Filename: "powershell.exe"; Parameters: "-Command ""$path = '{app}\logs'; icacls $path /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' /T /Q"""; StatusMsg: "Securing logs directory..."; Flags: runhidden waituntilterminated shellexec

; 6. Lock down certs directory: SYSTEM + Administrators only
Filename: "powershell.exe"; Parameters: "-Command ""$path = '{app}\certs'; icacls $path /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' /T /Q"""; StatusMsg: "Securing certificate directory..."; Flags: runhidden waituntilterminated shellexec

; 7. Register Windows Event Log source for OPSIS
Filename: "powershell.exe"; Parameters: "-Command ""if (-not [System.Diagnostics.EventLog]::SourceExists('OPSIS Agent')) {{ New-EventLog -LogName Application -Source 'OPSIS Agent' -ErrorAction SilentlyContinue }}"""; StatusMsg: "Registering event log source..."; Flags: runhidden waituntilterminated shellexec

; 8. Store API key in Windows Credential Manager (DPAPI encrypted) if provided
Filename: "powershell.exe"; Parameters: "-Command ""$key = Get-Content '{app}\data\agent.config.json' -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json | Select-Object -ExpandProperty apiKey -ErrorAction SilentlyContinue; if ($key -and $key -ne '') {{ cmdkey /generic:OPSISAgent_ApiKey /user:opsis /pass:$key | Out-Null; Write-Host 'API key stored in Credential Manager' }}"""; StatusMsg: "Securing API credentials..."; Flags: runhidden waituntilterminated shellexec

; 9. Generate IPC authentication secret for GUI-to-service communication
Filename: "powershell.exe"; Parameters: "-Command ""$secret = [System.Convert]::ToBase64String((1..32 | ForEach-Object {{ [byte](Get-Random -Minimum 0 -Maximum 256) }})); $regPath = 'HKLM:\SOFTWARE\OPSIS\Agent'; if (-not (Test-Path $regPath)) {{ New-Item -Path $regPath -Force | Out-Null }}; Set-ItemProperty -Path $regPath -Name 'IPCSecret' -Value $secret"""; StatusMsg: "Generating IPC authentication secret..."; Flags: runhidden waituntilterminated shellexec

; === SERVICE INSTALLATION ===

; 10. Install and start Windows Service using WinSW
Filename: "{app}\service\OpsisAgentService.exe"; Parameters: "install"; WorkingDir: "{app}\service"; StatusMsg: "Installing OPSIS Agent Service..."; Flags: runhidden waituntilterminated
Filename: "{app}\service\OpsisAgentService.exe"; Parameters: "start"; WorkingDir: "{app}\service"; StatusMsg: "Starting OPSIS Agent Service..."; Flags: runhidden waituntilterminated

; Offer to launch GUI
Filename: "{app}\opsis-agent-gui.exe"; WorkingDir: "{app}"; Description: "Launch OPSIS Control Panel"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Kill any running Tauri GUI processes first
Filename: "powershell.exe"; Parameters: "-Command ""Get-Process -Name opsis-agent-gui -ErrorAction SilentlyContinue | Stop-Process -Force"""; Flags: runhidden waituntilterminated; RunOnceId: "KillGUI"
; Stop and uninstall service
Filename: "{app}\service\OpsisAgentService.exe"; Parameters: "stop"; WorkingDir: "{app}\service"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\service\OpsisAgentService.exe"; Parameters: "uninstall"; WorkingDir: "{app}\service"; Flags: runhidden waituntilterminated; RunOnceId: "UninstallService"
; Remove stored credentials from Credential Manager
Filename: "powershell.exe"; Parameters: "-Command ""cmdkey /delete:OPSISAgent_ApiKey -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; RunOnceId: "DeleteCreds"
; Remove OPSIS registry keys
Filename: "powershell.exe"; Parameters: "-Command ""Remove-Item -Path 'HKLM:\SOFTWARE\OPSIS' -Recurse -Force -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanRegistry"
; Remove Defender exclusions
Filename: "powershell.exe"; Parameters: "-Command ""Remove-MpPreference -ExclusionPath '{app}' -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionProcess '{app}\dist\opsis-agent-service.exe' -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanDefender"
; Remove Event Log source
Filename: "powershell.exe"; Parameters: "-Command ""Remove-EventLog -Source 'OPSIS Agent' -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanEventLog"

[Registry]
; Add to startup for all users (if selected) - uses HKLM since installer runs as admin
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "OPSIS Agent"; ValueData: """{app}\opsis-agent-gui.exe"""; Tasks: autostart; Flags: uninsdeletevalue

[Code]
var
  ServerURLPage: TInputQueryWizardPage;

function InitializeSetup(): Boolean;
begin
  Result := True;
end;

procedure InitializeWizard;
begin
  // Create custom page for server URL and API key
  ServerURLPage := CreateInputQueryPage(wpSelectDir,
    'OPSIS Server Configuration',
    'Enter your OPSIS server connection details',
    'Enter the server URL and API key provided by your OPSIS administrator.');

  ServerURLPage.Add('Server URL (e.g., wss://opsis.yourdomain.com):', False);
  ServerURLPage.Add('API Key (e.g., opsis_xxxxxxxxxxxx):', False);
  ServerURLPage.Values[0] := '';
  ServerURLPage.Values[1] := '';
end;

procedure CreateServiceConfig();
var
  ConfigFile: string;
  ConfigContent: string;
  ServiceExe: string;
  AppPath: string;
begin
  AppPath := ExpandConstant('{app}');
  ServiceExe := AppPath + '\dist\opsis-agent-service.exe';
  ConfigFile := AppPath + '\service\OpsisAgentService.xml';

  ConfigContent := '<?xml version="1.0" encoding="UTF-8"?>' + #13#10;
  ConfigContent := ConfigContent + '<service>' + #13#10;
  ConfigContent := ConfigContent + '  <id>OpsisAgentService</id>' + #13#10;
  ConfigContent := ConfigContent + '  <name>OPSIS Agent Service</name>' + #13#10;
  ConfigContent := ConfigContent + '  <description>OPSIS Autonomous IT Management Agent</description>' + #13#10;
  ConfigContent := ConfigContent + '  <executable>' + ServiceExe + '</executable>' + #13#10;
  ConfigContent := ConfigContent + '  <arguments></arguments>' + #13#10;
  ConfigContent := ConfigContent + '  <logmode>rotate</logmode>' + #13#10;
  ConfigContent := ConfigContent + '  <logpath>' + AppPath + '\logs</logpath>' + #13#10;
  ConfigContent := ConfigContent + '  <workingdirectory>' + AppPath + '</workingdirectory>' + #13#10;
  ConfigContent := ConfigContent + '  <priority>Normal</priority>' + #13#10;
  ConfigContent := ConfigContent + '  <stoptimeout>30sec</stoptimeout>' + #13#10;
  ConfigContent := ConfigContent + '  <startmode>Automatic</startmode>' + #13#10;
  ConfigContent := ConfigContent + '  <env name="NODE_ENV" value="production"/>' + #13#10;
  ConfigContent := ConfigContent + '  <onfailure action="restart" delay="10 sec"/>' + #13#10;
  ConfigContent := ConfigContent + '  <onfailure action="restart" delay="20 sec"/>' + #13#10;
  ConfigContent := ConfigContent + '  <onfailure action="none"/>' + #13#10;
  ConfigContent := ConfigContent + '  <resetfailure>1 hour</resetfailure>' + #13#10;
  ConfigContent := ConfigContent + '</service>' + #13#10;

  SaveStringToFile(ConfigFile, ConfigContent, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigFile: string;
  ConfigContent: string;
begin
  if CurStep = ssPostInstall then
  begin
    // Create WinSW service configuration
    CreateServiceConfig();

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
