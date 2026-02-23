; OPSIS Agent Installer - Inno Setup Script
; Service: compiled standalone exe (pkg). GUI: localhost web UI served by agent service.

#define AppName "OPSIS Agent"
#define AppVersion "1.3.2"
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

[Files]
; Visual C++ Redistributable (required by keytar.node native module)
; Extracted early via nocompression so PrepareToInstall can run it before [Files] phase
Source: "tools\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall nocompression

; Compiled service executable (standalone - no Node.js needed)
Source: "dist\opsis-agent-service.exe"; DestDir: "{app}\dist"; Flags: ignoreversion

; Native module: keytar for Windows Credential Manager (DPAPI-encrypted credential storage)
Source: "node_modules\keytar\build\Release\keytar.node"; DestDir: "{app}\dist"; Flags: ignoreversion

; WinSW v2.12.0 self-contained service wrapper (bundles .NET runtime - no .NET install required)
Source: "tools\winsw\WinSW-x64.exe"; DestDir: "{app}\service"; DestName: "OpsisAgentService.exe"; Flags: ignoreversion

; Control panel web UI (served by agent service on localhost:19851)
Source: "src\gui\index.html"; DestDir: "{app}\dist\gui"; Flags: ignoreversion
Source: "src\gui\assets\*"; DestDir: "{app}\dist\gui\assets"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

; Runbooks (required at runtime)
Source: "runbooks\*"; DestDir: "{app}\runbooks"; Flags: ignoreversion recursesubdirs createallsubdirs

; Self-service portal
Source: "dist\portal\portal.html"; DestDir: "{app}\dist\portal"; Flags: ignoreversion

; Assets
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

; Config template
Source: "config\agent.config.json"; DestDir: "{app}\config"; Flags: ignoreversion skipifsourcedoesntexist
Source: "config\exclusions.json"; DestDir: "{app}\config"; Flags: ignoreversion

; Installer scripts
Source: "scripts\store-apikey.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "scripts\remove-credentials.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion

; License
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\config"
Name: "{app}\data"
Name: "{app}\logs"
Name: "{app}\certs"
Name: "{app}\service"
Name: "{app}\dist\portal"
Name: "{app}\dist\gui"
Name: "{app}\dist\gui\assets"

[Icons]
Name: "{group}\OPSIS Control Panel"; Filename: "http://localhost:19851"; IconFilename: "{app}\assets\icon.ico"
Name: "{autodesktop}\OPSIS Control Panel"; Filename: "http://localhost:19851"; IconFilename: "{app}\assets\icon.ico"; Tasks: desktopicon

[Run]
; === SECURITY HARDENING ===

; 1. Set PowerShell execution policy (required for agent monitoring commands)
Filename: "powershell.exe"; Parameters: "-Command ""Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"""; StatusMsg: "Configuring PowerShell execution policy..."; Flags: runhidden waituntilterminated shellexec

; 2. Defender exclusions are now applied in PrepareToInstall() before files are copied.
;    Re-apply here in case PrepareToInstall path differed (e.g. user changed install dir).
Filename: "powershell.exe"; Parameters: "-Command ""Add-MpPreference -ExclusionPath '{app}' -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionProcess '{app}\dist\opsis-agent-service.exe' -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionProcess '{app}\service\OpsisAgentService.exe' -ErrorAction SilentlyContinue"""; StatusMsg: "Verifying Defender exclusions..."; Flags: runhidden waituntilterminated shellexec

; 3. Set directory permissions
; First reset inheritance on the entire app directory to ensure clean state on reinstall,
; then grant SYSTEM + Administrators full control and Users read+execute on the app root.
; Sensitive subdirectories (data, logs, certs) are then locked to SYSTEM + Admins only.
; The service directory must be readable by SYSTEM for WinSW to load its XML config.

; 3a. Reset and set base permissions on entire install directory
Filename: "powershell.exe"; Parameters: "-Command ""icacls '{app}' /reset /T /Q; icacls '{app}' /grant 'NT AUTHORITY\SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'BUILTIN\Users:(OI)(CI)RX' /T /Q"""; StatusMsg: "Setting base directory permissions..."; Flags: runhidden waituntilterminated shellexec

; 3b. Lock down data directory: SYSTEM + Administrators only (contains API key, tickets)
Filename: "powershell.exe"; Parameters: "-Command ""icacls '{app}\data' /inheritance:r /grant:r 'NT AUTHORITY\SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' /T /Q"""; StatusMsg: "Securing data directory..."; Flags: runhidden waituntilterminated shellexec

; 3c. Lock down logs directory: SYSTEM + Administrators only
Filename: "powershell.exe"; Parameters: "-Command ""icacls '{app}\logs' /inheritance:r /grant:r 'NT AUTHORITY\SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' /T /Q"""; StatusMsg: "Securing logs directory..."; Flags: runhidden waituntilterminated shellexec

; 3d. Lock down certs directory: SYSTEM + Administrators only
Filename: "powershell.exe"; Parameters: "-Command ""icacls '{app}\certs' /inheritance:r /grant:r 'NT AUTHORITY\SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' /T /Q"""; StatusMsg: "Securing certificate directory..."; Flags: runhidden waituntilterminated shellexec

; 7. Register Windows Event Log source for OPSIS
Filename: "powershell.exe"; Parameters: "-Command ""if (-not [System.Diagnostics.EventLog]::SourceExists('OPSIS Agent')) {{ New-EventLog -LogName Application -Source 'OPSIS Agent' -ErrorAction SilentlyContinue }}"""; StatusMsg: "Registering event log source..."; Flags: runhidden waituntilterminated shellexec

; 8. Store API key in Windows Credential Manager (DPAPI encrypted) if provided
; Keytar uses 'OPSIS-Agent:apiKey' as credential target — cmdkey can't handle colons,
; so we use a PowerShell script with Win32 CredWrite API to match keytar's format
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\scripts\store-apikey.ps1"" -ConfigPath ""{app}\data\agent.config.json"""; StatusMsg: "Securing API credentials..."; Flags: runhidden waituntilterminated shellexec

; 9. Generate IPC authentication secret for GUI-to-service communication
Filename: "powershell.exe"; Parameters: "-Command ""$secret = [System.Convert]::ToBase64String((1..32 | ForEach-Object {{ [byte](Get-Random -Minimum 0 -Maximum 256) }})); $regPath = 'HKLM:\SOFTWARE\OPSIS\Agent'; if (-not (Test-Path $regPath)) {{ New-Item -Path $regPath -Force | Out-Null }}; Set-ItemProperty -Path $regPath -Name 'IPCSecret' -Value $secret"""; StatusMsg: "Generating IPC authentication secret..."; Flags: runhidden waituntilterminated shellexec

; === SERVICE INSTALLATION ===
; Service install/start is handled in CurStepChanged(ssPostInstall) for better error capture.

; 10. Verify service is running; retry start if stopped
Filename: "powershell.exe"; Parameters: "-Command ""$svc = Get-Service -Name 'OpsisAgentService' -ErrorAction SilentlyContinue; if ($svc -and $svc.Status -ne 'Running') {{ Start-Service -Name 'OpsisAgentService' -ErrorAction SilentlyContinue }}"""; StatusMsg: "Verifying service status..."; Flags: runhidden waituntilterminated shellexec

; Offer to open control panel in browser
Filename: "cmd.exe"; Parameters: "/c start http://localhost:19851"; Description: "Open OPSIS Control Panel"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
; Stop and uninstall service
Filename: "{app}\service\OpsisAgentService.exe"; Parameters: "stop"; WorkingDir: "{app}\service"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\service\OpsisAgentService.exe"; Parameters: "uninstall"; WorkingDir: "{app}\service"; Flags: runhidden waituntilterminated; RunOnceId: "UninstallService"
; Remove stored credentials from Credential Manager (cmdkey-stored + keytar-stored)
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\scripts\remove-credentials.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "DeleteCreds"
; Remove OPSIS registry keys
Filename: "powershell.exe"; Parameters: "-Command ""Remove-Item -Path 'HKLM:\SOFTWARE\OPSIS' -Recurse -Force -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanRegistry"
; Remove Defender exclusions
Filename: "powershell.exe"; Parameters: "-Command ""Remove-MpPreference -ExclusionPath '{app}' -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionProcess '{app}\dist\opsis-agent-service.exe' -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionProcess '{app}\service\OpsisAgentService.exe' -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanDefender"
; Remove Event Log source
Filename: "powershell.exe"; Parameters: "-Command ""Remove-EventLog -Source 'OPSIS Agent' -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanEventLog"

[Registry]
; No autostart registry entry needed — the service starts automatically and the control panel is just a web page

[Code]
var
  ServerURLPage: TInputQueryWizardPage;

function IsVCRedistInstalled(): Boolean;
var
  Version: String;
begin
  Result := RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Version', Version);
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  ServiceExe: string;
  AppPath: string;
begin
  Result := '';
  NeedsRestart := False;
  AppPath := ExpandConstant('{app}');
  ServiceExe := AppPath + '\service\OpsisAgentService.exe';

  // Install Visual C++ Redistributable if missing (required by keytar.node native module).
  // The vc_redist.x64.exe is available here because it uses Flags: nocompression in [Files],
  // which causes Inno Setup to extract it before PrepareToInstall runs.
  if not IsVCRedistInstalled() then
  begin
    if FileExists(ExpandConstant('{tmp}\vc_redist.x64.exe')) then
      Exec(ExpandConstant('{tmp}\vc_redist.x64.exe'), '/install /quiet /norestart', '',
        SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if not IsVCRedistInstalled() then
    begin
      Result := 'Visual C++ Redistributable could not be installed. Please install it manually from https://aka.ms/vs/17/release/vc_redist.x64.exe and re-run this installer.';
      Exit;
    end;
  end;

  // Add Defender exclusions BEFORE files are copied to prevent quarantine on fresh machines.
  // The [Files] section runs after PrepareToInstall, so exclusions must be set here.
  Exec('powershell.exe', '-Command "Add-MpPreference -ExclusionPath ''' + AppPath + ''' -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionProcess ''' + AppPath + '\dist\opsis-agent-service.exe'' -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionProcess ''' + AppPath + '\service\OpsisAgentService.exe'' -ErrorAction SilentlyContinue"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Brief pause to let Defender apply the exclusion
  Sleep(1000);

  // Clean up any orphaned service registration (e.g. from a previous failed install where
  // the exe no longer exists but the service name is still registered in SCM).
  // sc delete is harmless if the service doesn't exist.
  Exec('sc.exe', 'stop OpsisAgentService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
  Exec('sc.exe', 'delete OpsisAgentService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);

  // If OpsisAgentService.exe exists from a previous install, stop and uninstall via WinSW too
  if FileExists(ServiceExe) then
  begin
    Exec(ServiceExe, 'stop', AppPath + '\service', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(2000);
    Exec(ServiceExe, 'uninstall', AppPath + '\service', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1000);
  end;

  // Remove leftover .exe.config from previous installs that used .NET Framework WinSW
  DeleteFile(AppPath + '\service\OpsisAgentService.exe.config');

  // Also kill any lingering opsis-agent-service.exe process
  Exec('taskkill.exe', '/F /IM opsis-agent-service.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);
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

function NextButtonClick(CurPageID: Integer): Boolean;
var
  URL, Key, Tmp: string;
begin
  Result := True;
  if CurPageID = ServerURLPage.ID then
  begin
    URL := Trim(ServerURLPage.Values[0]);
    Key := Trim(ServerURLPage.Values[1]);

    // Both blank is fine (skip configuration)
    if (URL = '') and (Key = '') then
      Exit;

    // Detect swap: URL field has an API key, Key field has a URL
    if ((Pos('opsis_', URL) = 1) or (Pos('OPSIS_', URL) = 1)) and
       ((Pos('://', Key) > 0) or (Pos('.', Key) > 0)) then
    begin
      // Auto-swap the values
      Tmp := URL;
      ServerURLPage.Values[0] := Key;
      ServerURLPage.Values[1] := Tmp;
      MsgBox('It looks like the Server URL and API Key were entered in the wrong fields. They have been swapped automatically. Please verify and click Next again.', mbInformation, MB_OK);
      Result := False;
      Exit;
    end;

    // Validate URL field doesn't look like an API key
    if (Pos('opsis_', URL) = 1) or (Pos('OPSIS_', URL) = 1) then
    begin
      MsgBox('The Server URL field appears to contain an API key.' + #13#10 +
        'Please enter the server URL (e.g., wss://opsis.yourdomain.com) in the first field' + #13#10 +
        'and the API key (e.g., opsis_xxxx) in the second field.', mbError, MB_OK);
      Result := False;
      Exit;
    end;

    // Validate Key field doesn't look like a URL
    if (Pos('://', Key) > 0) or (Pos('wss:', Key) > 0) or (Pos('ws:', Key) > 0) or (Pos('http', Key) > 0) then
    begin
      MsgBox('The API Key field appears to contain a URL.' + #13#10 +
        'Please enter the API key (e.g., opsis_xxxx) in the second field' + #13#10 +
        'and the server URL in the first field.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;
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
  ExitCode: Integer;
  InstallOK: Boolean;
  AppPath: string;
  WinSWExe: string;
  LogFile: string;
begin
  if CurStep = ssPostInstall then
  begin
    // Create WinSW service configuration
    CreateServiceConfig();

    // Create agent.config.json only if it doesn't exist or user provided new values.
    // On reinstall/upgrade, preserve the existing config (already has serverUrl + apiKey).
    ConfigFile := ExpandConstant('{app}\data\agent.config.json');

    if (not FileExists(ConfigFile)) or (ServerURLPage.Values[0] <> '') or (ServerURLPage.Values[1] <> '') then
    begin
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

    // === SERVICE INSTALLATION (moved from [Run] for error capture) ===
    AppPath := ExpandConstant('{app}');
    WinSWExe := AppPath + '\service\OpsisAgentService.exe';
    LogFile := AppPath + '\logs\winsw-install.log';

    // Install service and log output for diagnostics
    InstallOK := False;
    Exec('powershell.exe',
      '-Command "& ''' + WinSWExe + ''' install 2>&1 | Out-File -FilePath ''' + LogFile + ''' -Encoding UTF8"',
      AppPath + '\service', SW_HIDE, ewWaitUntilTerminated, ExitCode);

    // Verify the service was registered
    if Exec('sc.exe', 'query OpsisAgentService', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    begin
      if ExitCode = 0 then
        InstallOK := True;
    end;

    if not InstallOK then
    begin
      // Try direct execution as fallback (without PowerShell wrapper)
      Exec(WinSWExe, 'install', AppPath + '\service', SW_HIDE, ewWaitUntilTerminated, ExitCode);
      // Check again
      if Exec('sc.exe', 'query OpsisAgentService', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
      begin
        if ExitCode = 0 then
          InstallOK := True;
      end;
    end;

    if InstallOK then
    begin
      // Start the service
      Exec(WinSWExe, 'start', AppPath + '\service', SW_HIDE, ewWaitUntilTerminated, ExitCode);
    end;
  end;

  if CurStep = ssDone then
  begin
    // Final verification: check if the service exists
    if Exec('sc.exe', 'query OpsisAgentService', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    begin
      if ExitCode <> 0 then
      begin
        if not FileExists(ExpandConstant('{app}\service\OpsisAgentService.exe')) or
           not FileExists(ExpandConstant('{app}\dist\opsis-agent-service.exe')) then
          MsgBox('The OPSIS Agent Service could not be installed because Windows Defender appears to have quarantined the service files.' + #13#10 + #13#10 +
            'To fix this:' + #13#10 +
            '1. Open Windows Security > Virus & threat protection > Protection history' + #13#10 +
            '2. Restore any quarantined OPSIS files' + #13#10 +
            '3. Re-run this installer to complete setup', mbError, MB_OK)
        else
          MsgBox('The OPSIS Agent Service could not be registered.' + #13#10 + #13#10 +
            'Diagnostic log saved to:' + #13#10 +
            ExpandConstant('{app}\logs\winsw-install.log') + #13#10 + #13#10 +
            'Common fixes:' + #13#10 +
            '1. Check the log file above for the specific error' + #13#10 +
            '2. Run "sc delete OpsisAgentService" from an admin command prompt, then re-run this installer' + #13#10 +
            '3. Ensure no Group Policy is blocking service creation', mbError, MB_OK);
      end;
    end;
  end;
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;

  // If not running elevated, re-launch the uninstaller with admin rights
  if not IsAdmin then
  begin
    if ShellExec('runas', ExpandConstant('{uninstallexe}'), '', '', SW_SHOWNORMAL, ewNoWait, ResultCode) then
    begin
      // Elevated instance launched — close this non-elevated one
      Result := False;
    end
    else
    begin
      MsgBox('Administrator privileges are required to uninstall OPSIS Agent. Please right-click and select "Run as administrator".', mbError, MB_OK);
      Result := False;
    end;
  end;
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
