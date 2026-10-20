; NetScope Windows installer (Inno Setup 6.1+). Built by scripts\build-installer.ps1,
; which passes the version and the directory with the release binaries:
;   ISCC.exe /DAppVersion=0.2.0 /DBinDir=..\target\release installer\netscope.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef BinDir
  #define BinDir "..\target\release"
#endif
#define AppName "NetScope"
#define AppPublisher "netscope project"
#define AppURL "https://github.com/netscope"
#define NpcapUrl "https://npcap.com/dist/npcap-1.89.exe"
; Evergreen bootstrapper: installs the WebView2 runtime that hosts the dashboard window.
#define WebView2Url "https://go.microsoft.com/fwlink/p/?LinkId=2124703"

[Setup]
AppId={{7D5B2C1E-5A7F-4E1B-9C3A-NETSCOPE0001}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Per-user install without UAC, or for all users when started elevated.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=NetScope-Setup-{#AppVersion}
SetupIconFile=..\assets\netscope.ico
UninstallDisplayIcon={app}\netscope-app.exe
UninstallDisplayName={#AppName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ShowLanguageDialog=auto
LicenseFile=..\LICENSE
CloseApplications=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[CustomMessages]
en.TaskDesktop=Create a &desktop shortcut
en.TaskAutostart=Start NetScope when I sign in to &Windows
en.TaskGeoip=Download geolocation data now (~140 MB, DB-IP Lite, CC BY 4.0)
en.TaskEgress=Allow the public IP check through cloudflare.com (shows the internet exit point)
en.RunApp=Start NetScope now
en.NpcapCaption=Packet capture driver
en.NpcapDescription=NetScope needs Npcap to see network traffic.
en.NpcapMissing=Npcap is not installed on this computer. Setup can download the Npcap installer from npcap.com and run it; keep "Install Npcap in WinPcap API-compatible Mode" checked. Without Npcap, NetScope can only open capture files and run the demo.
en.NpcapPresent=Npcap is already installed. Nothing to do here.
en.NpcapInstall=Download and install Npcap (recommended)
en.NpcapSkip=Skip, I will install it later from npcap.com
en.NpcapDownloading=Downloading Npcap…
en.NpcapFailed=The Npcap download or installation did not finish. You can install it later from https://npcap.com; NetScope will explain this again when it starts.
en.GeoipDownloading=Downloading geolocation databases…
en.GeoipFailed=The geolocation data could not be downloaded. You can do it later from the NetScope tray icon menu.
en.WebView2Installing=Installing the Microsoft Edge WebView2 runtime (needed for the program window)...
en.WebView2Failed=The WebView2 runtime could not be installed. NetScope will open its dashboard in your browser instead; you can install the runtime later from https://developer.microsoft.com/microsoft-edge/webview2/.
ru.TaskDesktop=Создать ярлык на &рабочем столе
ru.TaskAutostart=Запускать NetScope при входе в &Windows
ru.TaskGeoip=Скачать геоданные сейчас (~140 МБ, DB-IP Lite, CC BY 4.0)
ru.TaskEgress=Разрешить проверку внешнего IP через cloudflare.com (показывает точку выхода в интернет)
ru.RunApp=Запустить NetScope
ru.NpcapCaption=Драйвер захвата пакетов
ru.NpcapDescription=Чтобы видеть сетевой трафик, NetScope нужен драйвер Npcap.
ru.NpcapMissing=Npcap на этом компьютере не установлен. Установщик может скачать его с npcap.com и запустить; оставьте включённым пункт «Install Npcap in WinPcap API-compatible Mode». Без Npcap NetScope сможет только открывать файлы захвата и работать в демо-режиме.
ru.NpcapPresent=Npcap уже установлен. Здесь ничего делать не нужно.
ru.NpcapInstall=Скачать и установить Npcap (рекомендуется)
ru.NpcapSkip=Пропустить, установлю позже с npcap.com
ru.NpcapDownloading=Загрузка Npcap…
ru.NpcapFailed=Загрузка или установка Npcap не завершилась. Его можно поставить позже с https://npcap.com; NetScope напомнит об этом при запуске.
ru.GeoipDownloading=Загрузка баз геоданных…
ru.GeoipFailed=Не удалось скачать геоданные. Это можно сделать позже из меню значка NetScope в трее.
ru.WebView2Installing=Установка среды Microsoft Edge WebView2 (нужна для окна программы)...
ru.WebView2Failed=Не удалось установить среду WebView2. NetScope будет открывать панель в браузере; среду можно поставить позже с https://developer.microsoft.com/microsoft-edge/webview2/.

[Tasks]
Name: "desktopicon"; Description: "{cm:TaskDesktop}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "{cm:TaskAutostart}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "geoip"; Description: "{cm:TaskGeoip}"; GroupDescription: "{#AppName}:"
Name: "egress"; Description: "{cm:TaskEgress}"; GroupDescription: "{#AppName}:"

[Files]
Source: "{#BinDir}\netscope-app.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\netscope.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\webview2\WebView2Loader.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\webview2\LICENSE.txt"; DestDir: "{app}"; DestName: "LICENSE-WebView2Loader.txt"; Flags: ignoreversion
Source: "..\scripts\fetch-geoip.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{localappdata}\NetScope"; Check: not IsAdminInstallMode
Name: "{localappdata}\NetScope\geoip"; Check: not IsAdminInstallMode
Name: "{commonappdata}\NetScope\geoip"; Check: IsAdminInstallMode

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\netscope-app.exe"; Comment: "Network traffic analyzer"
Name: "{group}\{#AppName} (console)"; Filename: "{app}\netscope.exe"; Parameters: "--open"; Comment: "NetScope with a console window"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\netscope-app.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "NetScope"; ValueData: """{app}\netscope-app.exe"""; Flags: uninsdeletevalue; Tasks: autostart
; An entry the user enabled from the tray menu survives upgrades but is removed on uninstall.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "NetScope"; Flags: uninsdeletevalue dontcreatekey

[Run]
; Geolocation data goes to the per-user data folder, where the program looks for it.
; Geolocation data: the installing user's folder, or ProgramData (read by every user) for an all-users install.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\fetch-geoip.ps1"" -Dir ""{localappdata}\NetScope\geoip"""; StatusMsg: "{cm:GeoipDownloading}"; Tasks: geoip; Check: not IsAdminInstallMode; Flags: runhidden waituntilterminated skipifsilent
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\fetch-geoip.ps1"" -Dir ""{commonappdata}\NetScope\geoip"""; StatusMsg: "{cm:GeoipDownloading}"; Tasks: geoip; Check: IsAdminInstallMode; Flags: runhidden waituntilterminated skipifsilent
Filename: "{app}\netscope-app.exe"; Description: "{cm:RunApp}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /IM netscope-app.exe /F & taskkill /IM netscope.exe /F"; Flags: runhidden; RunOnceId: "StopNetScope"

[UninstallDelete]
Type: files; Name: "{localappdata}\NetScope\netscope.log"
Type: files; Name: "{localappdata}\NetScope\netscope.log.1"
Type: files; Name: "{localappdata}\NetScope\dashboard.url"
Type: filesandordirs; Name: "{localappdata}\NetScope\WebView2"

[Code]
var
  NpcapPage: TInputOptionWizardPage;
  DownloadPage: TDownloadWizardPage;

function NpcapInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll')) or RegKeyExists(HKLM, 'SOFTWARE\Npcap');
end;

function WebView2Installed: Boolean;
var
  V: String;
begin
  // The Evergreen runtime registers per machine or per user; Edge itself also ships it.
  Result := RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', V) or
            RegQueryStringValue(HKCU, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', V) or
            DirExists(ExpandConstant('{commonpf32}\Microsoft\EdgeWebView\Application'));
end;

procedure InstallWebView2;
var
  Code: Integer;
begin
  if WebView2Installed or WizardSilent then
    exit;
  DownloadPage.Clear;
  DownloadPage.Add('{#WebView2Url}', 'MicrosoftEdgeWebview2Setup.exe', '');
  DownloadPage.SetText(CustomMessage('WebView2Installing'), '');
  DownloadPage.Show;
  try
    try
      DownloadPage.Download;
      // The bootstrapper installs silently; it downloads the runtime itself.
      if not Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe'), '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, Code) or not WebView2Installed then
        MsgBox(CustomMessage('WebView2Failed'), mbInformation, MB_OK);
    except
      MsgBox(CustomMessage('WebView2Failed'), mbInformation, MB_OK);
    end;
  finally
    DownloadPage.Hide;
  end;
end;

procedure StopRunningInstances;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{cmd}'), '/C taskkill /IM netscope-app.exe /F & taskkill /IM netscope.exe /F', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), nil);
  NpcapPage := CreateInputOptionPage(wpSelectTasks, CustomMessage('NpcapCaption'), CustomMessage('NpcapDescription'), '', True, False);
  if NpcapInstalled then
  begin
    NpcapPage.Add(CustomMessage('NpcapPresent'));
    NpcapPage.Values[0] := True;
    NpcapPage.CheckListBox.ItemEnabled[0] := False;
  end
  else
  begin
    NpcapPage.SubCaptionLabel.Caption := CustomMessage('NpcapMissing');
    NpcapPage.Add(CustomMessage('NpcapInstall'));
    NpcapPage.Add(CustomMessage('NpcapSkip'));
    NpcapPage.Values[0] := True;
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  // The question only matters when Npcap is missing.
  Result := (PageID = NpcapPage.ID) and NpcapInstalled;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  StopRunningInstances;
end;

procedure WriteSettings;
var
  Path, Text: String;
begin
  // Read by netscope-app.exe; hand-editable. Written only when it does not exist yet,
  // so an upgrade keeps the user's changes. An all-users install runs as an administrator
  // whose profile is not the user's: the program then starts with built-in defaults.
  if IsAdminInstallMode then
    exit;
  Path := ExpandConstant('{localappdata}\NetScope\netscope.ini');
  if FileExists(Path) then
    exit;
  Text := '# NetScope settings (key=value). Restart NetScope after editing.' + #13#10 +
          '# port=8888   (default; when it is busy the next free port is used)' + #13#10 +
          'host=127.0.0.1' + #13#10 +
          '# interface=' + #13#10 +
          '# filter=' + #13#10;
  if WizardIsTaskSelected('egress') then
    Text := Text + 'egress_check=1' + #13#10
  else
    Text := Text + 'egress_check=0' + #13#10;
  Text := Text + 'show_window=1' + #13#10 +
          '# notifications: medium (default), high or off' + #13#10 +
          'notifications=medium' + #13#10;
  SaveStringToFile(Path, Text, False);
end;

procedure InstallNpcap;
var
  Installer: String;
  Code: Integer;
begin
  // The Npcap installer needs clicks; an unattended setup leaves it to the user.
  if NpcapInstalled or WizardSilent or (NpcapPage.Values[0] = False) then
    exit;
  DownloadPage.Clear;
  DownloadPage.Add('{#NpcapUrl}', 'npcap-setup.exe', '');
  DownloadPage.Show;
  try
    try
      DownloadPage.Download;
      Installer := ExpandConstant('{tmp}\npcap-setup.exe');
      // The free Npcap installer does not accept silent switches; it needs the user's clicks.
      if not Exec(Installer, '', '', SW_SHOW, ewWaitUntilTerminated, Code) or not NpcapInstalled then
        MsgBox(CustomMessage('NpcapFailed'), mbInformation, MB_OK);
    except
      MsgBox(CustomMessage('NpcapFailed'), mbInformation, MB_OK);
    end;
  finally
    DownloadPage.Hide;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    WriteSettings;
    InstallWebView2;
    InstallNpcap;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    StopRunningInstances;
end;
