; NSIS hooks (Tauri bundler). Names come from branding: PRODUCTNAME,
; MAINBINARYNAME and BUNDLEID are defined by Tauri from branding.properties
; (desktop/build.rs), never hard-coded here.
;
; 1. Firewall: inbound UDP for the LAN listener, Private network profile
;    only; removed again on uninstall. Per-machine install, so the installer
;    runs elevated and netsh can add the rule.
; 2. M1.1: a running Voidwire is closed silently (no "app is running"
;    dialog) before install, upgrade and uninstall. Install/upgrade close it
;    in every session (the per-machine exe must be replaced); uninstall closes
;    only the copy in the uninstalling user's session (QA 10-13).
; 3. The uninstaller's one data question (QA 10-13: Tauri's own "Delete the
;    application data" checkbox on the confirm page is skipped, so there is
;    only ours): "Remove all Voidwire data (keys, pairings)", checked by
;    default. It removes %APPDATA%\<BUNDLEID> and %LOCALAPPDATA%\<BUNDLEID>
;    (the WebView2 profile) of the user who started the uninstall: the
;    interactive user of this Windows session, resolved through
;    WTSQuerySessionInformation + their SID, not the account that approved
;    elevation (over-the-shoulder UAC). A silent uninstall (/S) removes the
;    data too. An upgrade (the installer running the old uninstaller, or
;    Tauri's /UPDATE) always keeps it.

!include "nsDialogs.nsh"

; Tauri defines PRODUCTNAME/MAINBINARYNAME/BUNDLEID only AFTER including this
; file, so top-level Functions below can't use them. scripts/tauri-dist-config.py
; renders this file into build/installer-hooks.nsh with the branding values
; filled in (the overlay points Tauri at that copy). Macros (expanded inside
; Tauri's sections) use Tauri's own defines.
!define /ifndef VW_APP_NAME "@APP_NAME@"
!define /ifndef VW_BINARY "@BINARY_NAME@"

!define VW_UPGRADE_ENV "VOIDWIRE_INSTALLER_UPGRADE"

; ---- close a running app, no prompt ----
!macro VW_KILL_APP
  ; Every session: install/upgrade must replace the per-machine exe.
  ; /T: child processes (WebView2) too. Exit code ignored (not running = fine).
  nsExec::Exec 'taskkill /F /T /IM "${VW_BINARY}.exe"'
  Pop $0
  Sleep 500
!macroend

; Installer GUI start: mark child processes (the old uninstaller that the
; reinstall page may run) as part of an upgrade, so they keep the data.
!define MUI_CUSTOMFUNCTION_GUIINIT VwInstallerGuiInit
Function VwInstallerGuiInit
  System::Call 'kernel32::SetEnvironmentVariable(t "${VW_UPGRADE_ENV}", t "1")'
FunctionEnd

; Leaving the Welcome page (the next MUI page Tauri inserts): close the app
; before the reinstall page can run an older uninstaller, whose own check
; would otherwise ask "is running, click OK to kill it".
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE VwWelcomeLeave
Function VwWelcomeLeave
  !insertmacro VW_KILL_APP
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
  !insertmacro VW_KILL_APP
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="${PRODUCTNAME} (LAN)"'
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="${PRODUCTNAME} (LAN)" dir=in action=allow program="$INSTDIR\${MAINBINARYNAME}.exe" protocol=UDP profile=private remoteip=localsubnet enable=yes description="${PRODUCTNAME}: receive links from your paired phone on your home network (Private networks only)."'
!macroend

; ---- uninstaller: the launching user ----
; Session of this process (an over-the-shoulder elevated uninstaller still
; runs in the standard user's session) and that session's interactive
; user's data folders. "" when unknown (then the current-user folders are
; used, as before).
Var VwSession
Var VwUserAppData
Var VwUserLocalAppData

Function un.VwResolveUser
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  StrCpy $VwSession ""
  StrCpy $VwUserAppData ""
  StrCpy $VwUserLocalAppData ""
  System::Call 'kernel32::GetCurrentProcessId() i .r0'
  System::Call 'kernel32::ProcessIdToSessionId(i r0, *i .r1) i .r2'
  ${If} $2 <> 0
    StrCpy $VwSession $1
  ${EndIf}
  ; WTS_CURRENT_SERVER_HANDLE=0, WTS_CURRENT_SESSION=-1, WTSUserName=5,
  ; WTSDomainName=7.
  StrCpy $3 ""
  StrCpy $4 ""
  System::Call 'wtsapi32::WTSQuerySessionInformationW(p 0, i -1, i 5, *p .r0, *i .r1) i .r2'
  ${If} $2 <> 0
    System::Call '*$0(&w${NSIS_MAX_STRLEN} .r3)'
    System::Call 'wtsapi32::WTSFreeMemory(p r0)'
  ${EndIf}
  System::Call 'wtsapi32::WTSQuerySessionInformationW(p 0, i -1, i 7, *p .r0, *i .r1) i .r2'
  ${If} $2 <> 0
    System::Call '*$0(&w${NSIS_MAX_STRLEN} .r4)'
    System::Call 'wtsapi32::WTSFreeMemory(p r0)'
  ${EndIf}
  ${If} $3 != ""
    ${If} $4 != ""
      StrCpy $3 "$4\$3"
    ${EndIf}
    ; Account name -> SID -> "S-1-5-21-...".
    System::Alloc 256
    Pop $0
    System::Call 'advapi32::LookupAccountNameW(p 0, w r3, p r0, *i 256, w .r4, *i ${NSIS_MAX_STRLEN}, *i .r1) i .r2'
    StrCpy $5 ""
    ${If} $2 <> 0
      System::Call 'advapi32::ConvertSidToStringSidW(p r0, *p .r1) i .r2'
      ${If} $2 <> 0
        System::Call '*$1(&w256 .r5)'
        System::Call 'kernel32::LocalFree(p r1)'
      ${EndIf}
    ${EndIf}
    System::Free $0
    ${If} $5 != ""
      ; The user is logged on (it is their session), so their hive is
      ; loaded under HKU; Shell Folders holds expanded paths (honours
      ; folder redirection).
      ReadRegStr $VwUserAppData HKU "$5\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" "AppData"
      ReadRegStr $VwUserLocalAppData HKU "$5\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" "Local AppData"
      ${If} $VwUserAppData == ""
      ${OrIf} $VwUserLocalAppData == ""
        ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$5" "ProfileImagePath"
        ${If} $0 != ""
          ExpandEnvStrings $0 $0
          StrCpy $VwUserAppData "$0\AppData\Roaming"
          StrCpy $VwUserLocalAppData "$0\AppData\Local"
        ${EndIf}
      ${EndIf}
    ${EndIf}
  ${EndIf}
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; ---- uninstaller: "Remove all data" page (first uninstaller page) ----
Var VwRemoveDataBox
; "" = page not shown (silent/passive) -> remove; "1" checked; "0" unchecked.
Var VwRemoveData

UninstPage custom un.VwDataPage un.VwDataLeave

Function un.VwDataPage
  ; Upgrades never show it (and keep the data).
  ReadEnvStr $0 "${VW_UPGRADE_ENV}"
  ${If} $0 == "1"
    Abort
  ${EndIf}
  ${GetOptions} $CMDLINE "/P" $0
  ${IfNot} ${Errors}
    Abort
  ${EndIf}
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 36u "Uninstall ${VW_APP_NAME}. Your pairing keys and paired devices are stored on this PC; leave the box checked to delete them as well."
  Pop $0
  ${NSD_CreateCheckbox} 0 44u 100% 12u "Remove all ${VW_APP_NAME} data (keys, pairings)"
  Pop $VwRemoveDataBox
  ${NSD_Check} $VwRemoveDataBox
  ; This page is the confirmation: its Next button uninstalls.
  GetDlgItem $0 $HWNDPARENT 1
  SendMessage $0 ${WM_SETTEXT} 0 "STR:$(^UninstallBtn)"
  nsDialogs::Show
FunctionEnd

Function un.VwDataLeave
  ${NSD_GetState} $VwRemoveDataBox $0
  ${If} $0 == ${BST_CHECKED}
    StrCpy $VwRemoveData "1"
  ${Else}
    StrCpy $VwRemoveData "0"
  ${EndIf}
  ; One data question only: skip Tauri's confirm page (and its unchecked
  ; "Delete the application data" box) and go straight to uninstalling.
  ; Pages: this one, Tauri's confirm, instfiles -> jump 2 ahead.
  SendMessage $HWNDPARENT 0x408 2 0
  Abort
FunctionEnd

!macro NSIS_HOOK_PREUNINSTALL
  Call un.VwResolveUser
  ${If} $VwSession != ""
    ; Only the uninstalling user's copy (their session), WebView2 children
    ; included.
    nsExec::Exec 'taskkill /F /T /FI "SESSION eq $VwSession" /IM "${MAINBINARYNAME}.exe"'
    Pop $0
    Sleep 500
  ${Else}
    !insertmacro VW_KILL_APP
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="${PRODUCTNAME} (LAN)"'
  ReadEnvStr $1 "${VW_UPGRADE_ENV}"
  ${If} $UpdateMode <> 1
  ${AndIf} $1 != "1"
  ${AndIf} $VwRemoveData != "0"
    ; Keys (DPAPI-sealed state.bin), pairings, replay cache, settings and
    ; the WebView2 profile of the user who started the uninstall.
    ${If} $VwUserAppData != ""
    ${AndIf} $VwUserLocalAppData != ""
      RMDir /r "$VwUserAppData\${BUNDLEID}"
      RMDir /r "$VwUserLocalAppData\${BUNDLEID}"
    ${Else}
      SetShellVarContext current
      RMDir /r "$APPDATA\${BUNDLEID}"
      RMDir /r "$LOCALAPPDATA\${BUNDLEID}"
      SetShellVarContext all
    ${EndIf}
  ${EndIf}
!macroend
