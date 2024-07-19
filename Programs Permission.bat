@Echo Off
Title Modifying Values v1.0

Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ConvertibleSlateMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ13Priority" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCR\CLSID\{09A5DFC5-8BA2-47DD-BF84-FFD7E0B24481}" /f
Reg.exe delete "HKCR\CLSID\{0DFA72F0-D26C-4987-A128-E3A5641C5568}" /f
Reg.exe delete "HKCR\CLSID\{10493933-661B-4083-9CE0-EFE48ADD0770}" /f
Reg.exe delete "HKCR\CLSID\{24AC8F2B-4D4A-4C17-9607-6A4B14068F97}" /f
Reg.exe delete "HKCR\CLSID\{3957a5ba-4448-bec4-24ac-16c4f5784ef5}" /f
Reg.exe delete "HKCR\CLSID\{C2D67532-D0FA-4022-89F7-8C1DF8A0C412}" /f
Reg.exe delete "HKCR\CLSID\{FF2F95A4-C6A1-4B48-BC87-8709250E0D03}" /f
Reg.exe delete "HKCR\WOW6432Node\CLSID\{09A5DFC5-8BA2-47DD-BF84-FFD7E0B24481}" /f
Reg.exe delete "HKCR\WOW6432Node\CLSID\{0DFA72F0-D26C-4987-A128-E3A5641C5568}" /f
Reg.exe delete "HKCR\WOW6432Node\CLSID\{10493933-661B-4083-9CE0-EFE48ADD0770}" /f
Reg.exe delete "HKCR\WOW6432Node\CLSID\{24AC8F2B-4D4A-4C17-9607-6A4B14068F97}" /f
Reg.exe delete "HKCR\WOW6432Node\CLSID\{3957a5ba-4448-bec4-24ac-16c4f5784ef5}" /f
Reg.exe delete "HKCR\WOW6432Node\CLSID\{C2D67532-D0FA-4022-89F7-8C1DF8A0C412}" /f
Reg.exe delete "HKCR\WOW6432Node\CLSID\{FF2F95A4-C6A1-4B48-BC87-8709250E0D03}" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.AppsInfo" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.AudioHelper" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.BrowserManager" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.ContextMenuManager" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.CortanaSettings" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.DesktopItem" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.DesktopLaunchersBrokered" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.DeviceAccessHelper" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.FileSystemAccessHelper" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.HostedFlowManager" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.InputsHelper" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.LaunchersBrokered" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.MapiHelper" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.MediaControlManager" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.MSAManager" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.OutlookHelper" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.PathCommanding" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.PersonaHelper" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.PowerHelper" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.ProcessHelper" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.SearchFolders" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.Speech.SpeechSettings" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.SpeechLanguageManager" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.SystemCommands" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.TaskbarNotificationManager" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Cortana.VisionHelper" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Internal.Services.Cortana.CortanaPermissionsAppServiceManager" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\WindowsInternal.Shell.UnifiedTile.Private.CortanaActivationBroker" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\CloudExperienceHostBroker.Cortana.OOBECortanaManager" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\CloudExperienceHostBroker.Cortana.OOBECortanaManagerCore" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\CloudExperienceHostBroker.Cortana.OOBECortanaManagerCoreForUser" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Media.Speech.Pal.CortanaAppManagement" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Cortana.ConstraintIndex.CSGSuggestion.CSGSuggester" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Cortana.ConstraintIndex.Search.ConstraintIndexDownloader" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Cortana.ConstraintIndex.Search.QueryFactory" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Cortana.ConstraintIndex.Search.SessionTelemetry" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Cortana.ConstraintIndex.Search.SettingsConstraintIndexRefresher" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Cortana.ConstraintIndex.Search.SettingsJsonGenerator" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\CLSID\{C91D3A4B-AB17-498A-967E-E72A877F3428}" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Services.Cortana.CortanaActionableInsights" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Services.Cortana.CortanaActionableInsightsOptions" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Services.Cortana.CortanaPermissionsManager" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Services.Cortana.CortanaSettings" /f
Reg.exe delete "HKCR\AppXq0pwa73vfcn2qdexp8cexcc6qk87xh1r" /f
Reg.exe delete "HKCR\AppID\{24AC8F2B-4D4A-4C17-9607-6A4B14068F97}" /f
Reg.exe delete "HKCR\WOW6432Node\AppID\{24AC8F2B-4D4A-4C17-9607-6A4B14068F97}" /f
Reg.exe add "HKCR\.reg\ShellNew" /v "ItemName" /t REG_EXPAND_SZ /d "@%%SystemRoot%%\system32\notepad.exe,-470" /f
Reg.exe add "HKCR\.reg\ShellNew" /v "NullFile" /t REG_SZ /d "" /f
Reg.exe add "HKCR\.txt\ShellNew" /v "ItemName" /t REG_EXPAND_SZ /d "@%%SystemRoot%%\system32\notepad.exe,-470" /f
Reg.exe add "HKCR\.txt\ShellNew" /v "NullFile" /t REG_SZ /d "" /f
Reg.exe add "HKCR\txtfilelegacy" /ve /t REG_SZ /d "Text Document" /f
Reg.exe add "HKCR\.bat\ShellNew" /v "ItemName" /t REG_SZ /d "%%windir%%\System32\acppage.dll,-6002" /f
Reg.exe add "HKCR\.bat\ShellNew" /v "NullFile" /t REG_SZ /d "" /f
Reg.exe delete "HKCR\.bmp\ShellNew" /f
Reg.exe delete "HKCR\.contact\ShellNew" /f
Reg.exe delete "HKCR\.rtf\ShellNew" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGazeInput" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessBackgroundSpatialPerception" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGraphicsCaptureWithoutBorder" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGraphicsCaptureProgrammatic" /t REG_DWORD /d "2" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGazeInput" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessBackgroundSpatialPerception" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGraphicsCaptureWithoutBorder" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGraphicsCaptureProgrammatic" /t REG_DWORD /d "2" /f
Reg.exe delete "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /f
Reg.exe delete "HKCU\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\calendar" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\callhistory" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts\Microsoft.XboxApp_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Prompt" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic\NonPackaged" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder\NonPackaged" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\calendar" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\callhistory" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Speech\Preferences" /v "EnableDocumentHarvesting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SpeechGestures" /v "RDCPolicyCollectionLevel" /t REG_DWORD /d "0" /f

