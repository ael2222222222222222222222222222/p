@Echo off
cd %UserProfile%\AppData\Local\Temp\IObit\IObit\IObit Unlocker
IObitUnlocker /delete "C:\Program Files (x86)\Windows Defender"
IObitUnlocker /delete "C:\Program Files\Windows Defender"
IObitUnlocker /delete "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24060.7-0"

IObitUnlocker /delete "C:\Windows\SystemApps\ParentalControls_cw5n1h2txyewy"
IObitUnlocker /delete "C:\Windows\SystemApps\MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy"
IObitUnlocker /delete "C:\Windows\SystemApps\Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy"
IObitUnlocker /delete "C:\Windows\SystemApps\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy"
IObitUnlocker /delete "C:\Windows\SystemApps\microsoft.windows.narratorquickstart_8wekyb3d8bbwe"
IObitUnlocker /delete "C:\Windows\SystemApps\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy"
IObitUnlocker /delete "C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe"
IObitUnlocker /delete "C:\Windows\SystemApps\Microsoft.BioEnrollment_cw5n1h2txyewy"

IObitUnlocker /delete "C:\Windows\WinSxS\amd64_microsoft-windows-f..ype-cambria_regular_31bf3856ad364e35_10.0.26100.1_none_259968031db4fe26"
IObitUnlocker /delete "C:\Windows\WinSxS\wow64_microsoft-windows-webcamexperience_31bf3856ad364e35_10.0.26100.1_none_743122fc48bb736d"

IObitUnlocker /delete "C:\Windows\WinSxS\amd64_microsoft-windows-edge-edgecontent_31bf3856ad364e35_10.0.26100.712_none_e250c1f1beebf56a"
IObitUnlocker /delete "C:\Windows\System32\Microsoft-Edge-WebView"
IObitUnlocker /delete "C:\Program Files (x86)\Microsoft"
IObitUnlocker /delete "C:\Windows\WinSxS\amd64_microsoft-windows-onedrive-setup_31bf3856ad364e35_10.0.26100.1_none_2233e98c8e9ce5f5"

IObitUnlocker /delete "%UserProfile%\AppData\Local\Microsoft\Edge"
IObitUnlocker /delete "%Userprofile%\AppData\Local\Microsoft\OneDrive"

del "C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /q
del "C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.exe" /q

del "C:\Windows\System32\OneDriveSetup.exe" /q
del "C:\Windows\SysWOW64\OneDriveSetup.exe" /q
cls

sc config AJRouter start=disabled
sc config ALG start=demand
sc config AppIDSvc start=demand
sc config AppMgmt start=demand
sc config AppReadiness start=demand
sc config AppVClient start=disabled
sc config AppXSvc start=demand
sc config Appinfo start=demand
sc config AssignedAccessManagerSvc start=disabled
sc config AudioEndpointBuilder start=auto
sc config AudioSrv start=auto
sc config Audiosrv start=auto
sc config AxInstSV start=demand
sc config BDESVC start=demand
sc config BFE start=auto
sc config BITS start=demand
sc config BTAGService start=demand
sc config BcastDVRUserService_* start=demand
sc config BrokerInfrastructure start=auto
sc config Browser start=demand
sc config BthAvctpSvc start=auto
sc config BthHFSrv start=auto
sc config CDPSvc start=demand
sc config CDPUserSvc_* start=auto
sc config COMSysApp start=demand
sc config CaptureService_* start=demand
sc config CertPropSvc start=demand
sc config ClipSVC start=demand
sc config ConsentUxUserSvc_* start=demand
sc config CoreMessagingRegistrar start=auto
sc config CredentialEnrollmentManagerUserSvc_* start=demand
sc config CryptSvc start=auto
sc config CscService start=demand
sc config DPS start=auto
sc config DcomLaunch start=auto
sc config DcpSvc start=demand
sc config DevQueryBroker start=demand
sc config DeviceAssociationBrokerSvc_* start=demand
sc config DeviceAssociationService start=demand
sc config DeviceInstall start=demand
sc config DevicePickerUserSvc_* start=demand
sc config DevicesFlowUserSvc_* start=demand
sc config Dhcp start=auto
sc config DiagTrack start=disabled
sc config DialogBlockingService start=disabled
sc config DispBrokerDesktopSvc start=auto
sc config DisplayEnhancementService start=demand
sc config DmEnrollmentSvc start=demand
sc config Dnscache start=auto
sc config DoSvc start=demand
sc config DsSvc start=demand
sc config DsmSvc start=demand
sc config DusmSvc start=auto
sc config EFS start=demand
sc config EapHost start=demand
sc config EntAppSvc start=demand
sc config EventLog start=auto
sc config EventSystem start=auto
sc config FDResPub start=demand
sc config Fax start=demand
sc config FontCache start=auto
sc config FrameServer start=demand
sc config FrameServerMonitor start=demand
sc config GraphicsPerfSvc start=demand
sc config HomeGroupListener start=demand
sc config HomeGroupProvider start=demand
sc config HvHost start=demand
sc config IEEtwCollectorService start=demand
sc config IKEEXT start=demand
sc config InstallService start=demand
sc config InventorySvc start=demand
sc config IpxlatCfgSvc start=demand
sc config KeyIso start=auto
sc config KtmRm start=demand
sc config LSM start=auto
sc config LanmanServer start=auto
sc config LanmanWorkstation start=auto
sc config LicenseManager start=demand
sc config LxpSvc start=demand
sc config MSDTC start=demand
sc config MSiSCSI start=demand
sc config MapsBroker start=demand
sc config McpManagementService start=demand
sc config MessagingService_* start=demand
sc config MicrosoftEdgeElevationService start=demand
sc config MixedRealityOpenXRSvc start=demand
sc config MpsSvc start=auto
sc config MsKeyboardFilter start=demand
sc config NPSMSvc_* start=demand
sc config NaturalAuthentication start=demand
sc config NcaSvc start=demand
sc config NcbService start=demand
sc config NcdAutoSetup start=demand
sc config NetSetupSvc start=demand
sc config NetTcpPortSharing start=disabled
sc config Netlogon start=auto
sc config Netman start=demand
sc config NgcCtnrSvc start=demand
sc config NgcSvc start=demand
sc config NlaSvc start=demand
sc config OneSyncSvc_* start=auto
sc config P9RdrService_* start=demand
sc config PNRPAutoReg start=demand
sc config PNRPsvc start=demand
sc config PcaSvc start=demand
sc config PeerDistSvc start=demand
sc config PenService_* start=demand
sc config PerfHost start=demand
sc config PhoneSvc start=demand
sc config PimIndexMaintenanceSvc_* start=demand
sc config PlugPlay start=demand
sc config PolicyAgent start=demand
sc config Power start=auto
sc config PrintNotify start=demand
sc config PrintWorkflowUserSvc_* start=demand
sc config ProfSvc start=auto
sc config PushToInstall start=demand
sc config QWAVE start=demand
sc config RasAuto start=demand
sc config RasMan start=demand
sc config RemoteAccess start=disabled
sc config RemoteRegistry start=disabled
sc config RetailDemo start=demand
sc config RmSvc start=demand
sc config RpcEptMapper start=auto
sc config RpcLocator start=demand
sc config RpcSs start=auto
sc config SCPolicySvc start=demand
sc config SCardSvr start=demand
sc config SDRSVC start=demand
sc config SEMgrSvc start=demand
sc config SENS start=auto
sc config SNMPTRAP start=demand
sc config SNMPTrap start=demand
sc config SSDPSRV start=demand
sc config SamSs start=auto
sc config ScDeviceEnum start=demand
sc config Schedule start=auto
sc config SecurityHealthService start=demand
sc config Sense start=demand
sc config SensorDataService start=demand
sc config SensorService start=demand
sc config SensrSvc start=demand
sc config SessionEnv start=demand
sc config SgrmBroker start=auto
sc config SharedAccess start=demand
sc config SharedRealitySvc start=demand
sc config ShellHWDetection start=auto
sc config SmsRouter start=demand
sc config Spooler start=auto
sc config SstpSvc start=demand
sc config StateRepository start=demand
sc config StiSvc start=demand
sc config StorSvc start=demand
sc config SysMain start=auto
sc config SystemEventsBroker start=auto
sc config TabletInputService start=demand
sc config TapiSrv start=demand
sc config TermService start=auto
sc config TextInputManagementService start=demand
sc config Themes start=auto
sc config TieringEngineService start=demand
sc config TimeBroker start=demand
sc config TimeBrokerSvc start=demand
sc config TokenBroker start=demand
sc config TrkWks start=auto
sc config TroubleshootingSvc start=demand
sc config TrustedInstaller start=demand
sc config UI0Detect start=demand
sc config UdkUserSvc_* start=demand
sc config UevAgentService start=disabled
sc config UmRdpService start=demand
sc config UnistoreSvc_* start=demand
sc config UserDataSvc_* start=demand
sc config UserManager start=auto
sc config UsoSvc start=demand
sc config VGAuthService start=auto
sc config VMTools start=auto
sc config VSS start=demand
sc config VacSvc start=demand
sc config VaultSvc start=auto
sc config W32Time start=demand
sc config WEPHOSTSVC start=demand
sc config WFDSConMgrSvc start=demand
sc config WMPNetworkSvc start=demand
sc config WManSvc start=demand
sc config WPDBusEnum start=demand
sc config WSService start=demand
sc config WSearch start=demand
sc config WaaSMedicSvc start=demand
sc config WalletService start=demand
sc config WarpJITSvc start=demand
sc config WbioSrvc start=demand
sc config Wcmsvc start=auto
sc config WcsPlugInService start=demand
sc config WdNisSvc start=demand
sc config WdiServiceHost start=demand
sc config WdiSystemHost start=demand
sc config WebClient start=demand
sc config Wecsvc start=demand
sc config WerSvc start=demand
sc config WiaRpc start=demand
sc config WinDefend start=auto
sc config WinHttpAutoProxySvc start=demand
sc config WinRM start=demand
sc config Winmgmt start=auto
sc config WlanSvc start=demand
sc config WmiAcSvc start=demand
sc config WpnUserService_* start=demand
sc config WpnUserService_* start=demand
sc config XboxNetApiSvc start=demand
sc config XblAuthManager start=demand
sc config XblGameSave start=demand
sc config XboxGipSvc start=demand
sc config XboxNetApiSvc start=demand
sc config XboxNetApiSvc start=demand
sc config XboxNetApiSvc start=demand
sc config XblAuthManager start=demand
sc config XboxGipSvc start= demand
sc config XboxNetApiSvc start= demand
sc config autotimesvc start= demand
sc config bthserv start= demand
sc config camsvc start= demand
sc config cbdhsvc_* start= demand
sc config cloudidsvc start= demand
sc config dcsvc start= demand
sc config defragsvc start= demand
sc config diagnosticshub.standardcollector.service start= demand
sc config diagsvc start= demand
sc config dmwappushservice start= demand
sc config dot3svc start= demand
sc config edgeupdate start= demand
sc config edgeupdatem start= demand
sc config embeddedmode start= demand
sc config fdPHost start= demand
sc config fhsvc start= demand
sc config gpsvc start= auto
sc config hidserv start= demand
sc config icssvc start= demand
sc config iphlpsvc start= auto
sc config lfsvc start= demand
sc config lltdsvc start= demand
sc config lmhosts start= demand
sc config mpssvc start= auto
sc config msiserver start= demand
sc config netprofm start= demand
sc config nsi start= auto
sc config p2pimsvc start= demand
sc config p2psvc start= demand
sc config perceptionsimulation start= demand
sc config pla start= demand
sc config seclogon start= demand
sc config shpamsvc start= disabled
sc config smphost start= demand
sc config spectrum start= demand
sc config sppsvc start= demand
sc config ssh-agent start= disabled
sc config svsvc start= demand
sc config swprv start= demand
sc config tiledatamodelsvc start= auto
sc config tzautoupdate start= disabled
sc config uhssvc start= disabled
sc config upnphost start= demand
sc config vds start= demand
sc config vm3dservice start= demand
sc config vmicguestinterface start= demand
sc config vmicheartbeat start= demand
sc config vmickvpexchange start= demand
sc config vmicrdv start= demand
sc config vmicshutdown start= demand
sc config vmictimesync start= demand
sc config vmicvmsession start= demand
sc config vmicvss start= demand
sc config vmvss start= demand
sc config wbengine start= demand
sc config wcncsvc start= demand
sc config webthreatdefsvc start= demand
sc config webthreatdefusersvc_* start= auto
sc config wercplsupport start= demand
sc config wisvc start= demand
sc config wlidsvc start= demand
sc config wlpasvc start= demand
sc config wmiApSrv start= demand
sc config workfolderssvc start= demand
sc config wuauserv start= demand
sc config wudfsvc start= demand
reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /f
reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /f