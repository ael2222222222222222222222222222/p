@Echo off
mode con: cols=70 lines=20
Color 5
echo --------------------------------------------------------------------------------------
    echo - View -
    echo - Enable Hidden Devices -
    start devmgmt.msc

    echo.
    echo - Remove all Audio - keeps what you use -

    echo  System Devices
    echo  Remote Desktop Device Redirector Bus
    echo  Umbus Root Bus Enumerator
    echo  High Precision Event Timer
    echo  Composite Bus Enumerator

    echo Software Devices
    echo Microsoft Radio Enumerator Bus
    echo Microsoft GS Wavetable Synth

    echo Network Adapters
    echo Disable ALL - WAN Miniport
    echo Intel(R) Wi-Fi 6 AX201 160MHz
    echo Microsoft Kernel Debug Network Adapter

    echo.
    echo  Disable Bluetooth if you don't use -
    echo.
    echo  Audio Inputs / Disable All You Don't Need Or Not Using -
    echo.
    echo  VIRTUAL MACHINE STUFF
    echo  NDIS Virtual Network Adapter Enumerator
    echo  Microsoft Virtual Drive Enumerator
    echo  Vmware VMCI Host Device

    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DONE. Windows Settings', 'GOOD WIND', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto UiTweak
