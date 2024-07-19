@Echo off
color 5
::LAST Update 7/19/2024
::Give Credits To This Account If You Found IT.
mode con: cols=80 lines=20
DISM > nul 2>&1 || (
    echo error: administrator privileges required
    pause
    exit /b 1
)

:BLTWUI
cls
color 5
Echo.
Echo.
Echo.
Echo             !Welcome %username%!
echo.
echo             ( BLTW UI )
Echo.
Echo           ^> \ Support Win10  \ Win11 \ ^<
Echo           ^>  \ Enable Windows \ -GGS- \ ^<
Echo           ^>   \ Type ^!BACK^!    \ -TwUi \ ^<
Echo           ^>    \ Type EnableWIN \ -:)^! \ ^<
Echo   -----------------------------------------------        -----------------
Echo    \ 1 Debloat APPS 2 MSI 3 Int Policy \Enjoy:) \        \ 11 7-Zip       \
Echo     \ 4 VMWARE + VirtualBox  5 VCC + D ----------\        \ 12 Phyton      \ 
Echo      \ 6 Firefox 7 Discord 8 Everting + Lighshot  \        \ 13 Tweak 7-Zip \
Echo       \ 9 RwEverthing + MOD 10 Modules Folder      \        \ 14 Permission  \
Echo.       ----------------------------------------------        ------------------
echo.
echo ^>           ( Type 'Back' To Proceed ) ^> "
echo ^>           ( Type 'EnableWIN To Proceed ) ^> "
set /p "BLTWUI=>           ( Type '1,15' To Proceed ) > "
if "%BLTWUI%"=="1" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING !!Debloat APPS!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\OOSU10.exe" "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
    call "%UserProfile%\AppData\Local\Temp\OOSU10.exe"
    
    if ERRORLEVEL 1 (
    echo Failed to download or execute OOSU10.exe
    del /s /f /q "%UserProfile%\AppData\Local\Temp\OOSU10.exe"
) else (
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\WPD.exe" "https://github.com/ael2222222222222222222222222222/p/raw/main/WPD.exe"
    call "%UserProfile%\AppData\Local\Temp\WPD.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\WPD.exe"

    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\geek.exe" "https://github.com/ael2222222222222222222222222222/p/raw/main/geek.exe"
    call "%UserProfile%\AppData\Local\Temp\geek.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\geek.exe"

    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\parkcontrolsetup64.exe" "https://dl.bitsum.com/files/parkcontrolsetup64.exe"
    call "%UserProfile%\AppData\Local\Temp\parkcontrolsetup64.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\parkcontrolsetup64.exe"
)
    del /s /f /q %temp%\*.*
    rd /s /q %temp%
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Debloat APPS!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="2" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING !!MSI Utility!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\MSI_util_v3.exe" "https://github.com/ael2222222222222222222222222222/p/raw/main/MSI_util_v3.exe"
    call "%UserProfile%\AppData\Local\Temp\MSI_util_v3.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\MSI_util_v3.exe"
    del /s /f /q %temp%\*.*
    rd /s /q %temp%
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!MSI Utility!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="3" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING !!Int Policy!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\intPolicy_x64.exe" "https://github.com/ael2222222222222222222222222222/p/raw/main/intPolicy_x64.exe"
    call "%UserProfile%\AppData\Local\Temp\intPolicy_x64.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\intPolicy_x64.exe"
    del /s /f /q %temp%\*.*
    rd /s /q %temp%
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Int Policy!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="4" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING !!Vmware + Virtualbox!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\VirtualBox-7.0.20-163906-Win.exe" "https://download.virtualbox.org/virtualbox/7.0.20/VirtualBox-7.0.20-163906-Win.exe"
    call "%UserProfile%\AppData\Local\Temp\VirtualBox-7.0.20-163906-Win.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\VirtualBox-7.0.20-163906-Win.exe"

    Echo VMWARE, SOON
    del /s /f /q %temp%\*.*
    rd /s /q %temp%
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Vmware + Virtualbox!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="5" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING !!Visual CC + DirectX!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%temp%\VisualCppRedist_AIO_x86_x64.exe" "https://github.com/abbodi1406/vcredist/releases/download/v0.78.0/VisualCppRedist_AIO_x86_x64.exe"
    %temp%\VisualCppRedist_AIO_x86_x64.exe /y
    del /f "%temp%\VisualCppRedist_AIO_x86_x64.exe"
    curl -g -k -L -# -o "%temp%\dxwebsetup.exe" "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"
    "%temp%\dxwebsetup.exe" 
    del /f "%temp%\dxwebsetup.exe"
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Visual CC + Direcxt!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="6" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING !!Firefox + Tweaks Firefox!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\Firefox Installer.exe" "https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US"
    call "%UserProfile%\AppData\Local\Temp\Firefox Installer.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\Firefox Installer.exe"
    del /s /f /q %temp%\*.*
    rd /s /q %temp%
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\DBT.bat" "https://raw.githubusercontent.com/ael2222222222222222222222222222/p/main/DBT.bat"
    call "%UserProfile%\AppData\Local\Temp\DBT.bat"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\DBT.bat"
    del /s /f /q %temp%\*.*
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Firefox + Tweaks Firefox!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="7" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING !!Discord!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\DiscordSetup.exe" "https://discord.com/api/downloads/distributions/app/installers/latest?channel=stable&platform=win&arch=x64"
    call "%UserProfile%\AppData\Local\Temp\DiscordSetup.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\DiscordSetup.exe"
    del /s /f /q %temp%\*.*
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Discord!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="8" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING !!Everthing + Lighshot!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\Everything-1.4.1.1024.x86-Setup.exe" "https://www.voidtools.com/Everything-1.4.1.1024.x86-Setup.exe"
    call "%UserProfile%\AppData\Local\Temp\Everything-1.4.1.1024.x86-Setup.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\Everything-1.4.1.1024.x86-Setup.exe"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\setup-lightshot.exe" "https://app.prntscr.com/build/setup-lightshot.exe"
    call "%UserProfile%\AppData\Local\Temp\setup-lightshot.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\setup-lightshot.exe"
    del /s /f /q %temp%\*.*   
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Everthing + Lighshot!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="9" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING !!Rw Everthing + MOD!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"   
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\SetupRw.exe" "https://github.com/ael2222222222222222222222222222/p/raw/main/SetupRw.exe"
    call "%UserProfile%\AppData\Local\Temp\SetupRw.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\SetupRw.exe"
    curl -g -k -L -# -o "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Run Ps1.bat" "https://raw.githubusercontent.com/ael2222222222222222222222222222/p/main/Run%20Ps1.bat"
    move "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Run Ps1.bat" "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Run Ps1.bat"
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Rw Everthing + MOD!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="10" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING. !!Modules Folder!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\Win11Debloat-master.zip" "https://github.com/ael2222222222222222222222222222/p/raw/main/Win11Debloat-master.zip"
    powershell Expand-Archive -Path "%UserProfile%\AppData\Local\Temp\Win11Debloat-master.zip" -DestinationPath "%UserProfile%\AppData\Local\Temp\Win11Debloat-master"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\Win11Debloat-master.zip"
    call "%UserProfile%\AppData\Local\Temp\Win11Debloat-master\Win11Debloat-master\Win11Debloat-master\Run.bat"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\DFNDER.zip" "https://github.com/ael2222222222222222222222222222/p/raw/main/DFNDER.zip"
    powershell Expand-Archive -Path "%UserProfile%\AppData\Local\Temp\DFNDER.zip" -DestinationPath "%UserProfile%\AppData\Local\Temp\DFNDER"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\DFNDER.zip"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\DFNDER\Script_Run.bat" "https://raw.githubusercontent.com/ael2222222222222222222222222222/p/main/Script_Run.bat"
    call "%UserProfile%\AppData\Local\Temp\DFNDER\Script_Run.bat"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\DFNDER\Script_Run.bat"
    del /s /f /q "%temp%\*.*"
    rd /s /q "%temp%"
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Modules Folder!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="11" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING. !!7-Zip!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\7z2407-x64.exe" "https://github.com/ael2222222222222222222222222222/p/raw/main/7z2407-x64.exe"
    call "%UserProfile%\AppData\Local\Temp\7z2407-x64.exe"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\7z2407-x64.exe"
    del /s /f /q %temp%\*.*
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!7-Zip!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI

) else if "%BLTWUI%"=="12" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING. !!Phyton!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%USERPROFILE%\AppData\Local\Temp\python-3.12.4-amd64.exe" "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
    "%USERPROFILE%\AppData\Local\Temp\python-3.12.4-amd64.exe"
    del /s /f /q "%USERPROFILE%\AppData\Local\Temp\python-3.12.4-amd64.exe"
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Phyton!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI

) else if "%BLTWUI%"=="13" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING. !!7-Zip.Bat!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%USERPROFILE%\AppData\Local\Temp\7zip.bat" "https://github.com/ael2222222222222222222222222222/p/raw/main/7zip.bat"
    call "%USERPROFILE%\AppData\Local\Temp\7zip.bat"
    del /s /f /q "%USERPROFILE%\AppData\Local\Temp\7zip.bat"
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!7-Zip Debloat!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI

) else if "%BLTWUI%"=="14" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('DOWNLOADING. !!Modules Folder!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    curl -g -k -L -# -o "%USERPROFILE%\AppData\Local\Temp\Programs Permission.bat" "https://raw.githubusercontent.com/ael2222222222222222222222222222/p/main/Programs%20Permission.bat"
    call "%USERPROFILE%\AppData\Local\Temp\Programs Permission.bat"
    del /s /f /q "%USERPROFILE%\AppData\Local\Temp\Programs Permission.bat"
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE INSTALLATION. !!Permission Changed!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else if "%BLTWUI%"=="BACK" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('You're Back To. !!Tweaking PC Ui!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('COMPLETED THE Blotware Ui Enjoy. !!UiTweak!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto UiTweak
) else if "%BLTWUI%"=="EnableWIN" (
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Enabling Your Windows.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"

    curl -g -k -L -# -o "%UserProfile%\AppData\Local\Temp\KMS_VL_ALL-44.zip" "https://codeload.github.com/kkkgo/KMS_VL_ALL/zip/refs/tags/44"
    powershell Expand-Archive -Path "%UserProfile%\AppData\Local\Temp\KMS_VL_ALL-44.zip" -DestinationPath "%UserProfile%\AppData\Local\Temp\KMS_VL_ALL-44"
    del /s /f /q "%UserProfile%\AppData\Local\Temp\KMS_VL_ALL-44.zip"
    call "%UserProfile%\AppData\Local\Temp\KMS_VL_ALL-44\KMS_VL_ALL-44\Activate.cmd"
    del /s /f /q %temp%\*.*
    rd /s /q %temp%
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('!!ENABLED WINDOWS SUCCESSFULLY!!.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
) else (
    Echo.
    Echo.
    Title Not Recognized 
    Echo.
    Echo.
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Invalid input: %BLTWUI% is not recognized.', 'Unknown', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Please type 1,15 Or !BACK! !EnableWIN! to proceed.', 'BlotwareUI', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information);"
    goto BLTWUI
)

