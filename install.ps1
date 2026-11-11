# Installs or updates NetScan for the current user, no admin rights needed:
#   irm https://raw.githubusercontent.com/eliagantenbein/netscan/main/install.ps1 | iex
# ASCII only: Windows PowerShell 5.1 reads a file without BOM in the ANSI code page.
# The script block keeps the preferences below out of the caller's session (iex runs in it).
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue' # the progress bar makes Invoke-WebRequest many times slower
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $url = 'https://github.com/eliagantenbein/netscan/releases/latest/download/NetScan.exe'
    $dir = Join-Path $env:LOCALAPPDATA 'Programs\NetScan'
    $exe = Join-Path $dir 'NetScan.exe'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    Write-Host 'Lade NetScan herunter ...'
    $download = "$exe.download"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $download

    $running = @(Get-Process -Name NetScan -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })
    if ($running) {
        Write-Host 'Beende das laufende NetScan fuer das Update ...'
        $running | Stop-Process -Force
        $running | Wait-Process -Timeout 10
    }
    Move-Item -Force -Path $download -Destination $exe

    $link = Join-Path ([Environment]::GetFolderPath('Programs')) 'NetScan.lnk'
    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($link)
    $shortcut.TargetPath = $exe
    $shortcut.WorkingDirectory = $dir
    $shortcut.Save()

    Write-Host "NetScan ist installiert: $exe"
    Write-Host 'Im Startmenue unter "NetScan". Dieselbe Zeile nochmals ausfuehren = Update.'
    Start-Process -FilePath $exe
}
