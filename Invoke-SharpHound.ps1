<#
.SYNOPSIS
    SharpHound.exe'yi PowerShell üzerinden in-memory çalıştırır.

.DESCRIPTION
    BloodHound veri toplayıcısı SharpHound'u .NET Reflection ile
    belleğe yükler. Toplanan veriler BloodHound'da analiz edilir.

    Desteklenen CollectionMethod'lar:
    - Default           : Grup üyelikleri, session, ACL, trust
    - All               : Tüm collection method'ları
    - Group             : Grup üyelikleri
    - Session           : Aktif oturumlar
    - LoggedOn          : Giriş yapmış kullanıcılar
    - Trusts            : Domain trust ilişkileri
    - ACL               : Erişim kontrol listeleri
    - ObjectProps       : Nesne özellikleri
    - Container         : OU ve container yapıları
    - LocalAdmin        : Local admin üyelikleri
    - RDP               : RDP erişim hakları
    - DCOM              : DCOM erişim hakları
    - PSRemote          : PS Remoting erişim hakları
    - SPNTargets        : SPN hedefleri
    - DCOnly            : Sadece DC'den LDAP sorguları (sessiz)

.PARAMETER Command
    SharpHound'a geçirilecek komut string'i.

.PARAMETER ExePath
    SharpHound.exe dosyasının yolu.

.EXAMPLE
    # Tüm veri toplama
    Invoke-SharpHound -Command "--CollectionMethods All"

.EXAMPLE
    # Sadece DC'den veri toplama (daha sessiz)
    Invoke-SharpHound -Command "--CollectionMethods DCOnly"

.EXAMPLE
    # Belirli domain için
    Invoke-SharpHound -Command "--CollectionMethods All --Domain target.local"

.EXAMPLE
    # Çıktı dizinini belirle
    Invoke-SharpHound -Command "--CollectionMethods All --OutputDirectory C:\Users\Public"

.EXAMPLE
    # Loop mode - periyodik toplama
    Invoke-SharpHound -Command "--CollectionMethods Session --Loop --LoopDuration 02:00:00"

.NOTES
    Orijinal Araç: SharpHound by BloodHound team (@_wald0, @harmj0y, @CptJesus)
    Wrapper: AD Red Team PowerShell Toolkit
#>

function Invoke-SharpHound {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$Command = "--CollectionMethods Default",

        [Parameter(Mandatory = $false)]
        [string]$ExePath
    )

    if (-not $ExePath) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $ExePath = Join-Path (Split-Path -Parent $scriptDir) "SharpHound.exe"
    }

    if (-not (Test-Path $ExePath)) {
        Write-Error "[!] SharpHound.exe bulunamadı: $ExePath"
        return
    }

    Write-Host "[*] SharpHound.exe yükleniyor: $ExePath" -ForegroundColor Cyan

    try {
        $bytes = [System.IO.File]::ReadAllBytes($ExePath)
        $assembly = [System.Reflection.Assembly]::Load($bytes)
        Write-Host "[+] Assembly belleğe yüklendi." -ForegroundColor Green

        $args = $Command.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
        Write-Host "[*] Çalıştırılıyor: SharpHound.exe $Command" -ForegroundColor Cyan
        Write-Host ("-" * 60) -ForegroundColor DarkGray

        $originalOut = [Console]::Out
        $stringWriter = New-Object System.IO.StringWriter
        [Console]::SetOut($stringWriter)

        try {
            $assembly.EntryPoint.Invoke($null, @(,[string[]]$args))
        }
        catch [System.Reflection.TargetInvocationException] {
            if ($_.Exception.InnerException) {
                Write-Warning "SharpHound exception: $($_.Exception.InnerException.Message)"
            }
        }
        finally {
            [Console]::SetOut($originalOut)
        }

        $output = $stringWriter.ToString()
        if ($output) { Write-Host $output }
        Write-Host ("-" * 60) -ForegroundColor DarkGray
        Write-Host "[+] SharpHound tamamlandı. Çıktı dosyalarını BloodHound'a import edin." -ForegroundColor Green
    }
    catch {
        Write-Error "[!] Hata: $($_.Exception.Message)"
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($args.Count -gt 0) {
        Invoke-SharpHound -Command ($args -join ' ')
    }
}
