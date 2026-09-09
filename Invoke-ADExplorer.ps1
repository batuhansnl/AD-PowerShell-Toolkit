<#
.SYNOPSIS
    ADExplorer.exe yerine PowerShell native AD enumeration aracı.

.DESCRIPTION
    Sysinternals ADExplorer'ın PowerShell alternatifi. LDAP sorgularını
    kullanarak Active Directory nesnelerini keşfeder ve analiz eder.

    Modüller:
    - Users       : Tüm domain kullanıcılarını listele
    - Admins      : Admin hesaplarını ve grup üyeliklerini göster
    - Groups      : Domain gruplarını listele
    - Computers   : Domain bilgisayarlarını listele
    - DCs         : Domain Controller'ları listele
    - Trusts      : Domain trust ilişkileri
    - ACL         : Belirli bir nesnenin ACL'sini analiz et
    - GPO         : Group Policy nesnelerini listele
    - OU          : Organizational Unit yapısını göster
    - SPN         : SPN kayıtlı hesapları listele (Kerberoast hedefleri)
    - ASREPRoast  : Pre-auth gerektirmeyen hesaplar (AS-REP Roast hedefleri)
    - Unconstrained : Unconstrained delegation yapılandırılmış nesneler
    - LAPS        : LAPS parolası okunabilir bilgisayarlar
    - Stale       : Uzun süredir giriş yapmamış hesaplar
    - Snapshot    : Tüm bilgileri JSON olarak kaydet
    - Search      : Serbest LDAP arama

    ADSI (System.DirectoryServices) kullanır, ek modül gerektirmez.
    AD PowerShell modülü olmadan da çalışır.

.PARAMETER Mode
    Çalıştırılacak enumeration modu.

.PARAMETER Target
    ACL modu için hedef nesne DN'si.

.PARAMETER SearchBase
    LDAP arama tabanı. Belirtilmezse mevcut domain kullanılır.

.PARAMETER LDAPFilter
    Search modunda kullanılacak LDAP filtresi.

.PARAMETER OutputPath
    Snapshot modunda çıktı dosyası yolu.

.PARAMETER DaysInactive
    Stale modunda inaktif gün sayısı eşiği. Varsayılan: 90

.EXAMPLE
    # Tüm kullanıcıları listele
    Invoke-ADExplorer -Mode Users

.EXAMPLE
    # Admin hesapları
    Invoke-ADExplorer -Mode Admins

.EXAMPLE
    # Kerberoast hedefleri (SPN kayıtlı hesaplar)
    Invoke-ADExplorer -Mode SPN

.EXAMPLE
    # AS-REP Roast hedefleri
    Invoke-ADExplorer -Mode ASREPRoast

.EXAMPLE
    # Domain Controller'lar
    Invoke-ADExplorer -Mode DCs

.EXAMPLE
    # Unconstrained Delegation
    Invoke-ADExplorer -Mode Unconstrained

.EXAMPLE
    # Domain trust'lar
    Invoke-ADExplorer -Mode Trusts

.EXAMPLE
    # LAPS parolaları
    Invoke-ADExplorer -Mode LAPS

.EXAMPLE
    # Snapshot al
    Invoke-ADExplorer -Mode Snapshot -OutputPath .\ad_snapshot.json

.EXAMPLE
    # Serbest LDAP arama
    Invoke-ADExplorer -Mode Search -LDAPFilter "(&(objectClass=user)(adminCount=1))"

.EXAMPLE
    # 90 günden fazla inaktif hesaplar
    Invoke-ADExplorer -Mode Stale -DaysInactive 90

.NOTES
    ADExplorer.exe yerine PowerShell native alternatif
    AD Red Team PowerShell Toolkit
    Gereksinim: Domain'e bağlı bir makine, ek modül gerektirmez
#>

function Invoke-ADExplorer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Users", "Admins", "Groups", "Computers", "DCs", "Trusts",
                     "ACL", "GPO", "OU", "SPN", "ASREPRoast", "Unconstrained",
                     "LAPS", "Stale", "Snapshot", "Search")]
        [string]$Mode,

        [Parameter(Mandatory = $false)]
        [string]$Target,

        [Parameter(Mandatory = $false)]
        [string]$SearchBase,

        [Parameter(Mandatory = $false)]
        [string]$LDAPFilter,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [int]$DaysInactive = 90
    )

    Write-Host "[*] AD Explorer - Mod: $Mode" -ForegroundColor Cyan

    # ADSI bağlantısı
    if ($SearchBase) {
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
    }
    else {
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $SearchBase = $rootDSE.Properties["defaultNamingContext"][0]
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
    }

    $domain = $SearchBase
    Write-Host "[*] Domain: $domain" -ForegroundColor Cyan
    Write-Host ("-" * 60) -ForegroundColor DarkGray

    # LDAP arama fonksiyonu
    function Search-LDAP {
        param(
            [string]$Filter,
            [string[]]$Properties = @("*"),
            [string]$Base = $SearchBase
        )
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Base")
        $searcher.Filter = $Filter
        $searcher.PageSize = 1000
        foreach ($prop in $Properties) {
            $searcher.PropertiesToLoad.Add($prop) | Out-Null
        }
        try {
            return $searcher.FindAll()
        }
        catch {
            Write-Error "[!] LDAP sorgu hatası: $($_.Exception.Message)"
            return $null
        }
    }

    switch ($Mode) {

        "Users" {
            Write-Host "[*] Domain kullanıcıları listeleniyor..." -ForegroundColor Yellow
            $results = Search-LDAP -Filter "(&(objectClass=user)(objectCategory=person))" -Properties @("samaccountname", "displayname", "mail", "lastlogon", "useraccountcontrol", "description", "memberof")

            $users = @()
            foreach ($result in $results) {
                $props = $result.Properties
                $uac = if ($props["useraccountcontrol"]) { $props["useraccountcontrol"][0] } else { 0 }
                $disabled = ($uac -band 0x0002) -ne 0
                $lastLogon = if ($props["lastlogon"] -and $props["lastlogon"][0] -gt 0) {
                    [DateTime]::FromFileTime($props["lastlogon"][0]).ToString("yyyy-MM-dd HH:mm")
                } else { "Hiç giriş yapmamış" }

                $users += [PSCustomObject]@{
                    SamAccountName = [string]$props["samaccountname"][0]
                    DisplayName    = [string]$props["displayname"][0]
                    Email          = [string]$props["mail"][0]
                    LastLogon      = $lastLogon
                    Disabled       = $disabled
                    Description    = [string]$props["description"][0]
                }
            }

            Write-Host "[+] Toplam kullanıcı: $($users.Count)" -ForegroundColor Green
            $users | Format-Table -AutoSize
        }

        "Admins" {
            Write-Host "[*] Admin hesapları analiz ediliyor..." -ForegroundColor Yellow

            $adminGroups = @(
                "Domain Admins",
                "Enterprise Admins",
                "Administrators",
                "Schema Admins",
                "Account Operators",
                "Backup Operators",
                "Server Operators",
                "Print Operators"
            )

            foreach ($group in $adminGroups) {
                $groupResults = Search-LDAP -Filter "(&(objectClass=group)(cn=$group))" -Properties @("member", "distinguishedname")
                if ($groupResults -and $groupResults.Count -gt 0) {
                    $members = $groupResults[0].Properties["member"]
                    $memberCount = if ($members) { $members.Count } else { 0 }

                    Write-Host ""
                    Write-Host "  [$group] - $memberCount üye" -ForegroundColor Cyan
                    if ($members) {
                        foreach ($member in $members) {
                            $memberName = ($member -split ',')[0] -replace '^CN=', ''
                            Write-Host "    → $memberName" -ForegroundColor White
                        }
                    }
                }
            }

            # AdminCount=1 olan hesaplar
            Write-Host ""
            Write-Host "[*] AdminCount=1 olan hesaplar (AdminSDHolder korumalı):" -ForegroundColor Yellow
            $adminCountResults = Search-LDAP -Filter "(&(objectClass=user)(adminCount=1))" -Properties @("samaccountname", "displayname")
            foreach ($result in $adminCountResults) {
                Write-Host "    → $($result.Properties['samaccountname'][0])" -ForegroundColor White
            }
        }

        "Groups" {
            Write-Host "[*] Domain grupları listeleniyor..." -ForegroundColor Yellow
            $results = Search-LDAP -Filter "(objectClass=group)" -Properties @("cn", "description", "member", "grouptype")

            $groups = @()
            foreach ($result in $results) {
                $props = $result.Properties
                $memberCount = if ($props["member"]) { $props["member"].Count } else { 0 }
                $groups += [PSCustomObject]@{
                    Name        = [string]$props["cn"][0]
                    Members     = $memberCount
                    Description = [string]$props["description"][0]
                }
            }

            Write-Host "[+] Toplam grup: $($groups.Count)" -ForegroundColor Green
            $groups | Sort-Object Members -Descending | Format-Table -AutoSize
        }

        "Computers" {
            Write-Host "[*] Domain bilgisayarları listeleniyor..." -ForegroundColor Yellow
            $results = Search-LDAP -Filter "(objectClass=computer)" -Properties @("cn", "operatingsystem", "operatingsystemversion", "lastlogon", "dnshostname")

            $computers = @()
            foreach ($result in $results) {
                $props = $result.Properties
                $lastLogon = if ($props["lastlogon"] -and $props["lastlogon"][0] -gt 0) {
                    [DateTime]::FromFileTime($props["lastlogon"][0]).ToString("yyyy-MM-dd")
                } else { "N/A" }

                $computers += [PSCustomObject]@{
                    Name      = [string]$props["cn"][0]
                    DNS       = [string]$props["dnshostname"][0]
                    OS        = [string]$props["operatingsystem"][0]
                    Version   = [string]$props["operatingsystemversion"][0]
                    LastLogon = $lastLogon
                }
            }

            Write-Host "[+] Toplam bilgisayar: $($computers.Count)" -ForegroundColor Green
            $computers | Format-Table -AutoSize
        }

        "DCs" {
            Write-Host "[*] Domain Controller'lar listeleniyor..." -ForegroundColor Yellow
            $results = Search-LDAP -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("cn", "dnshostname", "operatingsystem", "operatingsystemversion")

            foreach ($result in $results) {
                $props = $result.Properties
                Write-Host ""
                Write-Host "  DC: $($props['cn'][0])" -ForegroundColor Green
                Write-Host "    DNS:     $($props['dnshostname'][0])" -ForegroundColor White
                Write-Host "    OS:      $($props['operatingsystem'][0])" -ForegroundColor White
                Write-Host "    Version: $($props['operatingsystemversion'][0])" -ForegroundColor White
            }
        }

        "Trusts" {
            Write-Host "[*] Domain trust ilişkileri..." -ForegroundColor Yellow
            $results = Search-LDAP -Filter "(objectClass=trustedDomain)" -Properties @("cn", "trustdirection", "trusttype", "trustattributes", "trustpartner")

            $trustDirections = @{ 0 = "Disabled"; 1 = "Inbound"; 2 = "Outbound"; 3 = "Bidirectional" }
            $trustTypes = @{ 1 = "Downlevel (Non-AD)"; 2 = "Uplevel (AD)"; 3 = "MIT (Kerberos)"; 4 = "DCE" }

            foreach ($result in $results) {
                $props = $result.Properties
                $direction = $trustDirections[[int]$props["trustdirection"][0]]
                $type = $trustTypes[[int]$props["trusttype"][0]]

                Write-Host ""
                Write-Host "  Trust: $($props['cn'][0])" -ForegroundColor Green
                Write-Host "    Partner:   $($props['trustpartner'][0])" -ForegroundColor White
                Write-Host "    Direction: $direction" -ForegroundColor White
                Write-Host "    Type:      $type" -ForegroundColor White
            }

            if (-not $results -or $results.Count -eq 0) {
                Write-Host "[*] Trust ilişkisi bulunamadı." -ForegroundColor Yellow
            }
        }

        "SPN" {
            Write-Host "[*] SPN kayıtlı kullanıcı hesapları (Kerberoast hedefleri)..." -ForegroundColor Yellow
            $results = Search-LDAP -Filter "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*)(!(samaccountname=krbtgt)))" -Properties @("samaccountname", "serviceprincipalname", "memberof", "pwdlastset", "lastlogon")

            if ($results -and $results.Count -gt 0) {
                Write-Host "[+] $($results.Count) Kerberoast hedefi bulundu!" -ForegroundColor Red

                foreach ($result in $results) {
                    $props = $result.Properties
                    $pwdLastSet = if ($props["pwdlastset"] -and $props["pwdlastset"][0] -gt 0) {
                        [DateTime]::FromFileTime($props["pwdlastset"][0]).ToString("yyyy-MM-dd")
                    } else { "N/A" }

                    Write-Host ""
                    Write-Host "  Kullanıcı: $($props['samaccountname'][0])" -ForegroundColor Red
                    Write-Host "    Parola Değişim: $pwdLastSet" -ForegroundColor White
                    Write-Host "    SPN'ler:" -ForegroundColor White
                    foreach ($spn in $props["serviceprincipalname"]) {
                        Write-Host "      → $spn" -ForegroundColor Yellow
                    }
                }
            }
            else {
                Write-Host "[*] SPN kayıtlı kullanıcı hesabı bulunamadı." -ForegroundColor Green
            }
        }

        "ASREPRoast" {
            Write-Host "[*] Pre-auth gerektirmeyen hesaplar (AS-REP Roast hedefleri)..." -ForegroundColor Yellow
            # DONT_REQ_PREAUTH flag = 0x400000
            $results = Search-LDAP -Filter "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Properties @("samaccountname", "displayname", "memberof")

            if ($results -and $results.Count -gt 0) {
                Write-Host "[+] $($results.Count) AS-REP Roast hedefi bulundu!" -ForegroundColor Red

                foreach ($result in $results) {
                    $props = $result.Properties
                    Write-Host "  → $($props['samaccountname'][0]) ($($props['displayname'][0]))" -ForegroundColor Red
                }
            }
            else {
                Write-Host "[*] Pre-auth gerektirmeyen hesap bulunamadı." -ForegroundColor Green
            }
        }

        "Unconstrained" {
            Write-Host "[*] Unconstrained Delegation yapılandırılmış nesneler..." -ForegroundColor Yellow
            # TRUSTED_FOR_DELEGATION = 0x80000
            $results = Search-LDAP -Filter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))" -Properties @("cn", "dnshostname", "operatingsystem")

            if ($results -and $results.Count -gt 0) {
                Write-Host "[+] $($results.Count) Unconstrained Delegation nesnesi bulundu!" -ForegroundColor Red

                foreach ($result in $results) {
                    $props = $result.Properties
                    Write-Host "  → $($props['cn'][0]) | $($props['dnshostname'][0]) | $($props['operatingsystem'][0])" -ForegroundColor Red
                }
            }
            else {
                Write-Host "[*] Unconstrained Delegation nesnesi bulunamadı (DC'ler hariç)." -ForegroundColor Green
            }

            # Constrained Delegation
            Write-Host ""
            Write-Host "[*] Constrained Delegation nesneleri..." -ForegroundColor Yellow
            $constrainedResults = Search-LDAP -Filter "(&(objectCategory=*)(msds-allowedtodelegateto=*))" -Properties @("cn", "samaccountname", "msds-allowedtodelegateto")

            if ($constrainedResults -and $constrainedResults.Count -gt 0) {
                foreach ($result in $constrainedResults) {
                    $props = $result.Properties
                    Write-Host "  → $($props['samaccountname'][0])" -ForegroundColor Yellow
                    foreach ($target in $props["msds-allowedtodelegateto"]) {
                        Write-Host "      Delegate to: $target" -ForegroundColor White
                    }
                }
            }
        }

        "LAPS" {
            Write-Host "[*] LAPS parolaları kontrol ediliyor..." -ForegroundColor Yellow
            $results = Search-LDAP -Filter "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))" -Properties @("cn", "ms-mcs-admpwd", "ms-mcs-admpwdexpirationtime", "dnshostname")

            if ($results -and $results.Count -gt 0) {
                Write-Host "[+] $($results.Count) bilgisayar için LAPS parolası okunabilir!" -ForegroundColor Red

                foreach ($result in $results) {
                    $props = $result.Properties
                    $expiry = if ($props["ms-mcs-admpwdexpirationtime"] -and $props["ms-mcs-admpwdexpirationtime"][0] -gt 0) {
                        [DateTime]::FromFileTime($props["ms-mcs-admpwdexpirationtime"][0]).ToString("yyyy-MM-dd HH:mm")
                    } else { "N/A" }

                    Write-Host ""
                    Write-Host "  Bilgisayar: $($props['cn'][0])" -ForegroundColor Red
                    Write-Host "    Parola:   $($props['ms-mcs-admpwd'][0])" -ForegroundColor Green
                    Write-Host "    Bitiş:    $expiry" -ForegroundColor White
                }
            }
            else {
                Write-Host "[*] LAPS parolası okunamadı (yetki yok veya LAPS yapılandırılmamış)." -ForegroundColor Yellow
            }
        }

        "GPO" {
            Write-Host "[*] Group Policy nesneleri..." -ForegroundColor Yellow
            $results = Search-LDAP -Filter "(objectClass=groupPolicyContainer)" -Properties @("displayname", "cn", "gpcfilesyspath", "flags")

            foreach ($result in $results) {
                $props = $result.Properties
                $status = switch ([int]$props["flags"][0]) {
                    0 { "Enabled" }
                    1 { "User Disabled" }
                    2 { "Computer Disabled" }
                    3 { "All Disabled" }
                    default { "Unknown" }
                }

                Write-Host ""
                Write-Host "  GPO: $($props['displayname'][0])" -ForegroundColor Green
                Write-Host "    GUID:   $($props['cn'][0])" -ForegroundColor White
                Write-Host "    Path:   $($props['gpcfilesyspath'][0])" -ForegroundColor White
                Write-Host "    Status: $status" -ForegroundColor White
            }
        }

        "OU" {
            Write-Host "[*] Organizational Unit yapısı..." -ForegroundColor Yellow
            $results = Search-LDAP -Filter "(objectClass=organizationalUnit)" -Properties @("name", "distinguishedname", "description")

            foreach ($result in $results) {
                $props = $result.Properties
                $dn = [string]$props["distinguishedname"][0]
                $depth = ($dn -split "OU=" | Where-Object { $_ }).Count
                $indent = "  " * $depth

                Write-Host "$indent📁 $($props['name'][0])" -ForegroundColor Yellow
                if ($props["description"] -and $props["description"][0]) {
                    Write-Host "$indent   $($props['description'][0])" -ForegroundColor DarkGray
                }
            }
        }

        "Stale" {
            Write-Host "[*] $DaysInactive günden fazla inaktif hesaplar..." -ForegroundColor Yellow
            $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
            $cutoffFileTime = $cutoffDate.ToFileTime()

            $results = Search-LDAP -Filter "(&(objectClass=user)(objectCategory=person)(lastLogon<=$cutoffFileTime))" -Properties @("samaccountname", "lastlogon", "useraccountcontrol", "displayname")

            $staleUsers = @()
            foreach ($result in $results) {
                $props = $result.Properties
                $uac = if ($props["useraccountcontrol"]) { $props["useraccountcontrol"][0] } else { 0 }
                $disabled = ($uac -band 0x0002) -ne 0
                $lastLogon = if ($props["lastlogon"] -and $props["lastlogon"][0] -gt 0) {
                    [DateTime]::FromFileTime($props["lastlogon"][0]).ToString("yyyy-MM-dd")
                } else { "Hiç giriş yapmamış" }

                $staleUsers += [PSCustomObject]@{
                    SamAccountName = [string]$props["samaccountname"][0]
                    DisplayName    = [string]$props["displayname"][0]
                    LastLogon      = $lastLogon
                    Disabled       = $disabled
                }
            }

            Write-Host "[+] $($staleUsers.Count) inaktif hesap bulundu." -ForegroundColor Yellow
            $staleUsers | Sort-Object LastLogon | Format-Table -AutoSize
        }

        "Search" {
            if (-not $LDAPFilter) {
                Write-Error "[!] -LDAPFilter parametresi gerekli."
                Write-Host "[*] Örnek: Invoke-ADExplorer -Mode Search -LDAPFilter '(&(objectClass=user)(adminCount=1))'" -ForegroundColor Yellow
                return
            }

            Write-Host "[*] LDAP filtresi: $LDAPFilter" -ForegroundColor Yellow
            $results = Search-LDAP -Filter $LDAPFilter

            foreach ($result in $results) {
                Write-Host ""
                Write-Host "  DN: $($result.Properties['distinguishedname'][0])" -ForegroundColor Green
                foreach ($propName in $result.Properties.PropertyNames) {
                    $value = $result.Properties[$propName]
                    if ($value -and $propName -ne "distinguishedname") {
                        Write-Host "    $propName : $($value -join ', ')" -ForegroundColor White
                    }
                }
            }

            Write-Host ""
            Write-Host "[+] Toplam sonuç: $($results.Count)" -ForegroundColor Green
        }

        "Snapshot" {
            if (-not $OutputPath) {
                $OutputPath = ".\ad_snapshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            }

            Write-Host "[*] AD snapshot alınıyor... Bu işlem birkaç dakika sürebilir." -ForegroundColor Yellow

            $snapshot = @{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Domain    = $domain
                Users     = @()
                Groups    = @()
                Computers = @()
                DCs       = @()
                Trusts    = @()
                GPOs      = @()
            }

            # Users
            $userResults = Search-LDAP -Filter "(&(objectClass=user)(objectCategory=person))" -Properties @("samaccountname", "displayname", "mail", "lastlogon", "useraccountcontrol", "serviceprincipalname", "memberof")
            foreach ($r in $userResults) {
                $p = $r.Properties
                $snapshot.Users += @{
                    SamAccountName = [string]$p["samaccountname"][0]
                    DisplayName    = [string]$p["displayname"][0]
                    Email          = [string]$p["mail"][0]
                    SPN            = @($p["serviceprincipalname"])
                    MemberOf       = @($p["memberof"])
                }
            }

            # Groups
            $groupResults = Search-LDAP -Filter "(objectClass=group)" -Properties @("cn", "member", "description")
            foreach ($r in $groupResults) {
                $p = $r.Properties
                $snapshot.Groups += @{
                    Name        = [string]$p["cn"][0]
                    Members     = @($p["member"])
                    Description = [string]$p["description"][0]
                }
            }

            # Computers
            $compResults = Search-LDAP -Filter "(objectClass=computer)" -Properties @("cn", "operatingsystem", "dnshostname")
            foreach ($r in $compResults) {
                $p = $r.Properties
                $snapshot.Computers += @{
                    Name = [string]$p["cn"][0]
                    DNS  = [string]$p["dnshostname"][0]
                    OS   = [string]$p["operatingsystem"][0]
                }
            }

            # Save
            $snapshot | ConvertTo-Json -Depth 5 | Out-File $OutputPath -Encoding UTF8
            Write-Host "[+] Snapshot kaydedildi: $OutputPath" -ForegroundColor Green
            Write-Host "[+] Kullanıcı: $($snapshot.Users.Count) | Grup: $($snapshot.Groups.Count) | Bilgisayar: $($snapshot.Computers.Count)" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host ("-" * 60) -ForegroundColor DarkGray
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($args.Count -ge 1) {
        Invoke-ADExplorer -Mode $args[0]
    }
}
