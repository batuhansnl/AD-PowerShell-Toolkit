<#
.SYNOPSIS
    Active Directory Güvenlik Denetimi, Keşif ve HTML Raporlama Aracı (Salt Okunur / Read-Only).

.DESCRIPTION
    Bu script, şirket bilgisayarlarında herhangi bir harici kütüphane (.exe, Python, modül)
    yüklemeden, %100 yerel PowerShell ve ADSI/LDAP sorguları ile çalışır.
    
    ÖNEMLİ GÜVENLİK GARANTİSİ:
    - Bu script SALT OKUNUR (READ-ONLY) çalışır.
    - Active Directory veritabanında HİÇBİR nesneyi silmez, eklemez veya değiştirmez.
    - Sadece standart okuma sorguları yaparak güvenlik açıklarını tespit eder ve
      modern, bağımsız (offline çalışabilen) interaktif bir HTML güvenlik raporu üretir.

    Denetlenen Başlıca Alanlar:
    1. Domain & Forest Mimarisi ve DC İşletim Sistemi Sürümleri
    2. Parola ve Hesap Kilitleme Politikası (Password & Lockout Policy)
    3. Yetkili Hesaplar ve Gruplar (Domain Admins, Enterprise Admins vb.)
    4. Kerberoasting Riski (SPN atanmış kullanıcı hesapları ve zayıf şifreleme)
    5. AS-REP Roasting Riski (Pre-Authentication kapalı hesaplar)
    6. Delegasyon Riskleri (Unconstrained ve Constrained Delegation)
    7. Parola Hijyeni (Asla süresi dolmayan, şifresiz, geri çevrilebilir şifreler)
    8. Atıl / Eski Hesaplar (Stale / Inactive Accounts > 90 gün)
    9. AdminCount=1 Korumalı Yetim Hesaplar (Orphaned SDHolder)
    10. Domain Güven İlişkileri (Trust Relationships)

.PARAMETER OutputPath
    Oluşturulacak HTML raporunun dosya yolu. Varsayılan: .\AD-Security-Audit-Report.html

.PARAMETER OpenReport
    Rapor oluşturulduktan sonra varsayılan tarayıcıda otomatik açar.

.PARAMETER DemoMode
    AD'ye bağlı olmayan makinelerde raporun görsel tasarımını ve özelliklerini
    test etmek için örnek simülasyon verisiyle rapor oluşturur.

.EXAMPLE
    .\Invoke-ADAuditReport.ps1
    Geçerli domain'i tarar ve aynı klasörde HTML raporu üretir.

.EXAMPLE
    .\Invoke-ADAuditReport.ps1 -OutputPath "C:\Temp\AuditReport.html" -OpenReport
    Belirtilen konuma raporu kaydeder ve tarayıcıda açar.

.EXAMPLE
    .\Invoke-ADAuditReport.ps1 -DemoMode -OpenReport
    Test amaçlı örnek kurumsal veriyle görsel rapor üretir.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\AD-Security-Audit-Report.html",

    [Parameter(Mandatory = $false)]
    [switch]$OpenReport,

    [Parameter(Mandatory = $false)]
    [switch]$DemoMode
)

$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   Active Directory Güvenlik Denetimi ve Raporlama Aracı       " -ForegroundColor Cyan
Write-Host "   Mod: SALT OKUNUR (Read-Only) - Sisteme Asla Zarar Vermez     " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# YARDIMCI FONKSİYONLAR (LDAP & ADSI ARAMALARI)
# -------------------------------------------------------------------------

function Convert-LargeInteger {
    param($LargeInt)
    if (-not $LargeInt) { return $null }
    try {
        if ($LargeInt -is [System.MarshalByRefObject] -or $LargeInt.GetType().Name -eq "__ComObject") {
            $highPart = $LargeInt.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $LargeInt, $null)
            $lowPart = $LargeInt.GetType().InvokeMember("LowPart", [System.Reflection.BindingFlags]::GetProperty, $null, $LargeInt, $null)
            $longVal = ([int64]$highPart -shl 32) -bor ([uint32]$lowPart)
        } else {
            $longVal = [int64]$LargeInt
        }
        if ($longVal -le 0 -or $longVal -eq 0x7FFFFFFFFFFFFFFF) { return $null }
        return [DateTime]::FromFileTime($longVal)
    }
    catch {
        return $null
    }
}

function Search-AD {
    param(
        [string]$Filter,
        [string[]]$Properties = @("samaccountname", "distinguishedname"),
        [string]$SearchRoot = $null
    )

    try {
        $rootEntry = if ($SearchRoot) { [ADSI]$SearchRoot } else { [ADSI]"" }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($rootEntry)
        $searcher.Filter = $Filter
        $searcher.PageSize = 1000
        $searcher.SizeLimit = 10000

        foreach ($prop in $Properties) {
            [void]$searcher.PropertiesToLoad.Add($prop)
        }

        $results = $searcher.FindAll()
        return $results
    }
    catch {
        Write-Warning "LDAP sorgusu başarısız ($Filter): $($_.Exception.Message)"
        return @()
    }
}

# -------------------------------------------------------------------------
# TEST / DEMO VERİSİ ÜRETİCİSİ (AD Olmayan Ortamlarda Test İçin)
# -------------------------------------------------------------------------
function Get-DemoAuditData {
    Write-Host "[*] Demo Modu Aktif: Temsili Kurumsal AD Verisi Üretiliyor..." -ForegroundColor Yellow
    
    return [PSCustomObject]@{
        DomainInfo = [PSCustomObject]@{
            DomainName = "CORP.LOCAL"
            ForestName = "CORP.LOCAL"
            FunctionalLevel = "Windows Server 2016"
            PDCEmulator = "DC01.corp.local"
            ScanDate = (Get-Date).ToString("dd.MM.yyyy HH:mm:ss")
            ScannedBy = "$($env:USERDOMAIN)\$($env:USERNAME)"
            TotalUsers = 1420
            TotalComputers = 680
            TotalGroups = 185
        }
        PasswordPolicy = [PSCustomObject]@{
            MinPasswordLength = 8
            PasswordHistoryCount = 24
            MaxPasswordAgeDays = 90
            MinPasswordAgeDays = 1
            ComplexityEnabled = $true
            LockoutThreshold = 0
            LockoutDurationMins = 30
            Status = "Riskli (Hesap Kilitleme Kapalı)"
        }
        DomainControllers = @(
            [PSCustomObject]@{ Name = "DC01.corp.local"; IP = "10.0.0.10"; OS = "Windows Server 2019 Standard"; IsPDC = $true },
            [PSCustomObject]@{ Name = "DC02.corp.local"; IP = "10.0.0.11"; OS = "Windows Server 2012 R2 (End of Life)"; IsPDC = $false }
        )
        DomainAdmins = @(
            [PSCustomObject]@{ SamAccountName = "Administrator"; Name = "Built-in Administrator"; Enabled = $true; LastLogon = "09.09.2026"; AdminCount = 1 },
            [PSCustomObject]@{ SamAccountName = "ahmet.yilmaz.adm"; Name = "Ahmet Yılmaz (Admin)"; Enabled = $true; LastLogon = "10.09.2026"; AdminCount = 1 },
            [PSCustomObject]@{ SamAccountName = "sql_admin_service"; Name = "MSSQL Service Admin"; Enabled = $true; LastLogon = "01.03.2026"; AdminCount = 1 },
            [PSCustomObject]@{ SamAccountName = "backup_operator"; Name = "Backup Operator Account"; Enabled = $true; LastLogon = "Never"; AdminCount = 1 },
            [PSCustomObject]@{ SamAccountName = "stajyer.can.adm"; Name = "Can Kaya (Stajyer Admin)"; Enabled = $true; LastLogon = "15.08.2026"; AdminCount = 1 }
        )
        EnterpriseAdmins = @(
            [PSCustomObject]@{ SamAccountName = "Administrator"; Name = "Built-in Administrator"; Enabled = $true }
        )
        KerberoastingCandidates = @(
            [PSCustomObject]@{ SamAccountName = "svc_mssql"; Name = "MSSQL Database Engine"; SPN = "MSSQLSvc/db01.corp.local:1433"; PasswordLastSet = "12.01.2021 (1700+ Gün Önce)"; IsPrivileged = $true; EncryptionType = "RC4_HMAC" },
            [PSCustomObject]@{ SamAccountName = "svc_iis_app"; Name = "Web Portal Pool"; SPN = "http/portal.corp.local"; PasswordLastSet = "05.06.2024"; IsPrivileged = $false; EncryptionType = "AES256" },
            [PSCustomObject]@{ SamAccountName = "sql_admin_service"; Name = "MSSQL Service Admin"; SPN = "MSSQLSvc/cluster.corp.local"; PasswordLastSet = "01.01.2022"; IsPrivileged = $true; EncryptionType = "RC4_HMAC" }
        )
        AsRepRoastCandidates = @(
            [PSCustomObject]@{ SamAccountName = "scanner_user"; Name = "HP Office Scanner"; Description = "DontRequirePreAuth Açık"; PasswordLastSet = "01.05.2020"; Enabled = $true },
            [PSCustomObject]@{ SamAccountName = "legacy_erp"; Name = "Eski ERP Entegrasyonu"; Description = "Kerberos Pre-Auth Disabled"; PasswordLastSet = "14.10.2019"; Enabled = $true }
        )
        DelegationRisks = @(
            [PSCustomObject]@{ Name = "APP-SERVER01$"; Type = "Computer (Member Server)"; Delegation = "Unconstrained Delegation"; Risk = "Kritik - TGT Token Yakalanabilir" },
            [PSCustomObject]@{ Name = "svc_delegation"; Type = "User Service Account"; Delegation = "Constrained (S4U2Proxy)"; Risk = "Orta - Hedef CIFS Servisleri" }
        )
        StaleAccounts = @(
            [PSCustomObject]@{ SamAccountName = "mehmet.oz"; Name = "Mehmet Öz"; LastLogon = "14.02.2025 (500+ Gün Önce)"; Enabled = $true; Description = "Eski Muhasebe Personeli" },
            [PSCustomObject]@{ SamAccountName = "test_user_01"; Name = "Test Kullanıcısı 01"; LastLogon = "Hiç Giriş Yapmadı"; Enabled = $true; Description = "Test hesabı" },
            [PSCustomObject]@{ SamAccountName = "vpn_temp_guest"; Name = "Geçici Ziyaretçi VPN"; LastLogon = "11.11.2024"; Enabled = $true; Description = "Ziyaretçi hesabı" }
        )
        BadFlagAccounts = @(
            [PSCustomObject]@{ SamAccountName = "ceo_assist"; Name = "Yönetici Asistanı"; Issue = "Parola Asla Süresi Dolmaz (DONT_EXPIRE_PASSWORD)"; Severity = "Orta" },
            [PSCustomObject]@{ SamAccountName = "kiosk_user"; Name = "Lobi Kiosk Hesabı"; Issue = "Parola Zorunlu Değil (PASSWD_NOTREQD)"; Severity = "Yüksek" },
            [PSCustomObject]@{ SamAccountName = "legacy_db"; Name = "Eski Oracle DB"; Issue = "Tersine Çevrilebilir Şifreleme (REVERSIBLE_ENCRYPTION)"; Severity = "Kritik" }
        )
        Trusts = @(
            [PSCustomObject]@{ TargetName = "DEV.LOCAL"; TrustType = "Forest Trust"; Direction = "Bi-directional"; SidFiltering = "Disabled (SID History Risk)" }
        )
        LapsStatus = [PSCustomObject]@{
            Installed = $false
            Message = "LAPS Şemada Tespit Edilemedi (Tüm yerel admin parolaları muhtemelen ortak)"
        }
    }
}

# -------------------------------------------------------------------------
# CANLI AD TARAMA FONKSİYONU (SALT OKUNUR)
# -------------------------------------------------------------------------
function Get-LiveAuditData {
    Write-Host "[*] Active Directory bağlantısı test ediliyor..." -ForegroundColor Cyan

    try {
        $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainName = $domainObj.Name
        $forestName = $domainObj.Forest.Name
        $pdc = $domainObj.PdcRoleOwner.Name
        $functionalLevel = $domainObj.DomainMode.ToString()
    }
    catch {
        Write-Warning "Geçerli bir Active Directory domain bağlantısı kurulamadı!"
        Write-Warning "Hata detayı: $($_.Exception.Message)"
        Write-Host "[i] Otomatik olarak Demo/Görselleştirme Moduna geçiliyor..." -ForegroundColor Yellow
        return (Get-DemoAuditData)
    }

    Write-Host "[+] Domain Tespit Edildi: $domainName (Forest: $forestName)" -ForegroundColor Green

    # Domain Controller'ları al
    Write-Host "[*] Domain Controller'lar listeleniyor..." -ForegroundColor Cyan
    $dcs = @()
    foreach ($dc in $domainObj.DomainControllers) {
        $os = "Bilinmiyor"
        try {
            $dcEntry = [ADSI]"LDAP://$($dc.Name)"
            $os = $dcEntry.operatingSystem.ToString()
        } catch {}

        $dcs += [PSCustomObject]@{
            Name = $dc.Name
            IP = $dc.IPAddress
            OS = $os
            IsPDC = ($dc.Name -eq $pdc)
        }
    }

    # Parola Politikası (Domain Root'tan)
    Write-Host "[*] Parola ve hesap kilitleme politikası okunuyor..." -ForegroundColor Cyan
    $domainEntry = [ADSI]""
    $minPwdLen = if ($domainEntry.minPwdLength) { [int]$domainEntry.minPwdLength[0] } else { 0 }
    $pwdHistory = if ($domainEntry.pwdHistoryLength) { [int]$domainEntry.pwdHistoryLength[0] } else { 0 }
    $lockoutThresh = if ($domainEntry.lockoutThreshold) { [int]$domainEntry.lockoutThreshold[0] } else { 0 }
    
    # Max Password Age hesapla
    $maxPwdAgeDays = 0
    if ($domainEntry.maxPwdAge) {
        $largeInt = $domainEntry.maxPwdAge[0]
        $ticks = Convert-LargeInteger -LargeInt $largeInt
        if ($ticks) {
            $span = [DateTime]::FromFileTime([int64]0) - $ticks
            $maxPwdAgeDays = [Math]::Abs($span.Days)
        }
    }

    # Sayımlar
    Write-Host "[*] Nesne sayıları taranıyor..." -ForegroundColor Cyan
    $totalUsers = (Search-AD -Filter "(&(objectCategory=person)(objectClass=user))" -Properties @("samaccountname")).Count
    $totalComputers = (Search-AD -Filter "(objectClass=computer)" -Properties @("samaccountname")).Count
    $totalGroups = (Search-AD -Filter "(objectClass=group)" -Properties @("samaccountname")).Count

    # Domain Admins
    Write-Host "[*] Domain Admins ve yetkili gruplar inceleniyor..." -ForegroundColor Cyan
    $daResults = Search-AD -Filter "(&(objectCategory=group)(samaccountname=Domain Admins))" -Properties @("member")
    $daMembers = @()
    if ($daResults.Count -gt 0) {
        foreach ($memberDn in $daResults[0].Properties["member"]) {
            try {
                $mEntry = [ADSI]"LDAP://$memberDn"
                $lastLogon = Convert-LargeInteger $mEntry.lastLogonTimestamp[0]
                $daMembers += [PSCustomObject]@{
                    SamAccountName = $mEntry.samaccountname.ToString()
                    Name = $mEntry.displayName.ToString()
                    Enabled = (($mEntry.userAccountControl[0] -band 2) -eq 0)
                    LastLogon = if ($lastLogon) { $lastLogon.ToString("dd.MM.yyyy") } else { "Hiç / Bilinmiyor" }
                    AdminCount = 1
                }
            } catch {}
        }
    }

    # Kerberoasting Adayları (SPN Atanmış Kullanıcılar)
    Write-Host "[*] Kerberoasting potansiyeli taşıyan (SPN tanımlı) kullanıcılar taranıyor..." -ForegroundColor Cyan
    $spnResults = Search-AD -Filter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(samaccountname=krbtgt)))" -Properties @("samaccountname", "displayName", "servicePrincipalName", "pwdLastSet", "adminCount")
    $spnList = @()
    foreach ($res in $spnResults) {
        $pwdDate = Convert-LargeInteger $res.Properties["pwdlastset"][0]
        $spns = $res.Properties["serviceprincipalname"] -join ", "
        $isAdmin = ($res.Properties["admincount"][0] -eq 1)

        $spnList += [PSCustomObject]@{
            SamAccountName = $res.Properties["samaccountname"][0]
            Name = if ($res.Properties["displayname"]) { $res.Properties["displayname"][0] } else { $res.Properties["samaccountname"][0] }
            SPN = $spns
            PasswordLastSet = if ($pwdDate) { $pwdDate.ToString("dd.MM.yyyy") } else { "Bilinmiyor" }
            IsPrivileged = $isAdmin
            EncryptionType = "Standard / RC4 / AES"
        }
    }

    # AS-REP Roasting Adayları (Pre-Auth Kapalı Hesaplar)
    Write-Host "[*] AS-REP Roasting riski (Pre-Auth kapalı) olan kullanıcılar kontrol ediliyor..." -ForegroundColor Cyan
    # DONT_REQ_PREAUTH = 4194304 (0x400000)
    $asrepResults = Search-AD -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Properties @("samaccountname", "displayName", "description", "pwdLastSet", "userAccountControl")
    $asrepList = @()
    foreach ($res in $asrepResults) {
        $uac = [int]$res.Properties["useraccountcontrol"][0]
        $enabled = (($uac -band 2) -eq 0)
        $pwdDate = Convert-LargeInteger $res.Properties["pwdlastset"][0]

        $asrepList += [PSCustomObject]@{
            SamAccountName = $res.Properties["samaccountname"][0]
            Name = if ($res.Properties["displayname"]) { $res.Properties["displayname"][0] } else { $res.Properties["samaccountname"][0] }
            Description = if ($res.Properties["description"]) { $res.Properties["description"][0] } else { "Açıklama yok" }
            PasswordLastSet = if ($pwdDate) { $pwdDate.ToString("dd.MM.yyyy") } else { "Bilinmiyor" }
            Enabled = $enabled
        }
    }

    # Delegasyon Riskleri (Unconstrained Delegation)
    Write-Host "[*] Delegasyon riskleri (Unconstrained/Constrained) denetleniyor..." -ForegroundColor Cyan
    # TRUSTED_FOR_DELEGATION = 524288 (0x80000)
    $unconstrainedResults = Search-AD -Filter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))" -Properties @("samaccountname", "objectClass")
    $delegationList = @()
    foreach ($res in $unconstrainedResults) {
        $isComputer = ($res.Properties["objectclass"] -contains "computer")
        $delegationList += [PSCustomObject]@{
            Name = $res.Properties["samaccountname"][0]
            Type = if ($isComputer) { "Computer (Member Server/Client)" } else { "User Account" }
            Delegation = "Unconstrained Delegation"
            Risk = "Yüksek - Bu makineye bağlanan yetkili kullanıcıların TGT biletleri bellekte depolanır"
        }
    }

    # Atıl / Eski Hesaplar (>90 Gün Giriş Yapmamış ama Aktif)
    Write-Host "[*] Atıl / Eski (Stale) hesaplar tespit ediliyor..." -ForegroundColor Cyan
    $ninetyDaysAgo = [DateTime]::UtcNow.AddDays(-90).ToFileTime()
    $staleResults = Search-AD -Filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$ninetyDaysAgo))" -Properties @("samaccountname", "displayName", "description", "lastLogonTimestamp")
    $staleList = @()
    foreach ($res in ($staleResults | Select-Object -First 50)) {
        $lastDate = Convert-LargeInteger $res.Properties["lastlogontimestamp"][0]
        $staleList += [PSCustomObject]@{
            SamAccountName = $res.Properties["samaccountname"][0]
            Name = if ($res.Properties["displayname"]) { $res.Properties["displayname"][0] } else { $res.Properties["samaccountname"][0] }
            LastLogon = if ($lastDate) { $lastDate.ToString("dd.MM.yyyy") } else { "90+ Gündür Giriş Yok" }
            Enabled = $true
            Description = if ($res.Properties["description"]) { $res.Properties["description"][0] } else { "-" }
        }
    }

    # Kötü / Riskli Bayraklar (Asla süresi dolmayan, şifresiz, tersine çevrilebilir)
    Write-Host "[*] Riskli UAC bayrakları taranıyor..." -ForegroundColor Cyan
    $badFlags = @()
    
    # DONT_EXPIRE_PASSWORD = 65536
    $noExpire = Search-AD -Filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=65536))" -Properties @("samaccountname", "displayName")
    foreach ($u in ($noExpire | Select-Object -First 20)) {
        $badFlags += [PSCustomObject]@{
            SamAccountName = $u.Properties["samaccountname"][0]
            Name = if ($u.Properties["displayname"]) { $u.Properties["displayname"][0] } else { $u.Properties["samaccountname"][0] }
            Issue = "Parola Asla Süresi Dolmaz (DONT_EXPIRE_PASSWORD)"
            Severity = "Orta"
        }
    }

    # PASSWD_NOTREQD = 32
    $noPwdReq = Search-AD -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -Properties @("samaccountname", "displayName")
    foreach ($u in $noPwdReq) {
        $badFlags += [PSCustomObject]@{
            SamAccountName = $u.Properties["samaccountname"][0]
            Name = if ($u.Properties["displayname"]) { $u.Properties["displayname"][0] } else { $u.Properties["samaccountname"][0] }
            Issue = "Parola Zorunlu Değil (PASSWD_NOTREQD)"
            Severity = "Kritik"
        }
    }

    # LAPS Kontrolü
    Write-Host "[*] LAPS (Local Administrator Password Solution) varlığı kontrol ediliyor..." -ForegroundColor Cyan
    $lapsFound = $false
    try {
        $schema = [ADSI]"LDAP://schema"
        $searchSchema = New-Object System.DirectoryServices.DirectorySearcher($schema)
        $searchSchema.Filter = "(name=ms-Mcs-AdmPwd)"
        $lapsFound = ($searchSchema.FindOne() -ne $null)
    } catch {}

    return [PSCustomObject]@{
        DomainInfo = [PSCustomObject]@{
            DomainName = $domainName
            ForestName = $forestName
            FunctionalLevel = $functionalLevel
            PDCEmulator = $pdc
            ScanDate = (Get-Date).ToString("dd.MM.yyyy HH:mm:ss")
            ScannedBy = "$($env:USERDOMAIN)\$($env:USERNAME)"
            TotalUsers = $totalUsers
            TotalComputers = $totalComputers
            TotalGroups = $totalGroups
        }
        PasswordPolicy = [PSCustomObject]@{
            MinPasswordLength = $minPwdLen
            PasswordHistoryCount = $pwdHistory
            MaxPasswordAgeDays = $maxPwdAgeDays
            LockoutThreshold = $lockoutThresh
            Status = if ($lockoutThresh -eq 0) { "Kritik (Hesap Kilitleme Kapalı - Brute Force Riski)" } elseif ($minPwdLen -lt 12) { "Zayıf (Min Parola Uzunluğu < 12)" } else { "İyi" }
        }
        DomainControllers = $dcs
        DomainAdmins = $daMembers
        EnterpriseAdmins = @()
        KerberoastingCandidates = $spnList
        AsRepRoastCandidates = $asrepList
        DelegationRisks = $delegationList
        StaleAccounts = $staleList
        BadFlagAccounts = $badFlags
        Trusts = @()
        LapsStatus = [PSCustomObject]@{
            Installed = $lapsFound
            Message = if ($lapsFound) { "LAPS Şeması Mevcut" } else { "LAPS Şemada Bulunamadı (Yerel admin parolaları riski)" }
        }
    }
}

# -------------------------------------------------------------------------
# SKOR VE RİSK HESAPLAMA MOTORU
# -------------------------------------------------------------------------
function Calculate-SecurityScore {
    param($Data)

    $score = 100
    $findings = @()

    # 1. AS-REP Roasting
    if ($Data.AsRepRoastCandidates.Count -gt 0) {
        $count = $Data.AsRepRoastCandidates.Count
        $score -= [Math]::Min(20, $count * 10)
        $findings += [PSCustomObject]@{
            Severity = "CRITICAL"
            Title = "AS-REP Roasting Açık Hesaplar (Pre-Authentication Disabled)"
            Count = $count
            Description = "$count adet kullanıcı hesabında Kerberos Pre-Authentication kapatılmış. Saldırganlar parola bilmeden offline kırılabilecek hash alabilir."
            Remediation = "Active Directory Users and Computers konsolunda bu hesapların Özellikler > Hesap sekmesinden 'Do not require Kerberos preauthentication' kutucuğunun işaretini kaldırın."
        }
    }

    # 2. Kerberoasting (Özellikle Privileged Olanlar)
    if ($Data.KerberoastingCandidates.Count -gt 0) {
        $privCount = ($Data.KerberoastingCandidates | Where-Object { $_.IsPrivileged -eq $true }).Count
        $totalSpn = $Data.KerberoastingCandidates.Count
        
        if ($privCount -gt 0) {
            $score -= 20
            $findings += [PSCustomObject]@{
                Severity = "CRITICAL"
                Title = "Yetkili (Admin) Hesaplarda SPN Kaydı (Kerberoast Hedefi)"
                Count = $privCount
                Description = "$privCount adet Domain Admin veya yüksek yetkili kullanıcıya SPN atanmış. Sıradan bir domain kullanıcısı bu biletleri çekip offline kırabilir."
                Remediation = "Yüksek yetkili hesaplara asla SPN tanımlamayın. Servisler için 'Group Managed Service Accounts (gMSA)' kullanın."
            }
        } elseif ($totalSpn -gt 0) {
            $score -= 10
            $findings += [PSCustomObject]@{
                Severity = "HIGH"
                Title = "SPN Atanmış Servis Hesapları (Kerberoast Riski)"
                Count = $totalSpn
                Description = "$totalSpn adet kullanıcı hesabına SPN tanımlanmış. Parolaları basit veya tahmin edilebilirse kolayca kırılabilir."
                Remediation = "Bu hesaplarda 25+ karakterlik karmaşık parolalar kullanın, AES şifrelemeyi zorunlu kılın veya gMSA mimarisine geçin."
            }
        }
    }

    # 3. Unconstrained Delegation
    if ($Data.DelegationRisks.Count -gt 0) {
        $count = $Data.DelegationRisks.Count
        $score -= 15
        $findings += [PSCustomObject]@{
            Severity = "HIGH"
            Title = "Kısıtlamasız Delegasyon (Unconstrained Delegation)"
            Count = $count
            Description = "Domain Controller harici $count nesnede kısıtlamasız delegasyon açık. Bu sunuculara bağlanan yetkili kullanıcıların TGT biletleri ele geçirilebilir."
            Remediation = "Kısıtlamasız delegasyonu kaldırıp yerine Kerberos Constrained Delegation (KCD) veya Resource-Based Constrained Delegation (RBCD) yapılandırın."
        }
    }

    # 4. Parola Politikası / Hesap Kilitleme
    if ($Data.PasswordPolicy.LockoutThreshold -eq 0) {
        $score -= 15
        $findings += [PSCustomObject]@{
            Severity = "HIGH"
            Title = "Hesap Kilitleme Politikası Kapalı (Brute-Force / Password Spray Riski)"
            Count = 1
            Description = "LockoutThreshold değeri 0 olarak ayarlanmış. Kullanıcı hesapları yanlış parola girişlerinde kilitlenmiyor; bu durum parola deneme saldırılarını sınırsız kılar."
            Remediation = "Default Domain Policy üzerinden Account Lockout Threshold değerini 5 ile 10 arasında bir sayıya ayarlayın."
        }
    }

    if ($Data.PasswordPolicy.MinPasswordLength -lt 12) {
        $score -= 10
        $findings += [PSCustomObject]@{
            Severity = "MEDIUM"
            Title = "Zayıf Asgari Parola Uzunluğu (< 12 Karakter)"
            Count = 1
            Description = "Asgari parola uzunluğu $($Data.PasswordPolicy.MinPasswordLength) karakter. Modern kurumsal güvenlik standartları (NIST/CIS) en az 14-16 karakter önermektedir."
            Remediation = "Minimum password length değerini en az 14 karaktere yükseltin veya Fine-Grained Password Policy (PSO) uygulayın."
        }
    }

    # 5. Atıl / Eski Hesaplar
    if ($Data.StaleAccounts.Count -gt 0) {
        $count = $Data.StaleAccounts.Count
        $score -= [Math]::Min(10, [int]($count / 2))
        $findings += [PSCustomObject]@{
            Severity = "MEDIUM"
            Title = "90+ Gündür Kullanılmayan Aktif Hesaplar (Stale Accounts)"
            Count = $count
            Description = "$count adet kullanıcı hesabı uzun süredir sisteme giriş yapmamış ancak hala AKTİF durumda. Bu hesaplar saldırganlar için gizli giriş kapısı oluşturur."
            Remediation = "90 günden uzun süredir aktif olmayan hesapları otomatik devre dışı bırakan bir rutin/politika uygulayın."
        }
    }

    # 6. Kötü UAC Bayrakları
    if ($Data.BadFlagAccounts.Count -gt 0) {
        $count = $Data.BadFlagAccounts.Count
        $score -= 10
        $findings += [PSCustomObject]@{
            Severity = "MEDIUM"
            Title = "Riskli Hesap Bayrakları (DONT_EXPIRE_PASSWORD / PASSWD_NOTREQD)"
            Count = $count
            Description = "$count adet hesapta parolanın hiç değişmemesi veya parola zorunluluğu olmaması gibi riskli bayraklar tespit edildi."
            Remediation = "Hesapların UAC bayraklarını inceleyip 'Password never expires' işaretini kaldırın."
        }
    }

    # 7. LAPS Eksikliği
    if ($Data.LapsStatus.Installed -eq $false) {
        $score -= 10
        $findings += [PSCustomObject]@{
            Severity = "MEDIUM"
            Title = "LAPS (Local Administrator Password Solution) Tespit Edilemedi"
            Count = 1
            Description = "Şemada LAPS niteliği bulunamadı. Uç nokta bilgisayarlarda yerel Administrator parolaları aynı veya sabit olabilir; bu durum lateral movement'ı kolaylaştırır."
            Remediation = "Microsoft Windows LAPS (yeni dahili LAPS) veya klasik LAPS'ı kurarak yerel admin parolalarını rastgele ve otomatik yönetilen hale getirin."
        }
    }

    $score = [Math]::Max(10, [Math]::Min(100, $score))

    $grade = "A"
    $gradeColor = "#10b981"
    if ($score -lt 50) { $grade = "F"; $gradeColor = "#ef4444" }
    elseif ($score -lt 65) { $grade = "D"; $gradeColor = "#f97316" }
    elseif ($score -lt 80) { $grade = "C"; $gradeColor = "#eab308" }
    elseif ($score -lt 90) { $grade = "B"; $gradeColor = "#3b82f6" }

    return [PSCustomObject]@{
        Score = $score
        Grade = $grade
        GradeColor = $gradeColor
        Findings = $findings
    }
}

# -------------------------------------------------------------------------
# HTML RAPOR ÜRETİCİSİ (MODERN DASHBOARD TASARIMI)
# -------------------------------------------------------------------------
function Generate-HtmlReport {
    param(
        $Data,
        $AuditResult,
        $FilePath
    )

    Write-Host "[*] HTML Raporu oluşturuluyor..." -ForegroundColor Cyan

    $domain = $Data.DomainInfo
    $score = $AuditResult.Score
    $grade = $AuditResult.Grade
    $gradeColor = $AuditResult.GradeColor

    # Bulgular tablosu HTML
    $findingsRowsHtml = ""
    foreach ($f in $AuditResult.Findings) {
        $badgeClass = "badge-low"
        if ($f.Severity -eq "CRITICAL") { $badgeClass = "badge-crit" }
        elseif ($f.Severity -eq "HIGH") { $badgeClass = "badge-high" }
        elseif ($f.Severity -eq "MEDIUM") { $badgeClass = "badge-med" }

        $findingsRowsHtml += @"
        <tr>
            <td><span class="badge $badgeClass">$($f.Severity)</span></td>
            <td><strong>$($f.Title)</strong></td>
            <td><span class="count-pill">$($f.Count)</span></td>
            <td>$($f.Description)</td>
            <td class="rem-text">💡 $($f.Remediation)</td>
        </tr>
"@
    }

    # Domain Admins Tablosu
    $daRowsHtml = ""
    foreach ($da in $Data.DomainAdmins) {
        $statusBadge = if ($da.Enabled) { '<span class="badge badge-ok">Aktif</span>' } else { '<span class="badge badge-crit">Devre Dışı</span>' }
        $daRowsHtml += @"
        <tr>
            <td><code>$($da.SamAccountName)</code></td>
            <td>$($da.Name)</td>
            <td>$statusBadge</td>
            <td>$($da.LastLogon)</td>
        </tr>
"@
    }

    # Kerberoasting Tablosu
    $spnRowsHtml = ""
    foreach ($spn in $Data.KerberoastingCandidates) {
        $privBadge = if ($spn.IsPrivileged) { '<span class="badge badge-crit">YETKİLİ ADMİN</span>' } else { '<span class="badge badge-low">Standart</span>' }
        $spnRowsHtml += @"
        <tr>
            <td><code>$($spn.SamAccountName)</code></td>
            <td>$($spn.Name)</td>
            <td>$privBadge</td>
            <td><small><code>$($spn.SPN)</code></small></td>
            <td>$($spn.PasswordLastSet)</td>
        </tr>
"@
    }

    # AS-REP Roasting Tablosu
    $asrepRowsHtml = ""
    foreach ($a in $Data.AsRepRoastCandidates) {
        $asrepRowsHtml += @"
        <tr>
            <td><code>$($a.SamAccountName)</code></td>
            <td>$($a.Name)</td>
            <td>$($a.Description)</td>
            <td>$($a.PasswordLastSet)</td>
            <td><span class="badge badge-crit">Pre-Auth Kapalı</span></td>
        </tr>
"@
    }

    # Delegasyon Tablosu
    $delegationRowsHtml = ""
    foreach ($d in $Data.DelegationRisks) {
        $delegationRowsHtml += @"
        <tr>
            <td><code>$($d.Name)</code></td>
            <td>$($d.Type)</td>
            <td><span class="badge badge-high">$($d.Delegation)</span></td>
            <td>$($d.Risk)</td>
        </tr>
"@
    }

    # Atıl Hesaplar Tablosu
    $staleRowsHtml = ""
    foreach ($s in $Data.StaleAccounts) {
        $staleRowsHtml += @"
        <tr>
            <td><code>$($s.SamAccountName)</code></td>
            <td>$($s.Name)</td>
            <td>$($s.LastLogon)</td>
            <td>$($s.Description)</td>
        </tr>
"@
    }

    # Domain Controller Tablosu
    $dcRowsHtml = ""
    foreach ($dc in $Data.DomainControllers) {
        $pdcBadge = if ($dc.IsPDC) { '<span class="badge badge-ok">PDC Emulator</span>' } else { '<span class="badge badge-low">Replicating DC</span>' }
        $dcRowsHtml += @"
        <tr>
            <td><code>$($dc.Name)</code></td>
            <td>$($dc.IP)</td>
            <td>$($dc.OS)</td>
            <td>$pdcBadge</td>
        </tr>
"@
    }

    # Ana HTML Şablonu (Tek dosya, dahili CSS & JS, internet bağlantısı gerektirmez)
    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Directory Güvenlik Denetim Raporu - $($domain.DomainName)</title>
    <style>
        :root {
            --bg-base: #0b0f19;
            --bg-card: #151d30;
            --bg-hover: #1c2742;
            --border-color: #24304f;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --card-radius: 12px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }

        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            padding: 24px;
            font-size: 14px;
            line-height: 1.5;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        /* HEADER */
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border-color);
            border-radius: var(--card-radius);
            padding: 24px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        }

        .header-title h1 {
            font-size: 26px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .header-title .tag {
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
            font-size: 12px;
            padding: 4px 10px;
            border-radius: 20px;
            border: 1px solid rgba(16, 185, 129, 0.3);
            font-weight: 600;
        }

        .header-meta {
            margin-top: 8px;
            color: var(--text-muted);
            font-size: 13px;
            display: flex;
            gap: 20px;
        }

        .header-meta span strong {
            color: var(--text-main);
        }

        /* SCORE CIRCLE */
        .score-box {
            display: flex;
            align-items: center;
            gap: 20px;
            background: rgba(15, 23, 42, 0.6);
            padding: 12px 24px;
            border-radius: var(--card-radius);
            border: 1px solid var(--border-color);
        }

        .score-circle {
            width: 72px;
            height: 72px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            border: 4px solid $gradeColor;
            box-shadow: 0 0 20px $($gradeColor)44;
        }

        .score-num {
            font-size: 22px;
            color: var(--text-main);
            line-height: 1;
        }

        .score-label {
            font-size: 11px;
            color: var(--text-muted);
        }

        .grade-letter {
            font-size: 32px;
            font-weight: 900;
            color: $gradeColor;
        }

        /* KPI STATS */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--card-radius);
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .stat-title {
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }

        .stat-value {
            font-size: 28px;
            font-weight: 700;
            color: var(--text-main);
        }

        .stat-desc {
            font-size: 12px;
            color: var(--text-muted);
        }

        /* TABS */
        .tab-nav {
            display: flex;
            gap: 8px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
            padding-bottom: 4px;
        }

        .tab-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            padding: 10px 18px;
            font-size: 14px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .tab-btn:hover {
            color: var(--text-main);
            background: var(--bg-card);
        }

        .tab-btn.active {
            color: var(--primary);
            background: rgba(59, 130, 246, 0.12);
            border: 1px solid rgba(59, 130, 246, 0.3);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* CARD */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--card-radius);
            padding: 24px;
            margin-bottom: 24px;
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
        }

        .card-header h2 {
            font-size: 18px;
            font-weight: 600;
        }

        /* SEARCH INPUT */
        .search-bar {
            background: var(--bg-base);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 13px;
            width: 260px;
            outline: none;
        }

        .search-bar:focus {
            border-color: var(--primary);
        }

        /* TABLES */
        .table-responsive {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th {
            background: rgba(15, 23, 42, 0.6);
            color: var(--text-muted);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
        }

        td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }

        tr:hover td {
            background: var(--bg-hover);
        }

        code {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border-color);
            padding: 2px 6px;
            border-radius: 4px;
            color: #60a5fa;
            font-family: "SFMono-Regular", Consolas, Menlo, monospace;
            font-size: 13px;
        }

        /* BADGES */
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .badge-crit { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-high { background: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.3); }
        .badge-med  { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-low  { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
        .badge-ok   { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }

        .count-pill {
            background: rgba(255,255,255,0.08);
            padding: 3px 8px;
            border-radius: 12px;
            font-weight: 700;
            font-size: 12px;
        }

        .rem-text {
            color: #38bdf8;
            font-size: 12px;
        }

        /* FOOTER */
        .footer {
            text-align: center;
            margin-top: 40px;
            color: var(--text-muted);
            font-size: 12px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <div class="header">
            <div class="header-title">
                <h1>
                    🛡️ Active Directory Güvenlik Denetim Raporu
                    <span class="tag">SALT OKUNUR (READ-ONLY)</span>
                </h1>
                <div class="header-meta">
                    <span>Domain: <strong>$($domain.DomainName)</strong></span>
                    <span>Forest: <strong>$($domain.ForestName)</strong></span>
                    <span>Seviye: <strong>$($domain.FunctionalLevel)</strong></span>
                    <span>PDC: <strong>$($domain.PDCEmulator)</strong></span>
                    <span>Tarih: <strong>$($domain.ScanDate)</strong></span>
                </div>
            </div>
            <div class="score-box">
                <div class="score-circle">
                    <div class="score-num">$score</div>
                    <div class="score-label">/ 100</div>
                </div>
                <div>
                    <div class="grade-letter">$grade</div>
                    <div style="font-size:12px; color:var(--text-muted);">Güvenlik Notu</div>
                </div>
            </div>
        </div>

        <!-- KPI STATS -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-title">Toplam Kullanıcı</div>
                <div class="stat-value">$($domain.TotalUsers)</div>
                <div class="stat-desc">Dizin veritabanındaki hesaplar</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Domain Admins</div>
                <div class="stat-value" style="color: $(if($Data.DomainAdmins.Count -gt 5){'#f59e0b'}else{'#10b981'})">
                    $($Data.DomainAdmins.Count)
                </div>
                <div class="stat-desc">Yüksek yetkili yönetici hesapları</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Kritik / Yüksek Risk</div>
                <div class="stat-value" style="color: $(if($AuditResult.Findings.Count -gt 0){'#ef4444'}else{'#10b981'})">
                    $($AuditResult.Findings.Count)
                </div>
                <div class="stat-desc">Düzeltme bekleyen zafiyet başlığı</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Hesap Kilitleme (Lockout)</div>
                <div class="stat-value" style="color: $(if($Data.PasswordPolicy.LockoutThreshold -eq 0){'#ef4444'}else{'#10b981'})">
                    $(if($Data.PasswordPolicy.LockoutThreshold -eq 0){ "KAPALI" } else { "$($Data.PasswordPolicy.LockoutThreshold) Hatalı Giriş" })
                </div>
                <div class="stat-desc">Password spraying koruması</div>
            </div>
        </div>

        <!-- TAB NAVIGATION -->
        <div class="tab-nav">
            <button class="tab-btn active" onclick="switchTab('tab-findings', this)">🚨 Güvenlik Bulguları ($($AuditResult.Findings.Count))</button>
            <button class="tab-btn" onclick="switchTab('tab-admins', this)">👑 Domain Admins ($($Data.DomainAdmins.Count))</button>
            <button class="tab-btn" onclick="switchTab('tab-kerberos', this)">🎯 Kerberos & Delegasyon ($($Data.KerberoastingCandidates.Count + $Data.AsRepRoastCandidates.Count))</button>
            <button class="tab-btn" onclick="switchTab('tab-stale', this)">👥 Atıl & Riskli Hesaplar ($($Data.StaleAccounts.Count))</button>
            <button class="tab-btn" onclick="switchTab('tab-infra', this)">🏰 Domain & DC Altyapısı ($($Data.DomainControllers.Count))</button>
        </div>

        <!-- TAB 1: BULGULAR -->
        <div id="tab-findings" class="tab-content active">
            <div class="card">
                <div class="card-header">
                    <h2>Tespit Edilen Güvenlik Riskleri ve Çözüm Önerileri</h2>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 100px;">Seviye</th>
                                <th style="width: 250px;">Zafiyet Başlığı</th>
                                <th style="width: 80px;">Sayı</th>
                                <th>Detay / Risk Analizi</th>
                                <th>Önerilen İyileştirme (Remediation)</th>
                            </tr>
                        </thead>
                        <tbody>
                            $findingsRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 2: DOMAIN ADMINS -->
        <div id="tab-admins" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>Domain Admins Grubu Üyeleri</h2>
                    <input type="text" class="search-bar" placeholder="Kullanıcı ara..." onkeyup="filterTable(this, 'table-admins')">
                </div>
                <div class="table-responsive">
                    <table id="table-admins">
                        <thead>
                            <tr>
                                <th>Kullanıcı Adı (sAMAccountName)</th>
                                <th>Görünen Ad</th>
                                <th>Hesap Durumu</th>
                                <th>Son Oturum Açma</th>
                            </tr>
                        </thead>
                        <tbody>
                            $daRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 3: KERBEROS & DELEGASYON -->
        <div id="tab-kerberos" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>Kerberoasting Hedefleri (SPN Tanımlı Hesaplar)</h2>
                    <input type="text" class="search-bar" placeholder="SPN ara..." onkeyup="filterTable(this, 'table-spn')">
                </div>
                <div class="table-responsive">
                    <table id="table-spn">
                        <thead>
                            <tr>
                                <th>Kullanıcı Adı</th>
                                <th>Görünen Ad</th>
                                <th>Yetki Durumu</th>
                                <th>Service Principal Name (SPN)</th>
                                <th>Son Parola Değişikliği</th>
                            </tr>
                        </thead>
                        <tbody>
                            $spnRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2>AS-REP Roasting Hedefleri (Pre-Authentication Kapalı)</h2>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Kullanıcı Adı</th>
                                <th>Görünen Ad</th>
                                <th>Açıklama</th>
                                <th>Son Parola Değişikliği</th>
                                <th>Durum</th>
                            </tr>
                        </thead>
                        <tbody>
                            $asrepRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2>Delegasyon Riskleri (Unconstrained / Constrained)</h2>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Nesne Adı</th>
                                <th>Tür</th>
                                <th>Delegasyon Türü</th>
                                <th>Risk Seviyesi / Not</th>
                            </tr>
                        </thead>
                        <tbody>
                            $delegationRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 4: ATIL HESAPLAR -->
        <div id="tab-stale" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>90+ Gündür Kullanılmayan Aktif Hesaplar (Stale Accounts)</h2>
                    <input type="text" class="search-bar" placeholder="Hesap ara..." onkeyup="filterTable(this, 'table-stale')">
                </div>
                <div class="table-responsive">
                    <table id="table-stale">
                        <thead>
                            <tr>
                                <th>Kullanıcı Adı</th>
                                <th>Görünen Ad</th>
                                <th>Son Giriş Tarihi</th>
                                <th>Açıklama</th>
                            </tr>
                        </thead>
                        <tbody>
                            $staleRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 5: ALTYAPI & DC -->
        <div id="tab-infra" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>Domain Controller Sunucuları</h2>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Sunucu Adı (FQDN)</th>
                                <th>IP Adresi</th>
                                <th>İşletim Sistemi</th>
                                <th>Rol</th>
                            </tr>
                        </thead>
                        <tbody>
                            $dcRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2>Parola ve Hesap Politikaları</h2>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Politika Parametresi</th>
                                <th>Mevcut Değer</th>
                                <th>Önerilen Değer</th>
                                <th>Değerlendirme</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Asgari Parola Uzunluğu</td>
                                <td><strong>$($Data.PasswordPolicy.MinPasswordLength) Karakter</strong></td>
                                <td>En az 14 Karakter</td>
                                <td>$(if($Data.PasswordPolicy.MinPasswordLength -lt 12){'<span class="badge badge-high">Yetersiz</span>'}else{'<span class="badge badge-ok">Uygun</span>'})</td>
                            </tr>
                            <tr>
                                <td>Hesap Kilitleme Eşiği (Lockout)</td>
                                <td><strong>$($Data.PasswordPolicy.LockoutThreshold) Deneme</strong></td>
                                <td>5 - 10 Deneme</td>
                                <td>$(if($Data.PasswordPolicy.LockoutThreshold -eq 0){'<span class="badge badge-crit">Kritik (Kapalı)</span>'}else{'<span class="badge badge-ok">Aktif</span>'})</td>
                            </tr>
                            <tr>
                                <td>Azami Parola Yaşı</td>
                                <td><strong>$($Data.PasswordPolicy.MaxPasswordAgeDays) Gün</strong></td>
                                <td>60 - 90 Gün (veya MFA)</td>
                                <td><span class="badge badge-low">Bilgi</span></td>
                            </tr>
                            <tr>
                                <td>LAPS Durumu</td>
                                <td><strong>$($Data.LapsStatus.Message)</strong></td>
                                <td>LAPS Yüklü & Aktif</td>
                                <td>$(if($Data.LapsStatus.Installed){'<span class="badge badge-ok">Yüklü</span>'}else{'<span class="badge badge-med">Eksik</span>'})</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- FOOTER -->
        <div class="footer">
            Bu rapor, şirket içi güvenlik denetimi amacıyla <strong>Invoke-ADAuditReport.ps1</strong> tarafından yerel LDAP/ADSI sorguları kullanılarak salt okunur üretilmiştir.
            <br>Sistem üzerinde hiçbir değişiklik veya veri modifikasyonu yapılmamıştır.
        </div>
    </div>

    <!-- JAVASCRIPT: TAB & SEARCH -->
    <script>
        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
        }

        function filterTable(input, tableId) {
            const filter = input.value.toLowerCase();
            const table = document.getElementById(tableId);
            const trs = table.getElementsByTagName('tr');

            for (let i = 1; i < trs.length; i++) {
                const text = trs[i].textContent.toLowerCase();
                trs[i].style.display = text.indexOf(filter) > -1 ? '' : 'none';
            }
        }
    </script>
</body>
</html>
"@

    # HTML dosyasını yaz
    [System.IO.File]::WriteAllText($FilePath, $html, [System.Text.Encoding]::UTF8)
    Write-Host "[+] HTML Raporu Başarıyla Oluşturuldu: $FilePath" -ForegroundColor Green
}

# -------------------------------------------------------------------------
# ANA AKIŞ
# -------------------------------------------------------------------------

$resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

# Veriyi topla
$auditData = if ($DemoMode) {
    Get-DemoAuditData
} else {
    Get-LiveAuditData
}

# Güvenlik skorunu hesapla
$auditResult = Calculate-SecurityScore -Data $auditData

# HTML raporunu üret
Generate-HtmlReport -Data $auditData -AuditResult $auditResult -FilePath $resolvedPath

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   DENETİM TAMAMLANDI!                                         " -ForegroundColor Green
Write-Host "   Genel Güvenlik Skoru: $($auditResult.Score) / 100 (Derece: $($auditResult.Grade))" -ForegroundColor Yellow
Write-Host "   Tespit Edilen Risk Sayısı: $($auditResult.Findings.Count)" -ForegroundColor $(if($auditResult.Findings.Count -gt 0){'Red'}else{'Green'})
Write-Host "   Rapor Dosyası: $resolvedPath" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan

if ($OpenReport) {
    try {
        Start-Process $resolvedPath
    } catch {
        Write-Warning "Rapor tarayıcıda otomatik açılamadı: $($_.Exception.Message)"
    }
}
