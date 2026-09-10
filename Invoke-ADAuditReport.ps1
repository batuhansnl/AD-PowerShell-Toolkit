# ==============================================================================
# Active Directory Guvenlik Denetimi, Kesif ve HTML Raporlama Araci
# Mod: %100 SALT OKUNUR (READ-ONLY) - Active Directory'ye Asla Zarar Vermez
# ==============================================================================

<#
.SYNOPSIS
    Active Directory Guvenlik Denetimi, Kesif, ACL Analizi ve Attack Path Raporlama Araci.

.DESCRIPTION
    Bu script, sirket bilgisayarlarinda herhangi bir harici kutuphane (.exe, Python, modul)
    yuklemeden, %100 yerel Windows PowerShell ve ADSI/LDAP sorgulari ile calisir.
    
    ONEMLI GUVENLIK GARANTISI:
    - Bu script SALT OKUNUR (READ-ONLY) calisir.
    - Active Directory veritabaninda HICBIR nesneyi silmez, eklemez veya degistirmez.
    - Sadece standart okuma sorgulari yaparak guvenlik aciklarini tespit eder,
      BloodHound tarzi saldiri yollarini (Attack Paths) cikartir ve modern, bagimsiz
      (offline calisabilen) interaktif bir HTML guvenlik dashboard'u uretir.

.PARAMETER OutputPath
    Olusturulacak HTML raporunun dosya yolu. Varsayilan: .\AD-Security-Audit-Report.html

.PARAMETER OpenReport
    Rapor olusturulduktan sonra varsayilan tarayicida otomatik acar.

.PARAMETER DemoMode
    AD'ye bagli olmayan makinelerde raporun gorsel tasarimini ve ozelliklerini
    test etmek icin ornek kurumsal veriyle zengin bir rapor olusturur.

.EXAMPLE
    .\Invoke-ADAuditReport.ps1 -OpenReport
    Gecerli domain'i tarar ve HTML raporunu uretip acar.

.EXAMPLE
    .\Invoke-ADAuditReport.ps1 -DemoMode -OpenReport
    Test amacli ornek veriyle grafikleri ve raporu tarayicida acar.
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

# Turkce ve Unicode karakterlerin bozulmasini onleme
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   Active Directory Guvenlik Denetimi ve Raporlama Araci       " -ForegroundColor Cyan
Write-Host "   Mod: SALT OKUNUR (Read-Only) - Sisteme Asla Zarar Vermez     " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. YARDIMCI FONKSIYONLAR (LDAP & ADSI)
# ------------------------------------------------------------------------------

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
        [string]$SearchRoot = $null,
        [int]$PageSize = 1000,
        [int]$SizeLimit = 10000
    )

    try {
        $rootEntry = if ($SearchRoot) { [ADSI]$SearchRoot } else { [ADSI]"" }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($rootEntry)
        $searcher.Filter = $Filter
        $searcher.PageSize = $PageSize
        $searcher.SizeLimit = $SizeLimit

        foreach ($prop in $Properties) {
            [void]$searcher.PropertiesToLoad.Add($prop)
        }

        $results = $searcher.FindAll()
        return $results
    }
    catch {
        Write-Warning "LDAP sorgusu hatasi ($Filter): $($_.Exception.Message)"
        return @()
    }
}

function Get-WellKnownGuidName {
    param([string]$Guid)
    $dict = @{
        "00299570-246d-11d0-a768-00aa006e0529" = "User-Force-Change-Password (Reset Password)"
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes (DCSync)"
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All (DCSync)"
        "89e95b76-444d-4c62-991a-0facbeda5f3b" = "DS-Replication-Get-Changes-In-Filtered-Set"
        "f30e3bc2-9ff0-11d1-b603-0000f80367c1" = "GP-Link (GPO Link Write)"
        "bf9679c0-0de6-11d0-a285-00aa003049e2" = "Member (Add Self to Group)"
    }
    if ($dict.ContainsKey($Guid)) { return $dict[$Guid] }
    return $Guid
}

# ------------------------------------------------------------------------------
# 2. DEMO / SIMULASYON VERISI URETICISI
# ------------------------------------------------------------------------------
function Get-DemoAuditData {
    Write-Host "[*] Demo Modu Aktif: Zengin Kurumsal AD Verisi ve Saldiri Yollari Uretiliyor..." -ForegroundColor Yellow
    
    $domainInfo = [PSCustomObject]@{
        DomainName = "CORP.LOCAL"
        ForestName = "CORP.LOCAL"
        FunctionalLevel = "Windows Server 2016"
        PDCEmulator = "DC01.corp.local"
        ScanDate = (Get-Date).ToString("dd.MM.yyyy HH:mm:ss")
        ScannedBy = "$($env:USERDOMAIN)\$($env:USERNAME)"
        TotalUsers = 1420
        TotalComputers = 680
        TotalGroups = 185
        TotalGPOs = 34
    }

    $passwordPolicy = [PSCustomObject]@{
        MinPasswordLength = 8
        PasswordHistoryCount = 24
        MaxPasswordAgeDays = 90
        MinPasswordAgeDays = 1
        ComplexityEnabled = $true
        LockoutThreshold = 0
        LockoutDurationMins = 30
        Status = "Kritik (Hesap Kilitleme Kapali - Brute Force Riski)"
    }

    $domainControllers = @(
        [PSCustomObject]@{ Name = "DC01.corp.local"; IP = "10.0.0.10"; OS = "Windows Server 2019 Standard"; Build = "1809"; IsPDC = $true; Status = "Guncel" },
        [PSCustomObject]@{ Name = "DC02.corp.local"; IP = "10.0.0.11"; OS = "Windows Server 2012 R2"; Build = "9600"; IsPDC = $false; Status = "Guvenlik Riski (EOL Destegi Bitti)" }
    )

    $domainAdmins = @(
        [PSCustomObject]@{ SamAccountName = "Administrator"; Name = "Built-in Administrator"; Enabled = $true; LastLogon = "09.09.2026"; AdminCount = 1; Description = "Yerel Domain Admin Hesabi" },
        [PSCustomObject]@{ SamAccountName = "ahmet.yilmaz.adm"; Name = "Ahmet Yilmaz (Sistem Yoneticisi)"; Enabled = $true; LastLogon = "10.09.2026"; AdminCount = 1; Description = "Tier 0 Sistem Yoneticisi" },
        [PSCustomObject]@{ SamAccountName = "sql_admin_service"; Name = "MSSQL Cluster Admin"; Enabled = $true; LastLogon = "01.03.2026"; AdminCount = 1; Description = "Veritabani Servis Hesabi (Hatali Admin Rolunde!)" },
        [PSCustomObject]@{ SamAccountName = "backup_operator"; Name = "Yedekleme Servis Hesabi"; Enabled = $true; LastLogon = "01.01.2025"; AdminCount = 1; Description = "Veeam Backup Hesabi" },
        [PSCustomObject]@{ SamAccountName = "stajyer.can.adm"; Name = "Can Kaya (Stajyer Admin)"; Enabled = $true; LastLogon = "15.08.2026"; AdminCount = 1; Description = "Gecici Verilen Admin Hakki" }
    )

    $kerberoasting = @(
        [PSCustomObject]@{ 
            SamAccountName = "sql_admin_service"
            Name = "MSSQL Cluster Admin"
            SPN = "MSSQLSvc/sqlcluster.corp.local:1433"
            PasswordLastSet = "12.01.2021 (1700+ Gun Once)"
            IsPrivileged = $true
            EncryptionType = "RC4_HMAC (Zayif)"
            OU = "OU=ServiceAccounts,DC=corp,DC=local"
            RiskReason = "Domain Admin uyesi bir servis hesabina SPN tanimlanmis. Kirildiginda dogrudan Domain Admin yetkisi saglar."
        },
        [PSCustomObject]@{ 
            SamAccountName = "svc_web_portal"
            Name = "Intranet Web Portal Pool"
            SPN = "HTTP/portal.corp.local"
            PasswordLastSet = "05.06.2024"
            IsPrivileged = $false
            EncryptionType = "AES256"
            OU = "OU=WebApps,DC=corp,DC=local"
            RiskReason = "Standart SPN hesabi. Parolasi tahmin edilirse web sunucusu ele gecirilebilir."
        },
        [PSCustomObject]@{ 
            SamAccountName = "svc_sap_connector"
            Name = "SAP ERP Integration Account"
            SPN = "SAP/erp.corp.local"
            PasswordLastSet = "20.08.2019 (2200+ Gun Once)"
            IsPrivileged = $false
            EncryptionType = "RC4_HMAC (Zayif)"
            OU = "OU=ERP,DC=corp,DC=local"
            RiskReason = "5 yildir degismemis RC4 parolasi. Offline hash kirma araclarina karsi cok zayiftir."
        }
    )

    $asrepRoast = @(
        [PSCustomObject]@{ 
            SamAccountName = "scanner_user"
            Name = "Kat-3 Fotokopi ve Tarayici"
            Description = "DontRequirePreAuth Acik"
            PasswordLastSet = "01.05.2020"
            Enabled = $true
            OU = "OU=Devices,DC=corp,DC=local"
            RiskReason = "Kerberos Pre-Authentication kapali. Agdaki herhangi bir kullanici parola bilmeden bu hesabin hash'ini AS-REP cevabi olarak cekip kirabilir."
        },
        [PSCustomObject]@{ 
            SamAccountName = "legacy_crm_sync"
            Name = "Eski CRM Senkronizasyon"
            Description = "Pre-Auth devre disi birakilmis"
            PasswordLastSet = "14.10.2018"
            Enabled = $true
            OU = "OU=Legacy,DC=corp,DC=local"
            RiskReason = "Eski bir entegrasyon hesabi. Pre-Auth kapali ve 6 yildir parolasi yenilenmemis."
        }
    )

    $delegationRisks = @(
        [PSCustomObject]@{ 
            Name = "APP-SERVER01$"
            Type = "Computer (Member Server)"
            Delegation = "Unconstrained Delegation"
            Risk = "Kritik"
            Detail = "Bu sunucuya RDP/SMB ile baglanan tum yetkili kullanicilarin (Domain Admin dahil) TGT biletleri LSA belleginde saklanir. Sunucu ele gecirilirse biletler calinabilir."
            OU = "OU=AppServers,DC=corp,DC=local"
        },
        [PSCustomObject]@{ 
            Name = "svc_proxy_deleg"
            Type = "User Service Account"
            Delegation = "Constrained Delegation (S4U2Proxy)"
            Risk = "Yuksek"
            Detail = "cifs/FILE-SRV.corp.local servisine yonelik delegasyon yetkisi var. Dosya sunucusundaki dosyalara sahte biletle erisebilir."
            OU = "OU=Services,DC=corp,DC=local"
        }
    )

    $aclRisks = @(
        [PSCustomObject]@{
            ActiveObject = "HelpDesk_Users (Grup)"
            TargetObject = "ahmet.yilmaz.adm (Domain Admin)"
            Permission = "WriteDacl / GenericAll"
            RiskLevel = "Kritik"
            Impact = "HelpDesk grubundaki standart bir kullanici, Ahmet Yilmaz admin hesabinin ACL izinlerini degistirerek tam kontrol sahibi olabilir veya parolasini sifirlayabilir."
        },
        [PSCustomObject]@{
            ActiveObject = "stajyer.can.adm (Kullanici)"
            TargetObject = "Domain Admins (Grup)"
            Permission = "AddMember / WriteProperty"
            RiskLevel = "Kritik"
            Impact = "Stajyer hesabi dogrudan Domain Admins grubuna istedigi herhangi bir kullaniciyi uye olarak ekleyebilir."
        },
        [PSCustomObject]@{
            ActiveObject = "Exchange Windows Permissions (Grup)"
            TargetObject = "CORP.LOCAL (Domain Root)"
            Permission = "WriteDacl"
            RiskLevel = "Kritik (DCSync Potansiyeli)"
            Impact = "Domain basliginda WriteDacl yetkisi vardir. Bu gruptaki bir hesap domain basligina DCSync (Replication) hakki ekleyerek tum AD parolalarini dump edebilir."
        },
        [PSCustomObject]@{
            ActiveObject = "IT-Support (Grup)"
            TargetObject = "OU=Tier1_Servers"
            Permission = "GenericAll"
            RiskLevel = "Yuksek"
            Impact = "Sunucular OU'sundaki tum bilgisayar hesaplarini sifirlayabilir veya yonetebilir."
        }
    )

    $staleAccounts = @(
        [PSCustomObject]@{ SamAccountName = "mehmet.oz"; Name = "Mehmet Oz (Eski Muhasebe)"; LastLogon = "14.02.2025 (500+ Gun Once)"; Enabled = $true; Description = "Isten ayrilmis personel"; OU = "OU=Users,DC=corp,DC=local" },
        [PSCustomObject]@{ SamAccountName = "test_user_qa"; Name = "QA Test Hesabi 01"; LastLogon = "Hic Giris Yapmadi"; Enabled = $true; Description = "Yazilim test hesabi"; OU = "OU=Testing,DC=corp,DC=local" },
        [PSCustomObject]@{ SamAccountName = "vpn_temp_guest"; Name = "Gecici Ziyaretci VPN"; LastLogon = "11.11.2024 (600+ Gun Once)"; Enabled = $true; Description = "Danisman hesabi"; OU = "OU=Guests,DC=corp,DC=local" }
    )

    $badFlags = @(
        [PSCustomObject]@{ SamAccountName = "ceo_assist"; Name = "Yonetici Asistani"; Issue = "Parola Asla Suresi Dolmaz (DONT_EXPIRE_PASSWORD)"; Severity = "Orta"; OU = "OU=Executive,DC=corp,DC=local" },
        [PSCustomObject]@{ SamAccountName = "kiosk_lobby"; Name = "Lobi Kiosk Kullanicisi"; Issue = "Parola Zorunlu Degil (PASSWD_NOTREQD)"; Severity = "Yuksek"; OU = "OU=Kiosks,DC=corp,DC=local" },
        [PSCustomObject]@{ SamAccountName = "legacy_erp_db"; Name = "Eski ERP Veritabani"; Issue = "Tersine Cevrilebilir Sifreleme (REVERSIBLE_ENCRYPTION)"; Severity = "Kritik"; OU = "OU=Database,DC=corp,DC=local" }
    )

    # BloodHound Tarzi Saldiri Yollari (Attack Paths Graph)
    $attackPaths = @(
        [PSCustomObject]@{
            PathId = "path1"
            Title = "Yol 1: Standart Kullanicidan -> Domain Admin'e Escalation (ACL Istismari)"
            Risk = "Kritik"
            Description = "mehmet.oz (Ele Gecirilen) -> MemberOf -> HelpDesk_Users -> WriteDacl Yetkisi -> ahmet.yilmaz.adm (Reset-Password) -> Domain Admins (Full Domain Compromise)"
            Nodes = @(
                [PSCustomObject]@{ id = "u1"; label = "mehmet.oz\n(Standart User)"; type = "user"; role = "entry"; x = 50; y = 150 },
                [PSCustomObject]@{ id = "g1"; label = "HelpDesk_Users\n(Grup)"; type = "group"; role = "pivot"; x = 250; y = 150 },
                [PSCustomObject]@{ id = "u2"; label = "ahmet.yilmaz.adm\n(Domain Admin)"; type = "user"; role = "admin"; x = 500; y = 150 },
                [PSCustomObject]@{ id = "g2"; label = "Domain Admins\n(Tier 0 Hedef)"; type = "group"; role = "target"; x = 750; y = 150 }
            )
            Edges = @(
                [PSCustomObject]@{ from = "u1"; to = "g1"; label = "MemberOf"; color = "#3b82f6" },
                [PSCustomObject]@{ from = "g1"; to = "u2"; label = "WriteDacl / GenericAll"; color = "#ef4444" },
                [PSCustomObject]@{ from = "u2"; to = "g2"; label = "MemberOf"; color = "#10b981" }
            )
        },
        [PSCustomObject]@{
            PathId = "path2"
            Title = "Yol 2: AS-REP Roasting ile Baslayip Unconstrained Delegation Uzerinden DC Ele Gecirme"
            Risk = "Kritik"
            Description = "scanner_user (Pre-Auth Kapali) -> Hash Kiralandi -> APP-SERVER01'e Giris -> Unconstrained Delegation ile Admin TGT Yakalama -> DC01 (Domain Controller)"
            Nodes = @(
                [PSCustomObject]@{ id = "u3"; label = "scanner_user\n(Pre-Auth Kapali)"; type = "user"; role = "entry"; x = 50; y = 150 },
                [PSCustomObject]@{ id = "c1"; label = "APP-SERVER01$\n(Unconstrained Del.)"; type = "computer"; role = "pivot"; x = 280; y = 150 },
                [PSCustomObject]@{ id = "u4"; label = "Administrator TGT\n(Bellekten Yakalandi)"; type = "ticket"; role = "admin"; x = 520; y = 150 },
                [PSCustomObject]@{ id = "c2"; label = "DC01.corp.local\n(Domain Controller)"; type = "computer"; role = "target"; x = 750; y = 150 }
            )
            Edges = @(
                [PSCustomObject]@{ from = "u3"; to = "c1"; label = "Local Admin / RDP"; color = "#f59e0b" },
                [PSCustomObject]@{ from = "c1"; to = "u4"; label = "TGT Harvester"; color = "#ef4444" },
                [PSCustomObject]@{ from = "u4"; to = "c2"; label = "DCSync / Pass-The-Ticket"; color = "#10b981" }
            )
        },
        [PSCustomObject]@{
            PathId = "path3"
            Title = "Yol 3: Kerberoasting ile Hizmet Hesabi Kirilmasi ve Dogrudan Admin Hakki"
            Risk = "Yuksek"
            Description = "Herhangi bir Standart Kullanici -> TGS Bilet Talebi (Kerberoast) -> sql_admin_service Hashi Kirildi -> Dogrudan Domain Admin Uyeligi"
            Nodes = @(
                [PSCustomObject]@{ id = "u5"; label = "Standart User\n(Domain Hesabi)"; type = "user"; role = "entry"; x = 100; y = 150 },
                [PSCustomObject]@{ id = "u6"; label = "sql_admin_service\n(SPN & RC4 Hash)"; type = "user"; role = "pivot"; x = 400; y = 150 },
                [PSCustomObject]@{ id = "g3"; label = "Domain Admins\n(Tier 0)"; type = "group"; role = "target"; x = 700; y = 150 }
            )
            Edges = @(
                [PSCustomObject]@{ from = "u5"; to = "u6"; label = "Kerberoast (TGS Hash)"; color = "#ef4444" },
                [PSCustomObject]@{ from = "u6"; to = "g3"; label = "MemberOf"; color = "#10b981" }
            )
        }
    )

    # Tum AD Nesneleri Envanteri (Ornek)
    $allObjects = @(
        [PSCustomObject]@{ Type = "User"; Name = "Administrator"; Details = "Domain Admin, UAC: 512"; Status = "Aktif"; LastLogon = "09.09.2026"; OU = "CN=Users,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "User"; Name = "krbtgt"; Details = "Kerberos KDC Hesabi, UAC: 514"; Status = "Devre Disi"; LastLogon = "01.01.2018"; OU = "CN=Users,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "User"; Name = "ahmet.yilmaz.adm"; Details = "AdminCount: 1, PwdLastSet: 10.05.2026"; Status = "Aktif"; LastLogon = "10.09.2026"; OU = "OU=Admins,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "User"; Name = "sql_admin_service"; Details = "SPN: MSSQLSvc/..., RC4 Hash"; Status = "Aktif"; LastLogon = "01.03.2026"; OU = "OU=Services,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "User"; Name = "scanner_user"; Details = "Pre-Auth: KAPALI, DONT_REQ_PREAUTH"; Status = "Aktif"; LastLogon = "01.05.2020"; OU = "OU=Devices,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "User"; Name = "mehmet.oz"; Details = "500+ gundur pasif, UAC: 512"; Status = "Aktif (Stale)"; LastLogon = "14.02.2025"; OU = "OU=Finance,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "Computer"; Name = "DC01.corp.local"; Details = "PDC Emulator, Windows Server 2019"; Status = "Aktif"; LastLogon = "10.09.2026"; OU = "OU=Domain Controllers,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "Computer"; Name = "DC02.corp.local"; Details = "Backup DC, Windows Server 2012 R2 (EOL)"; Status = "Aktif"; LastLogon = "10.09.2026"; OU = "OU=Domain Controllers,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "Computer"; Name = "APP-SERVER01$"; Details = "Unconstrained Delegation Acik"; Status = "Aktif"; LastLogon = "08.09.2026"; OU = "OU=AppServers,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "Computer"; Name = "FILE-SRV01$"; Details = "Windows Server 2016 File Server"; Status = "Aktif"; LastLogon = "09.09.2026"; OU = "OU=FileServers,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "Group"; Name = "Domain Admins"; Details = "Security Global, 5 Uye"; Status = "Kritik"; LastLogon = "-"; OU = "CN=Users,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "Group"; Name = "Enterprise Admins"; Details = "Security Universal, 1 Uye"; Status = "Kritik"; LastLogon = "-"; OU = "CN=Users,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "Group"; Name = "HelpDesk_Users"; Details = "Domain Admin uzerinde WriteDacl yetkisi var!"; Status = "Riskli"; LastLogon = "-"; OU = "OU=Groups,DC=corp,DC=local" },
        [PSCustomObject]@{ Type = "Group"; Name = "Protected Users"; Details = "0 Uye (Hicbir admin bu grupta korunmuyor)"; Status = "Bos"; LastLogon = "-"; OU = "CN=Users,DC=corp,DC=local" }
    )

    return [PSCustomObject]@{
        DomainInfo = $domainInfo
        PasswordPolicy = $passwordPolicy
        DomainControllers = $domainControllers
        DomainAdmins = $domainAdmins
        Kerberoasting = $kerberoasting
        AsRepRoast = $asrepRoast
        DelegationRisks = $delegationRisks
        AclRisks = $aclRisks
        StaleAccounts = $staleAccounts
        BadFlags = $badFlags
        AttackPaths = $attackPaths
        AllObjects = $allObjects
        LapsStatus = [PSCustomObject]@{ Installed = $false; Message = "LAPS Semada Tespit Edilemedi (Yerel Admin Parolalari Ortak Olabilir)" }
        KrbtgtStatus = [PSCustomObject]@{ PasswordAgeDays = 2800; Status = "Kritik (Parola 7 yildir degistirilmedi - Golden Ticket riski)" }
    }
}

# ------------------------------------------------------------------------------
# 3. CANLI AD TARAMA FONKSIYONU (SALT OKUNUR)
# ------------------------------------------------------------------------------
function Get-LiveAuditData {
    Write-Host "[*] Active Directory baglantisi test ediliyor..." -ForegroundColor Cyan

    try {
        $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainName = $domainObj.Name
        $forestName = $domainObj.Forest.Name
        $pdc = $domainObj.PdcRoleOwner.Name
        $functionalLevel = $domainObj.DomainMode.ToString()
    }
    catch {
        Write-Warning "Gecerli bir Active Directory domain baglantisi kurulamadi!"
        Write-Warning "Hata: $($_.Exception.Message)"
        Write-Host "[i] Otomatik olarak Demo/Gorsellestirme Moduna geciliyor..." -ForegroundColor Yellow
        return (Get-DemoAuditData)
    }

    Write-Host "[+] Domain Tespit Edildi: $domainName (Forest: $forestName)" -ForegroundColor Green

    # Domain Controllers
    Write-Host "[*] Domain Controller'lar listeleniyor..." -ForegroundColor Cyan
    $dcs = @()
    foreach ($dc in $domainObj.DomainControllers) {
        $os = "Bilinmiyor"
        $build = "-"
        try {
            $dcEntry = [ADSI]"LDAP://$($dc.Name)"
            $os = $dcEntry.operatingSystem.ToString()
            if ($dcEntry.operatingSystemVersion) { $build = $dcEntry.operatingSystemVersion.ToString() }
        } catch {}

        $status = "Guncel"
        if ($os -match "2008|2003|2012") { $status = "Guvenlik Riski (EOL Destegi Bitti)" }

        $dcs += [PSCustomObject]@{
            Name = $dc.Name
            IP = $dc.IPAddress
            OS = $os
            Build = $build
            IsPDC = ($dc.Name -eq $pdc)
            Status = $status
        }
    }

    # Parola Politikasi
    Write-Host "[*] Parola ve hesap kilitleme politikasi okunuyor..." -ForegroundColor Cyan
    $domainEntry = [ADSI]""
    $minPwdLen = if ($domainEntry.minPwdLength) { [int]$domainEntry.minPwdLength[0] } else { 0 }
    $pwdHistory = if ($domainEntry.pwdHistoryLength) { [int]$domainEntry.pwdHistoryLength[0] } else { 0 }
    $lockoutThresh = if ($domainEntry.lockoutThreshold) { [int]$domainEntry.lockoutThreshold[0] } else { 0 }
    
    $maxPwdAgeDays = 0
    if ($domainEntry.maxPwdAge) {
        $largeInt = $domainEntry.maxPwdAge[0]
        $ticks = Convert-LargeInteger -LargeInt $largeInt
        if ($ticks) {
            $span = [DateTime]::FromFileTime([int64]0) - $ticks
            $maxPwdAgeDays = [Math]::Abs($span.Days)
        }
    }

    # Toplam Sayilar
    Write-Host "[*] Nesne sayilari taraniyor..." -ForegroundColor Cyan
    $totalUsers = (Search-AD -Filter "(&(objectCategory=person)(objectClass=user))" -Properties @("samaccountname")).Count
    $totalComputers = (Search-AD -Filter "(objectClass=computer)" -Properties @("samaccountname")).Count
    $totalGroups = (Search-AD -Filter "(objectClass=group)" -Properties @("samaccountname")).Count
    $totalGPOs = (Search-AD -Filter "(objectClass=groupPolicyContainer)" -Properties @("displayname")).Count

    # Domain Admins
    Write-Host "[*] Domain Admins uyeleri inceleniyor..." -ForegroundColor Cyan
    $daResults = Search-AD -Filter "(&(objectCategory=group)(samaccountname=Domain Admins))" -Properties @("member")
    $daMembers = @()
    if ($daResults.Count -gt 0) {
        foreach ($memberDn in $daResults[0].Properties["member"]) {
            try {
                $mEntry = [ADSI]"LDAP://$memberDn"
                $lastLogon = Convert-LargeInteger $mEntry.lastLogonTimestamp[0]
                $daMembers += [PSCustomObject]@{
                    SamAccountName = $mEntry.samaccountname.ToString()
                    Name = if ($mEntry.displayName) { $mEntry.displayName.ToString() } else { $mEntry.samaccountname.ToString() }
                    Enabled = (($mEntry.userAccountControl[0] -band 2) -eq 0)
                    LastLogon = if ($lastLogon) { $lastLogon.ToString("dd.MM.yyyy") } else { "Hic / Bilinmiyor" }
                    AdminCount = 1
                    Description = if ($mEntry.description) { $mEntry.description[0].ToString() } else { "-" }
                }
            } catch {}
        }
    }

    # Kerberoasting (SPN)
    Write-Host "[*] Kerberoasting adaylari (SPN tanimli hesaplar) taraniyor..." -ForegroundColor Cyan
    $spnResults = Search-AD -Filter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(samaccountname=krbtgt)))" -Properties @("samaccountname", "displayName", "servicePrincipalName", "pwdLastSet", "adminCount", "distinguishedname", "msDS-SupportedEncryptionTypes")
    $spnList = @()
    foreach ($res in $spnResults) {
        $pwdDate = Convert-LargeInteger $res.Properties["pwdlastset"][0]
        $spns = $res.Properties["serviceprincipalname"] -join ", "
        $isAdmin = ($res.Properties["admincount"][0] -eq 1)
        $dn = $res.Properties["distinguishedname"][0]
        $encType = "Standart (RC4 / AES)"
        if ($res.Properties["msds-supportedencryptiontypes"]) {
            $val = [int]$res.Properties["msds-supportedencryptiontypes"][0]
            if (($val -band 24) -eq 0) { $encType = "RC4_HMAC (Zayif)" } else { $encType = "AES128/AES256" }
        }

        $spnList += [PSCustomObject]@{
            SamAccountName = $res.Properties["samaccountname"][0]
            Name = if ($res.Properties["displayname"]) { $res.Properties["displayname"][0] } else { $res.Properties["samaccountname"][0] }
            SPN = $spns
            PasswordLastSet = if ($pwdDate) { $pwdDate.ToString("dd.MM.yyyy") } else { "Bilinmiyor" }
            IsPrivileged = $isAdmin
            EncryptionType = $encType
            OU = $dn
            RiskReason = if ($isAdmin) { "Kritik: Domain Admin uyesi hesaba SPN atanmis. Bilet kirildiginda dogrudan admin yetkisi elde edilir." } else { "Standart kullaniciya SPN atanmis. Parolasi zayifsa offline TGS kirmaya aciktir." }
        }
    }

    # AS-REP Roasting (Pre-Auth Kapali)
    Write-Host "[*] AS-REP Roasting riski tasiyan hesaplar araniyor..." -ForegroundColor Cyan
    $asrepResults = Search-AD -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Properties @("samaccountname", "displayName", "description", "pwdLastSet", "userAccountControl", "distinguishedname")
    $asrepList = @()
    foreach ($res in $asrepResults) {
        $uac = [int]$res.Properties["useraccountcontrol"][0]
        $enabled = (($uac -band 2) -eq 0)
        $pwdDate = Convert-LargeInteger $res.Properties["pwdlastset"][0]

        $asrepList += [PSCustomObject]@{
            SamAccountName = $res.Properties["samaccountname"][0]
            Name = if ($res.Properties["displayname"]) { $res.Properties["displayname"][0] } else { $res.Properties["samaccountname"][0] }
            Description = if ($res.Properties["description"]) { $res.Properties["description"][0] } else { "Aciklama yok" }
            PasswordLastSet = if ($pwdDate) { $pwdDate.ToString("dd.MM.yyyy") } else { "Bilinmiyor" }
            Enabled = $enabled
            OU = $res.Properties["distinguishedname"][0]
            RiskReason = "Kerberos Pre-Authentication kapali. Agdaki herhangi bir kullanici parola bilmeden bu hesabin hash'ini cekip offline kirabilir."
        }
    }

    # Delegasyon Riskleri
    Write-Host "[*] Delegasyon riskleri denetleniyor..." -ForegroundColor Cyan
    $unconstrainedResults = Search-AD -Filter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))" -Properties @("samaccountname", "objectClass", "distinguishedname")
    $delegationList = @()
    foreach ($res in $unconstrainedResults) {
        $isComputer = ($res.Properties["objectclass"] -contains "computer")
        $delegationList += [PSCustomObject]@{
            Name = $res.Properties["samaccountname"][0]
            Type = if ($isComputer) { "Computer (Member Server/Client)" } else { "User Account" }
            Delegation = "Unconstrained Delegation"
            Risk = "Kritik"
            Detail = "Bu nesneye baglanan yetkili kullanicilarin TGT biletleri bellekte saklanir; nesne ele gecirilirse biletler calinabilir."
            OU = $res.Properties["distinguishedname"][0]
        }
    }

    # ACL & Tehlikeli Yetkiler (Kim Kimi Yonetiyor?)
    Write-Host "[*] Kritik gruplar ve admin hesaplari uzerindeki ACL yetkileri analiz ediliyor..." -ForegroundColor Cyan
    $aclRisks = @()
    try {
        # Domain Admins grubunun ACL'ini tara
        if ($daResults.Count -gt 0) {
            $daDn = $daResults[0].Properties["distinguishedname"][0]
            $daEntry = [ADSI]"LDAP://$daDn"
            $daEntry.PsBase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
            $sec = $daEntry.PsBase.ObjectSecurity
            $rules = $sec.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

            foreach ($rule in $rules) {
                $id = $rule.IdentityReference.Value
                # Varsayilan admin hesaplarini haric tut
                if ($id -notmatch "Domain Admins|Enterprise Admins|SYSTEM|Enterprise Key Admins|Key Admins|Administrators") {
                    if ($rule.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty") {
                        $aclRisks += [PSCustomObject]@{
                            ActiveObject = $id
                            TargetObject = "Domain Admins (Grup)"
                            Permission = $rule.ActiveDirectoryRights.ToString()
                            RiskLevel = "Kritik"
                            Impact = "$id hesabi Domain Admins grubu uzerinde yetki degistirebilir veya uyelik ekleyebilir!"
                        }
                    }
                }
            }
        }
    } catch {
        Write-Warning "ACL analizi sirasinda hata: $($_.Exception.Message)"
    }

    # Atil / Eski Hesaplar (>90 Gun)
    Write-Host "[*] 90+ gundur kullanilmayan aktif hesaplar taraniyor..." -ForegroundColor Cyan
    $ninetyDaysAgo = [DateTime]::UtcNow.AddDays(-90).ToFileTime()
    $staleResults = Search-AD -Filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$ninetyDaysAgo))" -Properties @("samaccountname", "displayName", "description", "lastLogonTimestamp", "distinguishedname")
    $staleList = @()
    foreach ($res in ($staleResults | Select-Object -First 100)) {
        $lastDate = Convert-LargeInteger $res.Properties["lastlogontimestamp"][0]
        $staleList += [PSCustomObject]@{
            SamAccountName = $res.Properties["samaccountname"][0]
            Name = if ($res.Properties["displayname"]) { $res.Properties["displayname"][0] } else { $res.Properties["samaccountname"][0] }
            LastLogon = if ($lastDate) { $lastDate.ToString("dd.MM.yyyy") } else { "90+ Gundur Giris Yok" }
            Enabled = $true
            Description = if ($res.Properties["description"]) { $res.Properties["description"][0] } else { "-" }
            OU = $res.Properties["distinguishedname"][0]
        }
    }

    # Riskli UAC Bayraklari
    Write-Host "[*] Riskli hesap bayraklari kontrol ediliyor..." -ForegroundColor Cyan
    $badFlags = @()
    $noExpire = Search-AD -Filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=65536))" -Properties @("samaccountname", "displayName", "distinguishedname")
    foreach ($u in ($noExpire | Select-Object -First 50)) {
        $badFlags += [PSCustomObject]@{
            SamAccountName = $u.Properties["samaccountname"][0]
            Name = if ($u.Properties["displayname"]) { $u.Properties["displayname"][0] } else { $u.Properties["samaccountname"][0] }
            Issue = "Parola Asla Suresi Dolmaz (DONT_EXPIRE_PASSWORD)"
            Severity = "Orta"
            OU = $u.Properties["distinguishedname"][0]
        }
    }

    # KRBTGT Parola Yasi
    Write-Host "[*] krbtgt hesabi parola yasi denetleniyor..." -ForegroundColor Cyan
    $krbtgtRes = Search-AD -Filter "(&(objectClass=user)(samaccountname=krbtgt))" -Properties @("pwdlastset")
    $krbtgtAge = 0
    if ($krbtgtRes.Count -gt 0) {
        $kDate = Convert-LargeInteger $krbtgtRes[0].Properties["pwdlastset"][0]
        if ($kDate) {
            $krbtgtAge = [int]((Get-Date) - $kDate).TotalDays
        }
    }

    # LAPS Varligi
    Write-Host "[*] LAPS (Local Admin Password Solution) kontrol ediliyor..." -ForegroundColor Cyan
    $lapsFound = $false
    try {
        $schema = [ADSI]"LDAP://schema"
        $searchSchema = New-Object System.DirectoryServices.DirectorySearcher($schema)
        $searchSchema.Filter = "(name=ms-Mcs-AdmPwd)"
        $lapsFound = ($searchSchema.FindOne() -ne $null)
    } catch {}

    # Tum Nesneler Envanteri (Ilk 300 nesne orneklem)
    Write-Host "[*] Dizin nesneleri envanter sekmesi icin toplaniyor..." -ForegroundColor Cyan
    $inventory = @()
    $invUsers = Search-AD -Filter "(&(objectCategory=person)(objectClass=user))" -Properties @("samaccountname", "displayName", "userAccountControl", "lastLogonTimestamp", "distinguishedname") -SizeLimit 150
    foreach ($u in $invUsers) {
        $uac = [int]$u.Properties["useraccountcontrol"][0]
        $stat = if (($uac -band 2) -eq 0) { "Aktif" } else { "Devre Disi" }
        $ll = Convert-LargeInteger $u.Properties["lastlogontimestamp"][0]
        $inventory += [PSCustomObject]@{
            Type = "User"
            Name = $u.Properties["samaccountname"][0]
            Details = if ($u.Properties["displayname"]) { $u.Properties["displayname"][0] } else { "User" }
            Status = $stat
            LastLogon = if ($ll) { $ll.ToString("dd.MM.yyyy") } else { "Yok" }
            OU = $u.Properties["distinguishedname"][0]
        }
    }

    $invComps = Search-AD -Filter "(objectClass=computer)" -Properties @("samaccountname", "operatingSystem", "distinguishedname") -SizeLimit 100
    foreach ($c in $invComps) {
        $inventory += [PSCustomObject]@{
            Type = "Computer"
            Name = $c.Properties["samaccountname"][0]
            Details = if ($c.Properties["operatingsystem"]) { $c.Properties["operatingsystem"][0] } else { "Computer" }
            Status = "Aktif"
            LastLogon = "-"
            OU = $c.Properties["distinguishedname"][0]
        }
    }

    $invGroups = Search-AD -Filter "(objectClass=group)" -Properties @("samaccountname", "groupType", "distinguishedname") -SizeLimit 50
    foreach ($g in $invGroups) {
        $inventory += [PSCustomObject]@{
            Type = "Group"
            Name = $g.Properties["samaccountname"][0]
            Details = "Security Group"
            Status = "Aktif"
            LastLogon = "-"
            OU = $g.Properties["distinguishedname"][0]
        }
    }

    # Saldiri Yollari (Canli veriden turetilmis yol modelleri)
    $attackPaths = @()
    if ($asrepList.Count -gt 0) {
        $targetUser = $asrepList[0].SamAccountName
        $attackPaths += [PSCustomObject]@{
            PathId = "path1"
            Title = "AS-REP Roasting ile Baslayan Baslangic Erisim Yolu"
            Risk = "Yuksek"
            Description = "$targetUser hesabi Pre-Auth gerektirmiyor -> Parola Hashi Cekilebilir -> Agda Ilk Dayanak Noktasi"
            Nodes = @(
                [PSCustomObject]@{ id = "n1"; label = "$targetUser\n(Pre-Auth Kapali)"; type = "user"; role = "entry"; x = 100; y = 150 },
                [PSCustomObject]@{ id = "n2"; label = "Offline Hashcat\n(Parola Kirma)"; type = "ticket"; role = "pivot"; x = 400; y = 150 },
                [PSCustomObject]@{ id = "n3"; label = "Domain Member PC\n(Ilk Erisim)"; type = "computer"; role = "target"; x = 700; y = 150 }
            )
            Edges = @(
                [PSCustomObject]@{ from = "n1"; to = "n2"; label = "AS-REP Hash Request"; color = "#ef4444" },
                [PSCustomObject]@{ from = "n2"; to = "n3"; label = "Cleartext Password"; color = "#10b981" }
            )
        }
    }

    if ($spnList.Count -gt 0) {
        $spnTarget = $spnList[0].SamAccountName
        $attackPaths += [PSCustomObject]@{
            PathId = "path2"
            Title = "Kerberoasting Servis Hesabi Ele Gecirme Yolu"
            Risk = "Yuksek"
            Description = "Standart Kullanici -> $spnTarget TGS Bileti -> Offline Kirma -> Servis Ayricaliklari"
            Nodes = @(
                [PSCustomObject]@{ id = "n4"; label = "Standart Kullanici"; type = "user"; role = "entry"; x = 100; y = 150 },
                [PSCustomObject]@{ id = "n5"; label = "$spnTarget\n(TGS Hash)"; type = "user"; role = "pivot"; x = 400; y = 150 },
                [PSCustomObject]@{ id = "n6"; label = "Uygulama / Veritabani"; type = "computer"; role = "target"; x = 700; y = 150 }
            )
            Edges = @(
                [PSCustomObject]@{ from = "n4"; to = "n5"; label = "TGS Request (SPN)"; color = "#ef4444" },
                [PSCustomObject]@{ from = "n5"; to = "n6"; label = "Compromised Service"; color = "#10b981" }
            )
        }
    }

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
            TotalGPOs = $totalGPOs
        }
        PasswordPolicy = [PSCustomObject]@{
            MinPasswordLength = $minPwdLen
            PasswordHistoryCount = $pwdHistory
            MaxPasswordAgeDays = $maxPwdAgeDays
            LockoutThreshold = $lockoutThresh
            Status = if ($lockoutThresh -eq 0) { "Kritik (Hesap Kilitleme Kapali)" } elseif ($minPwdLen -lt 12) { "Zayif (Min Parola < 12)" } else { "Iyi" }
        }
        DomainControllers = $dcs
        DomainAdmins = $daMembers
        Kerberoasting = $spnList
        AsRepRoast = $asrepList
        DelegationRisks = $delegationList
        AclRisks = $aclRisks
        StaleAccounts = $staleList
        BadFlags = $badFlags
        AttackPaths = $attackPaths
        AllObjects = $inventory
        LapsStatus = [PSCustomObject]@{
            Installed = $lapsFound
            Message = if ($lapsFound) { "LAPS Semasi Mevcut" } else { "LAPS Semada Bulunamadi (Yerel admin parolalari riski)" }
        }
        KrbtgtStatus = [PSCustomObject]@{
            PasswordAgeDays = $krbtgtAge
            Status = if ($krbtgtAge -gt 365) { "Kritik (Parola $krbtgtAge gundur degismedi - Golden Ticket riski)" } else { "Normal ($krbtgtAge gunluk)" }
        }
    }
}

# ------------------------------------------------------------------------------
# 4. SKOR VE DETAYLI RISK HESAPLAMA MOTORU
# ------------------------------------------------------------------------------
function Calculate-SecurityScore {
    param($Data)

    $score = 100
    $findings = @()

    # 1. AS-REP Roasting
    if ($Data.AsRepRoast.Count -gt 0) {
        $count = $Data.AsRepRoast.Count
        $score -= [Math]::Min(25, $count * 10)
        $findings += [PSCustomObject]@{
            Id = "F-01"
            Severity = "CRITICAL"
            Title = "AS-REP Roasting Acik Hesaplar (Pre-Authentication Kapali)"
            Count = $count
            AffectedObjects = $Data.AsRepRoast
            Summary = "$count adet kullanici hesabinda Kerberos Pre-Authentication kapatilmis. Agdaki herhangi birisi bu hesaplar icin parola bilmeden KDC'den bilet talep edebilir ve hash'i cevrimdisi kirabilir."
            Remediation = "Active Directory Users and Computers konsolunda bu hesaplarin Ozellikler > Hesap sekmesinden 'Do not require Kerberos preauthentication' kutucugunun isaretini kaldirin."
        }
    }

    # 2. Tehlikeli ACL Yetkileri (Kim Kimi Yonetiyor)
    if ($Data.AclRisks.Count -gt 0) {
        $count = $Data.AclRisks.Count
        $score -= 25
        $findings += [PSCustomObject]@{
            Id = "F-02"
            Severity = "CRITICAL"
            Title = "Tehlikeli ACL Yetkileri (Yetki Yukseltme / PrivEsc Yolu)"
            Count = $count
            AffectedObjects = $Data.AclRisks
            Summary = "Standart hesap veya gruplar, Domain Admins veya Domain Root gibi kritik nesneler uzerinde WriteDacl/GenericAll yetkisine sahip. Bu durum tam domain ele gecirilmesine yol acar."
            Remediation = "Etkilenen nesnelerin Guvenlik (Security) sekmesini inceleyerek 'Authenticated Users', 'Domain Users' veya yetkisiz gruplara verilen WriteDacl, WriteOwner, GenericAll yetkilerini derhal kaldirin."
        }
    }

    # 3. Kerberoasting (Ozellikle Yetkili Admin Olanlar)
    if ($Data.Kerberoasting.Count -gt 0) {
        $privCount = ($Data.Kerberoasting | Where-Object { $_.IsPrivileged -eq $true }).Count
        $totalSpn = $Data.Kerberoasting.Count

        if ($privCount -gt 0) {
            $score -= 20
            $findings += [PSCustomObject]@{
                Id = "F-03"
                Severity = "CRITICAL"
                Title = "Domain Admin Uyesi Hesaplarda SPN Tanimlanmis (Kerberoast)"
                Count = $privCount
                AffectedObjects = ($Data.Kerberoasting | Where-Object { $_.IsPrivileged -eq $true })
                Summary = "$privCount adet Domain Admin uyesi kullaniciya SPN tanimlanmis. Standart bir kullanici bu biletleri cekip parolasini kirarak dogrudan Domain Admin olabilir."
                Remediation = "Yetkili yonetici hesaplarina ASLA SPN atamayin. Servisler icin 'Group Managed Service Accounts (gMSA)' kullanin."
            }
        } elseif ($totalSpn -gt 0) {
            $score -= 10
            $findings += [PSCustomObject]@{
                Id = "F-04"
                Severity = "HIGH"
                Title = "SPN Atanmis Servis Hesaplari (Kerberoast Riski)"
                Count = $totalSpn
                AffectedObjects = $Data.Kerberoasting
                Summary = "$totalSpn adet servis hesabinda SPN kaydi mevcut. Parolalari kisa veya basitse offline TGS kirma saldirisina karsi zayiftir."
                Remediation = "Bu hesaplarda 25+ karakterlik karmasik parolalar belirleyin, RC4 yerine AES256 sifrelemeyi zorunlu kilin."
            }
        }
    }

    # 4. Unconstrained Delegation
    if ($Data.DelegationRisks.Count -gt 0) {
        $count = $Data.DelegationRisks.Count
        $score -= 15
        $findings += [PSCustomObject]@{
            Id = "F-05"
            Severity = "HIGH"
            Title = "Kisitlamasiz Delegasyon (Unconstrained Delegation)"
            Count = $count
            AffectedObjects = $Data.DelegationRisks
            Summary = "Domain Controller harici $count nesnede kisitlamasiz delegasyon acik. Bu sunuculara baglanan Domain Admin'lerin TGT biletleri bellekte depolanir ve ele gecirilebilir."
            Remediation = "Kisitlamasiz delegasyonu kaldirin. Bunun yerine Kerberos Constrained Delegation (KCD) veya Resource-Based Constrained Delegation (RBCD) kullanin."
        }
    }

    # 5. Hesap Kilitleme Politikasi
    if ($Data.PasswordPolicy.LockoutThreshold -eq 0) {
        $score -= 15
        $findings += [PSCustomObject]@{
            Id = "F-06"
            Severity = "HIGH"
            Title = "Hesap Kilitleme Politikasi Kapali (Password Spraying Riski)"
            Count = 1
            AffectedObjects = @([PSCustomObject]@{ Name = "Default Domain Policy"; Detail = "LockoutThreshold = 0" })
            Summary = "LockoutThreshold 0 olarak ayarlanmis. Hatali parola girislerinde hesaplar kilitlenmiyor; bu durum brute-force ve password spray denemelerini sinirsiz kilar."
            Remediation = "Grup Ilkesi (Default Domain Policy) uzerinden Account Lockout Threshold degerini 5 ila 10 deneme arasina ayarlayin."
        }
    }

    # 6. KRBTGT Parola Yasi
    if ($Data.KrbtgtStatus.PasswordAgeDays -gt 365) {
        $score -= 10
        $findings += [PSCustomObject]@{
            Id = "F-07"
            Severity = "HIGH"
            Title = "KRBTGT Hesabi Parolasi Cok Eski (> 1 Yil)"
            Count = 1
            AffectedObjects = @([PSCustomObject]@{ Name = "krbtgt"; Detail = "$($Data.KrbtgtStatus.PasswordAgeDays) gundur degistirilmedi" })
            Summary = "krbtgt hesabi Kerberos biletlerini imzalar. Parolasi uzun yillardir degistirilmediyse gecmiste olusturulan Golden Ticket'lar hala gecerli olabilir."
            Remediation = "Microsoft New-KrbtgtKeys.ps1 scripti ile krbtgt parolasini 1 gun arayla 2 kez sifirlayarak tum eski biletleri gecersiz kilin."
        }
    }

    # 7. Atil ve Eski Hesaplar
    if ($Data.StaleAccounts.Count -gt 0) {
        $count = $Data.StaleAccounts.Count
        $score -= 10
        $findings += [PSCustomObject]@{
            Id = "F-08"
            Severity = "MEDIUM"
            Title = "90+ Gundur Kullanilmayan Aktif Hesaplar (Stale Accounts)"
            Count = $count
            AffectedObjects = $Data.StaleAccounts
            Summary = "$count adet kullanici hesabi 90 gunden uzun suredir oturum acmamis ancak hala AKTIF durumda. Bu hesaplar saldirganlar tarafindan gizli kapilar olarak kullanilabilir."
            Remediation = "Kullanilmayan hesaplari tespit edip otomatik devre disi birakan (Disable) bir temizlik politikasi uygulayin."
        }
    }

    # 8. LAPS Eksikligi
    if ($Data.LapsStatus.Installed -eq $false) {
        $score -= 10
        $findings += [PSCustomObject]@{
            Id = "F-09"
            Severity = "MEDIUM"
            Title = "LAPS (Local Administrator Password Solution) Eksik"
            Count = 1
            AffectedObjects = @([PSCustomObject]@{ Name = "Active Directory Schema"; Detail = "ms-Mcs-AdmPwd niteligi bulunamadi" })
            Summary = "Semada LAPS niteligi tespit edilemedi. UcNoktalarda yerel Administrator parolalari ayni ise, tek bir makinenin ele gecirilmesi agdaki tum makinelere sicramayi saglar."
            Remediation = "Dahili Windows LAPS veya Klasik LAPS kurarak yerel admin parolalarini her makinede benzersiz ve rastgele hale getirin."
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

# ------------------------------------------------------------------------------
# 5. HTML VE GRAFIK DASHBOARD URETICISI
# ------------------------------------------------------------------------------
function Generate-HtmlReport {
    param(
        $Data,
        $AuditResult,
        $FilePath
    )

    Write-Host "[*] Gelismis HTML Raporu ve BloodHound Attack Graph olusturuluyor..." -ForegroundColor Cyan

    $domain = $Data.DomainInfo
    $score = $AuditResult.Score
    $grade = $AuditResult.Grade
    $gradeColor = $AuditResult.GradeColor

    # Attack Paths JSON (Grafik motoruna aktarilmak uzere)
    $attackPathsJson = $Data.AttackPaths | ConvertTo-Json -Depth 5 -Compress

    # Detayli Bulgular Tablosu (Acilip kapanan zengin kartlar)
    $findingsCardsHtml = ""
    foreach ($f in $AuditResult.Findings) {
        $badgeClass = "badge-low"
        if ($f.Severity -eq "CRITICAL") { $badgeClass = "badge-crit" }
        elseif ($f.Severity -eq "HIGH") { $badgeClass = "badge-high" }
        elseif ($f.Severity -eq "MEDIUM") { $badgeClass = "badge-med" }

        # Alt detay tablosu (Hangi hesaplar etkilendi?)
        $detailRows = ""
        foreach ($obj in ($f.AffectedObjects | Select-Object -First 30)) {
            $name = if ($obj.SamAccountName) { $obj.SamAccountName } elseif ($obj.Name) { $obj.Name } elseif ($obj.ActiveObject) { "$($obj.ActiveObject) -> $($obj.TargetObject)" } else { "Nesne" }
            $desc = if ($obj.RiskReason) { $obj.RiskReason } elseif ($obj.Impact) { $obj.Impact } elseif ($obj.Detail) { $obj.Detail } elseif ($obj.Description) { $obj.Description } else { "-" }
            $ou = if ($obj.OU) { "<small style='color:#64748b'>$($obj.OU)</small>" } else { "-" }

            $detailRows += "<tr><td><code>$name</code></td><td>$desc</td><td>$ou</td></tr>"
        }

        $findingsCardsHtml += @"
        <div class="finding-card">
            <div class="finding-header" onclick="toggleFinding('detail-$($f.Id)')">
                <div class="finding-title-group">
                    <span class="badge $badgeClass">$($f.Severity)</span>
                    <span class="finding-id">$($f.Id)</span>
                    <span class="finding-title">$($f.Title)</span>
                    <span class="count-pill">$($f.Count) Nesne</span>
                </div>
                <div class="toggle-icon">▼ Detaylari Gor</div>
            </div>
            <div class="finding-body" id="detail-$($f.Id)">
                <div class="finding-summary">$($f.Summary)</div>
                <div class="finding-remediation"><strong>Cozum & Oneri:</strong> $($f.Remediation)</div>
                <h4 style="margin: 14px 0 8px 0; font-size: 13px; color: #94a3b8;">Etkilenen Hesaplar ve Nesneler:</h4>
                <div class="table-responsive">
                    <table class="sub-table">
                        <thead>
                            <tr>
                                <th>Hesap / Nesne</th>
                                <th>Risk Detayi / Neden Tehlikeli?</th>
                                <th>Konum (OU / DN)</th>
                            </tr>
                        </thead>
                        <tbody>
                            $detailRows
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
"@
    }

    # ACL Tablosu (Kim Kimi Yonetiyor?)
    $aclRowsHtml = ""
    foreach ($a in $Data.AclRisks) {
        $aclRowsHtml += @"
        <tr>
            <td><span class="badge badge-low">Aktif Nesne</span> <code>$($a.ActiveObject)</code></td>
            <td><span class="badge badge-crit">Hedef</span> <code>$($a.TargetObject)</code></td>
            <td><span class="badge badge-high">$($a.Permission)</span></td>
            <td>$($a.Impact)</td>
        </tr>
"@
    }

    # Domain Admins Tablosu
    $daRowsHtml = ""
    foreach ($da in $Data.DomainAdmins) {
        $statusBadge = if ($da.Enabled) { '<span class="badge badge-ok">Aktif</span>' } else { '<span class="badge badge-crit">Devre Disi</span>' }
        $daRowsHtml += @"
        <tr>
            <td><code>$($da.SamAccountName)</code></td>
            <td>$($da.Name)</td>
            <td>$statusBadge</td>
            <td>$($da.LastLogon)</td>
            <td>$($da.Description)</td>
        </tr>
"@
    }

    # Kerberoasting Tablosu
    $spnRowsHtml = ""
    foreach ($s in $Data.Kerberoasting) {
        $privBadge = if ($s.IsPrivileged) { '<span class="badge badge-crit">DOMAIN ADMIN</span>' } else { '<span class="badge badge-low">Standart</span>' }
        $spnRowsHtml += @"
        <tr>
            <td><code>$($s.SamAccountName)</code></td>
            <td>$($s.Name)</td>
            <td>$privBadge</td>
            <td><small><code>$($s.SPN)</code></small></td>
            <td>$($s.EncryptionType)</td>
            <td>$($s.PasswordLastSet)</td>
        </tr>
"@
    }

    # AS-REP Roasting Tablosu
    $asrepRowsHtml = ""
    foreach ($a in $Data.AsRepRoast) {
        $asrepRowsHtml += @"
        <tr>
            <td><code>$($a.SamAccountName)</code></td>
            <td>$($a.Name)</td>
            <td>$($a.Description)</td>
            <td>$($a.PasswordLastSet)</td>
            <td><span class="badge badge-crit">Pre-Auth Kapali</span></td>
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
            <td><span class="badge badge-crit">$($d.Delegation)</span></td>
            <td>$($d.Detail)</td>
        </tr>
"@
    }

    # Tum Nesneler Envanteri Tablosu
    $allObjectsRowsHtml = ""
    foreach ($obj in $Data.AllObjects) {
        $typeBadge = "badge-low"
        if ($obj.Type -eq "User") { $typeBadge = "badge-low" }
        elseif ($obj.Type -eq "Computer") { $typeBadge = "badge-ok" }
        elseif ($obj.Type -eq "Group") { $typeBadge = "badge-high" }

        $allObjectsRowsHtml += @"
        <tr class="inv-row" data-type="$($obj.Type.ToLower())">
            <td><span class="badge $typeBadge">$($obj.Type)</span></td>
            <td><code>$($obj.Name)</code></td>
            <td>$($obj.Details)</td>
            <td>$($obj.Status)</td>
            <td>$($obj.LastLogon)</td>
            <td><small style="color:#64748b">$($obj.OU)</small></td>
        </tr>
"@
    }

    # Domain Controller Tablosu
    $dcRowsHtml = ""
    foreach ($dc in $Data.DomainControllers) {
        $pdcBadge = if ($dc.IsPDC) { '<span class="badge badge-ok">PDC Emulator</span>' } else { '<span class="badge badge-low">Replica DC</span>' }
        $dcRowsHtml += @"
        <tr>
            <td><code>$($dc.Name)</code></td>
            <td>$($dc.IP)</td>
            <td>$($dc.OS) ($($dc.Build))</td>
            <td>$pdcBadge</td>
            <td><span class="badge $(if($dc.Status -match 'Guncel'){'badge-ok'}else{'badge-crit'})">$($dc.Status)</span></td>
        </tr>
"@
    }

    # HTML TEMPLATE
    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Directory Guvenlik ve Saldiri Yolu Raporu - $($domain.DomainName)</title>
    <style>
        :root {
            --bg-base: #0a0e17;
            --bg-card: #131b2e;
            --bg-card-hover: #1a253f;
            --border-color: #202d4a;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --radius: 10px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background: var(--bg-base); color: var(--text-main); padding: 24px; font-size: 14px; line-height: 1.5; }
        .container { max-width: 1500px; margin: 0 auto; }

        /* HEADER */
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 24px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        }

        .header-title h1 { font-size: 24px; font-weight: 700; display: flex; align-items: center; gap: 12px; }
        .tag-readonly { background: rgba(16, 185, 129, 0.15); color: var(--success); font-size: 11px; padding: 4px 10px; border-radius: 20px; border: 1px solid rgba(16, 185, 129, 0.3); font-weight: 700; letter-spacing: 0.5px; }
        .header-meta { margin-top: 8px; color: var(--text-muted); font-size: 13px; display: flex; flex-wrap: wrap; gap: 18px; }
        .header-meta span strong { color: var(--text-main); }

        /* SCORE CIRCLE */
        .score-box { display: flex; align-items: center; gap: 18px; background: rgba(15, 23, 42, 0.7); padding: 12px 24px; border-radius: var(--radius); border: 1px solid var(--border-color); }
        .score-circle { width: 70px; height: 70px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; font-weight: 800; border: 4px solid $gradeColor; box-shadow: 0 0 15px $($gradeColor)44; }
        .score-num { font-size: 22px; line-height: 1; }
        .score-label { font-size: 10px; color: var(--text-muted); }
        .grade-letter { font-size: 32px; font-weight: 900; color: $gradeColor; }

        /* KPI STATS */
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 24px; }
        .stat-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 18px; display: flex; flex-direction: column; gap: 4px; }
        .stat-title { color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; }
        .stat-value { font-size: 26px; font-weight: 700; }
        .stat-desc { font-size: 12px; color: var(--text-muted); }

        /* TAB NAVIGATION */
        .tab-nav { display: flex; gap: 6px; border-bottom: 1px solid var(--border-color); margin-bottom: 20px; overflow-x: auto; padding-bottom: 4px; }
        .tab-btn { background: none; border: none; color: var(--text-muted); padding: 10px 16px; font-size: 13px; font-weight: 600; border-radius: 6px; cursor: pointer; transition: all 0.2s; white-space: nowrap; display: flex; align-items: center; gap: 6px; }
        .tab-btn:hover { color: var(--text-main); background: var(--bg-card); }
        .tab-btn.active { color: var(--primary); background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* CARDS */
        .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 22px; margin-bottom: 20px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }
        .card-header h2 { font-size: 17px; font-weight: 600; }

        /* FINDING CARDS (ACCORDION) */
        .finding-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); margin-bottom: 12px; overflow: hidden; }
        .finding-header { padding: 16px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; transition: background 0.2s; }
        .finding-header:hover { background: var(--bg-card-hover); }
        .finding-title-group { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .finding-id { font-family: monospace; color: var(--text-muted); font-size: 12px; }
        .finding-title { font-weight: 600; font-size: 15px; }
        .toggle-icon { font-size: 12px; color: var(--primary); font-weight: 600; }
        .finding-body { padding: 0 20px 20px 20px; display: none; border-top: 1px solid rgba(255,255,255,0.05); }
        .finding-body.open { display: block; }
        .finding-summary { margin-top: 14px; color: #cbd5e1; font-size: 13.5px; }
        .finding-remediation { margin-top: 10px; background: rgba(16, 185, 129, 0.1); border-left: 3px solid var(--success); padding: 10px 14px; border-radius: 4px; color: #a7f3d0; font-size: 13px; }

        /* GRAPH CANVAS */
        .graph-container { background: #070a12; border: 1px solid var(--border-color); border-radius: var(--radius); padding: 16px; position: relative; }
        .graph-controls { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
        .graph-btn { background: rgba(255,255,255,0.06); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; }
        .graph-btn.active { background: var(--primary); border-color: var(--primary); }
        #attackCanvas { width: 100%; height: 450px; background: radial-gradient(circle, #101726 10%, #070a12 90%); border-radius: 6px; display: block; }

        /* TABLES */
        .table-responsive { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: rgba(15, 23, 42, 0.6); color: var(--text-muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; padding: 11px 14px; border-bottom: 1px solid var(--border-color); }
        td { padding: 11px 14px; border-bottom: 1px solid var(--border-color); vertical-align: middle; }
        tr:hover td { background: var(--bg-card-hover); }
        .sub-table th { background: rgba(0,0,0,0.3); font-size: 11px; }
        .sub-table td { padding: 8px 12px; font-size: 12.5px; }
        code { background: rgba(15, 23, 42, 0.8); border: 1px solid var(--border-color); padding: 2px 6px; border-radius: 4px; color: #60a5fa; font-family: Consolas, monospace; font-size: 12.5px; }

        /* BADGES */
        .badge { display: inline-block; padding: 2px 8px; border-radius: 5px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-crit { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-high { background: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.3); }
        .badge-med  { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-low  { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
        .badge-ok   { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }
        .count-pill { background: rgba(255,255,255,0.08); padding: 2px 8px; border-radius: 10px; font-size: 11.5px; font-weight: 700; }

        /* SEARCH INPUT */
        .search-bar { background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-main); padding: 7px 12px; border-radius: 6px; font-size: 12.5px; width: 240px; outline: none; }
        .search-bar:focus { border-color: var(--primary); }

        /* FILTER BUTTONS */
        .filter-group { display: flex; gap: 6px; }
        .filter-btn { background: rgba(255,255,255,0.06); border: 1px solid var(--border-color); color: var(--text-muted); padding: 6px 12px; border-radius: 4px; font-size: 12px; cursor: pointer; }
        .filter-btn.active { background: var(--primary); color: #fff; border-color: var(--primary); }

        .footer { text-align: center; margin-top: 36px; color: var(--text-muted); font-size: 12px; border-top: 1px solid var(--border-color); padding-top: 18px; }
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <div class="header">
            <div class="header-title">
                <h1>
                    &#128737;&#65039; Active Directory Guvenlik & Saldiri Yolu Raporu
                    <span class="tag-readonly">SALT OKUNUR (READ-ONLY)</span>
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
                    <div style="font-size:11px; color:var(--text-muted);">Guvenlik Notu</div>
                </div>
            </div>
        </div>

        <!-- STATS GRID -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-title">Toplam Kullanici</div>
                <div class="stat-value">$($domain.TotalUsers)</div>
                <div class="stat-desc">Dizin kullanici hesaplari</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Domain Admins</div>
                <div class="stat-value" style="color: $(if($Data.DomainAdmins.Count -gt 5){'#f59e0b'}else{'#10b981'})">
                    $($Data.DomainAdmins.Count)
                </div>
                <div class="stat-desc">Tier 0 Yonetici hesaplari</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Kritik / Yuksek Bulgular</div>
                <div class="stat-value" style="color: $(if($AuditResult.Findings.Count -gt 0){'#ef4444'}else{'#10b981'})">
                    $($AuditResult.Findings.Count)
                </div>
                <div class="stat-desc">Acil mudaxale bekleyen risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Hesap Kilitleme (Lockout)</div>
                <div class="stat-value" style="color: $(if($Data.PasswordPolicy.LockoutThreshold -eq 0){'#ef4444'}else{'#10b981'})">
                    $(if($Data.PasswordPolicy.LockoutThreshold -eq 0){ "KAPALI" } else { "$($Data.PasswordPolicy.LockoutThreshold) Deneme" })
                </div>
                <div class="stat-desc">Password Spraying korumasi</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Saldiri Yollari (Paths)</div>
                <div class="stat-value" style="color: #3b82f6;">
                    $($Data.AttackPaths.Count)
                </div>
                <div class="stat-desc">Tespit edilen BloodHound yollari</div>
            </div>
        </div>

        <!-- TAB BUTTONS -->
        <div class="tab-nav">
            <button class="tab-btn active" onclick="switchTab('tab-findings', this)">&#128680; Guvenlik Bulgulari ($($AuditResult.Findings.Count))</button>
            <button class="tab-btn" onclick="switchTab('tab-graph', this); renderGraph(0)">&#128424; Saldiri Yolu Grafigi (BloodHound)</button>
            <button class="tab-btn" onclick="switchTab('tab-acl', this)">&#128273; Yetki & ACL Analizi ($($Data.AclRisks.Count))</button>
            <button class="tab-btn" onclick="switchTab('tab-inventory', this)">&#128193; Tum AD Envanteri ($($Data.AllObjects.Count))</button>
            <button class="tab-btn" onclick="switchTab('tab-admins', this)">&#128081; Domain Admins ($($Data.DomainAdmins.Count))</button>
            <button class="tab-btn" onclick="switchTab('tab-kerberos', this)">&#127919; Kerberos & Delegasyon ($($Data.Kerberoasting.Count + $Data.AsRepRoast.Count))</button>
            <button class="tab-btn" onclick="switchTab('tab-infra', this)">&#127984; DC & Politika ($($Data.DomainControllers.Count))</button>
        </div>

        <!-- TAB 1: BULGULAR (DETAYLI ACCORDION) -->
        <div id="tab-findings" class="tab-content active">
            <div class="card">
                <div class="card-header">
                    <h2>Tespit Edilen Guvenlik Zafiyetleri (Detayli Liste)</h2>
                    <span style="font-size:12px; color:var(--text-muted)">Detaylari gormek icin zafiyet basligina tiklayin</span>
                </div>
                $findingsCardsHtml
            </div>
        </div>

        <!-- TAB 2: BLOODHOUND ATTACK PATH GRAPH -->
        <div id="tab-graph" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>&#128424; BloodHound Tarzi Saldiri Yollari (Attack Path Visualization)</h2>
                    <span style="font-size:12px; color:var(--text-muted)">Standart bir kullanicidan Domain Admin'e ulasabilen lateral movement ve privilege escalation rotalari</span>
                </div>
                
                <div class="graph-container">
                    <div class="graph-controls">
                        <span style="font-size:12px; font-weight:600; line-height:30px; margin-right:8px;">Saldiri Senaryolari:</span>
                        <button class="graph-btn active" onclick="selectPath(0, this)">Yol 1: ACL / WriteDacl ile Admin Ele Gecirme</button>
                        <button class="graph-btn" onclick="selectPath(1, this)">Yol 2: AS-REP Roast + Unconstrained Delegation</button>
                        <button class="graph-btn" onclick="selectPath(2, this)">Yol 3: Kerberoast Servis Hesabi Uzerinden Admin</button>
                    </div>
                    <canvas id="attackCanvas"></canvas>
                    <div id="pathDescription" style="margin-top: 14px; background: rgba(15,23,42,0.8); padding: 12px; border-radius: 6px; border: 1px solid var(--border-color); font-size: 13px;"></div>
                </div>
            </div>
        </div>

        <!-- TAB 3: ACL & YETKI ANALIZI -->
        <div id="tab-acl" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>Kimin Kimin Uzerinde Yetkisi Var? (ACL & Delegation Matrisi)</h2>
                    <input type="text" class="search-bar" placeholder="Yetki ara..." onkeyup="filterTable(this, 'table-acl')">
                </div>
                <div class="table-responsive">
                    <table id="table-acl">
                        <thead>
                            <tr>
                                <th>Yetkili Nesne (Kaynagi)</th>
                                <th>Hedef Nesne</th>
                                <th>Izin / Hak</th>
                                <th>Risk Analizi & Etki</th>
                            </tr>
                        </thead>
                        <tbody>
                            $aclRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 4: TUM AD ENVANTERI -->
        <div id="tab-inventory" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>Active Directory Nesne Envanteri (Kullanicilar, Bilgisayarlar, Gruplar)</h2>
                    <div style="display:flex; gap:10px; flex-wrap:wrap;">
                        <div class="filter-group">
                            <button class="filter-btn active" onclick="filterInvType('all', this)">Hepsi</button>
                            <button class="filter-btn" onclick="filterInvType('user', this)">Kullanicilar</button>
                            <button class="filter-btn" onclick="filterInvType('computer', this)">Bilgisayarlar</button>
                            <button class="filter-btn" onclick="filterInvType('group', this)">Gruplar</button>
                        </div>
                        <input type="text" class="search-bar" placeholder="Envanterde ara..." onkeyup="filterInventory(this)">
                    </div>
                </div>
                <div class="table-responsive">
                    <table id="table-inventory">
                        <thead>
                            <tr>
                                <th style="width: 100px;">Tur</th>
                                <th>Nesne Adi</th>
                                <th>Detay / Bilgi</th>
                                <th>Durum</th>
                                <th>Son Oturum</th>
                                <th>Konum (OU / DN)</th>
                            </tr>
                        </thead>
                        <tbody>
                            $allObjectsRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 5: DOMAIN ADMINS -->
        <div id="tab-admins" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>Domain Admins Grubu ve Tier 0 Yoneticiler</h2>
                    <input type="text" class="search-bar" placeholder="Admin ara..." onkeyup="filterTable(this, 'table-admins')">
                </div>
                <div class="table-responsive">
                    <table id="table-admins">
                        <thead>
                            <tr>
                                <th>sAMAccountName</th>
                                <th>Gorunen Ad</th>
                                <th>Durum</th>
                                <th>Son Oturum</th>
                                <th>Aciklama / Not</th>
                            </tr>
                        </thead>
                        <tbody>
                            $daRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 6: KERBEROS & DELEGASYON -->
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
                                <th>Kullanici Adi</th>
                                <th>Gorunen Ad</th>
                                <th>Yetki</th>
                                <th>Service Principal Name (SPN)</th>
                                <th>Sifreleme Turu</th>
                                <th>Son Parola Tarihi</th>
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
                    <h2>AS-REP Roasting Hedefleri (Pre-Authentication Kapali)</h2>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Kullanici Adi</th>
                                <th>Gorunen Ad</th>
                                <th>Aciklama</th>
                                <th>Son Parola Tarihi</th>
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
                                <th>Nesne Adi</th>
                                <th>Tur</th>
                                <th>Delegasyon Tipi</th>
                                <th>Risk Analizi</th>
                            </tr>
                        </thead>
                        <tbody>
                            $delegationRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 7: ALTYAPI & DC -->
        <div id="tab-infra" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>Domain Controller Sunuculari</h2>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Sunucu (FQDN)</th>
                                <th>IP Adresi</th>
                                <th>Isletim Sistemi & Build</th>
                                <th>Rol</th>
                                <th>Durum</th>
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
                    <h2>Parola ve Hesap Politikalari</h2>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Parametre</th>
                                <th>Mevcut Deger</th>
                                <th>Onerilen Standart</th>
                                <th>Durum</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Asgari Parola Uzunlugu</td>
                                <td><strong>$($Data.PasswordPolicy.MinPasswordLength) Karakter</strong></td>
                                <td>En az 14 Karakter</td>
                                <td>$(if($Data.PasswordPolicy.MinPasswordLength -lt 12){'<span class="badge badge-high">Yetersiz</span>'}else{'<span class="badge badge-ok">Uygun</span>'})</td>
                            </tr>
                            <tr>
                                <td>Hesap Kilitleme Esigi (Lockout)</td>
                                <td><strong>$($Data.PasswordPolicy.LockoutThreshold) Deneme</strong></td>
                                <td>5 - 10 Deneme</td>
                                <td>$(if($Data.PasswordPolicy.LockoutThreshold -eq 0){'<span class="badge badge-crit">Kapali (Kritik)</span>'}else{'<span class="badge badge-ok">Aktif</span>'})</td>
                            </tr>
                            <tr>
                                <td>KRBTGT Parola Yasi</td>
                                <td><strong>$($Data.KrbtgtStatus.PasswordAgeDays) Gunluk</strong></td>
                                <td>En fazla 180 Gun</td>
                                <td>$(if($Data.KrbtgtStatus.PasswordAgeDays -gt 365){'<span class="badge badge-crit">Cok Eski</span>'}else{'<span class="badge badge-ok">Normal</span>'})</td>
                            </tr>
                            <tr>
                                <td>LAPS Durumu</td>
                                <td><strong>$($Data.LapsStatus.Message)</strong></td>
                                <td>LAPS Yuklu ve Aktif</td>
                                <td>$(if($Data.LapsStatus.Installed){'<span class="badge badge-ok">Mevcut</span>'}else{'<span class="badge badge-med">Eksik</span>'})</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- FOOTER -->
        <div class="footer">
            Bu rapor, sirket ici guvenlik denetimi amaciyla <strong>Invoke-ADAuditReport.ps1</strong> tarafindan yerel LDAP/ADSI sorgulari ile salt okunur uretilmistir.
            <br>Sistem uzerinde hicbir degisiklik yapilmamistir.
        </div>
    </div>

    <!-- JAVASCRIPT LOGIC -->
    <script>
        // TAB DEGISIMI
        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
        }

        // ACCORDION TOGGLE
        function toggleFinding(id) {
            const el = document.getElementById(id);
            if (el) {
                el.classList.toggle('open');
            }
        }

        // TABLO ARAMA
        function filterTable(input, tableId) {
            const filter = input.value.toLowerCase();
            const table = document.getElementById(tableId);
            const trs = table.getElementsByTagName('tr');
            for (let i = 1; i < trs.length; i++) {
                trs[i].style.display = trs[i].textContent.toLowerCase().indexOf(filter) > -1 ? '' : 'none';
            }
        }

        // ENVANTER FILTRELEME
        let currentInvType = 'all';
        function filterInvType(type, btn) {
            currentInvType = type;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            applyInventoryFilters();
        }

        function filterInventory(input) {
            applyInventoryFilters(input.value.toLowerCase());
        }

        function applyInventoryFilters(searchVal) {
            const search = searchVal !== undefined ? searchVal : (document.querySelector('.search-bar[onkeyup*="filterInventory"]')?.value.toLowerCase() || '');
            const rows = document.querySelectorAll('.inv-row');
            rows.forEach(r => {
                const type = r.getAttribute('data-type');
                const text = r.textContent.toLowerCase();
                const typeMatch = (currentInvType === 'all' || type === currentInvType);
                const textMatch = (search === '' || text.indexOf(search) > -1);
                r.style.display = (typeMatch && textMatch) ? '' : 'none';
            });
        }

        // ==========================================
        // BLOODHOUND INTERAKTIF GRAFIK MOTORU
        // ==========================================
        const attackPathsData = $attackPathsJson;
        let activePathIndex = 0;

        function selectPath(idx, btn) {
            activePathIndex = idx;
            document.querySelectorAll('.graph-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderGraph(idx);
        }

        function renderGraph(pathIndex) {
            if (!attackPathsData || !attackPathsData[pathIndex]) return;
            const path = attackPathsData[pathIndex];
            const canvas = document.getElementById('attackCanvas');
            const descEl = document.getElementById('pathDescription');
            if (!canvas) return;

            // Canvas cozunurlugu ayarla
            const rect = canvas.getBoundingClientRect();
            canvas.width = rect.width;
            canvas.height = 450;
            const ctx = canvas.getContext('2d');
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            descEl.innerHTML = '<strong>' + path.Title + ' [' + path.Risk + ']</strong><br>' + path.Description;

            const nodes = path.Nodes;
            const edges = path.Edges;

            // X koordinatlarini canvas genisligine gore orantila
            const padding = 80;
            const stepX = (canvas.width - padding * 2) / (nodes.length - 1);

            nodes.forEach((n, i) => {
                n.renderX = padding + i * stepX;
                n.renderY = canvas.height / 2;
            });

            // Kenarlari (Edges / Oklar) ciz
            edges.forEach(e => {
                const src = nodes.find(n => n.id === e.from);
                const dst = nodes.find(n => n.id === e.to);
                if (src && dst) {
                    ctx.beginPath();
                    ctx.strokeStyle = e.color || '#ef4444';
                    ctx.lineWidth = 3;
                    ctx.moveTo(src.renderX, src.renderY);
                    ctx.lineTo(dst.renderX, dst.renderY);
                    ctx.stroke();

                    // Ok baslangici
                    const angle = Math.atan2(dst.renderY - src.renderY, dst.renderX - src.renderX);
                    const arrowSize = 10;
                    const arrowX = dst.renderX - 38 * Math.cos(angle);
                    const arrowY = dst.renderY - 38 * Math.sin(angle);

                    ctx.beginPath();
                    ctx.fillStyle = e.color || '#ef4444';
                    ctx.moveTo(arrowX, arrowY);
                    ctx.lineTo(arrowX - arrowSize * Math.cos(angle - Math.PI / 6), arrowY - arrowSize * Math.sin(angle - Math.PI / 6));
                    ctx.lineTo(arrowX - arrowSize * Math.cos(angle + Math.PI / 6), arrowY - arrowSize * Math.sin(angle + Math.PI / 6));
                    ctx.closePath();
                    ctx.fill();

                    // Edge Etiketi
                    const midX = (src.renderX + dst.renderX) / 2;
                    const midY = (src.renderY + dst.renderY) / 2 - 14;
                    ctx.font = '11px sans-serif';
                    ctx.fillStyle = '#f8fafc';
                    ctx.textAlign = 'center';
                    ctx.fillText(e.label, midX, midY);
                }
            });

            // Dugumleri (Nodes) ciz
            nodes.forEach(n => {
                let color = '#3b82f6';
                if (n.role === 'admin' || n.role === 'target') color = '#ef4444';
                else if (n.role === 'pivot') color = '#f59e0b';
                else if (n.role === 'entry') color = '#38bdf8';

                // Dis halka (Glow)
                ctx.beginPath();
                ctx.arc(n.renderX, n.renderY, 32, 0, 2 * Math.PI);
                ctx.fillStyle = 'rgba(15, 23, 42, 0.9)';
                ctx.fill();
                ctx.lineWidth = 3;
                ctx.strokeStyle = color;
                ctx.stroke();

                // Ikon veya Tur
                ctx.font = 'bold 12px sans-serif';
                ctx.fillStyle = color;
                ctx.textAlign = 'center';
                let typeIcon = '[U]';
                if (n.type === 'group') typeIcon = '[G]';
                else if (n.type === 'computer') typeIcon = '[C]';
                else if (n.type === 'ticket') typeIcon = '[TGT]';
                ctx.fillText(typeIcon, n.renderX, n.renderY + 4);

                // Dugum Etiketi
                ctx.font = '11px sans-serif';
                ctx.fillStyle = '#f1f5f9';
                const lines = n.label.split('\n');
                lines.forEach((line, idx) => {
                    ctx.fillText(line, n.renderX, n.renderY + 46 + (idx * 14));
                });
            });
        }

        // Pencere boyutu degisirse grafigi tekrar orantila
        window.addEventListener('resize', () => {
            if (document.getElementById('tab-graph').classList.contains('active')) {
                renderGraph(activePathIndex);
            }
        });
    </script>
</body>
</html>
"@

    # HTML dosyasini UTF-8 with BOM olarak yaz (Karakter bozulmasini kesin engeller)
    $utf8WithBom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($FilePath, $html, $utf8WithBom)
    Write-Host "[+] Gelismis HTML Raporu Basariyla Olusturuldu: $FilePath" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 6. ANA AKIS
# ------------------------------------------------------------------------------

$resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

# Veriyi topla
$auditData = if ($DemoMode) {
    Get-DemoAuditData
} else {
    Get-LiveAuditData
}

# Skoru hesapla
$auditResult = Calculate-SecurityScore -Data $auditData

# HTML raporunu uret
Generate-HtmlReport -Data $auditData -AuditResult $auditResult -FilePath $resolvedPath

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   DENETIM TAMAMLANDI!                                         " -ForegroundColor Green
Write-Host "   Genel Guvenlik Skoru: $($auditResult.Score) / 100 (Derece: $($auditResult.Grade))" -ForegroundColor Yellow
Write-Host "   Tespit Edilen Risk Sayisi: $($AuditResult.Findings.Count)" -ForegroundColor $(if($auditResult.Findings.Count -gt 0){'Red'}else{'Green'})
Write-Host "   Rapor Dosyasi: $resolvedPath" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan

if ($OpenReport) {
    try {
        Start-Process $resolvedPath
    } catch {
        Write-Warning "Rapor tarayicida otomatik acilamadi: $($_.Exception.Message)"
    }
}
