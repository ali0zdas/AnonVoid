<div align="center">

  <img src="packaging/desktop/anonvoid.svg" width="130" height="130" alt="AnonVoid Logo" />

  # AnonVoid (`anonvoid`)
  ### Dijital Adli Bilişim (Anti-Forensics) İz Temizleyicisi ve Saydam Ağ Gizlilik Kalkanı
  *Zero Self-Footprint Anti-Forensics Engine & Transparent Network Shield for Linux*

  <p align="center">
    <a href="https://github.com/ali0zdas/AnonVoid"><img src="https://img.shields.io/badge/Version-1.0.0-00ff88?style=for-the-badge&logo=shield" alt="Version" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge" alt="License: GPL v3" /></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+" /></a>
    <a href="https://www.kali.org/"><img src="https://img.shields.io/badge/Distro-Kali%20%7C%20Debian%20%7C%20Arch%20%7C%20Fedora-557C94?style=for-the-badge&logo=linux&logoColor=white" alt="Distributions" /></a>
    <a href="https://github.com/ali0zdas/AnonVoid"><img src="https://img.shields.io/badge/Security-Zero_Self--Footprint-00d4ff?style=for-the-badge" alt="Zero Self-Footprint" /></a>
    <a href="https://github.com/ali0zdas/AnonVoid"><img src="https://img.shields.io/badge/Tests-56%2F56_Passing-brightgreen?style=for-the-badge" alt="Tests Passing" /></a>
  </p>

  <p align="center">
    <b>Sıfır İz. Çift Katmanlı Ayrıcalık Ayrımı. Tavizsiz Dijital Adli Temizlik ve Ağ Kalkanı.</b>
  </p>

</div>

---

## 📌 İçindekiler
- [Genel Bakış](#-genel-bakış)
- [Temel Güvenlik Sütunları](#-temel-güvenlik-sütunları)
- [Öne Çıkan Yetenekler](#-öne-çıkan-yetenekler)
  - [1. Adli İz ve Sistem Temizlik Motoru](#1-adli-iz-ve-sistem-temizlik-motoru-forensics-core)
  - [2. Ağ ve Gizlilik Omurgası](#2-ağ-ve-gizlilik-omurgası-network-stack)
  - [3. Taktiksel Acil Durum / Panik Protokolü](#3-taktiksel-acil-durum--panik-protokolü-nuke)
- [Sistem Mimarisi](#-sistem-mimarisi)
- [Modern Görsel Arayüz (PyQt6) & Temalar](#-modern-görsel-arayüz-pyqt6--temalar)
- [Kurulum ve Hızlı Başlangıç](#-kurulum-ve-hızlı-başlangıç)
- [Kullanım ve Komut Satırı Seçenekleri](#-kullanım-ve-komut-satırı-seçenekleri)
- [Birim Testler ve Doğrulama](#-birim-testler-ve-doğrulama)
- [Güvenlik ve Tehdit Modeli](#-güvenlik-ve-tehdit-modeli)
- [Lisans ve İletişim](#-lisans-ve-iletişim)

---

## 🛡️ Genel Bakış

**AnonVoid**, Linux ortamlarında (başta Kali Linux, Debian, Ubuntu, Arch Linux ve Fedora olmak üzere) kullanıcıların ve güvenlik uzmanlarının arkalarında bırakabileceği tüm dijital ayak izlerini (footprint/fingerprint) adli bilişim standartlarında ortadan kaldıran; aynı zamanda sistemin tüm giden ağ trafiğini çekirdek seviyesinde (`nftables`) Tor ve DNSCrypt üzerinden şeffaf tünelleyerek tam anonimlik sağlayan açık kaynaklı, yüksek güvenlikli bir anti-forensics platformudur.

Geleneksel temizlik araçlarının aksine AnonVoid, **kendisinin sistemde adli iz bırakmasını engelleyen (Zero Self-Footprint)** ve masaüstü arayüzü ile root çekirdeğini birbirinden yalıtan **Ayrıcalık Ayrımı (Privilege Boundary)** mimarisine sahiptir.

---

## ⚡ Temel Güvenlik Sütunları

| Prensip | Uygulama ve Teknik Standart |
| :--- | :--- |
| **Sıfır Kendi İzi (Zero Self-Footprint)** | Diske asla `.pyc` veya `__pycache__` yazılmaz (`sys.dont_write_bytecode = True`, `PYTHONDONTWRITEBYTECODE=1`). Hassas bellek bölgeleri `libc.memset` / `explicit_bzero` ile anında sıfırlanır, `mlock` ile Linux swap alanına yazılması engellenir. |
| **Ayrıcalık Ayrımı (Privilege Separation)** | Grafik kullanıcı arayüzü (PyQt6) Wayland ve çekirdek güvenliği gereğince **ASLA root veya sudo ile çalıştırılamaz** (`os.getuid() == 0` engeli). Sistemik işlemler `/run/anonvoid/daemon.sock` üzerinden root daemon ile yürütülür. |
| **Kernel Doğrulamalı IPC (SO_PEERCRED)** | Daemon, bağlanan istemcinin kimliğini kullanıcının beyanına göre değil, Linux çekirdeğinden `SO_PEERCRED` ile doğrudan okur. Yalnızca yetkili kullanıcılar ve beyaz listedeki komutlar işleme alınır. |
| **Katı Şema & `O_NOFOLLOW` Güvencesi** | Dosya açılışlarında sembolik bağ saldırılarını (symlink race condition) önlemek için `os.O_NOFOLLOW` bayrağı kullanılır. Port ve UID doğrulamaları katı aralık kontrolünden geçirilir. |
| **Adli Anomali Önleme** | Sistem logları körü körüne 0 bayt yapılmaz; `journalctl --vacuum-time=1s` ve `logrotate -f` simülasyonu ile olağan sistem davranışı görünümü korunur. |

---

## 🚀 Öne Çıkan Yetenekler

### 1. Adli İz ve Sistem Temizlik Motoru (Forensics Core)
* **Shell & Terminal Geçmişi Hijyeni:** `bash`, `zsh`, `fish`, `python`, `mysql`, `psql` ve `node` geçmiş dosyaları rastgele baytlar (`/dev/urandom`) ve sıfır (`0x00`) ile çok aşamalı ezilerek (`shred`) diskten silinir.
* **Sistem Günlükleri:** `systemd-journald` logları vakumlanır, `/var/log/*` rotasyon kalıntıları temizlenir, `wtmp`, `btmp` ve `lastlog` oturum kayıtları hijyenik hale getirilir.
* **Masaüstü Artefaktları & Önbellekler:** XDG küçük resimleri (`thumbnails`), son kullanılan dosyalar (`recently-used.xbel`), Çöp Kutusu (`Trash`), Chromium ve Firefox disk önbellekleri temizlenir.
* **RAM ve Bellek Hijyeni:** `drop_caches` ile Linux sayfa önbellekleri (pagecache, dentries, inodes) boşaltılır; `compact_memory` çalıştırılır; takas alanı (`swapoff`) sıfırlanarak yeniden devreye alınır.
* **Depolama & SSD/NVMe Blok Yönetimi:** SSD donanım tespiti (`/sys/block`), FTL aşınma dengelemesini aşmak üzere `fstrim -av` tetiklemesi ve dosya sistemi boş alan sıfırlama (free-space zeroing).
* **Paket Yöneticisi & Sandbox:** APT, Pacman, DNF, Zypper paket kalıntıları ile Flatpak ve Snap sandbox artıklarının temizlenmesi.

### 2. Ağ ve Gizlilik Omurgası (Network Stack)
* **nftables / iptables Çekirdek Duvarı:** Tüm giden TCP trafiği Tor `TransPort` (9040), tüm giden DNS trafiği Tor `DNSPort` (5300) yönlendirmesine tabi tutulur.
* **DoH / DoT Sızıntı Kalkanı:** 1.1.1.1, 8.8.8.8, 9.9.9.9 gibi genel DoH sağlayıcılarının 443 portu çekirdek seviyesinde `DROP` edilir.
* **IPv6 Koruması:** IPv6 üzerinden oluşabilecek kimlik ve coğrafi sızıntılar `ip6 table` üzerinden tüm giden trafiğin bloklanmasıyla engellenir.
* **Döngü (Routing Loop) Engeli:** `meta skuid debian-tor -> accept` kuralı ile Tor servisinin kendi trafiği muaf tutulur.
* **.onion Sanal IP Alanı:** `10.192.0.0/10` bloğu yerel ağ muafiyetinden ayrı tutularak doğrudan Tor tüneline yönlendirilir.
* **In-Place MAC Sahteleme:** NetworkManager ile yarış durumuna girmeden ağ bağdaştırıcısının MAC adresi yerinde sahtelenir.
* **Canlı Sızıntı Testi:** IP adresi, ISP, WebRTC, DNS ve Tor çıkış düğümü tek tuşla taranıp puanlanır.

### 3. Taktiksel Acil Durum / Panik Protokolü (Nuke)
Tehlike anında arayüzdeki acil durum butonuna basıldığında veya CLI üzerinden `--panic` tetiklendiğinde:
1. nftables/iptables kuralları anında tüm dış ağ trafiğini dondurur (`DROP all`).
2. Aktif terminal oturumu ve shell geçmişi sıfırlanır.
3. Linux RAM önbellekleri serbest bırakılır.
4. Tercihe bağlı olarak sistem güvenli şekilde anında kapatılır.

---

## 🏗️ Sistem Mimarisi

AnonVoid, ayrıcalıksız kullanıcı arayüzü ile sistem yetkilerine sahip arka plan servisini birbirinden ayıran çift katmanlı bir mimari kullanır:

```
+--------------------------------------------------------------------------+
|                       KULLANICI ALANI (Kullanıcı UID)                    |
|                                                                          |
|   [ PyQt6 Modern Arayüz ]        veya        [ CLI / Taktiksel Wipe ]     |
|             \                                    /                       |
|              \                                  /                        |
|               v                                v                         |
|     +----------------------------------------------------+               |
|     |  Asenkron IPC İstemcisi (core/daemon_client.py)   |               |
|     +----------------------------------------------------+               |
+-----------------------------------|--------------------------------------+
                                    |
                  Unix Domain Socket: /run/anonvoid/daemon.sock
                  İzinler: 0660 root:anonvoid
                  Doğrulama: SO_PEERCRED (Kernel UID/GID Denetimi)
                                    |
+-----------------------------------|--------------------------------------+
|                     AYRICALIKLI ÇEKİRDEK (Root Daemon)                    |
|                                                                          |
|     +----------------------------------------------------+               |
|     |         AnonVoid Root Daemon (core/daemon.py)      |               |
|     |     (Katı Komut Beyaz Listesi & Şema Denetimi)     |               |
|     +----------------------------------------------------+               |
|            |                                      |                      |
|            v                                      v                      |
|  [ core/forensics/ ]                     [ core/network/ ]               |
|  - lowlevel (libc memset/mlock)          - firewall (nftables/iptables)  |
|  - shell (urandom shred)                 - tor (TransPort/DNSPort)       |
|  - logs (journal vacuum/logrotate)       - dnscrypt (DNSCrypt-proxy)     |
|  - memory (drop_caches/swapoff)          - mac (In-place OUI spoofing)   |
|  - storage (fstrim/zero_free_space)      - panic (Emergency Nuke)        |
+--------------------------------------------------------------------------+
```

---

## 🎨 Modern Görsel Arayüz (PyQt6) & Temalar

AnonVoid, karanlık mod ve siber güvenlik estetiğine odaklanmış **5 Dinamik Görsel Tema** ile donatılmıştır:

* **OLED:** Saf siyah (`#000000`) zemin ve yüksek kontrastlı minimalist siberpunk çizgileri.
* **Circuit:** Matriks yeşili (`#00ff88`) ve koyu zümrüt detaylar.
* **Binary:** Siber mavi (`#00d4ff`) ve derin lacivert tonlar.
* **Pixel:** Retro 8-bit / siberpunk mor ve neon vurgular.
* **Light:** Yüksek aydınlatmalı ortamlarda çalışmak için temiz gri/beyaz düzeni.

---

## 📦 Kurulum ve Hızlı Başlangıç

### Sistem Gereksinimleri
* **İşletim Sistemi:** Kali Linux, Debian 11+, Ubuntu 20.04+, Arch Linux, Fedora 36+
* **Python Sürümü:** Python 3.10 veya üzeri
* **Gerekli Paketler:** `tor`, `nftables` (veya `iptables`), `systemd`

### Tek Adımda Evrensel Kurulum

Depoyu klonlayın ve dağıtımınıza uygun şekilde servis, grup ve ikili dosyaları yapılandıran evrensel kurulum betiğini çalıştırın:

```bash
# Depoyu klonlayın
git clone https://github.com/ali0zdas/AnonVoid.git
cd AnonVoid

# Kurulumu root yetkisiyle başlatın
sudo bash install.sh
```

Kurulum betiği otomatik olarak:
1. `anonvoid` sistem grubunu oluşturur ve mevcut kullanıcınızı bu gruba ekler.
2. Bağımlılıkları kontrol eder (`tor`, `nftables`, `python3-pyqt6` vb.).
3. `anonvoid.service` systemd arka plan servisini kurar ve başlatır.
4. `/usr/local/bin/anonvoid` kısayolunu ve masaüstü uygulamasını (`.desktop`) sisteme kaydeder.

> **Not:** Grubun geçerli olması için oturumu kapatıp açabilir veya `newgrp anonvoid` komutunu kullanabilirsiniz.

### Kaldırma (Uninstall)
AnonVoid'i tüm servis, kısayol ve konfigürasyonlarıyla birlikte sistemden tamamen temizlemek için:
```bash
sudo bash install.sh --uninstall
```

---

## 💻 Kullanım ve Komut Satırı Seçenekleri

AnonVoid hem grafik arayüz (GUI) hem de uçbirim üzerinden çalışan doğrudan CLI modlarını destekler:

```bash
# 1. Grafik Kullanıcı Arayüzünü Başlatma (Ayrıcalıksız kullanıcı olarak)
anonvoid

# 2. Taktiksel Temizle ve Kapan (Clean & Exit)
# Arka planda servis bırakmadan tüm geçmişi, logları ve önbellekleri siler
anonvoid --wipe

# 3. Terminal Üzerinden Canlı Sızıntı Testi
anonvoid --leak-test

# 4. Acil Durum Panik Modu (Ağı Dondur, Belleği Sıfırla)
anonvoid --panic

# 5. Root Daemon Servisini Elle Çalıştırma (Systemd dışında)
sudo anonvoid --service
```

---

## 🧪 Birim Testler ve Doğrulama

AnonVoid kod tabanı; IPC haberleşmesi, şema güvenliği, adli temizlik çağrıları, ağ duvarı kuralları ve paketleme yapılarını kapsayan **56 adet kapsamlı birim test** ile korunmaktadır:

```bash
# Tüm birim test paketini çalıştırma
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## 🔒 Güvenlik ve Tehdit Modeli

1. **Wayland ve X11 Root Güvenliği:** GUI sürecinin asla `root` olarak çalıştırılamaması, olası Qt veya X11/Wayland bellek açıklarının ayrıcalık yükseltme (privilege escalation) için kullanılmasını imkansız kılar.
2. **IPC Şema Koruması:** Daemon'a giden istekler katı bir JSON şemasından geçer. Keyfi kabuk komutu (shell command) veya dinamik kod çalıştırma desteği bulunmaz.
3. **Kendi Kendini Yok Etme Hijyeni:** Taktiksel temizlik modu (`--wipe`), geride hiçbir geçici soket, PID dosyası veya log bırakmadan doğrudan işletim sistemi belleğini temizler.

---

## ⚖️ Lisans ve İletişim

* **Geliştirici:** Ali Özdaş ([@ali0zdas](https://github.com/ali0zdas))
* **Depo Adresi:** [https://github.com/ali0zdas/AnonVoid](https://github.com/ali0zdas/AnonVoid)
* **Lisans:** Bu proje [GNU General Public License v3.0 (GPLv3)](LICENSE) kapsamında lisanslanmıştır. Açık kaynak standartlarına ve güvenlik ilkelerine tam uyumludur.

---

<div align="center">
  <sub>AnonVoid — Zero-Footprint Digital Forensics Eraser & Transparent Network Privacy Shield.</sub>
</div>
