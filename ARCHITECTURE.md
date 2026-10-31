# ARCHITECTURE.md — Sistem Mimarisi ve Tasarım Spesifikasyonu

Bu doküman, AnonVoid (Tümleşik Ayak İzi ve Ağ Gizliliği Aracı) projesinin uçtan uca mimarisini, güvenlik sınırlarını, modül hiyerarşisini ve yaşam döngüsünü tanımlar.

---

## 1. Yüksek Seviye Mimari Şeması

```
+-------------------------------------------------------------------------+
|                  KULLANICI KATMANI (Unprivileged GUI)                    |
|                                                                         |
|   +-----------------------------------------------------------------+   |
|   |         PyQt6 / Slint Masaüstü Arayüzü (Temalar: OLED, Circuit) |   |
|   |  - Gösterge Paneli (Dashboard) & Servis Kartları                |   |
|   |  - Adli Temizlik Seçim Matrisi (Shell, Logs, Cache, Swap, SSD)  |   |
|   |  - Canlı Ağ Sızıntı Test Paneli (Leak Test Runner)              |   |
|   |  - Acil Durum / Panik Butonu (Nuke Switch)                      |   |
|   +-----------------------------------------------------------------+   |
|                                   |                                     |
|                                   v                                     |
|   +-----------------------------------------------------------------+   |
|   |   GUI Daemon İstemcisi (daemon_client.py)                        |   |
|   |   - Asenkron İş Parçacıkları (Worker QThread)                   |   |
|   |   - JSON Komut Formatlama (Strict Schema)                       |   |
|   +-----------------------------------------------------------------+   |
+-----------------------------------|-------------------------------------+
                                    |
                    Unix Domain Socket (/run/anonvoid/daemon.sock)
                    Erişim: mode 0660, root:anonvoid
                    Kimlik Denetimi: SO_PEERCRED (Çekirdek UID Doğrulama)
                                    |
+-----------------------------------|-------------------------------------+
|                  SİSTEM KATMANI (Privileged Root Daemon)                |
|                                   v                                     |
|   +-----------------------------------------------------------------+   |
|   |   Root Daemon Servisi (core/daemon.py)                          |   |
|   |   - Startup Self-Heal (Askıda kalan firewall & DNS düzeltici)   |   |
|   |   - Komut Beyaz Listesi Doğrulayıcısı (Command Whitelisting)    |   |
|   |   - Kullanıcı İstemci Kimlik Bağlayıcı (Client Rebinding)       |   |
|   +-----------------------------------------------------------------+   |
|          |                                            |                 |
|          v                                            v                 |
|   +--------------------------+         +----------------------------+   |
|   | ADLİ TEMİZLİK ÇEKİRDEĞİ  |         | AĞ VE GİZLİLİK ÇEKİRDEĞİ   |   |
|   | (core/forensics/)        |         | (core/network/ & core/)    |   |
|   | - Shell History Wipe     |         | - Tor Transparent Proxy    |   |
|   | - Log Vacuum (journald)  |         | - nftables Firewall Engine |   |
|   | - MRU & Cache Sanitizer  |         | - DNSCrypt & resolvectl    |   |
|   | - Metadata & EXIF Strip  |         | - DoH Block & IPv6 Drop    |   |
|   | - Memory & Swap Zeroize  |         | - MAC Randomizer           |   |
|   | - Exposure Risk Radar    |         | - Tor Capsule Sandbox      |   |
|   | - SSD TRIM & blkdiscard  |         | - USB Guard Kill-Switch    |   |
|   | - ctypes / libc.so.6     |         | - Adli Sızıntı Testleri    |   |
|   +--------------------------+         +----------------------------+   |
+-------------------------------------------------------------------------+
```

---

## 2. Güvenlik Güven Sınırı (Trust Boundary) ve IPC

Proje, **sertleştirilmiş (hardened)** kurumsal siber güvenlik prensiplerine göre tasarlanmıştır:
1. **İstemci Asla Güvenilmez:** Masaüstü kullanıcısının ev dizinindeki yapılandırma dosyaları (`config.json`) tamamen kullanıcının kontrolündedir. Daemon bu dosyayı okurken:
   * `O_NOFOLLOW` bayrağı ile açar (sembolik bağ tuzaklarını önler),
   * Dosya boyutu sınırlandırılır,
   * Portlar `cfg_port()` ile `1-65535` aralığında doğrulanır,
   * String parametreler sıkı regex karakter kontrollerinden geçirilir.
2. **Çekirdek Düzeyinde Kimlik Tespiti (`SO_PEERCRED`):** İstemcinin sokete bağlandığı andaki gerçek `uid` ve `gid` değerleri Linux çekirdeğinden okunur. Kullanıcının masaüstü oturumu (`$XDG_RUNTIME_DIR`, `$HOME`) bu kimlikle ilişkilendirilir.
3. **Katı Beyaz Liste Protokolü (Whitelisting):**
   * Daemon sadece şu standart komutları kabul eder: `ping`, `connect <json>`, `disconnect`, `clean_forensics <json>`, `new_circuit`, `leak_test`, `scan_exposure`, `sanitize_metadata <json>`, `panic`, `status`.
   * Raw komut satırı veya shell script enjeksiyonu mimari olarak imkansızdır.
4. **Soket Yolu ve Dizin Doğrulaması (Path Traversal Koruması):**
   * Daemon soketi yalnızca `/run/` altında kabul edilir; `..` traversal dizilimleri veya null (`\x00`) baytları kesinlikle reddedilir.
5. **Başlangıçta Kendi Kendini İyileştirme (Startup Self-Heal):**
   * Sistem veya daemon kazaen kapandığında askıda kalan `anonvoid` / `fp-cleaner` nftables tabloları temizlenir.
   * `systemd-resolved` ve `/etc/resolv.conf` ayarları orijinal durumuna getirilir.
   * Yetim Tor süreçleri ve kilit dosyaları (`.lock`) süpürülür.

---

## 3. Çok Aşamalı Yaşam Döngüsü (Multi-Mode Lifecycle)

Uygulama temel senaryolarda çalışacak şekilde kurgulanmıştır:

### A. Taktiksel / Anlık Temizlik Modu (Clean & Exit)
* **Amaç:** Kullanıcının pentest veya gizli çalışma sonrasında arkasında hiçbir iz bırakmadan sistemi temizlemesi (`anonvoid --wipe`).
* **Akış:** Shell geçmişi, log vakumlama, son dosyalar, swap/RAM temizliği, SSD TRIM çalışır ve `sys.exit(0)` ile kapanır.

### B. Aktif Gizlilik Oturumu Modu (Active Shield)
* **Amaç:** Canlı internet bağlantısında Tor şeffaf proxy, DNSCrypt ve Kill-Switch koruması sağlamak.
* **Akış:** Firewall kuralları girilir, IPv6 kapatılır, DoH sunucuları engellenir, MAC adresi randomize edilir. Disconnect dendiğinde tüm kurallar geri alınır.

### C. Uygulama Bazlı Tor Kapsülü (NetNS Sandbox & Torsocks)
* **Amaç:** Tüm sistemi Tor'a yönlendirmeden tek bir komutu veya uygulamayı izole Tor ağ kafesinde çalıştırmak (`anonvoid --exec <komut>`).
* **Akış:** SOCKS5h ortam değişkenleri veya `torsocks` ile DNS/TCP sızıntısız sarmalama yapılır; root yetkileri hedef kullanıcının UID/GID'sine düşürülür.

### D. Canlı Adli Maruziyet Radarı ve Meta Veri Temizliği
* **Amaç:** Dosyaları silmeden adli risk skoru (0-100) üretmek (`anonvoid --scan-exposure`) ve belgelerdeki EXIF/PNG meta verilerini temizlemek (`anonvoid --sanitize-meta <dosya/dizin>`).

---

## 4. Dizin ve Modül Hiyerarşisi

```
AnonVoid/
├── AGENTS.md                   # Ajan operasyonel kısıtlamaları
├── ARCHITECTURE.md             # Bu mimari dokümanı
├── TASK_MEMORY.md              # Görev takibi ve hafıza
├── KNOWN_ISSUES.md             # Adli tuzaklar ve bilinen kısıtlamalar
├── docs/                       # Derin teknik spesifikasyonlar
│   ├── NETWORK_STACK.md        # AnonVoid ağ ve gizlilik omurgası spesifikasyonu
│   ├── FORENSICS_CLEANER.md    # Disk, bellek, log ve artefakt temizliği
│   └── ROADMAP.md              # Adım adım geliştirme planı
├── main.py                     # Giriş noktası (GUI, --service, --exec, --wipe vb.)
├── install.sh                  # Çoklu dağıtım kurucusu
│   ├── core/
│   │   ├── config.py           # Şema doğrulamalı JSON yapılandırma & path traversal koruması
│   │   ├── daemon.py           # Root IPC daemon servisi
│   │   ├── daemon_client.py    # GUI soket istemcisi
│   │   ├── usb_guard.py        # Donanımsal USB Kill-Switch & Dead Man's Switch
│   │   ├── netns_sandbox.py    # Uygulama bazlı Tor Kapsülü & yetki düşürme
│   │   ├── panic.py            # Acil durum nuke mekanizması
│   │   ├── forensics/          # ADLİ İZ TEMİZLEME VE MARUZİYET MODÜLLERİ
│   │   │   ├── manager.py      # Adli temizlik orkestratörü & Canlı Maruziyet Radarı
│   │   │   ├── metadata.py     # Saf Python PNG/JPEG EXIF ve meta veri imha aracı
│   │   │   ├── shell.py        # Bash, zsh, fish, python history shredder
│   │   │   ├── logs.py         # journald vacuum & logrotate simulation
│   │   │   ├── cache.py        # Thumbnails, MRU, recently-used, trash
│   │   │   ├── memory.py       # Swap wipe, drop_caches, compact_memory
│   │   │   ├── storage.py      # SSD TRIM, free space zeroing, blkdiscard
│   │   │   ├── package_mgr.py  # APT, Pacman, DNF, Snap, Flatpak önbellekleri
│   │   │   └── lowlevel.py     # ctypes / libc.so.6 (memset, mlock, sync, ptrace koruması)
│   │   └── network/            # GELİŞMİŞ AĞ VE GİZLİLİK OMURGASI
│   │       ├── firewall.py     # nftables/iptables, .onion split, DoH block, UDP/ICMP drop
│   │       ├── tor.py          # torrc patching, bridge desteği, Five Eyes filtresi
│   │       ├── dnscrypt.py     # dnscrypt-proxy & resolvectl entegrasyonu
│   │       ├── mac.py          # Akıllı in-place MAC sahteleme
│   │       ├── leak_test.py    # Tor exit, DNS, IPv6, WebRTC testleri
│   │       └── panic.py        # Ağ düzeyinde acil durum kill-switch
│   └── gui/                    # KULLANICI ARAYÜZÜ (PyQt6)
│       ├── main_window.py      # Ana pencere ve dinamik durum halkası
│       ├── forensics_panel.py  # Temizlik seçenekleri, Maruziyet Radarı ve EXIF temizleme butonu
│       ├── settings_panel.py   # Ağ, Tor köprüleri, Five Eyes ve USB Kill-Switch ayarları
│       ├── leak_panel.py       # Canlı sızıntı test ekranı
│       ├── themes.py           # 5 tema (OLED, Circuit, Light, Binary, Pixel)
│       └── widgets.py          # Özel servis kartları ve hız göstergesi
```
