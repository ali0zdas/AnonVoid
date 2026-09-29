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
|   | (core/forensics/)        |         | (core/network/)            |   |
|   | - Shell History Wipe     |         | - Tor Transparent Proxy    |   |
|   | - Log Vacuum (journald)  |         | - nftables Firewall Engine |   |
|   | - MRU & Cache Sanitizer  |         | - DNSCrypt & resolvectl    |   |
|   | - Memory & Swap Zeroize  |         | - DoH Block & IPv6 Drop    |   |
|   | - SSD TRIM & blkdiscard  |         | - MAC Randomizer           |   |
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
   * Daemon sadece şu standart komutları kabul eder: `ping`, `connect <json>`, `disconnect`, `clean_forensics <json>`, `new_circuit`, `leak_test`, `panic`, `status`.
   * Raw komut satırı veya shell script enjeksiyonu mimari olarak imkansızdır.
4. **Başlangıçta Kendi Kendini İyileştirme (Startup Self-Heal):**
   * Sistem veya daemon kazaen kapandığında askıda kalan `anonvoid` / `fp-cleaner` nftables tabloları temizlenir.
   * `systemd-resolved` ve `/etc/resolv.conf` ayarları orijinal durumuna getirilir.
   * Yetim Tor süreçleri ve kilit dosyaları (`.lock`) süpürülür.

---

## 3. İki Aşamalı Yaşam Döngüsü (Dual-Mode Lifecycle)

Uygulama iki temel senaryoda çalışacak şekilde kurgulanmıştır:

### A. Taktiksel / Anlık Temizlik Modu (Clean & Exit)
* **Amaç:** Kullanıcının pentest veya gizli çalışma sonrasında arkasında hiçbir iz bırakmadan sistemi temizlemesi.
* **Akış:**
  1. Kullanıcı GUI'yi açar veya CLI parametresi verir (`anonvoid --wipe`).
  2. Modüller yürütülür (Shell geçmişi, log vakumlama, son dosyalar, swap/RAM temizliği, SSD TRIM).
  3. Temizlik tamamlandığında uygulama `sys.exit(0)` ile kapanır.
  4. Arkasında aktif hiçbir arka plan servisi veya RAM tüketimi bırakmaz.

### B. Aktif Gizlilik Oturumu Modu (Active Shield)
* **Amaç:** Canlı internet bağlantısında Tor şeffaf proxy, DNSCrypt ve Kill-Switch koruması sağlamak.
* **Akış:**
  1. Kullanıcı istediği servisleri (Tor, DNSCrypt, I2P) seçip **CONNECT** butonuna basar.
  2. Firewall kuralları girilir, IPv6 kapatılır, DoH sunucuları engellenir, MAC adresi randomize edilir.
  3. İstenirse uygulama sistem tepsisine (system tray) küçülür.
  4. **DISCONNECT** dendiğinde tüm kurallar geri alınır, oturum izleri temizlenir ve kalkan güvenle iner.

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
├── main.py                     # Giriş noktası (GUI veya --service)
├── install.sh                  # Çoklu dağıtım kurucusu
│   ├── core/
│   │   ├── config.py           # Şema doğrulamalı JSON yapılandırma
│   │   ├── daemon.py           # Root IPC daemon servisi
│   │   ├── daemon_client.py    # GUI soket istemcisi
│   │   ├── panic.py            # Acil durum nuke mekanizması
│   │   ├── forensics/          # ADLİ İZ TEMİZLEME MODÜLLERİ
│   │   │   ├── shell.py        # Bash, zsh, fish, python history shredder
│   │   │   ├── logs.py         # journald vacuum & logrotate simulation
│   │   │   ├── cache.py        # Thumbnails, MRU, recently-used, trash
│   │   │   ├── memory.py       # Swap wipe, drop_caches, compact_memory
│   │   │   ├── storage.py      # SSD TRIM, free space zeroing, blkdiscard
│   │   │   ├── package_mgr.py  # APT, Pacman, DNF, Snap, Flatpak önbellekleri
│   │   │   └── lowlevel.py     # ctypes / libc.so.6 (memset, mlock, sync)
│   │   └── network/            # GELİŞMİŞ AĞ VE GİZLİLİK OMURGASI
│   │       ├── firewall.py     # nftables/iptables, .onion split, DoH block
│   │       ├── tor.py          # torrc patching, circuit renewal, control port
│   │       ├── dnscrypt.py     # dnscrypt-proxy & resolvectl entegrasyonu
│   │       ├── mac.py          # Akıllı in-place MAC sahteleme
│   │       ├── leak_test.py    # Tor exit, DNS, IPv6, WebRTC testleri
│   │       └── i2p.py          # i2pd ve redsocks şeffaf proxy desteği
│   └── gui/                    # KULLANICI ARAYÜZÜ (PyQt6)
│       ├── main_window.py      # Ana pencere ve dinamik durum halkası
│       ├── forensics_panel.py  # Temizlik seçenekleri ve ilerleme çubukları
│       ├── settings_panel.py   # Ağ ve genel ayarlar
│       ├── themes.py           # 5 tema (OLED, Circuit, Light, Binary, Pixel)
│       └── widgets.py          # Özel servis kartları ve hız göstergesi
```
