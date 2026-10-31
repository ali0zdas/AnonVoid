"""AnonVoid - Güvenli Yapılandırma ve Şema Doğrulama Modülü.

Bu modül; istemci yapılandırmalarının doğrulanması, port ve kullanıcı kimliği (UID)
aralık kontrolleri, sembolik bağ (symlink) tuzaklarına karşı güvenli dosya okuma/yazma
ve derin varsayılan birleştirme (deep-merge) işlemlerini yürütür.
"""

from __future__ import annotations

import copy
import json
import os
import re
import stat
import sys
from typing import Any, Dict, List, Optional, Union

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# UID regex deseni: Yalnızca 1-10 basamaklı pozitif ondalık ASCII sayıları kabul eder
UID_REGEX = re.compile(r"^[0-9]{1,10}$")

# Güvenli ağ arayüzü adı regex deseni (Linux IFNAMSIZ sınırı: 16 karakter)
INTERFACE_REGEX = re.compile(r"^[a-zA-Z0-9_.:-]{1,16}$")

# İzin verilen maksimum yapılandırma dosyası boyutu (1 Megabayt)
MAX_CONFIG_FILE_SIZE = 1024 * 1024

# Varsayılan Sistem Yapılandırması
DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "1.0.0",
    "network": {
        "enabled": False,
        "tor_enabled": True,
        "dnscrypt_enabled": True,
        "i2p_enabled": False,
        "tor_socks_port": 9050,
        "tor_trans_port": 9040,
        "tor_dns_port": 5300,
        "tor_control_port": 9051,
        "circuit_interval_sec": 600,
        "dnscrypt_port": 5380,
        "dnscrypt_listen": "127.0.0.1",
        "block_doh": True,
        "drop_ipv6": True,
        "mac_randomize": True,
        "mac_in_place": True,
        "excluded_interfaces": [
            "lo",
            "docker.*",
            "veth.*",
            "virbr.*",
            "wg.*",
            "tun.*",
            "tap.*",
            "cni.*",
            "flannel.*",
        ],
        "kill_switch": True,
        "use_bridges": False,
        "bridge_type": "obfs4",
        "custom_bridges": [],
        "exit_nodes": "",
        "exclude_five_eyes": False,
        "auto_renew_interval_sec": 0,
    },
    "forensics": {
        "clean_shell_history": True,
        "clean_journal_logs": True,
        "clean_text_logs": True,
        "clean_thumbnails": True,
        "clean_mru_cache": True,
        "clean_trash": True,
        "clean_memory_caches": True,
        "clean_swap": False,
        "ssd_trim": True,
        "free_space_zeroing": False,
        "clean_package_cache": True,
    },
    "daemon": {
        "socket_path": "/run/anonvoid/daemon.sock",
        "socket_group": "anonvoid",
        "socket_mode": 0o660,
        "max_request_size": 65536,
        "request_timeout_sec": 30.0,
    },
    "gui": {
        "theme": "oled",
        "close_to_tray": True,
        "notify_on_circuit_change": True,
        "auto_leak_test_on_connect": True,
        "auto_leak_test": False,
        "ram_suppression": False,
    },
    "security": {
        "usb_killswitch_enabled": False,
        "usb_authorized_device_id": "",
        "usb_panic_shutdown": False,
    },
}


def cfg_port(val: Any, default: Optional[int] = None) -> int:
    """Verilen port değerinin 1-65535 aralığında geçerli bir TCP/UDP portu olduğunu doğrular.

    Args:
        val: Doğrulanacak port değeri (int veya string).
        default: Değer geçersiz olduğunda dönülecek varsayılan değer.

    Returns:
        int: Doğrulanmış port numarası.

    Raises:
        ValueError: Port değeri geçersiz ve varsayılan belirtilmemişse.
    """
    try:
        if isinstance(val, str):
            val_clean = val.strip()
            if not val_clean.isdigit():
                raise ValueError(f"Port sayısal olmalıdır: {val!r}")
            port = int(val_clean)
        elif isinstance(val, (int, float)):
            port = int(val)
        else:
            raise ValueError(f"Geçersiz port veri türü: {type(val).__name__}")

        if 1 <= port <= 65535:
            return port
        raise ValueError(f"Port 1 ile 65535 aralığında olmalıdır, alınan: {port}")
    except (ValueError, TypeError) as err:
        if default is not None:
            if isinstance(default, int) and 1 <= default <= 65535:
                return default
            raise ValueError(f"Geçersiz varsayılan port değeri: {default}") from err
        raise ValueError(f"Port doğrulama hatası: {err}") from err


def cfg_uid(val: Any, default: Optional[int] = None) -> int:
    """Verilen UID değerinin güvenli pozitif ondalık bir tamsayı olduğunu doğrular.

    Args:
        val: Doğrulanacak kullanıcı kimliği (UID).
        default: Değer geçersiz olduğunda dönülecek varsayılan değer.

    Returns:
        int: Doğrulanmış kullanıcı kimliği.

    Raises:
        ValueError: Değer geçersiz ve varsayılan belirtilmemişse.
    """
    try:
        val_str = str(val).strip()
        if not UID_REGEX.match(val_str):
            raise ValueError(f"Geçersiz UID biçimi: {val!r}")
        uid = int(val_str)
        if 0 <= uid <= 4294967295:
            return uid
        raise ValueError(f"UID izin verilen aralığın (0-4294967295) dışında: {uid}")
    except (ValueError, TypeError) as err:
        if default is not None:
            if isinstance(default, int) and 0 <= default <= 4294967295:
                return default
            raise ValueError(f"Geçersiz varsayılan UID değeri: {default}") from err
        raise ValueError(f"UID doğrulama hatası: {err}") from err


def cfg_bool(val: Any, default: bool = False) -> bool:
    """Verilen değerin mantıksal bir boole değeri olduğunu doğrular.

    Args:
        val: Doğrulanacak değer.
        default: Hatalı veya tanımsız durumlarda varsayılan boole.

    Returns:
        bool: Doğrulanmış boole değeri.
    """
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        val_lower = val.strip().lower()
        if val_lower in ("true", "1", "yes", "on", "evet", "aktif"):
            return True
        if val_lower in ("false", "0", "no", "off", "hayır", "pasif"):
            return False
    return default


def cfg_interface_name(val: Any, default: Optional[str] = None) -> str:
    """Ağ arayüzü adının Linux standartlarına uygun olduğunu doğrular.

    Args:
        val: Arayüz adı (örn: eth0, wlan0).
        default: Arayüz adı geçersiz olduğunda dönülecek varsayılan değer.

    Returns:
        str: Doğrulanmış arayüz adı.

    Raises:
        ValueError: Arayüz adı geçersizse ve varsayılan belirtilmemişse.
    """
    if isinstance(val, str):
        val_clean = val.strip()
        if INTERFACE_REGEX.match(val_clean):
            return val_clean
    if default is not None:
        if isinstance(default, str) and INTERFACE_REGEX.match(default.strip()):
            return default.strip()
        raise ValueError(f"Geçersiz varsayılan ağ arayüzü adı: {default!r}")
    raise ValueError(f"Geçersiz ağ arayüzü adı: {val!r}")


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """İki sözlüğü özyinelemeli (deep-merge) olarak birleştirir.

    Temel sözlük (base) bozulmaz, override sözlüğündeki geçerli değerler üzerine eklenir.

    Args:
        base: Temel varsayılan sözlük.
        override: Üzerine yazılacak kullanıcı yapılandırması.

    Returns:
        Dict[str, Any]: Birleştirilmiş yeni sözlük.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def validate_network_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Ağ yapılandırma parametrelerini şema ve aralık kontrollerinden geçirir."""
    validated: Dict[str, Any] = {}
    base_net = DEFAULT_CONFIG["network"]

    validated["enabled"] = cfg_bool(cfg.get("enabled", base_net["enabled"]))
    validated["tor_enabled"] = cfg_bool(cfg.get("tor_enabled", base_net["tor_enabled"]))
    validated["dnscrypt_enabled"] = cfg_bool(cfg.get("dnscrypt_enabled", base_net["dnscrypt_enabled"]))
    validated["i2p_enabled"] = cfg_bool(cfg.get("i2p_enabled", base_net["i2p_enabled"]))

    validated["tor_socks_port"] = cfg_port(cfg.get("tor_socks_port", base_net["tor_socks_port"]), base_net["tor_socks_port"])
    validated["tor_trans_port"] = cfg_port(cfg.get("tor_trans_port", base_net["tor_trans_port"]), base_net["tor_trans_port"])
    validated["tor_dns_port"] = cfg_port(cfg.get("tor_dns_port", base_net["tor_dns_port"]), base_net["tor_dns_port"])
    validated["tor_control_port"] = cfg_port(cfg.get("tor_control_port", base_net["tor_control_port"]), base_net["tor_control_port"])

    circuit_int = cfg.get("circuit_interval_sec", base_net["circuit_interval_sec"])
    try:
        circuit_int_int = int(circuit_int)
        validated["circuit_interval_sec"] = max(30, min(86400, circuit_int_int))
    except (ValueError, TypeError):
        validated["circuit_interval_sec"] = base_net["circuit_interval_sec"]

    validated["dnscrypt_port"] = cfg_port(cfg.get("dnscrypt_port", base_net["dnscrypt_port"]), base_net["dnscrypt_port"])
    listen_addr = str(cfg.get("dnscrypt_listen", base_net["dnscrypt_listen"])).strip()
    if listen_addr in ("127.0.0.1", "::1", "localhost"):
        validated["dnscrypt_listen"] = listen_addr
    else:
        validated["dnscrypt_listen"] = "127.0.0.1"

    validated["block_doh"] = cfg_bool(cfg.get("block_doh", base_net["block_doh"]))
    validated["drop_ipv6"] = cfg_bool(cfg.get("drop_ipv6", base_net["drop_ipv6"]))
    validated["mac_randomize"] = cfg_bool(cfg.get("mac_randomize", base_net["mac_randomize"]))
    validated["mac_in_place"] = cfg_bool(cfg.get("mac_in_place", base_net["mac_in_place"]))
    validated["kill_switch"] = cfg_bool(cfg.get("kill_switch", base_net["kill_switch"]))

    validated["use_bridges"] = cfg_bool(cfg.get("use_bridges", base_net["use_bridges"]))
    bridge_type = str(cfg.get("bridge_type", base_net["bridge_type"])).strip().lower()
    if bridge_type in ("obfs4", "meek", "snowflake", "webtunnel"):
        validated["bridge_type"] = bridge_type
    else:
        validated["bridge_type"] = base_net["bridge_type"]

    custom_bridges = cfg.get("custom_bridges", base_net["custom_bridges"])
    if isinstance(custom_bridges, list):
        clean_bridges = []
        for b in custom_bridges:
            if isinstance(b, str) and 1 <= len(b.strip()) <= 512:
                clean_b = re.sub(r"[\r\n\x00]", "", b.strip())
                if clean_b:
                    clean_bridges.append(clean_b)
        validated["custom_bridges"] = clean_bridges
    else:
        validated["custom_bridges"] = list(base_net["custom_bridges"])

    exit_nodes = str(cfg.get("exit_nodes", base_net["exit_nodes"])).strip()
    clean_exit = re.sub(r"[^a-zA-Z0-9{},.~*_-]", "", exit_nodes)
    validated["exit_nodes"] = clean_exit

    validated["exclude_five_eyes"] = cfg_bool(cfg.get("exclude_five_eyes", base_net["exclude_five_eyes"]))

    try:
        auto_renew = int(cfg.get("auto_renew_interval_sec", base_net["auto_renew_interval_sec"]))
        validated["auto_renew_interval_sec"] = max(0, min(86400, auto_renew))
    except (ValueError, TypeError):
        validated["auto_renew_interval_sec"] = base_net["auto_renew_interval_sec"]

    # Arayüz desenleri listesi doğrulaması
    excluded = cfg.get("excluded_interfaces", base_net["excluded_interfaces"])
    if isinstance(excluded, list):
        clean_patterns = []
        for item in excluded:
            if isinstance(item, str) and 1 <= len(item.strip()) <= 32:
                # Tehlikeli shell karakterlerini filtrele
                clean_item = re.sub(r"[^a-zA-Z0-9_.*-]", "", item.strip())
                if clean_item:
                    clean_patterns.append(clean_item)
        validated["excluded_interfaces"] = clean_patterns
    else:
        validated["excluded_interfaces"] = list(base_net["excluded_interfaces"])

    return validated


def validate_forensics_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Adli temizlik yapılandırmasını doğrular."""
    validated: Dict[str, Any] = {}
    base_f = DEFAULT_CONFIG["forensics"]

    for key, default_val in base_f.items():
        validated[key] = cfg_bool(cfg.get(key, default_val), default_val)

    return validated


def validate_security_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Güvenlik ve USB Kill-Switch yapılandırmasını doğrular."""
    validated: Dict[str, Any] = {}
    base_sec = DEFAULT_CONFIG["security"]

    validated["usb_killswitch_enabled"] = cfg_bool(
        cfg.get("usb_killswitch_enabled", base_sec["usb_killswitch_enabled"])
    )

    dev_id = cfg.get("usb_authorized_device_id", cfg.get("usb_Authorized_device_id", base_sec["usb_authorized_device_id"]))
    if isinstance(dev_id, str):
        clean_dev = re.sub(r"[^a-zA-Z0-9:-]", "", dev_id.strip())
        validated["usb_authorized_device_id"] = clean_dev
    else:
        validated["usb_authorized_device_id"] = ""

    validated["usb_panic_shutdown"] = cfg_bool(
        cfg.get("usb_panic_shutdown", base_sec["usb_panic_shutdown"])
    )

    return validated


def validate_full_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Tüm yapılandırma sözlüğünü şema ve aralık kontrollerinden geçirir."""
    if not isinstance(cfg, dict):
        return copy.deepcopy(DEFAULT_CONFIG)

    validated = copy.deepcopy(DEFAULT_CONFIG)
    validated["version"] = str(cfg.get("version", DEFAULT_CONFIG["version"]))

    if "network" in cfg and isinstance(cfg["network"], dict):
        validated["network"] = validate_network_config(cfg["network"])

    if "forensics" in cfg and isinstance(cfg["forensics"], dict):
        validated["forensics"] = validate_forensics_config(cfg["forensics"])

    if "security" in cfg and isinstance(cfg["security"], dict):
        validated["security"] = validate_security_config(cfg["security"])

    if "daemon" in cfg and isinstance(cfg["daemon"], dict):
        daemon_cfg = cfg["daemon"]
        base_daemon = DEFAULT_CONFIG["daemon"]

        sock_path = str(daemon_cfg.get("socket_path", base_daemon["socket_path"])).strip()
        # Güvenli soket yolu kontrolü: yalnızca kök dosya sistemindeki /run/
        # altı kabul edilir. Path traversal (..) ve null bayt (\x00) kesinlikle reddedilir.
        if (
            sock_path.startswith("/run/")
            and "\x00" not in sock_path
            and ".." not in sock_path.split("/")
        ):
            validated["daemon"]["socket_path"] = sock_path
        else:
            validated["daemon"]["socket_path"] = base_daemon["socket_path"]

        validated["daemon"]["socket_group"] = re.sub(
            r"[^a-zA-Z0-9_-]", "", str(daemon_cfg.get("socket_group", base_daemon["socket_group"])).strip()
        )

        try:
            req_size = int(daemon_cfg.get("max_request_size", base_daemon["max_request_size"]))
            validated["daemon"]["max_request_size"] = max(1024, min(1048576, req_size))
        except (ValueError, TypeError):
            validated["daemon"]["max_request_size"] = base_daemon["max_request_size"]

    if "gui" in cfg and isinstance(cfg["gui"], dict):
        gui_cfg = cfg["gui"]
        base_gui = DEFAULT_CONFIG["gui"]
        theme = str(gui_cfg.get("theme", base_gui["theme"])).lower().strip()
        if theme in ("oled", "circuit", "light", "binary", "pixel"):
            validated["gui"]["theme"] = theme
        else:
            validated["gui"]["theme"] = base_gui["theme"]

        validated["gui"]["close_to_tray"] = cfg_bool(gui_cfg.get("close_to_tray", base_gui["close_to_tray"]))
        validated["gui"]["notify_on_circuit_change"] = cfg_bool(
            gui_cfg.get("notify_on_circuit_change", base_gui["notify_on_circuit_change"])
        )
        validated["gui"]["auto_leak_test_on_connect"] = cfg_bool(
            gui_cfg.get("auto_leak_test_on_connect", base_gui["auto_leak_test_on_connect"])
        )
        validated["gui"]["auto_leak_test"] = cfg_bool(
            gui_cfg.get("auto_leak_test", base_gui["auto_leak_test"])
        )
        validated["gui"]["ram_suppression"] = cfg_bool(
            gui_cfg.get("ram_suppression", base_gui["ram_suppression"])
        )

    return validated


def safe_load_config(filepath: str, fallback_to_default: bool = True) -> Dict[str, Any]:
    """Yapılandırma dosyasını sembolik bağ (symlink) ve boyut kontrolleriyle güvenle okur.

    Güvenlik Önlemleri:
      - os.O_NOFOLLOW kullanılarak sembolik bağ saldırıları engellenir.
      - Normal dosya (regular file) kontrolü yapılır (FIFO / cihaz dosyası tuzakları).
      - Dosya boyutu 1MB ile sınırlandırılır.

    Args:
        filepath: Okunacak dosyanın mutlak yolu.
        fallback_to_default: Hata durumunda varsayılan yapılandırmaya dönülsün mü.

    Returns:
        Dict[str, Any]: Doğrulanmış yapılandırma sözlüğü.

    Raises:
        OSError, ValueError: Dosya güvenli değilse veya bozuksa (fallback False ise).
    """
    if not os.path.exists(filepath):
        if fallback_to_default:
            return copy.deepcopy(DEFAULT_CONFIG)
        raise FileNotFoundError(f"Yapılandırma dosyası bulunamadı: {filepath}")

    # Sembolik bağ doğrudan reddedilir
    if os.path.islink(filepath):
        msg = f"Güvenlik İhlali: Yapılandırma dosyası bir sembolik bağ (symlink) olamaz: {filepath}"
        if fallback_to_default:
            return copy.deepcopy(DEFAULT_CONFIG)
        raise PermissionError(msg)

    # O_NOFOLLOW ve O_CLOEXEC bayrakları ile aç
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    fd = -1
    try:
        fd = os.open(filepath, flags)
        st = os.fstat(fd)

        # Normal dosya kontrolü
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Hedef yol normal bir dosya değil: {filepath}")

        # Boyut kontrolü
        if st.st_size > MAX_CONFIG_FILE_SIZE:
            raise ValueError(
                f"Yapılandırma dosyası çok büyük ({st.st_size} bayt). "
                f"İzin verilen üst sınır: {MAX_CONFIG_FILE_SIZE} bayt"
            )

        total_size = st.st_size
        chunks: List[bytes] = []
        bytes_read = 0
        while bytes_read < total_size:
            chunk = os.read(fd, min(4096, total_size - bytes_read))
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)

        content = b"".join(chunks)
        raw_text = content.decode("utf-8")
        data = json.loads(raw_text)

        # Şema doğrulama ve varsayılanlarla birleştirme
        merged = deep_merge(DEFAULT_CONFIG, data)
        return validate_full_config(merged)
    except Exception as err:
        if fallback_to_default:
            return copy.deepcopy(DEFAULT_CONFIG)
        raise RuntimeError(f"Yapılandırma dosyası güvenle okunamadı ({filepath}): {err}") from err
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def safe_save_config(
    filepath: str,
    data: Dict[str, Any],
    uid: Optional[int] = None,
    gid: Optional[int] = None,
) -> bool:
    """Yapılandırma dosyasını atomik olarak ve güvenli izinlerle (0600) diske kaydeder.

    Args:
        filepath: Kaydedilecek hedef yol.
        data: Kaydedilecek yapılandırma verisi.
        uid: Varsa atanacak kullanıcı kimliği.
        gid: Varsa atanacak grup kimliği.

    Returns:
        bool: İşlem başarılı ise True.
    """
    # Veriyi önce doğrula
    validated = validate_full_config(data)
    json_bytes = json.dumps(validated, indent=2, ensure_ascii=False).encode("utf-8")

    parent_dir = os.path.dirname(os.path.abspath(filepath))
    os.makedirs(parent_dir, mode=0o700, exist_ok=True)

    # Hedef dosya bir sembolik bağ ise ezmeyi reddet
    if os.path.islink(filepath):
        raise PermissionError(f"Hedef dosya bir sembolik bağ olamaz: {filepath}")

    tmp_file = f"{filepath}.tmp.{os.getpid()}"
    if os.path.exists(tmp_file) or os.path.islink(tmp_file):
        try:
            os.unlink(tmp_file)
        except OSError:
            pass

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    fd = -1
    try:
        # İzinleri doğrudan 0600 (sadece sahibi okuyup yazabilir) olarak aç
        fd = os.open(tmp_file, flags, 0o600)
        os.write(fd, json_bytes)
        os.fsync(fd)
        os.close(fd)
        fd = -1

        # Sahiplik ayarla (Linux üzerinde root çalışırken kullanıcıya vermek için)
        if uid is not None and gid is not None and hasattr(os, "chown"):
            try:
                os.chown(tmp_file, uid, gid)
            except (PermissionError, OSError):
                pass

        # Atomik isim değiştirme
        os.replace(tmp_file, filepath)
        return True
    except Exception as err:
        if os.path.exists(tmp_file):
            try:
                os.unlink(tmp_file)
            except OSError:
                pass
        raise RuntimeError(f"Yapılandırma güvenle kaydedilemedi ({filepath}): {err}") from err
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
