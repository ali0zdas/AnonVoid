"""AnonVoid - C-Seviyesi Düşük Düzey Bellek ve Disk Hijyeni Modülü.

Bu modül; ctypes aracılığıyla doğrudan Linux C standart kütüphanesine (libc.so.6) bağlanarak
bellek sıfırlama (memset / explicit_bzero), swap'e yazılmayı engelleme (mlock / mlockall),
süreç bellek dökümü ve ptrace engelleme (prctl / RLIMIT_CORE), disk tamponlarını fiziksel
diske zorlama (sync) ve güvenli dosya ezme (shred) işlemlerini yürütür.
"""

from __future__ import annotations

import ctypes
import logging
import os
import secrets
import stat
import string
import sys
from typing import Any, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

logger = logging.getLogger("AnonVoidLowLevel")

# Linux libc kütüphanesi bağlantısı
_libc: Optional[ctypes.CDLL] = None
_has_explicit_bzero = False

if sys.platform.startswith("linux"):
    try:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # 64-bit mimarilerde pointer kesilmesini (pointer truncation) önlemek için argtypes ve restype tanımla
        if hasattr(_libc, "explicit_bzero"):
            _libc.explicit_bzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            _libc.explicit_bzero.restype = None
            _has_explicit_bzero = True

        if hasattr(_libc, "memset"):
            _libc.memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
            _libc.memset.restype = ctypes.c_void_p

        if hasattr(_libc, "mlockall"):
            _libc.mlockall.argtypes = [ctypes.c_int]
            _libc.mlockall.restype = ctypes.c_int

        if hasattr(_libc, "munlockall"):
            _libc.munlockall.argtypes = []
            _libc.munlockall.restype = ctypes.c_int

        if hasattr(_libc, "sync"):
            _libc.sync.argtypes = []
            _libc.sync.restype = None

        if hasattr(_libc, "prctl"):
            _libc.prctl.argtypes = [
                ctypes.c_int,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            _libc.prctl.restype = ctypes.c_int

    except (OSError, AttributeError) as err:
        logger.warning("libc.so.6 kütüphanesine bağlanılamadı: %s", err)
        _libc = None


def secure_zero_memory(target: Any, length: int) -> bool:
    """Verilen bellek bloğunu C seviyesinde sıfırlar.

    Derleyicinin veya yorumlayıcının işlemi optimize edip atlamasını önlemek için
    mümkünse explicit_bzero, aksi halde memset kullanılır.

    str veya bytes gibi immutable nesneler geldiğinde TypeError vermesini
    önler (bytearray veya memoryview kontrolü yapar; bytes ise ctypes üzerinden
    sıfırlamayı dener).

    Args:
        target: Bellek adresi (int), ctypes işaretçisi/dizisi, bytearray, bytes veya memoryview.
        length: Sıfırlanacak bayt uzunluğu.

    Returns:
        bool: İşlem başarılı ise True.
    """
    if length <= 0:
        return True

    # 1. C kütüphanesi ile doğrudan sıfırlama (explicit_bzero / memset)
    if _libc is not None:
        try:
            ptr: Optional[ctypes.c_void_p] = None

            if isinstance(target, int):
                ptr = ctypes.c_void_p(target)
            elif isinstance(target, bytearray):
                c_arr = (ctypes.c_char * len(target)).from_buffer(target)
                ptr = ctypes.cast(c_arr, ctypes.c_void_p)
            elif isinstance(target, memoryview):
                if target.readonly:
                    logger.debug("Salt-okunur memoryview C seviyesinde sıfırlanamaz.")
                    return False
                c_arr = (ctypes.c_char * len(target)).from_buffer(target)
                ptr = ctypes.cast(c_arr, ctypes.c_void_p)
            elif isinstance(target, bytes):
                # bytes nesnesinin dahili tampon adresini char işaretçisi olarak al
                ptr = ctypes.cast(ctypes.c_char_p(target), ctypes.c_void_p)
            else:
                ptr = ctypes.cast(target, ctypes.c_void_p)

            if ptr is not None:
                c_len = ctypes.c_size_t(length)
                if _has_explicit_bzero and hasattr(_libc, "explicit_bzero"):
                    _libc.explicit_bzero(ptr, c_len)
                elif hasattr(_libc, "memset"):
                    _libc.memset(ptr, 0, c_len)
                return True
        except Exception as err:
            logger.debug("C bellek sıfırlama denenirken istisna oluştu: %s", err)

    # 2. Python Seviyesinde Güvenli Fallback
    if isinstance(target, bytearray):
        for i in range(min(len(target), length)):
            target[i] = 0
        return True

    if isinstance(target, memoryview):
        if not target.readonly:
            try:
                for i in range(min(len(target), length)):
                    target[i] = 0
                return True
            except TypeError:
                return False
        return False

    # str veya bytes immutable nesnedir; Python seviyesinde doğrudan indeks ataması yapılamaz
    if isinstance(target, (str, bytes)):
        return False

    try:
        # ctypes array kontrolü (yalnızca değiştirilebilir nesneler için)
        for i in range(min(len(target), length)):
            target[i] = 0
        return True
    except (TypeError, Exception):
        pass

    return False


def secure_wipe_bytearray(data: bytearray) -> None:
    """Python bytearray nesnesinin bellekteki içeriğini C seviyesinde sıfırlar."""
    if not isinstance(data, bytearray) or len(data) == 0:
        return

    buf_len = len(data)
    cleared = False
    if _libc is not None:
        try:
            c_arr = (ctypes.c_char * buf_len).from_buffer(data)
            cleared = secure_zero_memory(c_arr, buf_len)
        except (BufferError, TypeError, Exception):
            cleared = False

    if not cleared:
        for i in range(buf_len):
            data[i] = 0


def disable_coredumps_and_ptrace() -> bool:
    """Linux üzerinde süreç bellek dökümlerini (core dump) ve ptrace izlemesini engeller.

    Güvenlik Adımları:
      1. resource.setrlimit(resource.RLIMIT_CORE, (0, 0)) ile core dump dosya boyutu sıfırlanır.
      2. prctl(PR_SET_DUMPABLE, 0) ile sürecin bellek dökümü ve root dışı ptrace izlemesi kapatılır.

    Returns:
        bool: Linux üzerinde başarıyla uygulandıysa True, Windows veya hata durumunda False.
    """
    if not sys.platform.startswith("linux"):
        return False

    success = True
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        logger.info("RLIMIT_CORE başarıyla (0, 0) olarak sınırlandırıldı.")
    except Exception as err:
        logger.warning("RLIMIT_CORE sınırlandırılamadı: %s", err)
        success = False

    PR_SET_DUMPABLE = 4  # Linux sys/prctl.h sabiti
    if _libc is not None and hasattr(_libc, "prctl"):
        try:
            ret = _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
            if ret == 0:
                logger.info("prctl(PR_SET_DUMPABLE, 0) başarıyla uygulandı; bellek dökümü ve ptrace engellendi.")
            else:
                logger.warning("prctl(PR_SET_DUMPABLE, 0) başarısız oldu (çıkış kodu: %d).", ret)
                success = False
        except Exception as err:
            logger.warning("prctl çağrısı başarısız oldu: %s", err)
            success = False
    else:
        success = False

    return success


def lock_process_memory() -> bool:
    """RAM'deki süreç verilerinin takas (swap) alanına yazılmasını engeller (mlockall).

    MCL_CURRENT (1): Şu anda ayrılmış tüm sayfaları kilitler.
    MCL_FUTURE (2): Gelecekte ayrılacak tüm sayfaları kilitler.

    Returns:
        bool: Başarılı ise True, yetki yetersizse False.
    """
    if _libc is not None and hasattr(_libc, "mlockall"):
        MCL_CURRENT = 1
        MCL_FUTURE = 2
        flags = MCL_CURRENT | MCL_FUTURE
        ret = _libc.mlockall(ctypes.c_int(flags))
        if ret == 0:
            logger.info("mlockall başarıyla uygulandı; süreç belleği swap'e kilitlendi.")
            return True
        errno = ctypes.get_errno()
        logger.warning("mlockall çağrısı başarısız oldu (errno: %d). Root yetkisi gerekebilir.", errno)
        return False
    return False


def unlock_process_memory() -> bool:
    """Süreç belleği üzerindeki swap kilidini kaldırır (munlockall)."""
    if _libc is not None and hasattr(_libc, "munlockall"):
        ret = _libc.munlockall()
        return ret == 0
    return False


def sync_disks() -> None:
    """Tüm işletim sistemi disk tamponlarını (page cache) fiziksel diske zorlar (sync)."""
    if _libc is not None and hasattr(_libc, "sync"):
        _libc.sync()
    else:
        try:
            if hasattr(os, "sync"):
                os.sync()
        except (AttributeError, OSError):
            pass


def shred_file(
    filepath: str,
    passes: int = 1,
    zero_fill: bool = True,
    remove_after: bool = True,
) -> bool:
    """Bir dosyayı rastgele verilerle ezerek, boyutunu sıfırlayıp güvenle siler.

    Güvenlik Adımları:
      1. Sembolik bağlar (symlink) tespit edilir ve ezilmeden reddedilir (O_NOFOLLOW).
      2. Normal bir dosya olup olmadığı (S_ISREG) doğrulanır (FIFO/cihaz tuzaklarını önler).
      3. Dosya boyutunca os.urandom ile üzerine 'passes' tur yazılır.
      4. İsteğe bağlı olarak son turda tüm dosya sıfır baytlarla (0x00) ezilir.
      5. Dosya ftruncate(0) ile 0 bayt boyutuna çekilir.
      6. sync_disks() çağrılarak disk kontrolcüsünün önbelleği diske yazması zorlanır.
      7. Dosya silinmeden önce dosya adı aynı dizinde rastgele ASCII karakterlerle
         yeniden adlandırılır (Filename Scrambling - dizin indekslerinde eski ad kalmaz).
      8. Dosya os.unlink ile dosya sisteminden kaldırılır.

    Args:
        filepath: Ezilecek dosyanın mutlak yolu.
        passes: Rastgele veriyle üzerine yazma tur sayısı.
        zero_fill: Silmeden önce son turda sıfır yazılıp yazılmayacağı.
        remove_after: Ezme sonrası dosyanın silinip silinmeyeceği.

    Returns:
        bool: İşlem başarılı ise True.
    """
    if not os.path.exists(filepath):
        return False

    # Sembolik bağ saldırılarına karşı mutlak koruma
    if os.path.islink(filepath):
        logger.warning("Güvenlik Uyarısı: Sembolik bağ ezilmeyecek, doğrudan silinecek: %s", filepath)
        try:
            os.unlink(filepath)
            return True
        except OSError:
            return False

    flags = os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    fd = -1
    try:
        fd = os.open(filepath, flags)
        st = os.fstat(fd)

        # Cihaz veya FIFO gibi özel dosyaları ezmeye çalışma
        if not stat.S_ISREG(st.st_mode):
            logger.warning("Özel dosya türü ezilemez: %s", filepath)
            return False

        file_size = st.st_size

        if file_size > 0:
            chunk_size = 65536  # 64 KB bloklar
            # 1. Tur(lar): Rastgele baytlar ile üzerine yaz
            for _ in range(max(1, passes)):
                os.lseek(fd, 0, os.SEEK_SET)
                bytes_left = file_size
                while bytes_left > 0:
                    current_write = min(bytes_left, chunk_size)
                    random_bytes = os.urandom(current_write)
                    os.write(fd, random_bytes)
                    bytes_left -= current_write
                os.fsync(fd)

            # 2. Tur: Sıfır baytlar (0x00) ile ezme
            if zero_fill:
                os.lseek(fd, 0, os.SEEK_SET)
                zero_chunk = b"\x00" * chunk_size
                bytes_left = file_size
                while bytes_left > 0:
                    current_write = min(bytes_left, chunk_size)
                    os.write(fd, zero_chunk[:current_write])
                    bytes_left -= current_write
                os.fsync(fd)

        # 3. Dosya boyutunu sıfıra çek (truncate)
        os.ftruncate(fd, 0)
        os.fsync(fd)
        os.close(fd)
        fd = -1

        # 4. Donanım tamponlarını zorla
        sync_disks()

        # 5. Dosyayı kaldır (Filename Scrambling ile adli dosya adı kalıntısını yok et)
        if remove_after:
            target_to_unlink = filepath
            try:
                parent_dir = os.path.dirname(os.path.abspath(filepath))
                random_name = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
                scrambled_path = os.path.join(parent_dir, f".void_{random_name}.tmp")
                os.rename(filepath, scrambled_path)
                target_to_unlink = scrambled_path
            except Exception as rename_err:
                logger.debug("Dosya adı karıştırma (scrambling) uygulanamadı, doğrudan siliniyor: %s", rename_err)
                target_to_unlink = filepath

            try:
                os.unlink(target_to_unlink)
            except OSError as unlink_err:
                logger.error("Dosya silinemedi (%s): %s", target_to_unlink, unlink_err)
                return False

        return True

    except Exception as err:
        logger.error("Dosya güvenle ezilemedi (%s): %s", filepath, err)
        return False
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
