"""AnonVoid - C-Seviyesi Düşük Düzey Bellek ve Disk Hijyeni Modülü.

Bu modül; ctypes aracılığıyla doğrudan Linux C standart kütüphanesine (libc.so.6) bağlanarak
bellek sıfırlama (memset / explicit_bzero), swap'e yazılmayı engelleme (mlock / mlockall),
disk tamponlarını fiziksel diske zorlama (sync) ve güvenli dosya ezme (shred) işlemlerini yürütür.
"""

from __future__ import annotations

import ctypes
import logging
import os
import stat
import sys
from typing import Any, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

logger = logging.getLogger("FPCleanerLowLevel")

# Linux libc kütüphanesi bağlantısı
_libc: Optional[ctypes.CDLL] = None
_has_explicit_bzero = False

if sys.platform.startswith("linux"):
    try:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # explicit_bzero (glibc 2.25+) derleyici optimizasyonları tarafından silinemez
        if hasattr(_libc, "explicit_bzero"):
            _has_explicit_bzero = True
    except (OSError, AttributeError) as err:
        logger.warning("libc.so.6 kütüphanesine bağlanılamadı: %s", err)
        _libc = None


def secure_zero_memory(target: Any, length: int) -> bool:
    """Verilen bellek bloğunu C seviyesinde sıfırlar.

    Derleyicinin veya yorumlayıcının işlemi optimize edip atlamasını önlemek için
    mümkünse explicit_bzero, aksi halde memset kullanılır.

    Args:
        target: Bellek adresi (int) veya ctypes işaretçisi/dizisi.
        length: Sıfırlanacak bayt uzunluğu.

    Returns:
        bool: İşlem başarılı ise True.
    """
    if length <= 0:
        return True

    if _libc is not None:
        try:
            if isinstance(target, int):
                ptr = ctypes.c_void_p(target)
            else:
                ptr = ctypes.cast(target, ctypes.c_void_p)

            c_len = ctypes.c_size_t(length)

            if _has_explicit_bzero and hasattr(_libc, "explicit_bzero"):
                _libc.explicit_bzero(ptr, c_len)
            elif hasattr(_libc, "memset"):
                _libc.memset(ptr, 0, c_len)
            return True
        except Exception as err:
            logger.error("C bellek sıfırlama hatası: %s", err)

    # Fallback: Python veya ctypes array seviyesinde yerinde sıfırla
    if isinstance(target, bytearray):
        for i in range(min(len(target), length)):
            target[i] = 0
        return True

    try:
        # ctypes array kontrolü
        for i in range(min(len(target), length)):
            target[i] = b"\x00" if isinstance(target[0], (bytes, str)) else 0
        return True
    except Exception:
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
      5. Dosya truncate(0) ile 0 bayt boyutuna çekilir.
      6. sync_disks() çağrılarak disk kontrolcüsünün önbelleği diske yazması zorlanır.
      7. Dosya os.unlink ile dosya sisteminden kaldırılır.

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

        # 5. Dosyayı kaldır
        if remove_after:
            os.unlink(filepath)

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
