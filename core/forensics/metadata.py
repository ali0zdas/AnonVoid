"""AnonVoid - Meta Veri İmha Aracı (Metadata & Exif Sanitizer).

Bu modül; dijital fotoğraflar (JPEG, PNG), belgeler ve ofis dosyalarında bulunan
hassas meta verileri (kamera modeli, seri numarası, GPS koordinatları, oluşturma
ve düzenleme zaman damgaları, yazar ve yazılım bilgileri) temizler.

Özellikler:
  - Harici bağımlılık olmadan saf Python ile PNG (tEXt, zTXt, iTXt, eXIf, tIME) chunk temizliği.
  - Harici bağımlılık olmadan saf Python ile JPEG (APP1/EXIF, APP13/IPTC, COM) segment temizliği.
  - Sistemde mevcutsa MAT2 (Metadata Anonymisation Toolkit 2) ve ExifTool entegrasyonu.
  - Sembolik bağ (symlink) güvenlik denetimi (O_NOFOLLOW / islink).
"""

from __future__ import annotations

import logging
import os
import secrets
import shutil
import stat
import struct
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.lowlevel import sync_disks

logger = logging.getLogger("AnonVoidMetadata")


def _sanitize_png_bytes(data: bytes) -> Tuple[bytes, int, int]:
    """PNG baytlarından tEXt, zTXt, iTXt, eXIf ve tIME chunk'larını ayıklar.

    Args:
        data: Ham PNG dosya baytları.

    Returns:
        Tuple[bytes, int, int]: (Temizlenmiş baytlar, silinen chunk adedi, silinen bayt miktarı).
    """
    PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("Geçersiz PNG dosya imzası.")

    METADATA_CHUNKS = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"}
    out = bytearray(PNG_SIGNATURE)
    idx = 8
    removed_count = 0
    removed_bytes = 0
    data_len = len(data)

    while idx + 8 <= data_len:
        length = struct.unpack(">I", data[idx : idx + 4])[0]
        chunk_type = data[idx + 4 : idx + 8]
        chunk_total_len = 12 + length  # 4(uzunluk) + 4(tür) + length + 4(crc)

        if idx + chunk_total_len > data_len:
            break

        if chunk_type in METADATA_CHUNKS:
            removed_count += 1
            removed_bytes += chunk_total_len
        else:
            out.extend(data[idx : idx + chunk_total_len])

        idx += chunk_total_len
        if chunk_type == b"IEND":
            break

    return bytes(out), removed_count, removed_bytes


def _sanitize_jpeg_bytes(data: bytes) -> Tuple[bytes, int, int]:
    """JPEG baytlarından APP1 (EXIF/XMP), APP13 (IPTC) ve COM (Comment) segmentlerini ayıklar.

    Args:
        data: Ham JPEG dosya baytları.

    Returns:
        Tuple[bytes, int, int]: (Temizlenmiş baytlar, silinen segment adedi, silinen bayt miktarı).
    """
    if len(data) < 4 or data[:2] != b"\xFF\xD8":
        raise ValueError("Geçersiz JPEG SOI dosya başlığı.")

    out = bytearray(b"\xFF\xD8")
    idx = 2
    data_len = len(data)
    removed_count = 0
    removed_bytes = 0

    # EXIF (APP1 - 0xE1), IPTC (APP13 - 0xED), Yorum (COM - 0xFE)
    STRIP_MARKERS = {0xE1, 0xED, 0xFE}

    while idx < data_len:
        if data[idx] != 0xFF:
            idx += 1
            continue

        # 0xFF dolgularını atla
        while idx < data_len and data[idx] == 0xFF:
            idx += 1

        if idx >= data_len:
            break

        marker = data[idx]
        idx += 1

        if marker == 0x00:
            out.extend(b"\xFF\x00")
            continue

        if marker == 0xD9:  # EOI (Dosya sonu)
            out.extend(b"\xFF\xD9")
            break

        if 0xD0 <= marker <= 0xD7 or marker == 0x01:  # Restart işaretçileri
            out.extend(bytes([0xFF, marker]))
            continue

        if marker == 0xDA:  # SOS (Start of Scan) - Görüntü verisi başlangıcı
            out.extend(bytes([0xFF, marker]))
            out.extend(data[idx:])
            break

        if idx + 2 > data_len:
            break

        seg_len = struct.unpack(">H", data[idx : idx + 2])[0]
        if seg_len < 2 or (idx + seg_len) > data_len:
            break

        if marker in STRIP_MARKERS:
            removed_count += 1
            removed_bytes += 2 + seg_len
        else:
            out.extend(bytes([0xFF, marker]))
            out.extend(data[idx : idx + seg_len])

        idx += seg_len

    return bytes(out), removed_count, removed_bytes


def _write_atomic(filepath: str, cleaned_data: bytes) -> bool:
    """Temizlenen veriyi hedef dosyaya atomik ve güvenli biçimde yazar."""
    parent_dir = os.path.dirname(os.path.abspath(filepath))
    random_suffix = secrets.token_hex(8)
    tmp_path = os.path.join(parent_dir, f".void_meta_{random_suffix}.tmp")

    try:
        # Orijinal izinleri al
        orig_stat = os.stat(filepath)

        # O_NOFOLLOW bayrağı ile sembolik bağ saldırısını önle
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC

        fd = os.open(tmp_path, flags, orig_stat.st_mode)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(cleaned_data)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

        # Dosya sahipliğini ve izinlerini eşitle
        if hasattr(os, "chown"):
            try:
                os.chown(tmp_path, orig_stat.st_uid, orig_stat.st_gid)
            except OSError:
                pass

        os.replace(tmp_path, filepath)
        sync_disks()
        return True

    except Exception as err:
        logger.error("Atomik dosya yazma hatası (%s): %s", filepath, err)
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return False


def sanitize_file_metadata(filepath: str) -> Dict[str, Any]:
    """Tek bir dosyanın meta verilerini güvenle temizler.

    Dosya türüne göre saf Python ayrıştırıcı (PNG/JPEG) veya sistemdeki
    MAT2 / ExifTool araçlarını kullanır.

    Args:
        filepath: Temizlenecek dosyanın mutlak yolu.

    Returns:
        Dict[str, Any]: İşlem özeti ve sonuç raporu.
    """
    result: Dict[str, Any] = {
        "success": False,
        "file": filepath,
        "method": "none",
        "bytes_reduced": 0,
        "tags_or_chunks_removed": 0,
        "error": None,
    }

    if not os.path.exists(filepath):
        result["error"] = "Dosya bulunamadı."
        return result

    # Sembolik bağ güvenlik denetimi
    if os.path.islink(filepath):
        result["error"] = "Güvenlik kuralı: Sembolik bağlar (symlink) meta veri temizliğine tabi tutulamaz."
        return result

    if not os.path.isfile(filepath):
        result["error"] = "Yalnızca normal dosyalar işlenebilir."
        return result

    ext = os.path.splitext(filepath)[1].lower()
    orig_size = os.path.getsize(filepath)

    try:
        # 1. Saf Python PNG Ayrıştırıcı
        if ext == ".png":
            with open(filepath, "rb") as f:
                data = f.read()

            cleaned, count, bytes_stripped = _sanitize_png_bytes(data)
            if count > 0:
                if _write_atomic(filepath, cleaned):
                    result["success"] = True
                    result["method"] = "pure_python_png"
                    result["bytes_reduced"] = max(0, orig_size - len(cleaned))
                    result["tags_or_chunks_removed"] = count
                    logger.info("PNG meta verileri temizlendi: %s (Chunk: %d)", filepath, count)
                    return result
                else:
                    result["error"] = "Temizlenen PNG diske yazılamadı."
                    return result
            else:
                result["success"] = True
                result["method"] = "pure_python_png"
                result["tags_or_chunks_removed"] = 0
                logger.info("PNG dosyasında temizlenecek meta veri bulunamadı: %s", filepath)
                return result

        # 2. Saf Python JPEG Ayrıştırıcı
        elif ext in (".jpg", ".jpeg"):
            with open(filepath, "rb") as f:
                data = f.read()

            cleaned, count, bytes_stripped = _sanitize_jpeg_bytes(data)
            if count > 0:
                if _write_atomic(filepath, cleaned):
                    result["success"] = True
                    result["method"] = "pure_python_jpeg"
                    result["bytes_reduced"] = max(0, orig_size - len(cleaned))
                    result["tags_or_chunks_removed"] = count
                    logger.info("JPEG EXIF/IPTC meta verileri temizlendi: %s (Segment: %d)", filepath, count)
                    return result
                else:
                    result["error"] = "Temizlenen JPEG diske yazılamadı."
                    return result
            else:
                result["success"] = True
                result["method"] = "pure_python_jpeg"
                result["tags_or_chunks_removed"] = 0
                logger.info("JPEG dosyasında temizlenecek meta veri bulunamadı: %s", filepath)
                return result

        # 3. PDF, Ofis Belgeleri veya Diğer Dosyalar için MAT2 / ExifTool
        has_mat2 = shutil.which("mat2") is not None
        has_exiftool = shutil.which("exiftool") is not None

        if has_mat2:
            try:
                proc = subprocess.run(
                    ["mat2", "--inplace", filepath],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if proc.returncode == 0:
                    new_size = os.path.getsize(filepath) if os.path.exists(filepath) else orig_size
                    result["success"] = True
                    result["method"] = "mat2"
                    result["bytes_reduced"] = max(0, orig_size - new_size)
                    logger.info("MAT2 ile meta veri temizlendi: %s", filepath)
                    return result
            except Exception as mat_err:
                logger.debug("MAT2 çalıştırma hatası: %s", mat_err)

        if has_exiftool:
            try:
                proc = subprocess.run(
                    ["exiftool", "-all=", "-overwrite_original", filepath],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if proc.returncode == 0:
                    new_size = os.path.getsize(filepath) if os.path.exists(filepath) else orig_size
                    result["success"] = True
                    result["method"] = "exiftool"
                    result["bytes_reduced"] = max(0, orig_size - new_size)
                    logger.info("ExifTool ile meta veri temizlendi: %s", filepath)
                    return result
            except Exception as exif_err:
                logger.debug("ExifTool çalıştırma hatası: %s", exif_err)

        result["error"] = (
            f"'{ext}' formatı için sistemde uygun temizleyici (mat2 veya exiftool) bulunamadı."
        )
        return result

    except Exception as err:
        result["error"] = f"Meta veri temizlenirken hata oluştu: {err}"
        logger.error("Meta veri temizleme hatası (%s): %s", filepath, err)
        return result


def sanitize_directory_metadata(
    dirpath: str,
    recursive: bool = True,
    allowed_extensions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Bir dizindeki tüm dosyaların meta verilerini güvenle temizler.

    Sembolik bağları ve özel dosyaları atlar; yalnızca normal dosyaları işler.

    Args:
        dirpath: Taranacak dizin yolu.
        recursive: Alt dizinlerin taranıp taranmayacağı.
        allowed_extensions: İsteğe bağlı dosya uzantı filtresi (örn: ['.png', '.jpg', '.pdf']).

    Returns:
        Dict[str, Any]: Toplu işlem istatistikleri.
    """
    logger.info("Dizin meta veri temizliği başlatılıyor: %s", dirpath)
    report: Dict[str, Any] = {
        "success": False,
        "total_files": 0,
        "sanitized_files": 0,
        "skipped_files": 0,
        "total_bytes_reduced": 0,
        "errors": [],
        "results": [],
    }

    if not os.path.isdir(dirpath):
        report["errors"].append(f"Dizin bulunamadı: {dirpath}")
        return report

    valid_exts = set(allowed_extensions) if allowed_extensions else None

    for root, dirs, files in os.walk(dirpath):
        if not recursive and root != dirpath:
            break

        for filename in files:
            file_path = os.path.join(root, filename)

            # Sembolik bağları atla
            if os.path.islink(file_path):
                report["skipped_files"] += 1
                continue

            if valid_exts:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in valid_exts:
                    continue

            report["total_files"] += 1
            res = sanitize_file_metadata(file_path)
            report["results"].append(res)

            if res["success"]:
                report["sanitized_files"] += 1
                report["total_bytes_reduced"] += res.get("bytes_reduced", 0)
            else:
                if res.get("error"):
                    report["errors"].append(f"{file_path}: {res['error']}")

    report["success"] = len(report["errors"]) == 0
    sync_disks()
    return report
