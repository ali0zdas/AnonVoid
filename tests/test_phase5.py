#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonVoid — Faz 5: Paketleme, Kurulum ve Dağıtım Doğrulama Testleri
"""

import sys
import os
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

# Bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Proje kök dizinini ekle
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from packaging.build_nuitka import build_nuitka_command, check_nuitka_installed


class TestPhase5Packaging(unittest.TestCase):
    """Faz 5 paketleme, kurulum ve dağıtım bileşenleri testleri."""

    def test_01_install_script_integrity(self):
        """install.sh kurulum ve kaldırma betiği bütünlük ve mantık kontrolü."""
        install_sh = PROJECT_ROOT / "install.sh"
        self.assertTrue(install_sh.is_file(), "install.sh dosyası mevcut olmalıdır")

        content = install_sh.read_text(encoding="utf-8")
        self.assertIn("#!/usr/bin/env bash", content)
        self.assertIn("set -euo pipefail", content)
        self.assertIn("INSTALL_DIR=\"/opt/anonvoid\"", content)
        self.assertIn("GROUP_NAME=\"anonvoid\"", content)
        self.assertIn("--uninstall", content, "Kaldırma parametresi mevcut olmalıdır")
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", content, "Bytecode engelleme zorunludur")
        self.assertIn("debian|ubuntu|kali", content, "Debian türevleri desteklenmelidir")
        self.assertIn("arch|manjaro", content, "Arch Linux türevleri desteklenmelidir")
        self.assertIn("fedora|rhel", content, "Fedora/RHEL türevleri desteklenmelidir")
        self.assertIn("opensuse", content, "openSUSE türevleri desteklenmelidir")

    def test_02_systemd_service_integrity(self):
        """anonvoid.service systemd ünite dosyası standart uyumluluğu."""
        service_file = PROJECT_ROOT / "packaging" / "systemd" / "anonvoid.service"
        if not service_file.is_file():
            service_file = PROJECT_ROOT / "packaging" / "systemd" / "fp-cleaner.service"
        self.assertTrue(service_file.is_file(), "Systemd servis ünitesi mevcut olmalıdır")

        content = service_file.read_text(encoding="utf-8")
        self.assertIn("[Unit]", content)
        self.assertIn("[Service]", content)
        self.assertIn("[Install]", content)
        self.assertIn("User=root", content)
        self.assertIn("RuntimeDirectory=anonvoid", content)
        self.assertIn("Environment=PYTHONDONTWRITEBYTECODE=1", content)
        self.assertIn("WantedBy=multi-user.target", content)

    def test_03_desktop_entry_and_icon(self):
        """XDG desktop kısayolu ve SVG simgesi doğrulaması."""
        desktop_file = PROJECT_ROOT / "packaging" / "desktop" / "anonvoid.desktop"
        if not desktop_file.is_file():
            desktop_file = PROJECT_ROOT / "packaging" / "desktop" / "fp-cleaner.desktop"

        svg_file = PROJECT_ROOT / "packaging" / "desktop" / "anonvoid.svg"
        if not svg_file.is_file():
            svg_file = PROJECT_ROOT / "packaging" / "desktop" / "fp-cleaner.svg"

        self.assertTrue(desktop_file.is_file(), "Desktop dosyası mevcut olmalıdır")
        self.assertTrue(svg_file.is_file(), "SVG ikon dosyası mevcut olmalıdır")

        # Desktop içeriği
        d_content = desktop_file.read_text(encoding="utf-8")
        self.assertIn("[Desktop Entry]", d_content)
        self.assertIn("Type=Application", d_content)
        self.assertIn("Name=AnonVoid", d_content)
        self.assertIn("Exec=anonvoid", d_content)
        self.assertIn("Icon=anonvoid", d_content)
        self.assertIn("Categories=", d_content)
        self.assertIn("Security;", d_content)
        self.assertIn("System;", d_content)

        # SVG XML geçerliliği
        svg_tree = ET.parse(svg_file)
        root = svg_tree.getroot()
        self.assertTrue(root.tag.endswith("svg"), "Kök etiket svg olmalıdır")
        self.assertIn("viewBox", root.attrib, "SVG viewBox özelliğine sahip olmalıdır")

    def test_04_nuitka_pipeline(self):
        """Nuitka derleme boru hattı komut oluşturucu testi."""
        main_py = PROJECT_ROOT / "main.py"
        dist_dir = PROJECT_ROOT / "dist"

        cmd_onefile = build_nuitka_command(main_py, dist_dir, onefile=True, lto=True)
        self.assertIn("--onefile", cmd_onefile)
        self.assertIn("--enable-plugin=pyqt6", cmd_onefile)
        self.assertIn("--include-package=core", cmd_onefile)
        self.assertIn("--include-package=gui", cmd_onefile)
        self.assertIn("--output-filename=anonvoid", cmd_onefile)
        self.assertIn("--lto=yes", cmd_onefile)

        cmd_standalone = build_nuitka_command(main_py, dist_dir, onefile=False, lto=False)
        self.assertNotIn("--onefile", cmd_standalone)
        self.assertNotIn("--lto=yes", cmd_standalone)
        self.assertIn("--standalone", cmd_standalone)

    def test_05_appimage_structure(self):
        """AppImage AppRun ve build_appimage.sh bileşenleri testi."""
        apprun = PROJECT_ROOT / "packaging" / "appimage" / "AppRun"
        build_sh = PROJECT_ROOT / "packaging" / "appimage" / "build_appimage.sh"

        self.assertTrue(apprun.is_file(), "AppRun dosyası mevcut olmalıdır")
        self.assertTrue(build_sh.is_file(), "build_appimage.sh mevcut olmalıdır")

        apprun_content = apprun.read_text(encoding="utf-8")
        self.assertIn("APPDIR", apprun_content)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", apprun_content)
        self.assertIn("exec", apprun_content)

        build_content = build_sh.read_text(encoding="utf-8")
        self.assertIn("AppDir", build_content)
        self.assertIn("appimagetool", build_content)
        self.assertIn(".AppImage", build_content)

    def test_06_arch_aur_packaging(self):
        """Arch Linux PKGBUILD ve install kancaları kontrolü."""
        pkgbuild = PROJECT_ROOT / "packaging" / "arch" / "PKGBUILD"
        install_hook = PROJECT_ROOT / "packaging" / "arch" / "anonvoid.install"
        if not install_hook.is_file():
            install_hook = PROJECT_ROOT / "packaging" / "arch" / "fp-cleaner.install"

        self.assertTrue(pkgbuild.is_file(), "PKGBUILD mevcut olmalıdır")
        self.assertTrue(install_hook.is_file(), "install kancası mevcut olmalıdır")

        pkg_content = pkgbuild.read_text(encoding="utf-8")
        self.assertIn("pkgname=anonvoid", pkg_content)
        self.assertIn("pkgver=1.0.0", pkg_content)
        self.assertIn("python-pyqt6", pkg_content)
        self.assertIn("package()", pkg_content)
        self.assertIn("/opt/anonvoid", pkg_content)

        hook_content = install_hook.read_text(encoding="utf-8")
        self.assertIn("post_install()", hook_content)
        self.assertIn("groupadd -r anonvoid", hook_content)
        self.assertIn("pre_remove()", hook_content)

    def test_07_debian_packaging(self):
        """Debian control, postinst, prerm, postrm ve build_deb.sh kontrolü."""
        deb_dir = PROJECT_ROOT / "packaging" / "debian"
        control = deb_dir / "control"
        postinst = deb_dir / "postinst"
        prerm = deb_dir / "prerm"
        postrm = deb_dir / "postrm"
        build_deb = deb_dir / "build_deb.sh"

        for file_path in (control, postinst, prerm, postrm, build_deb):
            self.assertTrue(file_path.is_file(), f"{file_path.name} mevcut olmalıdır")

        control_content = control.read_text(encoding="utf-8")
        self.assertIn("Package: anonvoid", control_content)
        self.assertIn("python3-pyqt6", control_content)
        self.assertIn("Architecture: all", control_content)

        postinst_content = postinst.read_text(encoding="utf-8")
        self.assertIn("anonvoid", postinst_content)
        self.assertIn("systemctl enable", postinst_content)

        prerm_content = prerm.read_text(encoding="utf-8")
        self.assertIn("systemctl stop", prerm_content)

        build_content = build_deb.read_text(encoding="utf-8")
        self.assertIn("dpkg-deb", build_content)
        self.assertIn(".deb", build_content)


if __name__ == "__main__":
    unittest.main()
