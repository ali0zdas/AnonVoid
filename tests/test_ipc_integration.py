"""AnonVoid - Faz 1 IPC Uçtan Uca Entegrasyon Testi.

Daemon ve DaemonClient arasındaki gerçek soket iletişimini, JSON serileştirmesini,
zaman aşımı ve hata mekanizmalarını doğrular.
"""

from __future__ import annotations

import os
import sys
try:
    import grp
except ImportError:
    grp = None
import tempfile
import threading
import time
import unittest
from unittest import mock

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.daemon import RootDaemon
from core.daemon_client import (
    DaemonClient,
    DaemonConnectionError,
    DaemonResponseError,
)

import socket

HAS_AF_UNIX = hasattr(socket, "AF_UNIX") and hasattr(os, "getgid") and grp is not None


def secure_tmpdir() -> tempfile.TemporaryDirectory:
    """Güvenli, kullanıcıya özel geçici dizin üretir.

    AGENTS.md gereği herkese yazılabilir /tmp kullanılmaz; sembolik bağ ve FIFO
    saldırılarına karşı $XDG_RUNTIME_DIR (0700) tercih edilir.
    """
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir and os.path.isdir(runtime_dir) and os.access(runtime_dir, os.W_OK):
        return tempfile.TemporaryDirectory(prefix="anonvoid-test-", dir=runtime_dir)
    fallback = os.path.expanduser("~/.cache/anonvoid/test-tmp")
    os.makedirs(fallback, mode=0o700, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix="anonvoid-test-", dir=fallback)


def current_primary_group() -> str:
    """Testi çalıştıran kullanıcının birincil grup adını döndürür."""
    if grp is None or not hasattr(os, "getgid"):
        return "root"
    return grp.getgrgid(os.getgid()).gr_name


@unittest.skipUnless(HAS_AF_UNIX, "Bu platformda AF_UNIX soket desteği bulunmuyor.")
class TestIPCIntegration(unittest.TestCase):
    """Daemon ve DaemonClient tam entegrasyon testleri."""

    def setUp(self):
        self.tmpdir = secure_tmpdir()
        self.sock_path = os.path.join(self.tmpdir.name, "test_daemon.sock")
        self.daemon = RootDaemon(
            socket_path=self.sock_path,
            socket_group=current_primary_group(),
        )
        self.daemon_thread = threading.Thread(target=self.daemon.start, daemon=True)
        self.daemon_thread.start()

        # Daemon'ın soketi açmasını bekle
        start_wait = time.time()
        while not os.path.exists(self.sock_path) and time.time() - start_wait < 3.0:
            time.sleep(0.05)

        if not os.path.exists(self.sock_path):
            self.fail(f"Daemon soketi açılmadı: {self.sock_path}")

        self.client = DaemonClient(socket_path=self.sock_path)

    def tearDown(self):
        self.daemon.stop()
        self.daemon_thread.join(timeout=2.0)
        self.tmpdir.cleanup()

    def test_ping_pong(self):
        """İstemcinin daemon'a ping atıp pong yanıtı aldığını doğrular."""
        self.assertTrue(self.client.is_daemon_alive(timeout=2.0))
        resp = self.client.ping()
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["data"]["message"], "pong")

    def test_get_status(self):
        """Daemon durum raporunun doğru alındığını test eder."""
        resp = self.client.get_status()
        self.assertEqual(resp["status"], "ok")
        self.assertIn("uptime_sec", resp["data"])
        self.assertFalse(resp["data"]["network_shield_active"])

    def test_connect_refused_when_tor_not_verified(self):
        """Tor doğrulanamıyorsa kill-switch KURULMAMALIDIR.

        Regresyon testi. nftables kural seti tüm giden TCP trafiğini Tor
        TransPort'a yönlendirir ("kill-switch"). Tor çalışmazken bu kural,
        sistemin bütün internet erişimini ve o anda açık olan her bağlantıyı
        düşürür; kullanıcı "bağlantım gitti", geliştirici ajanı da yarım
        kalan görevler yaşar.

        Bu yüzden emin olunamayan durum "hazır" kabul edilmemeli ve güvenlik
        duvarına hiç dokunulmamalıdır.
        """
        not_ready = {
            "ready": False,
            "reason": "Tor kontrol portundan bootstrap durumu okunamadı.",
            "bootstrap_percent": None,
            "process_running": True,
            "socks_port": 9050,
        }

        net_cfg = {"tor_enabled": True, "tor_socks_port": 9050, "mac_randomize": False}
        with (
            mock.patch("core.daemon.is_tor_running_service", return_value=True),
            mock.patch("core.daemon.wait_for_tor_ready", return_value=not_ready),
            mock.patch.object(self.daemon.tor_manager, "configure_and_reload", return_value=True),
            mock.patch.object(self.daemon.firewall, "apply_rules", return_value=True) as mock_rules,
            mock.patch.object(self.daemon.dnscrypt_manager, "apply_dns_lock", return_value={"success": True}),
        ):
            resp = self.client.connect_network(net_cfg)

        self.assertEqual(resp["status"], "ok")
        data = resp["data"]
        self.assertFalse(data["connected"], "Tor doğrulanmadan kalkan etkinleştirildi!")
        self.assertFalse(data["firewall_active"])
        self.assertIn("error", data)
        self.assertTrue(data["error"].strip(), "Kullanıcıya gösterilecek açıklama yok.")
        self.assertFalse(data["tor_check"]["ready"])

        # En kritik doğrulama: güvenlik duvarı kuralları ASLA uygulanmamalı.
        mock_rules.assert_not_called()

        # Durum da "aktif" görünmemeli.
        status = self.client.get_status()
        self.assertFalse(status["data"]["network_shield_active"])

    def test_connect_applies_rules_when_tor_verified(self):
        """Tor doğrulandığında kalkan kurulur ve `disconnect` ile sökerilir.

        Testin gerçek sistemi değiştirmemesi için MAC sahtelemesi, DNS kilidi,
        Tor yapılandırması ve güvenlik duvarı tamamen sahte nesnelerdir;
        yalnızca daemon içindeki akış ve durum geçişleri sınanır.
        """
        ready = {
            "ready": True,
            "reason": "Tor bootstrap tamamlandı (%100).",
            "bootstrap_percent": 100,
            "process_running": True,
            "socks_port": 9050,
        }

        net_cfg = {
            "tor_enabled": True,
            "tor_socks_port": 9050,
            "dnscrypt_enabled": False,
            "mac_randomize": False,
        }
        ports = {
            "trans": {"port": 9040, "source": "tor", "detail": ""},
            "dns": {"port": 5353, "source": "tor", "detail": ""},
            "socks": {"port": 9050, "source": "tor", "detail": ""},
        }
        with (
            mock.patch("core.daemon.is_tor_running_service", return_value=True),
            mock.patch("core.daemon.wait_for_tor_ready", return_value=ready),
            mock.patch("core.daemon.get_tor_listener_port", side_effect=lambda kind, **kw: ports[kind]),
            mock.patch.object(self.daemon.tor_manager, "configure_and_reload", return_value=True),
            mock.patch.object(self.daemon.firewall, "apply_rules", return_value=True) as mock_rules,
            mock.patch("core.daemon.test_tor_circuit_socks", return_value=True),
        ):
            resp = self.client.connect_network(net_cfg)
            self.assertEqual(resp["status"], "ok")
            self.assertTrue(resp["data"]["connected"])
            self.assertTrue(resp["data"]["tor_check"]["ready"])
            mock_rules.assert_called_once()
            # Regresyon: kural, yapılandırma varsayılanı (5300) değil Tor'un
            # gerçekte dinlediği port (Kali'de 5353) ile yazılmalıdır.
            self.assertEqual(mock_rules.call_args.kwargs["dns_port"], 5353)
            self.assertEqual(mock_rules.call_args.kwargs["trans_port"], 9040)

            status = self.client.get_status()
            self.assertTrue(status["data"]["network_shield_active"])

            # Kapat
            with mock.patch.object(self.daemon.firewall, "flush_rules", return_value=True) as mock_flush:
                disc = self.client.disconnect_network()

        self.assertEqual(disc["status"], "ok")
        self.assertFalse(disc["data"]["connected"])
        mock_flush.assert_called_once()

    def test_connect_does_not_touch_mac_when_firewall_fails(self):
        """Güvenlik duvarı kurulamazsa MAC adresine HİÇ dokunulmamalıdır.

        Yeni sıralamada MAC sahtelemesi en son adımdır. Kalkan kurulamadıysa
        ağ arayüzünü değiştirmenin bir faydası yoktur; aksine sanal makine
        NAT ağlarında bağlantıyı keser.
        """
        ready = {
            "ready": True,
            "reason": "Tor bootstrap tamamlandı ve devre doğrulandı (%100).",
            "bootstrap_percent": 100,
            "process_running": True,
            "socks_port": 9050,
            "circuit_verified": True,
        }
        net_cfg = {
            "tor_enabled": True,
            "tor_socks_port": 9050,
            "dnscrypt_enabled": False,
            "mac_randomize": True,
        }
        with (
            mock.patch("core.daemon.is_tor_running_service", return_value=True),
            mock.patch("core.daemon.wait_for_tor_ready", return_value=ready),
            mock.patch("core.daemon.get_tor_listener_port", return_value={"port": 9040, "source": "tor", "detail": ""}),
            mock.patch.object(self.daemon.tor_manager, "configure_and_reload", return_value=True),
            mock.patch.object(self.daemon.firewall, "apply_rules", return_value=False),
            mock.patch.object(self.daemon.mac_manager, "randomize_all_physical_interfaces") as mock_mac,
        ):
            resp = self.client.connect_network(net_cfg)

        self.assertFalse(resp["data"]["connected"])
        mock_mac.assert_not_called()

    def test_mac_randomization_rolled_back_if_tor_breaks(self):
        """MAC değişikliği Tor'u bozarsa yalnızca MAC geri alınır; kalkan kalır.

        Regresyon: MAC değişikliği VM NAT ağlarında DHCP kirasını bozar ve
        bağlantıyı keser. Bu, kullanıcının "internetim gitti" şikâyetinin
        kök nedeniydi. Artık kalkan ayakta kalır, MAC geri alınır.
        """
        ready = {
            "ready": True,
            "reason": "Tor bootstrap tamamlandı ve devre doğrulandı (%100).",
            "bootstrap_percent": 100,
            "process_running": True,
            "socks_port": 9050,
            "circuit_verified": True,
        }
        mac_results = {"eth0": {"interface": "eth0", "old_mac": "aa:bb:cc:dd:ee:ff", "success": True}}
        net_cfg = {
            "tor_enabled": True,
            "tor_socks_port": 9050,
            "dnscrypt_enabled": False,
            "mac_randomize": True,
        }
        with (
            mock.patch("core.daemon.is_tor_running_service", return_value=True),
            mock.patch("core.daemon.wait_for_tor_ready", return_value=ready),
            mock.patch("core.daemon.get_tor_listener_port", return_value={"port": 9040, "source": "tor", "detail": ""}),
            mock.patch.object(self.daemon.tor_manager, "configure_and_reload", return_value=True),
            mock.patch.object(self.daemon.firewall, "apply_rules", return_value=True),
            mock.patch.object(
                self.daemon.mac_manager,
                "randomize_all_physical_interfaces",
                return_value=mac_results,
            ),
            mock.patch("core.daemon.test_tor_circuit_socks", side_effect=[True, False]),
            mock.patch.object(self.daemon.mac_manager, "restore_all") as mock_restore,
        ):
            resp = self.client.connect_network(net_cfg)

        # Kalkan AÇIK kalmalı
        self.assertTrue(resp["data"]["connected"])
        # MAC geri alınmış olmalı
        self.assertTrue(resp["data"]["mac_rolled_back"])
        self.assertEqual(resp["data"]["mac_randomized"], {})
        mock_restore.assert_called_once()

    def test_circuit_renewal(self):
        """Tor devre yenileme isteşinin daemon durumunu güncellemesini test eder.

        Gerçek bir Tor süreci (127.0.0.1:9051) gerektirmemesi için Control Port
        çağrısı sahte bir yanıtla değiştirilir; burada sınanan konu soket
        iletişimi, SO_PEERCRED yetkilendirmesi ve durum güncellemesidir.
        """
        fake_renewal = {
            "success": True,
            "message": "Tor devresi başarıyla yenilendi (Yeni IP atandı).",
            "timestamp": time.time(),
        }
        with mock.patch("core.daemon.renew_tor_circuit", return_value=fake_renewal) as mocked:
            resp = self.client.new_tor_circuit()

        mocked.assert_called_once()
        self.assertEqual(resp["status"], "ok")
        self.assertTrue(resp["data"]["success"])
        self.assertEqual(resp["data"]["message"], fake_renewal["message"])

        # Başarılı yenileme daemon durum kaydına da yansımalıdır
        status = self.client.get_status()
        self.assertGreater(status["data"]["last_circuit_renewal"], 0.0)

    def test_circuit_renewal_failure_is_reported(self):
        """Tor çalışmıyorken devre yenileme hatası istemciye dürüstçe bildirilmelidir."""
        failure = {
            "success": False,
            "message": "Tor kontrol portuna bağlanılamadı.",
            "timestamp": time.time(),
        }
        with mock.patch("core.daemon.renew_tor_circuit", return_value=failure):
            resp = self.client.new_tor_circuit()

        self.assertEqual(resp["status"], "ok")
        self.assertFalse(resp["data"]["success"])
        self.assertIn("bağlanılamadı", resp["data"]["message"])

    def test_clean_forensics(self):
        """Adli temizlik komutunun iletilmesini test eder."""
        targets = {"clean_shell_history": True, "clean_trash": True}
        resp = self.client.clean_forensics(targets)
        self.assertEqual(resp["status"], "ok")
        self.assertTrue(resp["data"]["started"])

    def test_emergency_panic(self):
        """Acil durum panik komutunu test eder."""
        resp = self.client.emergency_panic()
        self.assertEqual(resp["status"], "ok")
        self.assertTrue(resp["data"]["nuked"])

    def test_invalid_command_raises_error(self):
        """İzin verilmeyen bir komut yollandığında DaemonResponseError fırlatılmasını test eder."""
        with self.assertRaises(DaemonResponseError):
            self.client.send_request("forbidden_shell_cmd")


if __name__ == "__main__":
    unittest.main()
