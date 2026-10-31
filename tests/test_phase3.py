"""AnonVoid - Faz 3 Ağ ve Gizlilik Çekirdeği Birim Testleri.

Bu dosya; nftables .onion sanal IP ayrımını, DoH engellemesini, IPv6 drop kurallarını,
torrc şablonlamasını, MAC sahteleme mantığını, sızıntı test paketini ve panik butonunu test eder.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import time
import unittest
from unittest import mock

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.network.dnscrypt import DNSCryptManager, get_active_network_interfaces
from core.network.firewall import TOR_LOCAL_NETS, FirewallEngine
# DİKKAT: Üretim modülündeki "test_*" adlı yardımcılar doğrudan içe
# aktarılırsa pytest onları TEST SANIP koşturur. Bu, hem anlamsız
# PytestReturnNotNoneWarning üretir hem de test koşusunda gerçek ağ
# istekleri (STUN/IPv6/DNS probları) yapılmasına yol açar. Bu yüzden
# alias ile "test_" öneki olmayan adlara bağlanırlar; sınamalar kendi
# TestCase metotları içinde açıkça çağrılır.
from core.network.leak_test import (
    get_system_identity_exposure,
    resolve_with_deadline,
    run_full_leak_test,
)
from core.network.leak_test import test_dns_leak as probe_dns_leak
from core.network.leak_test import test_ipv6_leak as probe_ipv6_leak
from core.network.leak_test import test_webrtc_udp_leak as probe_webrtc_leak
from core.network.mac import generate_random_mac, get_physical_interfaces
from core.network.panic import execute_panic_nuke
from core.network.tor import check_tor_ready, get_bootstrap_progress, get_tor_dns_port
from core.network.tor import TorManager, renew_tor_circuit


class TestFirewallEngine(unittest.TestCase):
    """core/network/firewall.py testleri."""

    def setUp(self):
        self.fw = FirewallEngine(table_name="fp-test")

    def test_onion_address_space_isolation(self):
        """10.192.0.0/10 .onion sanal IP alanının bilerek LAN istisnalarından hariç tutulduğunu test eder."""
        self.assertNotIn("10.192.0.0/10", TOR_LOCAL_NETS)
        self.assertIn("10.0.0.0/9", TOR_LOCAL_NETS)
        self.assertIn("10.128.0.0/10", TOR_LOCAL_NETS)

    def test_build_nft_ruleset_structure(self):
        """Üretilen nftables kural kümesinin güvenlik gereksinimlerini karşıladığını test eder."""
        ruleset = self.fw.build_nft_ruleset(
            trans_port=9040,
            dns_port=5300,
            tor_uid=110,
            block_doh=True,
            drop_ipv6=True,
        )

        # Temel kontroller
        self.assertIn("table inet fp-test", ruleset)
        self.assertIn("table ip6 fp-test", ruleset)
        self.assertIn("policy drop", ruleset)  # IPv6 drop
        self.assertIn("redirect to :9040", ruleset)  # TransPort
        self.assertIn("redirect to :5300", ruleset)  # DNSPort
        self.assertIn("meta skuid 110 accept", ruleset)  # Tor UID muafiyeti
        self.assertIn("1.1.1.1", ruleset)  # DoH engeli
        self.assertIn("8.8.8.8", ruleset)  # DoH engeli

    def test_dns_redirect_precedes_lan_exception_in_nat_output(self):
        """nat_output zincirinde dport 53 redirect kuralının ip daddr LAN istisnasından ÖNCE geldiğini doğrular."""
        ruleset = self.fw.build_nft_ruleset(trans_port=9040, dns_port=5300)
        self.assertIn("chain nat_output", ruleset)
        nat_part = ruleset.split("chain nat_output")[1]

        dns_redirect_idx = nat_part.find("udp dport 53 redirect to :5300")
        lan_return_idx = nat_part.find("ip daddr {")

        self.assertNotEqual(dns_redirect_idx, -1, "nat_output içinde DNS yönlendirme kuralı bulunamadı")
        self.assertNotEqual(lan_return_idx, -1, "nat_output içinde LAN istisna kuralı bulunamadı")
        self.assertLess(
            dns_redirect_idx,
            lan_return_idx,
            "DNS yönlendirme kuralı LAN istisnasından ÖNCE gelmelidir; aksi halde yerel DNS LAN kuralına takılır!",
        )

    def test_output_drops_udp_and_icmp(self):
        """chain output içinde meta l4proto udp drop ve meta l4proto icmp drop kurallarının bulunduğunu doğrular."""
        ruleset = self.fw.build_nft_ruleset(trans_port=9040, dns_port=5300)
        self.assertIn("chain output {", ruleset)
        output_part = ruleset.split("chain output {")[1].split("chain nat_output")[0]

        self.assertIn("meta l4proto udp drop", output_part, "UDP paketlerini düşüren kural output zincirinde yok")
        self.assertIn("meta l4proto icmp drop", output_part, "ICMP paketlerini düşüren kural output zincirinde yok")


class TestTorManager(unittest.TestCase):
    """core/network/tor.py testleri."""

    def test_generate_torrc_content(self):
        """torrc şablonunun doğru direktifleri ürettiğini test eder."""
        mgr = TorManager()
        content = mgr.generate_torrc_content(trans_port=9040, dns_port=5300, socks_port=9050, control_port=9051)

        self.assertIn("TransPort 9040", content)
        self.assertIn("DNSPort 5300", content)
        self.assertIn("ControlPort 9051", content)
        self.assertIn("VirtualAddrNetworkIPv4 10.192.0.0/10", content)
        self.assertIn("AutomapHostsOnResolve 1", content)
        self.assertIn("AvoidDiskWrites 1", content)

    def test_bridges_and_five_eyes_directives(self):
        """use_bridges (obfs4 / snowflake) ve exclude_five_eyes verildiğinde ilgili direktiflerin üretildiğini doğrular."""
        mgr = TorManager()

        # 1. obfs4 + exclude_five_eyes
        torrc_obfs4 = mgr.generate_torrc_content(
            use_bridges=True,
            bridge_type="obfs4",
            exclude_five_eyes=True,
        )
        self.assertIn("UseBridges 1", torrc_obfs4)
        self.assertIn("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy", torrc_obfs4)
        self.assertIn("ExcludeExitNodes", torrc_obfs4)
        self.assertIn("StrictNodes 1", torrc_obfs4)

        # 2. snowflake + exclude_five_eyes
        torrc_snowflake = mgr.generate_torrc_content(
            use_bridges=True,
            bridge_type="snowflake",
            exclude_five_eyes=True,
        )
        self.assertIn("UseBridges 1", torrc_snowflake)
        self.assertIn("ClientTransportPlugin snowflake exec /usr/bin/snowflake-client", torrc_snowflake)
        self.assertIn("Bridge ", torrc_snowflake)
        self.assertIn("ExcludeExitNodes", torrc_snowflake)
        self.assertIn("StrictNodes 1", torrc_snowflake)

    def test_does_not_clobber_existing_torrc(self):
        """Mevcut torrc EZİLMEMELİ; yalnızca eksik direktifler eklenmeli.

        Opsec paritesi: dağıtım yapılandırması korunur. Aksi halde
        Debian/Kali'nin User/DataDirectory gibi ayarları kaybolur.
        """
        with tempfile.TemporaryDirectory() as tmp:
            torrc = os.path.join(tmp, "torrc")
            original = (
                "# dağıtım yapılandırması\n"
                "DNSPort 127.0.0.1:5353\n"
                "User debian-tor\n"
            )
            with open(torrc, "w", encoding="utf-8") as handle:
                handle.write(original)

            manager = TorManager(torrc_path=torrc)
            changed = manager._ensure_torrc_directives(dns_port=5300)

            self.assertTrue(changed)
            with open(torrc, "r", encoding="utf-8") as handle:
                after = handle.read()

            # Mevcut satırlar korunmuş olmalı
            self.assertIn("User debian-tor", after)
            # Var olan DNSPort korunmalı, ikinci bir DNSPort eklenmemeli
            self.assertEqual(after.count("DNSPort"), 1)
            self.assertIn("DNSPort 127.0.0.1:5353", after)
            # Eksikler eklenmiş olmalı
            self.assertIn("CookieAuthentication 1", after)
            self.assertIn("TransPort", after)

            # İkinci çağrı idempotent olmalı
            self.assertFalse(manager._ensure_torrc_directives(dns_port=5300))

    def test_renew_circuit_offline_safety(self):
        """Tor çalışmıyorken devre yenilemenin kontrollü hata döndüğünü test eder."""
        # Olmayan port
        res = renew_tor_circuit(control_port=59999)
        self.assertFalse(res["success"])
        self.assertIn("bağlanılamadı", res["message"])


class TestMACRandomizer(unittest.TestCase):
    """core/network/mac.py testleri."""

    def test_generate_random_mac(self):
        """Üretilen MAC adresinin geçerli ve yerel unicast olduğunu test eder."""
        mac_regex = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
        for _ in range(20):
            mac = generate_random_mac()
            self.assertTrue(mac_regex.match(mac))

            # İlk bayt kontrolü (Unicast ve locally-administered: 0x02 biti 1, 0x01 biti 0)
            first_byte = int(mac.split(":")[0], 16)
            self.assertEqual(first_byte & 0x01, 0, "Multicast bit kapalı olmalıdır")
            self.assertEqual(first_byte & 0x02, 2, "Locally administered bit açık olmalıdır")


class TestLeakTestSuite(unittest.TestCase):
    """core/network/leak_test.py testleri."""

    def test_system_identity_exposure(self):
        """Hostname ve saat dilimi kontrollerini test eder."""
        ident = get_system_identity_exposure()
        self.assertIn("hostname", ident)
        self.assertIn("timezone", ident)
        self.assertIn("is_utc", ident)

    def test_ipv6_leak_safe(self):
        """IPv6 sızıntı denetiminin güvenle sonuç ürettiğini test eder."""
        res = probe_ipv6_leak(timeout=1.0)
        self.assertIn("leak_detected", res)
        self.assertIn("message", res)

    def test_webrtc_udp_leak_safe(self):
        """WebRTC STUN testinin güvenle sonuç ürettiğini test eder."""
        res = probe_webrtc_leak(timeout=1.0)
        self.assertIn("leak_detected", res)

    def test_full_leak_test_report_structure(self):
        """Tam sızıntı testi raporunun tüm alanları içerdiğini test eder."""
        report = run_full_leak_test()
        self.assertIn("timestamp", report)
        self.assertIn("is_fully_anonymous", report)
        self.assertIn("tor", report)
        self.assertIn("ipv6", report)
        self.assertIn("dns", report)
        self.assertIn("webrtc", report)
        self.assertIn("system_identity", report)

    def test_full_leak_test_completes_within_budget(self):
        """Sızıntı testi paketi daima belirlenen süre bütçesinde bitmelidir.

        Regresyon testi: DNS çözümlemesi daha önce süresiz `gethostbyname`
        çağrısıyla yapılıyordu. Kalkan etkinken (DNS 127.0.0.1:5300'e
        yönlendirilmiş ama Tor çalışmıyorken) çözümleme dakikalarca
        bloklanıyor, istemci 30 saniyelik zaman aşımına takılıyor ve
        arayüz yanıt vermiyordu.
        """
        start = time.time()
        report = run_full_leak_test()
        elapsed = time.time() - start

        # Varsayılan zaman aşımları 8 + 3 + 4 + 3 = 18 sn; güvenlik payıyla 40 sn.
        self.assertLess(
            elapsed,
            40.0,
            f"Sızıntı testi {elapsed:.1f} sn sürdü; DNS çözümlemesi yine sınırsız.",
        )
        self.assertGreaterEqual(report["duration_sec"], 0.0)

    def test_dns_leak_respects_timeout(self):
        """DNS sızıntı testi kendi zaman aşımı parametresini gerçekten uygulamalıdır."""
        start = time.time()
        result = probe_dns_leak(timeout=2.0)
        elapsed = time.time() - start

        self.assertLess(elapsed, 12.0, "test_dns_leak zaman aşımını uygulamıyor.")
        self.assertIn("tor_dns_responsive", result)
        # Test artık iddia ettiği şeyi ölçüyor: Tor DNSPort'a doğrudan sorgu.
        self.assertIn("system_matches_tor", result)

    def test_resolve_with_deadline_returns_none_on_timeout(self):
        """Çözümlenemeyen adlar için çözümleme sınırı uygulanır."""
        start = time.time()
        ip = resolve_with_deadline("bu-ad-kisa-surede-cozulemez.invalid", timeout=2.0)
        elapsed = time.time() - start

        self.assertIsNone(ip)
        self.assertLess(elapsed, 12.0)


class TestTorReadinessGuards(unittest.TestCase):
    """Kill-switch öncesi Tor hazırlık denetimlerinin testleri.

    Bu testler bir GÜVENLİK davranışını sabitler: emin olunamayan durum
    "hazır" kabul edilmez. Aksi halde nftables kuralı tüm giden TCP'yi
    çalışmayan bir Tor TransPort'a yönlendirir ve sistemin bütün
    bağlantıları (kullanıcının iş oturumu dahil) düşer.
    """

    def test_bootstrap_percent_parsed_from_control_reply(self):
        """Kontrol portundan bootstrap yüzdesi doğru okunmalıdır."""
        reply = '250 OK\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\n250 OK'
        with mock.patch("core.network.tor._control_command", return_value=reply):
            self.assertEqual(get_bootstrap_progress(), 100)

        partial = '250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 TAG=done\n250 OK'
        with mock.patch("core.network.tor._control_command", return_value=partial):
            self.assertEqual(get_bootstrap_progress(), 45)

    def test_bootstrap_percent_none_when_unreachable(self):
        """Kontrol portu okunamazsa bilinmiyor dönmeli, 100 DEĞİL."""
        with mock.patch("core.network.tor._control_command", return_value=""):
            self.assertIsNone(get_bootstrap_progress())

    def test_not_ready_when_control_unreadable(self):
        """Süreç ayakta olsa bile durum okunamıyorsa hazır sayılmamalıdır."""
        with (
            mock.patch("core.network.tor.is_tor_running", return_value=True),
            mock.patch("core.network.tor.get_bootstrap_progress", return_value=None),
            mock.patch("core.network.tor.socket.create_connection"),
        ):
            result = check_tor_ready()
        self.assertFalse(result["ready"])
        self.assertIsNone(result["bootstrap_percent"])
        self.assertIn("doğrulanamadı", result["reason"])

    def test_not_ready_when_bootstrap_incomplete(self):
        """Bootstrap tamamlanmadan kill-switch için hazır sayılmamalıdır."""
        with (
            mock.patch("core.network.tor.is_tor_running", return_value=True),
            mock.patch("core.network.tor.get_bootstrap_progress", return_value=50),
            mock.patch("core.network.tor.socket.create_connection"),
        ):
            result = check_tor_ready()
        self.assertFalse(result["ready"])
        self.assertIn("50", result["reason"])

    def test_not_ready_when_process_down(self):
        with mock.patch("core.network.tor.is_tor_running", return_value=False):
            result = check_tor_ready()
        self.assertFalse(result["ready"])

    def test_ready_only_when_bootstrap_complete(self):
        with (
            mock.patch("core.network.tor.is_tor_running", return_value=True),
            mock.patch("core.network.tor.get_bootstrap_progress", return_value=100),
            mock.patch("core.network.tor.socket.create_connection"),
        ):
            result = check_tor_ready()
        self.assertTrue(result["ready"])
        self.assertEqual(result["bootstrap_percent"], 100)

    def test_socks_port_must_be_listening(self):
        """Servis ayakta görünse de SOCKS portu kapalıysa hazır sayılmamalıdır."""
        import socket as real_socket

        def refuse(*_args, **_kwargs):
            raise real_socket.error("Connection refused")

        with (
            mock.patch("core.network.tor.is_tor_running", return_value=True),
            mock.patch("core.network.tor.get_bootstrap_progress", return_value=100),
            mock.patch("core.network.tor.socket.create_connection", side_effect=refuse),
        ):
            result = check_tor_ready()
        self.assertFalse(result["ready"])
        self.assertIn("SOCKS", result["reason"])


class TestTorrcReadOnlyResilience(unittest.TestCase):
    """torrc yazılamasa bile Tor başlatılmalıdır.

    Regresyon: systemd `ProtectSystem=full` /etc'yi salt-okunur yaptığı için
    `/etc/tor/torrc` yazılamıyordu. Eski kod bu durumda `False` dönüp Tor'u
    HİÇ başlatmıyordu; kullanıcı "korumayı başlat" deyince yükleme bitiyor ve
    hiçbir şey olmuyordu. Doğru davranış: torrc yazımı en iyi çaba, servis
    yine de başlatılmalı.
    """

    def test_starts_tor_even_if_torrc_not_writable(self):
        from core.network.tor import TorManager

        manager = TorManager(torrc_path="/etc/tor/torrc")
        readonly = OSError(30, "Read-only file system")

        with (
            mock.patch("core.network.tor.TorManager.backup_torrc", return_value=True),
            mock.patch("core.network.tor.open", side_effect=readonly, create=True),
            mock.patch.object(manager, "reload_service", return_value=True) as mock_reload,
        ):
            result = manager.configure_and_reload()

        self.assertTrue(result, "torrc yazılamasa da Tor başlatılmalıydı.")
        mock_reload.assert_called_once()

    def test_reload_service_starts_stopped_multiinstance_unit(self):
        """Kali'de tor.service kapalıdır; `start` denenmelidir."""
        from core.network.tor import TorManager

        manager = TorManager()
        calls = []

        def fake_run(cmd, **_kwargs):
            calls.append(cmd)
            class P:
                returncode = 0
            return P()

        with (
            mock.patch("core.network.tor.subprocess.run", side_effect=fake_run),
            mock.patch("core.network.tor.is_tor_running", return_value=True),
        ):
            self.assertTrue(manager.reload_service())

        self.assertIn(["systemctl", "start", "tor"], calls)


class TestTorDnsPortDiscovery(unittest.TestCase):
    """DNSPort keşfi: sabit 5300 varsayımı hatalıydı.

    Dağıtım öntanımları farklı portlar kullanabilir (Kali'de 5353). Sabit
    port sorgulamak, sağlıklı çalışan bir Tor'u "DNS yanıt vermiyor" gibi
    gösterebilir ve kullanıcıyı yanlış yönlendirir.
    """

    def test_parses_quoted_listener_from_control_port(self):
        reply = '250-net/listeners/dns="127.0.0.1:5353"\n250 OK'
        with mock.patch("core.network.tor._control_command", return_value=reply):
            result = get_tor_dns_port()
        self.assertEqual(result["port"], 5353)
        self.assertEqual(result["source"], "tor")

    def test_multiple_listeners_prefers_loopback(self):
        reply = '250-net/listeners/dns="0.0.0.0:5300" "127.0.0.1:5353"\n250 OK'
        with mock.patch("core.network.tor._control_command", return_value=reply):
            result = get_tor_dns_port()
        self.assertEqual(result["port"], 5353)

    def test_falls_back_when_control_unavailable(self):
        with mock.patch("core.network.tor._control_command", return_value=""):
            result = get_tor_dns_port(fallback=5300)
        self.assertEqual(result["port"], 5300)
        self.assertEqual(result["source"], "fallback")

    def test_query_uses_discovered_port(self):
        """Keşfedilen port gerçekten sorguya uygulanmalıdır."""
        from core.network import leak_test as lt

        with mock.patch.object(lt, "get_tor_dns_port", return_value={"port": 5353, "source": "tor", "detail": ""}):
            with mock.patch.object(lt, "query_tor_dnsport", return_value={"responsive": True, "ip": "1.2.3.4", "error": None}) as mocked:
                result = lt.test_dns_leak(timeout=1.0)

        self.assertEqual(result["dns_port"], 5353)
        self.assertEqual(result["dns_port_source"], "tor")
        self.assertEqual(mocked.call_args.kwargs["dns_port"], 5353)


class TestPanicModule(unittest.TestCase):

    def test_execute_panic_nuke_safe(self):
        """Panik butonu yürütümünün güvenli şekilde sonuçlandığını test eder."""
        with tempfile.TemporaryDirectory() as fake_home:
            # Fake shell file
            bash_file = os.path.join(fake_home, ".bash_history")
            with open(bash_file, "w") as f:
                f.write("gizli_komut_123\n")

            report = execute_panic_nuke(
                target_home=fake_home,
                wipe_shell=True,
                clear_ram=True,
                shutdown_system=False,  # Test ortamında sistemi kapatma
            )

            self.assertTrue(report["nuked"])
            self.assertTrue(report["shell_wiped"])
            self.assertFalse(os.path.exists(bash_file))


if __name__ == "__main__":
    unittest.main()
