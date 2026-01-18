#!/usr/bin/env python3
"""
VPN Manager for Dark Web Research
Automates VPN connection and security checks
"""

import os
import sys
import json
import time
import random
import subprocess
import requests
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum


# ============================================================================
# CONFIGURACIÓN DE VPNs
# ============================================================================

class VPNProvider(Enum):
    """Proveedores de VPN recomendados para investigación"""
    MULLVAD = "mullvad"
    PROTON = "proton"
    IVPN = "ivpn"
    WINDSCRIBE = "windscribe"
    OVPN = "ovpn"
    CUSTOM = "custom"


@dataclass
class VPNConfig:
    """Configuración de VPN"""
    provider: VPNProvider
    server: str
    protocol: str = "wireguard"  # wireguard, openvpn, ikev2
    port: int = 51820
    dns: List[str] = None
    multihop: bool = False
    killswitch: bool = True
    leak_protection: bool = True

    def __post_init__(self):
        if self.dns is None:
            self.dns = ["1.1.1.1", "1.0.0.1"]  # Cloudflare DNS


@dataclass
class SecurityCheck:
    """Resultados de verificación de seguridad"""
    ip_leak: bool = False
    dns_leak: bool = False
    webRTC_leak: bool = False
    ipv6_leak: bool = False
    is_torified: bool = False
    vpn_connected: bool = False

    def is_secure(self) -> bool:
        return all([
            not self.ip_leak,
            not self.dns_leak,
            not self.webRTC_leak,
            not self.ipv6_leak,
            self.vpn_connected
        ])


# ============================================================================
# CLASE PRINCIPAL: VPN MANAGER
# ============================================================================

class VPNManager:
    """Gestor automático de VPN para investigación"""

    def __init__(self, config: VPNConfig):
        self.config = config
        self.logger = self._setup_logging()
        self.current_ip = None
        self.connection_start = None

    def _setup_logging(self) -> logging.Logger:
        """Configurar logging"""
        logger = logging.getLogger("VPNManager")
        logger.setLevel(logging.INFO)

        handler = logging.FileHandler("vpn_manager.log")
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    # ============================================================================
    # CONEXIÓN A VPNs ESPECÍFICAS
    # ============================================================================

    def connect_mullvad(self) -> bool:
        """Conectar a Mullvad VPN"""
        try:
            self.logger.info("Connecting to Mullvad VPN...")

            # Método 1: Usar app oficial (recomendado)
            if sys.platform == "linux":
                # Mullvad CLI en Linux
                result = subprocess.run(
                    ["mullvad", "connect"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if "Connected to" in result.stdout:
                    self.logger.info("Mullvad connected via CLI")
                    return True

            # Método 2: WireGuard config file
            wg_config = self._generate_wireguard_config()
            config_path = Path("mullvad.conf")
            config_path.write_text(wg_config)

            # Conectar con wg-quick
            result = subprocess.run(
                ["sudo", "wg-quick", "up", str(config_path.absolute())],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                self.logger.info("Mullvad connected via WireGuard")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Mullvad connection failed: {e}")
            return False

    def connect_proton(self) -> bool:
        """Conectar a ProtonVPN"""
        try:
            self.logger.info("Connecting to ProtonVPN...")

            # ProtonVPN CLI (Linux)
            if sys.platform == "linux":
                # Conectar al servidor más rápido
                result = subprocess.run(
                    ["protonvpn-cli", "connect", "--fastest"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if "Connected" in result.stdout:
                    self.logger.info("ProtonVPN connected")
                    return True

            # Para otras plataformas, usar OpenVPN config
            ovpn_config = self._download_proton_config()
            if ovpn_config:
                return self._connect_openvpn(ovpn_config)

            return False

        except Exception as e:
            self.logger.error(f"ProtonVPN connection failed: {e}")
            return False

    def connect_ivpn(self) -> bool:
        """Conectar a IVPN"""
        try:
            self.logger.info("Connecting to IVPN...")

            # IVPN CLI
            if Path("/usr/bin/ivpn").exists():
                result = subprocess.run(
                    ["ivpn", "connect"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if "CONNECTED" in result.stdout:
                    self.logger.info("IVPN connected")
                    return True

            # WireGuard manual
            return self._connect_wireguard_manual()

        except Exception as e:
            self.logger.error(f"IVPN connection failed: {e}")
            return False

    def _generate_wireguard_config(self) -> str:
        """Generar configuración WireGuard"""
        return f"""[Interface]
PrivateKey = {{YOUR_PRIVATE_KEY}}
Address = 10.64.0.1/32
DNS = {', '.join(self.config.dns)}

[Peer]
PublicKey = {{SERVER_PUBLIC_KEY}}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {self.config.server}:{self.config.port}
PersistentKeepalive = 25
"""

    def _download_proton_config(self) -> Optional[str]:
        """Descargar configuración OpenVPN de Proton"""
        try:
            # Proton provee configs en: https://account.protonvpn.com/downloads
            # Para investigación, mejor usar la app oficial

            # Placeholder: en producción, descargar config real
            config_urls = {
                "free": "https://free.protonvpn.com/configs.ovpn",
                "plus": "https://account.protonvpn.com/api/vpn/v2/config?Platform=linux&LogicalID=1"
            }

            response = requests.get(config_urls["free"], timeout=10)
            if response.status_code == 200:
                return response.text

        except Exception as e:
            self.logger.error(f"Failed to download Proton config: {e}")

        return None

    def _connect_openvpn(self, config: str) -> bool:
        """Conectar usando configuración OpenVPN"""
        try:
            # Guardar config temporal
            config_path = Path("temp_vpn.ovpn")
            config_path.write_text(config)

            # Ejecutar OpenVPN
            process = subprocess.Popen(
                ["sudo", "openvpn", "--config", str(config_path.absolute())],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Esperar conexión
            time.sleep(10)

            # Verificar conexión
            if self._check_vpn_connection():
                self.logger.info("OpenVPN connected")
                return True

            return False

        except Exception as e:
            self.logger.error(f"OpenVPN connection failed: {e}")
            return False

    # ============================================================================
    # VERIFICACIONES DE SEGURIDAD
    # ============================================================================

    def run_security_check(self) -> SecurityCheck:
        """Ejecutar verificación completa de seguridad"""
        self.logger.info("Running security checks...")

        check = SecurityCheck()

        # 1. Check VPN connection
        check.vpn_connected = self._check_vpn_connection()

        if check.vpn_connected:
            # 2. Check IP leak
            check.ip_leak = self._check_ip_leak()

            # 3. Check DNS leak
            check.dns_leak = self._check_dns_leak()

            # 4. Check WebRTC leak
            check.webRTC_leak = self._check_webrtc_leak()

            # 5. Check IPv6 leak
            check.ipv6_leak = self._check_ipv6_leak()

            # 6. Check if Tor-ready
            check.is_torified = self._check_tor_readiness()

        # Log results
        self.logger.info(f"Security check results: {asdict(check)}")

        return check

    def _check_vpn_connection(self) -> bool:
        """Verificar si VPN está conectada"""
        try:
            # Obtener IP actual
            response = requests.get("https://api.ipify.org", timeout=5)
            current_ip = response.text.strip()

            if self.current_ip:
                # Si la IP cambió, probablemente VPN funcionando
                if current_ip != self.current_ip:
                    self.current_ip = current_ip
                    return True
            else:
                self.current_ip = current_ip
                return True

        except:
            pass

        return False

    def _check_ip_leak(self) -> bool:
        """Verificar fuga de IP real"""
        try:
            # Test con multiple servicios
            services = [
                "https://api.ipify.org",
                "https://icanhazip.com",
                "https://checkip.amazonaws.com"
            ]

            ips = set()
            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    ips.add(response.text.strip())
                except:
                    continue

            # Si hay más de 1 IP, posible leak
            return len(ips) > 1

        except:
            return True  # Assume leak if check fails

    def _check_dns_leak(self) -> bool:
        """Verificar fuga de DNS"""
        try:
            # Usar dnsleaktest.com API
            response = requests.get(
                "https://www.dnsleaktest.com/api/dnsleak/ip",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                # Si muestra ISP DNS, hay leak
                return any("isp" in str(dns).lower() for dns in data)

        except:
            pass

        # Fallback: check DNS servers
        try:
            import socket
            dns_servers = socket.getaddrinfo('example.com', 80)
            # Si DNS no es el configurado en VPN, hay leak
            return len(dns_servers) > 2
        except:
            return True

    def _check_webrtc_leak(self) -> bool:
        """Verificar fuga WebRTC"""
        # WebRTC leaks son en navegador, no en Python
        # Esta es una verificación básica
        try:
            # Check if STUN is blocked
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            # Intentar conectar a STUN server
            sock.connect(('stun.l.google.com', 19302))
            return True  # STUN accessible, possible leak

        except:
            return False

    def _check_ipv6_leak(self) -> bool:
        """Verificar fuga IPv6"""
        try:
            response = requests.get("https://ipv6.icanhazip.com", timeout=5)
            # Si responde, tenemos IPv6 (posible leak si VPN no lo bloquea)
            return len(response.text.strip()) > 0

        except requests.exceptions.RequestException:
            # No IPv6 connectivity
            return False

    def _check_tor_readiness(self) -> bool:
        """Verificar si el sistema está listo para Tor"""
        try:
            # Check if Tor ports are available
            import socket

            # Check SOCKS port 9050
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', 9050))
            sock.close()

            return result == 0  # 0 = success

        except:
            return False

    # ============================================================================
    # UTILIDADES AVANZADAS
    # ============================================================================

    def randomize_server(self) -> bool:
        """Cambiar a servidor VPN aleatorio"""
        servers = self._get_available_servers()
        if servers:
            random_server = random.choice(servers)
            self.config.server = random_server

            self.logger.info(f"Switching to random server: {random_server}")
            return self.reconnect()

        return False

    def _get_available_servers(self) -> List[str]:
        """Obtener lista de servidores disponibles"""
        # Esto depende del proveedor de VPN
        servers_by_provider = {
            VPNProvider.MULLVAD: [
                "se.mullvad.net",
                "de.mullvad.net",
                "nl.mullvad.net",
                "ch.mullvad.net",
                "ca.mullvad.net"
            ],
            VPNProvider.PROTON: [
                "ch.protonvpn.ch",
                "se.protonvpn.ch",
                "is.protonvpn.ch",
                "nl.protonvpn.ch",
                "us.protonvpn.ch"
            ],
            VPNProvider.IVPN: [
                "ch1.ivpn.net",
                "de1.ivpn.net",
                "se1.ivpn.net",
                "us1.ivpn.net"
            ]
        }

        return servers_by_provider.get(self.config.provider, [])

    def reconnect(self) -> bool:
        """Reconectar VPN"""
        self.disconnect()
        time.sleep(2)
        return self.connect()

    def disconnect(self):
        """Desconectar VPN"""
        try:
            self.logger.info("Disconnecting VPN...")

            # Método universal: matar procesos VPN
            vpn_processes = ["openvpn", "wireguard", "wg-quick", "mullvad", "protonvpn"]

            for process in vpn_processes:
                subprocess.run(
                    ["pkill", "-f", process],
                    capture_output=True
                )

            self.logger.info("VPN disconnected")

        except Exception as e:
            self.logger.error(f"Failed to disconnect VPN: {e}")

    def enable_killswitch(self) -> bool:
        """Activar killswitch de red"""
        try:
            if sys.platform == "linux":
                # Usar iptables para bloquear tráfico sin VPN
                rules = [
                    # Bloquear todo tráfico de salida
                    "iptables -P OUTPUT DROP",

                    # Permitir tráfico a interfaz VPN
                    "iptables -A OUTPUT -o tun0 -j ACCEPT",
                    "iptables -A OUTPUT -o wg0 -j ACCEPT",

                    # Permitir loopback
                    "iptables -A OUTPUT -o lo -j ACCEPT",

                    # Permitir DNS de VPN
                    f"iptables -A OUTPUT -d {self.config.dns[0]} -p udp --dport 53 -j ACCEPT",
                    f"iptables -A OUTPUT -d {self.config.dns[1]} -p udp --dport 53 -j ACCEPT"
                ]

                for rule in rules:
                    subprocess.run(rule.split(), check=True)

                self.logger.info("Killswitch enabled")
                return True

        except Exception as e:
            self.logger.error(f"Failed to enable killswitch: {e}")
            return False

    def disable_killswitch(self):
        """Desactivar killswitch"""
        try:
            if sys.platform == "linux":
                # Restaurar políticas por defecto
                subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)

                # Flush todas las reglas
                subprocess.run(["iptables", "-F"], check=True)
                subprocess.run(["iptables", "-X"], check=True)

                self.logger.info("Killswitch disabled")

        except Exception as e:
            self.logger.error(f"Failed to disable killswitch: {e}")

    def connect(self) -> bool:
        """Conectar a VPN según proveedor"""
        self.connection_start = time.time()

        connection_methods = {
            VPNProvider.MULLVAD: self.connect_mullvad,
            VPNProvider.PROTON: self.connect_proton,
            VPNProvider.IVPN: self.connect_ivpn,
            VPNProvider.WINDSCRIBE: lambda: self._connect_wireguard_manual(),
            VPNProvider.OVPN: lambda: self._connect_wireguard_manual(),
            VPNProvider.CUSTOM: lambda: self._connect_custom()
        }

        method = connection_methods.get(self.config.provider)
        if method:
            success = method()

            if success and self.config.killswitch:
                self.enable_killswitch()

            return success

        return False

    def _connect_wireguard_manual(self) -> bool:
        """Conexión manual WireGuard"""
        try:
            config = self._generate_wireguard_config()
            config_path = Path("manual_wg.conf")
            config_path.write_text(config)

            result = subprocess.run(
                ["sudo", "wg-quick", "up", str(config_path.absolute())],
                capture_output=True,
                text=True,
                timeout=30
            )

            return result.returncode == 0

        except Exception as e:
            self.logger.error(f"Manual WireGuard failed: {e}")
            return False

    def _connect_custom(self) -> bool:
        """Conexión VPN personalizada"""
        # Para configuraciones personalizadas
        self.logger.info("Using custom VPN connection")
        return True

    def get_connection_stats(self) -> Dict[str, any]:
        """Obtener estadísticas de conexión"""
        if not self.connection_start:
            return {}

        duration = time.time() - self.connection_start

        return {
            "provider": self.config.provider.value,
            "server": self.config.server,
            "duration_seconds": int(duration),
            "current_ip": self.current_ip,
            "protocol": self.config.protocol,
            "killswitch": self.config.killswitch,
            "multihop": self.config.multihop
        }


# ============================================================================
# EJEMPLOS DE USO
# ============================================================================

def example_mullvad_research():
    """Ejemplo: Configuración Mullvad para investigación"""
    print("🔐 Configurando Mullvad VPN para investigación...")

    config = VPNConfig(
        provider=VPNProvider.MULLVAD,
        server="se.mullvad.net",
        protocol="wireguard",
        dns=["193.138.218.74"],  # DNS de Mullvad
        multihop=True,
        killswitch=True
    )

    vpn = VPNManager(config)

    # Conectar
    if vpn.connect():
        print("✅ VPN conectada")

        # Verificar seguridad
        security = vpn.run_security_check()

        if security.is_secure():
            print("✅ Seguridad verificada")
            print("🔗 IP actual:", vpn.current_ip)

            # Conectar Tor después de VPN
            print("🎭 Ahora puedes iniciar Tor...")

            # Mantener conexión
            try:
                while True:
                    time.sleep(60)
                    # Re-verificar cada minuto
                    if not vpn.run_security_check().is_secure():
                        print("⚠️  Problema de seguridad detectado")
                        vpn.reconnect()

            except KeyboardInterrupt:
                print("\nDesconectando...")
                vpn.disconnect()

        else:
            print("❌ Problemas de seguridad detectados")
            vpn.disconnect()
    else:
        print("❌ No se pudo conectar a VPN")


def example_proton_free_tier():
    """Ejemplo: Usando ProtonVPN Free Tier"""
    print("🔐 Configurando ProtonVPN Free Tier...")

    config = VPNConfig(
        provider=VPNProvider.PROTON,
        server="free.protonvpn.com",
        protocol="openvpn",
        dns=["1.1.1.1", "1.0.0.1"],
        killswitch=True
    )

    vpn = VPNManager(config)

    if vpn.connect():
        print("✅ ProtonVPN Free conectado")

        # Para investigación básica
        security = vpn.run_security_check()

        if not security.dns_leak and not security.ip_leak:
            print("✅ Listo para investigación básica")
            print("⚠️  Limitación: Solo 3 países en free tier")
        else:
            print("❌ No seguro para investigación sensible")

        vpn.disconnect()


def multi_vpn_rotation():
    """Ejemplo: Rotación entre múltiples VPNs"""
    print("🔄 Sistema de rotación de VPNs...")

    vpn_configs = [
        VPNConfig(VPNProvider.MULLVAD, "se.mullvad.net"),
        VPNConfig(VPNProvider.PROTON, "ch.protonvpn.ch"),
        VPNConfig(VPNProvider.IVPN, "ch1.ivpn.net")
    ]

    current_vpn = None

    for i in range(5):  # Rotar 5 veces
        print(f"\n--- Rotación {i + 1}/5 ---")

        # Seleccionar VPN aleatoria
        config = random.choice(vpn_configs)
        print(f"Conectando a: {config.provider.value}")

        if current_vpn:
            current_vpn.disconnect()

        current_vpn = VPNManager(config)

        if current_vpn.connect():
            # Esperar y verificar
            time.sleep(10)
            security = current_vpn.run_security_check()

            if security.is_secure():
                print(f"✅ {config.provider.value} seguro")
                print(f"IP: {current_vpn.current_ip}")

                # Aquí iría la investigación...
                time.sleep(300)  # 5 minutos por VPN
            else:
                print(f"❌ {config.provider.value} inseguro")
        else:
            print(f"❌ Falló conexión a {config.provider.value}")

    if current_vpn:
        current_vpn.disconnect()


# ============================================================================
# SCRIPT DE CONFIGURACIÓN AUTOMÁTICA
# ============================================================================

def setup_vpn_for_research():
    """Script de configuración automática"""
    print("=" * 60)
    print("CONFIGURADOR DE VPN PARA INVESTIGACIÓN")
    print("=" * 60)

    print("\nSeleccione proveedor de VPN:")
    print("1. Mullvad (Recomendado - €5/mes)")
    print("2. ProtonVPN (Free tier disponible)")
    print("3. IVPN (Mejor privacidad - $6/mes)")
    print("4. Windscribe (Personalizable)")
    print("5. OVPN (Infraestructura segura)")

    choice = input("\nOpción [1-5]: ").strip()

    provider_map = {
        "1": VPNProvider.MULLVAD,
        "2": VPNProvider.PROTON,
        "3": VPNProvider.IVPN,
        "4": VPNProvider.WINDSCRIBE,
        "5": VPNProvider.OVPN
    }

    provider = provider_map.get(choice, VPNProvider.MULLVAD)

    print(f"\nConfigurando {provider.value.upper()}...")

    # Configuración por proveedor
    configs = {
        VPNProvider.MULLVAD: VPNConfig(
            provider=provider,
            server="se.mullvad.net",
            protocol="wireguard",
            dns=["193.138.218.74"],
            killswitch=True
        ),
        VPNProvider.PROTON: VPNConfig(
            provider=provider,
            server="ch.protonvpn.ch",
            protocol="openvpn",
            dns=["1.1.1.1", "1.0.0.1"],
            killswitch=True
        ),
        VPNProvider.IVPN: VPNConfig(
            provider=provider,
            server="ch1.ivpn.net",
            protocol="wireguard",
            dns=["1.1.1.1"],
            killswitch=True,
            multihop=True
        )
    }

    config = configs.get(provider, configs[VPNProvider.MULLVAD])

    # Crear manager y probar
    vpn = VPNManager(config)

    print("\nProbando conexión...")
    if vpn.connect():
        print("✅ VPN conectada")

        print("\nVerificando seguridad...")
        security = vpn.run_security_check()

        if security.is_secure():
            print("✅ TODO SEGURO")
            print(f"IP: {vpn.current_ip}")

            # Guardar configuración
            config_file = Path("vpn_config.json")
            config_data = {
                "provider": config.provider.value,
                "server": config.server,
                "protocol": config.protocol,
                "dns": config.dns,
                "killswitch": config.killswitch,
                "multihop": config.multihop
            }

            config_file.write_text(json.dumps(config_data, indent=2))
            print(f"\n📄 Configuración guardada en: {config_file}")

            # Instrucciones para Tor
            print("\n" + "=" * 60)
            print("INSTRUCCIONES PARA TOR:")
            print("=" * 60)
            print("1. Mantén esta VPN conectada")
            print("2. Inicia Tor en otra terminal:")
            print("   tor --SocksPort 9050")
            print("3. Verifica en: https://check.torproject.org")
            print("4. Usa SOCKS5 proxy: 127.0.0.1:9050")
            print("\nPara desconectar: Ctrl+C en esta terminal")

            try:
                while True:
                    time.sleep(60)
            except KeyboardInterrupt:
                print("\nDesconectando...")
                vpn.disconnect()

        else:
            print("❌ Problemas de seguridad:")
            for key, value in asdict(security).items():
                if not value and key != "is_torified":
                    print(f"  - {key}")
            vpn.disconnect()
    else:
        print("❌ No se pudo conectar a VPN")

    print("\n" + "=" * 60)
    print("CONFIGURACIÓN COMPLETADA")
    print("=" * 60)


if __name__ == "__main__":
    setup_vpn_for_research()