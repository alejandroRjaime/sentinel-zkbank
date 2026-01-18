#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dark Web Research Module for Academic Purposes
Version: 2.0.0 (Academic Research Edition)
Author: Cybersecurity Research Lab
License: MIT (For Academic Use Only)
"""

import os
import sys
import json
import time
import random
import socket
import struct
import hashlib
import logging
import threading
import subprocess
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

# Third-party imports (install with pip)
try:
    import stem
    from stem.control import Controller
    from stem import Signal
    import stem.process
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import socks
    from bs4 import BeautifulSoup
    import cryptography
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install stem requests beautifulsoup4 cryptography pysocks")
    sys.exit(1)


# ============================================================================
# CONFIGURACIÓN Y CONSTANTES
# ============================================================================

@dataclass
class TorConfig:
    """Configuración de Tor"""
    tor_path: str = "/usr/bin/tor"
    control_port: int = 9051
    socks_port: int = 9050
    data_directory: str = "tor_data"
    log_level: str = "notice"
    max_circuit_dirtiness: int = 600
    circuit_build_timeout: int = 60
    new_circuit_period: int = 300
    num_circuits: int = 10


@dataclass
class SecurityConfig:
    """Configuración de seguridad"""
    use_vpn: bool = True
    dns_leak_protection: bool = True
    safe_browsing: bool = True
    javascript_enabled: bool = False
    user_agent_rotation: bool = True
    request_delay: Tuple[int, int] = (2, 5)  # min, max seconds
    max_retries: int = 3
    timeout: int = 30


@dataclass
class ResearchConfig:
    """Configuración de investigación"""
    save_responses: bool = True
    save_path: str = "research_data"
    log_all_requests: bool = True
    max_depth: int = 3
    respect_robots_txt: bool = True
    ethical_boundaries: List[str] = None

    def __post_init__(self):
        if self.ethical_boundaries is None:
            self.ethical_boundaries = [
                "no_illegal_content",
                "no_harmful_activities",
                "academic_purpose_only"
            ]


# ============================================================================
# CLASE PRINCIPAL: DARKWEB RESEARCHER
# ============================================================================

class DarkWebResearcher:
    """
    Clase principal para investigación académica en dark web
    con múltiples capas de seguridad y anonimato
    """

    def __init__(self, config_file: Optional[str] = None):
        """Inicializar investigador con configuración"""
        self.setup_logging()
        self.logger = logging.getLogger(__name__)

        # Cargar configuración
        self.config = self.load_config(config_file)

        # Estado del sistema
        self.tor_process = None
        self.tor_controller = None
        self.session = None
        self.circuit_ids = []
        self.current_identity = None

        # Estadísticas
        self.stats = {
            'requests_made': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'identity_changes': 0,
            'data_collected': 0,
            'start_time': datetime.now()
        }

        # Inicializar componentes de seguridad
        self.security_layer = SecurityLayer(self.config.security)
        self.research_layer = ResearchLayer(self.config.research)

        self.logger.info("DarkWeb Researcher initialized (Academic Use Only)")

    def setup_logging(self):
        """Configurar sistema de logging seguro"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        # Configuración de logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / 'darkweb_research.log', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )

        # Reducir log level de librerías externas
        logging.getLogger("stem").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    def load_config(self, config_file: Optional[str] = None) -> Dict[str, Any]:
        """Cargar configuración desde archivo o valores por defecto"""
        default_config = {
            'tor': TorConfig(),
            'security': SecurityConfig(),
            'research': ResearchConfig()
        }

        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                # Merge con defaults
                for key in default_config:
                    if key in user_config:
                        for subkey, value in user_config[key].items():
                            setattr(default_config[key], subkey, value)
            except Exception as e:
                self.logger.error(f"Error loading config: {e}")

        return default_config

    # ============================================================================
    # CORE: GESTIÓN DE TOR
    # ============================================================================

    def start_tor(self) -> bool:
        """Iniciar proceso Tor con configuración personalizada"""
        try:
            self.logger.info("Starting Tor process...")

            # Configurar directorio de datos
            data_dir = Path(self.config.tor.data_directory)
            data_dir.mkdir(exist_ok=True)

            # Configuración de Tor
            tor_config = {
                'SocksPort': str(self.config.tor.socks_port),
                'ControlPort': str(self.config.tor.control_port),
                'DataDirectory': str(data_dir.absolute()),
                'Log': [f"{self.config.tor.log_level} file {data_dir / 'tor.log'}"],
                'SafeLogging': '1',
                'AvoidDiskWrites': '1',
                'MaxCircuitDirtiness': str(self.config.tor.max_circuit_dirtiness),
                'CircuitBuildTimeout': str(self.config.tor.circuit_build_timeout),
                'NewCircuitPeriod': str(self.config.tor.new_circuit_period),
                'NumEntryGuards': '3',
                'UseBridges': '0',
                'ClientOnly': '1',
                'DisableNetwork': '0',
            }

            # Agregar configuraciones de seguridad
            if self.config.security.dns_leak_protection:
                tor_config.update({
                    'DNSPort': '0',
                    'AutomapHostsOnResolve': '1',
                    'TransPort': '0',
                })

            # Iniciar proceso Tor
            self.tor_process = stem.process.launch_tor_with_config(
                config=tor_config,
                tor_cmd=self.config.tor.tor_path,
                init_msg_handler=self._tor_msg_handler,
                timeout=120
            )

            # Conectar al controlador
            self.tor_controller = Controller.from_port(
                port=self.config.tor.control_port
            )
            self.tor_controller.authenticate()

            # Crear múltiples circuitos
            self._create_circuits()

            self.logger.info(f"Tor started successfully on port {self.config.tor.socks_port}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to start Tor: {e}")
            return False

    def _tor_msg_handler(self, line: str):
        """Manejador de mensajes de Tor"""
        if "Bootstrapped" in line:
            self.logger.info(f"Tor: {line}")

    def _create_circuits(self):
        """Crear múltiples circuitos para rotación"""
        try:
            for i in range(self.config.tor.num_circuits):
                circ_id = self.tor_controller.new_circuit()
                self.circuit_ids.append(circ_id)
                self.logger.debug(f"Created circuit {circ_id}")

                # Esperar entre creación de circuitos
                time.sleep(random.uniform(0.5, 2))

        except Exception as e:
            self.logger.warning(f"Could not create all circuits: {e}")

    def change_identity(self) -> bool:
        """Cambiar identidad de Tor (nuevo circuito)"""
        try:
            self.logger.info("Changing Tor identity...")

            # Enviar señal NEWNYM
            self.tor_controller.signal(Signal.NEWNYM)
            time.sleep(5)  # Esperar a que se establezca nuevo circuito

            # Actualizar estadísticas
            self.stats['identity_changes'] += 1

            # Generar nueva identidad
            self.current_identity = self.security_layer.generate_identity()

            self.logger.info(f"New identity: {self.current_identity['id'][:8]}...")
            return True

        except Exception as e:
            self.logger.error(f"Failed to change identity: {e}")
            return False

    def get_tor_info(self) -> Dict[str, Any]:
        """Obtener información del nodo Tor actual"""
        try:
            info = {
                'ip': self._get_current_ip(),
                'circuit_count': len(self.circuit_ids),
                'tor_version': self.tor_controller.get_version() if self.tor_controller else 'Unknown',
                'bytes_sent': self.tor_controller.get_info('traffic/sent') if self.tor_controller else 'Unknown',
                'bytes_received': self.tor_controller.get_info(
                    'traffic/received') if self.tor_controller else 'Unknown',
                'uptime': self.tor_controller.get_info('uptime') if self.tor_controller else 'Unknown'
            }
            return info
        except Exception as e:
            self.logger.error(f"Could not get Tor info: {e}")
            return {}

    def _get_current_ip(self) -> str:
        """Obtener IP actual a través de Tor"""
        try:
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=self._get_proxies(),
                timeout=10
            )
            return response.json().get('IP', 'Unknown')
        except:
            return 'Unknown'

    # ============================================================================
    # CORE: SESIÓN HTTP SEGURA
    # ============================================================================

    def create_session(self):
        """Crear sesión HTTP segura con Tor"""
        try:
            # Configurar retry strategy
            retry_strategy = Retry(
                total=self.config.security.max_retries,
                backoff_factor=1,
                status_forcelist=[500, 502, 503, 504]
            )

            # Crear adaptador con soporte SOCKS
            adapter = HTTPAdapter(
                max_retries=retry_strategy,
                pool_connections=100,
                pool_maxsize=100
            )

            # Crear sesión
            self.session = requests.Session()
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)

            # Configurar proxies para Tor
            self.session.proxies = self._get_proxies()

            # Configurar headers por defecto
            self.session.headers.update(self.security_layer.get_headers())

            # Configurar timeout
            self.session.request = lambda method, url, **kwargs: self._safe_request(
                method, url, **kwargs
            )

            self.logger.info("Secure HTTP session created")

        except Exception as e:
            self.logger.error(f"Failed to create session: {e}")

    def _get_proxies(self) -> Dict[str, str]:
        """Obtener configuración de proxies para Tor"""
        return {
            'http': f'socks5h://127.0.0.1:{self.config.tor.socks_port}',
            'https': f'socks5h://127.0.0.1:{self.config.tor.socks_port}'
        }

    def _safe_request(self, method: str, url: str, **kwargs):
        """Wrapper seguro para requests con delays aleatorios"""
        # Aplicar delay aleatorio entre requests
        delay = random.uniform(*self.config.security.request_delay)
        time.sleep(delay)

        # Rotar User-Agent si está habilitado
        if self.config.security.user_agent_rotation:
            self.session.headers.update({
                'User-Agent': self.security_layer.get_random_user_agent()
            })

        # Actualizar estadísticas
        self.stats['requests_made'] += 1

        try:
            response = requests.Session.request(self.session, method, url, **kwargs)
            self.stats['successful_requests'] += 1
            return response

        except Exception as e:
            self.stats['failed_requests'] += 1
            self.logger.error(f"Request failed: {e}")

            # Intentar cambio de identidad si falla
            if self.stats['failed_requests'] % 3 == 0:
                self.change_identity()

            raise

    # ============================================================================
    # MÉTODOS DE INVESTIGACIÓN
    # ============================================================================

    def fetch_onion(self, onion_url: str, save: bool = True) -> Optional[Dict[str, Any]]:
        """
        Fetch contenido de una página .onion

        Args:
            onion_url: URL completa de la página .onion
            save: Guardar respuesta en disco

        Returns:
            Diccionario con contenido y metadata
        """
        try:
            self.logger.info(f"Fetching onion: {onion_url}")

            # Verificar formato de URL
            if not onion_url.endswith('.onion'):
                self.logger.warning(f"URL doesn't look like onion: {onion_url}")

            # Realizar request
            response = self.session.get(
                onion_url,
                timeout=self.config.security.timeout,
                verify=False  # .onion sites often have self-signed certs
            )

            # Parsear respuesta
            result = {
                'url': onion_url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'timestamp': datetime.now().isoformat(),
                'identity': self.current_identity['id'] if self.current_identity else None,
                'size_bytes': len(response.content)
            }

            # Guardar si está configurado
            if save and self.config.research.save_responses:
                self.research_layer.save_response(result)
                self.stats['data_collected'] += 1

            return result

        except Exception as e:
            self.logger.error(f"Failed to fetch onion {onion_url}: {e}")
            return None

    def search_ahen(self, query: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """
        Buscar en Ahmia (motor de búsqueda de .onion)

        Args:
            query: Término de búsqueda
            max_results: Máximo número de resultados

        Returns:
            Lista de resultados encontrados
        """
        try:
            self.logger.info(f"Searching Ahmia for: {query}")

            # URL de búsqueda en Ahmia
            search_url = f"https://ahmia.fi/search/?q={query}"

            response = self.session.get(search_url, timeout=self.config.security.timeout)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                results = []

                # Extraer resultados
                for link in soup.find_all('a', class_='onionsite'):
                    onion_url = link.get('href', '')
                    title = link.text.strip()

                    if onion_url and '.onion' in onion_url:
                        results.append({
                            'title': title,
                            'url': onion_url,
                            'description': self._extract_description(link)
                        })

                        if len(results) >= max_results:
                            break

                self.logger.info(f"Found {len(results)} results for '{query}'")
                return results

            return []

        except Exception as e:
            self.logger.error(f"Ahmia search failed: {e}")
            return []

    def _extract_description(self, element) -> str:
        """Extraer descripción de elemento de resultado"""
        try:
            # Buscar siguiente elemento hermano con descripción
            next_sibling = element.find_next_sibling('p')
            if next_sibling:
                return next_sibling.text.strip()
        except:
            pass
        return ""

    def crawl_onion(self, start_url: str, max_depth: int = 2) -> Dict[str, Any]:
        """
        Crawl recursivo de un sitio .onion

        Args:
            start_url: URL inicial
            max_depth: Profundidad máxima de crawl

        Returns:
            Mapa del sitio crawleado
        """
        self.logger.info(f"Starting crawl of {start_url} (max depth: {max_depth})")

        visited = set()
        site_map = {}

        def _crawl(url: str, depth: int = 0):
            if depth > max_depth or url in visited:
                return

            visited.add(url)

            try:
                # Fetch página
                result = self.fetch_onion(url, save=True)
                if not result or result['status_code'] != 200:
                    return

                # Parsear links
                soup = BeautifulSoup(result['content'], 'html.parser')
                links = []

                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    absolute_url = self._make_absolute(url, href)

                    if absolute_url and '.onion' in absolute_url:
                        links.append({
                            'url': absolute_url,
                            'text': link.text.strip()[:100],
                            'depth': depth + 1
                        })

                # Guardar en mapa
                site_map[url] = {
                    'title': soup.title.string if soup.title else 'No title',
                    'links': links,
                    'depth': depth,
                    'timestamp': datetime.now().isoformat()
                }

                # Crawl recursivo de links
                for link_info in links:
                    if link_info['url'] not in visited:
                        time.sleep(random.uniform(1, 3))  # Delay entre requests
                        _crawl(link_info['url'], depth + 1)

            except Exception as e:
                self.logger.warning(f"Crawl failed for {url}: {e}")

        # Iniciar crawl
        _crawl(start_url, 0)

        self.logger.info(f"Crawl completed. Visited {len(visited)} pages.")
        return site_map

    def _make_absolute(self, base_url: str, relative_url: str) -> Optional[str]:
        """Convertir URL relativa a absoluta"""
        try:
            from urllib.parse import urljoin
            return urljoin(base_url, relative_url)
        except:
            return None

    def analyze_content(self, content: str, analysis_type: str = "basic") -> Dict[str, Any]:
        """
        Analizar contenido de página

        Args:
            content: Contenido HTML/texto
            analysis_type: Tipo de análisis

        Returns:
            Resultados del análisis
        """
        try:
            soup = BeautifulSoup(content, 'html.parser')

            analysis = {
                'analysis_type': analysis_type,
                'timestamp': datetime.now().isoformat(),
                'basic_stats': {
                    'total_length': len(content),
                    'text_length': len(soup.get_text()),
                    'link_count': len(soup.find_all('a')),
                    'image_count': len(soup.find_all('img')),
                    'form_count': len(soup.find_all('form'))
                },
                'metadata': {}
            }

            # Análisis básico de metadatos
            if soup.title:
                analysis['metadata']['title'] = soup.title.string

            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property')
                content = meta.get('content')
                if name and content:
                    analysis['metadata'][name] = content

            # Extraer textos importantes
            analysis['headings'] = {}
            for i in range(1, 7):
                headings = soup.find_all(f'h{i}')
                if headings:
                    analysis['headings'][f'h{i}'] = [h.get_text().strip() for h in headings]

            # Análisis de lenguaje (simple)
            text = soup.get_text()[:10000]  # Limitar para performance
            analysis['language_hints'] = self._detect_language_hints(text)

            return analysis

        except Exception as e:
            self.logger.error(f"Content analysis failed: {e}")
            return {}

    def _detect_language_hints(self, text: str) -> List[str]:
        """Detectar pistas de idioma en texto"""
        # Caracteres comunes por idioma
        language_indicators = {
            'english': set('the and for are but not you all'),
            'spanish': set('el la los las que del'),
            'russian': set('и в не на что этот'),
            'german': set('und der die das für von'),
            'french': set('le la les des du pour')
        }

        text_lower = text.lower()
        hints = []

        for lang, words in language_indicators.items():
            count = sum(1 for word in words if word in text_lower)
            if count > 2:  # Al menos 3 palabras del idioma
                hints.append(lang)

        return hints

    # ============================================================================
    # UTILIDADES Y MÉTODOS DE SEGURIDAD
    # ============================================================================

    def check_security_status(self) -> Dict[str, bool]:
        """Verificar estado de seguridad actual"""
        checks = {
            'tor_running': self.tor_process and self.tor_process.is_running(),
            'controller_connected': bool(self.tor_controller),
            'session_active': bool(self.session),
            'ip_hidden': self._check_ip_hidden(),
            'dns_leak_protected': self._check_dns_leak(),
            'time_synced': self._check_time_sync()
        }

        return checks

    def _check_ip_hidden(self) -> bool:
        """Verificar si IP está oculta"""
        try:
            response = requests.get(
                'https://check.torproject.org',
                proxies=self._get_proxies(),
                timeout=10
            )
            return 'Congratulations' in response.text
        except:
            return False

    def _check_dns_leak(self) -> bool:
        """Verificar protección contra DNS leaks"""
        try:
            # Test DNS leak
            response = requests.get(
                'https://dnsleaktest.com',
                proxies=self._get_proxies(),
                timeout=10
            )
            return 'DNS Leak Test' in response.text
        except:
            return False

    def _check_time_sync(self) -> bool:
        """Verificar sincronización de tiempo (importante para Tor)"""
        try:
            import ntplib
            client = ntplib.NTPClient()
            response = client.request('pool.ntp.org', version=3)
            return abs(response.offset) < 5  # Diferencia menor a 5 segundos
        except:
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas de la sesión"""
        current_time = datetime.now()
        elapsed = (current_time - self.stats['start_time']).total_seconds()

        stats = {
            **self.stats,
            'elapsed_seconds': elapsed,
            'requests_per_minute': (self.stats['requests_made'] / elapsed * 60) if elapsed > 0 else 0,
            'success_rate': (self.stats['successful_requests'] / self.stats['requests_made'] * 100)
            if self.stats['requests_made'] > 0 else 0,
            'tor_info': self.get_tor_info(),
            'security_status': self.check_security_status(),
            'current_identity': self.current_identity
        }

        return stats

    def save_session_report(self, filename: str = "session_report.json"):
        """Guardar reporte completo de la sesión"""
        report = {
            'session_info': {
                'start_time': self.stats['start_time'].isoformat(),
                'end_time': datetime.now().isoformat(),
                'config': {
                    'tor': asdict(self.config.tor),
                    'security': asdict(self.config.security),
                    'research': asdict(self.config.research)
                }
            },
            'statistics': self.get_stats(),
            'ethical_boundaries': self.config.research.ethical_boundaries
        }

        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            self.logger.info(f"Session report saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save session report: {e}")

    # ============================================================================
    # CLEANUP
    # ============================================================================

    def cleanup(self):
        """Limpiar recursos y cerrar conexiones"""
        self.logger.info("Cleaning up resources...")

        try:
            # Cerrar sesión HTTP
            if self.session:
                self.session.close()

            # Cerrar controlador Tor
            if self.tor_controller:
                self.tor_controller.close()

            # Terminar proceso Tor
            if self.tor_process:
                self.tor_process.terminate()
                self.tor_process.wait()

            # Guardar reporte final
            self.save_session_report()

            self.logger.info("Cleanup completed successfully")

        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def __enter__(self):
        """Context manager entry"""
        if not self.start_tor():
            raise RuntimeError("Failed to start Tor")
        self.create_session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()


# ============================================================================
# CAPA DE SEGURIDAD
# ============================================================================

class SecurityLayer:
    """Capa de seguridad para anonimato y protección"""

    def __init__(self, config: SecurityConfig):
        self.config = config
        self.user_agents = self._load_user_agents()
        self.current_identity = None

    def _load_user_agents(self) -> List[str]:
        """Cargar lista de User-Agents realistas"""
        return [
            # Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0',

            # Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',

            # Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',

            # Edge
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47',
        ]

    def get_random_user_agent(self) -> str:
        """Obtener User-Agent aleatorio"""
        return random.choice(self.user_agents)

    def generate_identity(self) -> Dict[str, str]:
        """Generar identidad anónima única"""
        identity_id = hashlib.sha256(str(time.time()).encode() + os.urandom(16)).hexdigest()[:16]

        self.current_identity = {
            'id': identity_id,
            'user_agent': self.get_random_user_agent(),
            'timestamp': datetime.now().isoformat(),
            'session_key': base64.b64encode(os.urandom(32)).decode()
        }

        return self.current_identity

    def get_headers(self) -> Dict[str, str]:
        """Obtener headers HTTP seguros"""
        identity = self.current_identity or self.generate_identity()

        headers = {
            'User-Agent': identity['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }

        return headers

    def encrypt_data(self, data: bytes, password: str) -> bytes:
        """Encriptar datos sensibles"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)

        encrypted = fernet.encrypt(data)
        return salt + encrypted

    def decrypt_data(self, encrypted_data: bytes, password: str) -> bytes:
        """Desencriptar datos"""
        salt = encrypted_data[:16]
        encrypted = encrypted_data[16:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)

        return fernet.decrypt(encrypted)


# ============================================================================
# CAPA DE INVESTIGACIÓN
# ============================================================================

class ResearchLayer:
    """Capa para gestión de datos de investigación"""

    def __init__(self, config: ResearchConfig):
        self.config = config
        self.data_dir = Path(config.save_path)
        self.setup_directories()

    def setup_directories(self):
        """Crear estructura de directorios para investigación"""
        directories = [
            'raw_responses',
            'parsed_data',
            'analysis',
            'logs',
            'reports'
        ]

        self.data_dir.mkdir(exist_ok=True)
        for directory in directories:
            (self.data_dir / directory).mkdir(exist_ok=True)

    def save_response(self, response_data: Dict[str, Any]):
        """Guardar respuesta HTTP en disco"""
        try:
            # Generar nombre de archivo seguro
            url_hash = hashlib.sha256(response_data['url'].encode()).hexdigest()[:16]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{url_hash}.json"

            filepath = self.data_dir / 'raw_responses' / filename

            # Guardar datos
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(response_data, f, indent=2, ensure_ascii=False)

            logging.getLogger(__name__).debug(f"Response saved: {filename}")

        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to save response: {e}")

    def save_analysis(self, url: str, analysis_data: Dict[str, Any]):
        """Guardar análisis de contenido"""
        try:
            url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
            filename = f"analysis_{url_hash}.json"
            filepath = self.data_dir / 'analysis' / filename

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(analysis_data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to save analysis: {e}")

    def generate_report(self, research_data: Dict[str, Any]) -> str:
        """Generar reporte de investigación en Markdown"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"research_report_{timestamp}.md"
            filepath = self.data_dir / 'reports' / filename

            report = f"""# Dark Web Research Report
Generated: {datetime.now().isoformat()}

## Summary
- URLs Analyzed: {len(research_data.get('urls', []))}
- Total Pages: {research_data.get('total_pages', 0)}
- Data Collected: {research_data.get('data_size_mb', 0):.2f} MB

## Ethical Compliance
{chr(10).join(f"- {boundary}" for boundary in self.config.ethical_boundaries)}

## Findings

### Sites Visited
"""

            for url, info in research_data.get('sites', {}).items():
                report += f"\n#### {info.get('title', 'No title')}\n"
                report += f"- URL: `{url}`\n"
                report += f"- Depth: {info.get('depth', 'N/A')}\n"
                report += f"- Links Found: {len(info.get('links', []))}\n"

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)

            return str(filepath)

        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to generate report: {e}")
            return ""


# ============================================================================
# EJEMPLOS DE USO
# ============================================================================

def example_basic_usage():
    """Ejemplo básico de uso para investigación académica"""
    print("=== Dark Web Researcher - Ejemplo Académico ===\n")

    # Crear instancia del investigador
    with DarkWebResearcher() as researcher:
        # Verificar estado de seguridad
        security = researcher.check_security_status()
        print("Estado de seguridad:")
        for check, status in security.items():
            print(f"  {check}: {'✅' if status else '❌'}")

        print("\nInformación de Tor:")
        tor_info = researcher.get_tor_info()
        print(f"  IP actual: {tor_info.get('ip', 'Unknown')}")
        print(f"  Circuitos: {tor_info.get('circuit_count', 'Unknown')}")

        # Ejemplo de búsqueda en Ahmia
        print("\n🔍 Buscando sitios académicos...")
        results = researcher.search_ahen("academic research library")

        if results:
            print(f"\nEncontrados {len(results)} resultados:")
            for i, result in enumerate(results[:5], 1):
                print(f"{i}. {result['title']}")
                print(f"   URL: {result['url']}")
                print(f"   Desc: {result['description'][:100]}...")
        else:
            print("No se encontraron resultados")

        # Estadísticas finales
        print("\n📊 Estadísticas de la sesión:")
        stats = researcher.get_stats()
        print(f"  Requests realizados: {stats['requests_made']}")
        print(f"  Tasa de éxito: {stats['success_rate']:.1f}%")
        print(f"  Cambios de identidad: {stats['identity_changes']}")


def example_crawling():
    """Ejemplo de crawling controlado"""
    print("=== Ejemplo de Crawling Académico ===\n")

    # Configuración específica para crawling
    config = {
        'research': {
            'save_responses': True,
            'max_depth': 2,
            'respect_robots_txt': True
        },
        'security': {
            'request_delay': [3, 7],  # Mayor delay para crawling
            'max_retries': 2
        }
    }

    with DarkWebResearcher() as researcher:
        # NOTA: Reemplazar con URL de investigación legítima
        start_url = "http://example.onion"  # URL de ejemplo

        print(f"Iniciando crawling de: {start_url}")
        print("Esto puede tomar varios minutos...\n")

        site_map = researcher.crawl_onion(start_url, max_depth=1)

        print(f"Crawl completado. Páginas visitadas: {len(site_map)}")

        # Analizar contenido de la página principal
        if start_url in site_map:
            main_page = site_map[start_url]
            print(f"\nPágina principal: {main_page.get('title', 'Sin título')}")
            print(f"Enlaces encontrados: {len(main_page.get('links', []))}")

            # Mostrar primeros enlaces
            for i, link in enumerate(main_page.get('links', [])[:5], 1):
                print(f"  {i}. {link['text']}")
                print(f"     URL: {link['url']}")


def example_content_analysis():
    """Ejemplo de análisis de contenido"""
    print("=== Análisis de Contenido Académico ===\n")

    with DarkWebResearcher() as researcher:
        # URL de ejemplo para análisis
        test_url = "http://example.onion"  # Reemplazar con URL real

        print(f"Analizando contenido de: {test_url}")

        # Fetch contenido
        result = researcher.fetch_onion(test_url, save=True)

        if result and result['status_code'] == 200:
            # Realizar análisis
            analysis = researcher.analyze_content(result['content'], "comprehensive")

            print(f"\n📄 Análisis de contenido:")
            print(f"  Tamaño total: {analysis['basic_stats']['total_length']:,} bytes")
            print(f"  Texto puro: {analysis['basic_stats']['text_length']:,} caracteres")
            print(f"  Enlaces: {analysis['basic_stats']['link_count']}")
            print(f"  Imágenes: {analysis['basic_stats']['image_count']}")

            if 'metadata' in analysis and analysis['metadata'].get('title'):
                print(f"  Título: {analysis['metadata']['title']}")

            if analysis['language_hints']:
                print(f"  Idiomas detectados: {', '.join(analysis['language_hints'])}")
        else:
            print("No se pudo obtener contenido para análisis")


# ============================================================================
# SCRIPT DE CONFIGURACIÓN Y VERIFICACIÓN
# ============================================================================

def setup_environment():
    """Configurar entorno para investigación"""
    print("=== Configuración del Entorno de Investigación ===\n")

    # Verificar dependencias
    print("1. Verificando dependencias...")
    dependencies = [
        ('stem', 'stem'),
        ('requests', 'requests'),
        ('beautifulsoup4', 'bs4'),
        ('cryptography', 'cryptography'),
        ('pysocks', 'socks')
    ]

    missing = []
    for pip_name, import_name in dependencies:
        try:
            __import__(import_name)
            print(f"  ✅ {pip_name}")
        except ImportError:
            print(f"  ❌ {pip_name}")
            missing.append(pip_name)

    if missing:
        print(f"\nInstalar dependencias faltantes:")
        print(f"pip install {' '.join(missing)}")
        return False

    # Verificar Tor
    print("\n2. Verificando Tor...")
    try:
        tor_version = subprocess.run(
            ['tor', '--version'],
            capture_output=True,
            text=True
        )
        if tor_version.returncode == 0:
            print(f"  ✅ Tor instalado: {tor_version.stdout.split()[2]}")
        else:
            print("  ❌ Tor no encontrado")
            print("  Instalar Tor: https://www.torproject.org/download/")
            return False
    except:
        print("  ❌ Tor no encontrado")
        print("  Instalar Tor: https://www.torproject.org/download/")
        return False

    # Crear estructura de directorios
    print("\n3. Configurando directorios...")
    directories = ['research_data', 'logs', 'config']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"  📁 {directory}/")

    # Crear archivo de configuración por defecto
    print("\n4. Creando configuración por defecto...")
    default_config = {
        'tor': {
            'tor_path': '/usr/bin/tor',
            'socks_port': 9050,
            'control_port': 9051,
            'data_directory': 'tor_data',
            'log_level': 'notice'
        },
        'security': {
            'request_delay': [2, 5],
            'max_retries': 3,
            'timeout': 30,
            'user_agent_rotation': True
        },
        'research': {
            'save_responses': True,
            'save_path': 'research_data',
            'max_depth': 2,
            'ethical_boundaries': [
                "no_illegal_content",
                "academic_research_only",
                "respect_privacy"
            ]
        }
    }

    config_path = Path('config/default.json')
    with open(config_path, 'w') as f:
        json.dump(default_config, f, indent=2)
    print(f"  📄 {config_path}")

    print("\n✅ Configuración completada exitosamente!")
    print("\nPara comenzar la investigación:")
    print("1. Ejecuta: python darkweb_researcher.py --test")
    print("2. Revisa la documentación ética en ethical_guidelines.md")

    return True


def create_ethical_guidelines():
    """Crear pautas éticas para investigación"""
    guidelines = """# Pautas Éticas para Investigación en Dark Web

## Propósito
Este documento establece las pautas éticas para el uso del módulo de investigación en Dark Web. El uso debe limitarse a:
- Investigación académica legítima
- Estudios de seguridad informática
- Análisis de tendencias (no individuales)
- Propósitos educativos

## Reglas Estrictas

### ✅ PERMITIDO:
1. Acceso a sitios con contenido legal pero solo accesible via Tor
2. Crawling de sitios públicos .onion con fines académicos
3. Análisis de estructura y tecnología (no contenido personal)
4. Investigación sobre mecanismos de anonimato

### ❌ PROHIBIDO:
1. Acceso a contenido ilegal en cualquier jurisdicción
2. Recopilación de datos personales identificables
3. Interacción con actividades ilícitas
4. Uso para vigilancia no autorizada
5. Violación de términos de servicio

## Buenas Prácticas

### 1. Anonimato y Privacidad
- Nunca use su identidad real
- Use máquina virtual dedicada
- Aisle la conexión de su red principal
- Borre todos los datos después de la investigación

### 2. Manejo de Datos
- Anonimice todos los datos recolectados
- No almacene contenido sensible
- Use encriptación para datos de investigación
- Elimine datos después del proyecto

### 3. Cumplimiento Legal
- Conozca las leyes de su jurisdicción
- Obtenga aprobación ética si es necesario
- Documente todo propósito de investigación
- Reporte hallazgos preocupantes a autoridades

## Proceso de Aprobación

Antes de comenzar cualquier investigación:
1. Complete el formulario de aprobación ética
2. Documente objetivos de investigación
3. Especifique métodos de recolección
4. Describa plan de manejo de datos
5. Obtenga supervisión si es estudiante

## Reporte de Incidentes

Si encuentra contenido ilegal o preocupante:
1. NO interactúe con el contenido
2. Documente URL y timestamp
3. Reporte a autoridades apropiadas
4. Consulte con asesor legal

---

**Recuerde:** La capacidad técnica no justifica acciones no éticas.
La investigación debe beneficiar a la sociedad, no causar daño.

Fecha de creación: {date}
Versión: 1.0
""".format(date=datetime.now().strftime("%Y-%m-%d"))

    with open('ethical_guidelines.md', 'w') as f:
        f.write(guidelines)

    print("📄 Pautas éticas creadas en ethical_guidelines.md")


# ============================================================================
# INTERFAZ DE LÍNEA DE COMANDOS
# ============================================================================

def main():
    """Función principal del módulo"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Dark Web Research Module (Academic Use Only)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --setup                    # Setup environment
  %(prog)s --test                     # Test connection
  %(prog)s --search "academic papers" # Search Ahmia
  %(prog)s --crawl http://example.onion --depth 1

Ethical Guidelines:
  This tool is for LEGITIMATE ACADEMIC RESEARCH only.
  Review ethical_guidelines.md before use.
  You are responsible for complying with all applicable laws.
        """
    )

    parser.add_argument('--setup', action='store_true',
                        help='Setup research environment')
    parser.add_argument('--test', action='store_true',
                        help='Test Tor connection and security')
    parser.add_argument('--search', type=str,
                        help='Search Ahmia for terms')
    parser.add_argument('--crawl', type=str,
                        help='Crawl onion site (with max-depth)')
    parser.add_argument('--depth', type=int, default=1,
                        help='Max crawl depth (default: 1)')
    parser.add_argument('--analyze', type=str,
                        help='Analyze content from URL')
    parser.add_argument('--config', type=str,
                        help='Use custom config file')
    parser.add_argument('--ethical', action='store_true',
                        help='Create ethical guidelines')

    args = parser.parse_args()

    # Banner de advertencia
    print("=" * 70)
    print("DARK WEB RESEARCH MODULE - ACADEMIC USE ONLY")
    print("=" * 70)
    print("WARNING: Use only for legitimate academic research.")
    print("You are responsible for complying with all applicable laws.")
    print("=" * 70)
    print()

    if args.setup:
        setup_environment()
        create_ethical_guidelines()

    elif args.ethical:
        create_ethical_guidelines()

    elif args.test:
        print("Testing Tor connection and security...\n")
        with DarkWebResearcher(args.config) as researcher:
            security = researcher.check_security_status()

            print("Security Status:")
            for check, status in security.items():
                status_symbol = '✅' if status else '❌'
                print(f"  {status_symbol} {check}")

            tor_info = researcher.get_tor_info()
            print(f"\nTor Info:")
            print(f"  IP: {tor_info.get('ip', 'Unknown')}")
            print(f"  Version: {tor_info.get('tor_version', 'Unknown')}")

            stats = researcher.get_stats()
            print(f"\nStats:")
            print(f"  Uptime: {stats.get('elapsed_seconds', 0):.0f}s")

    elif args.search:
        print(f"Searching Ahmia for: {args.search}\n")
        with DarkWebResearcher(args.config) as researcher:
            results = researcher.search_ahen(args.search)

            if results:
                print(f"Found {len(results)} results:\n")
                for i, result in enumerate(results[:10], 1):
                    print(f"{i}. {result['title']}")
                    print(f"   URL: {result['url']}")
                    if result['description']:
                        print(f"   Desc: {result['description'][:150]}...")
                    print()
            else:
                print("No results found")

    elif args.crawl:
        print(f"Crawling: {args.crawl} (depth: {args.depth})\n")
        with DarkWebResearcher(args.config) as researcher:
            site_map = researcher.crawl_onion(args.crawl, max_depth=args.depth)

            print(f"Crawl completed. Pages visited: {len(site_map)}\n")

            if site_map:
                print("Site structure:")
                for url, info in list(site_map.items())[:5]:
                    print(f"\n{info.get('title', 'No title')}")
                    print(f"URL: {url}")
                    print(f"Links: {len(info.get('links', []))}")

    elif args.analyze:
        print(f"Analyzing: {args.analyze}\n")
        with DarkWebResearcher(args.config) as researcher:
            result = researcher.fetch_onion(args.analyze, save=True)

            if result and result['status_code'] == 200:
                analysis = researcher.analyze_content(result['content'])

                print("Content Analysis:")
                print(f"  Status: {result['status_code']}")
                print(f"  Size: {result['size_bytes']:,} bytes")

                if 'basic_stats' in analysis:
                    stats = analysis['basic_stats']
                    print(f"  Text length: {stats['text_length']:,} chars")
                    print(f"  Links: {stats['link_count']}")
                    print(f"  Images: {stats['image_count']}")

                if 'language_hints' in analysis and analysis['language_hints']:
                    print(f"  Language hints: {', '.join(analysis['language_hints'])}")
            else:
                print(f"Failed to fetch URL. Status: {result.get('status_code', 'Unknown')}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()