# En Whonix Gateway:
sudo apt update
sudo apt install wireguard-tools

# Crear configuración WireGuard
sudo nano /etc/wireguard/mullvad.conf

# Contenido:
[Interface]
PrivateKey = TU_LLAVE_PRIVADA
Address = 10.64.0.1/32
DNS = 193.138.218.74

[Peer]
PublicKey = LLAVE_PÚBLICA_SERVIDOR
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = se.mullvad.net:443  # Puerto 443 para evadir bloqueos
PersistentKeepalive = 25

# Activar
sudo wg-quick up mullvad

# Configurar Whonix para usar Mullvad
# Editar /usr/local/etc/torrc.d/50_user.conf
SocksPort 9050
SocksPolicy accept 10.64.0.0/24
RunAsDaemon 1


┌─────────────────────────────────────────────────────┐
│         CONFIGURACIÓN DE ANONIMIDAD MÁXIMA          │
├─────────────────────────────────────────────────────┤
│                                                     │
│  MÁQUINA HOST:                                      │
│    • Whonix Gateway (aislamiento total)             │
│    o Tails OS (live USB, sin persistencia)          │
│                                                     │
│  CONEXIÓN:                                          │
│    [Whonix Workstation] → [Whonix Gateway] →        │
│    [Mullvad VPN] → [Tor Network] → [Destino]        │
│                                                     │
│  CARACTERÍSTICAS:                                   │
│    • VPN paga con Monero/envío efectivo             │
│    • Cuenta solo con número aleatorio               │
│    • WireGuard en puerto 443 (evade bloqueos)       │
│    • Killswitch activado                            │
│    • DNS exclusivo de Mullvad                       │
│    • Máquina virtual sin acceso a host              │
│    • Sin persistencia (se borra todo al apagar)     │
└─────────────────────────────────────────────────────┘
