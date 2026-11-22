# Yunexal Edge Router (`yunexal-router`)

Високопродуктивний Edge-маршрутизатор та L4/L7-щит для мульти-серверного Minecraft хостингу на **Rust + eBPF/XDP (`aya`)** із zero-copy ядровою пересилкою `splice(2)`, підтримкою **HAProxy PROXY Protocol v2** та **UDP-роутингом** (Simple Voice Chat / Geyser Bedrock).

## Основні можливості

- **eBPF / XDP Shield у драйвері NIC (`bpf/xdp_shield.bpf.c`):**
  - Вбудований байткод завантажується напряму через `aya` (`DRV_MODE` з автоматичним fallback на `SKB_MODE`).
  - Не чіпає SSH/HTTP/HTTPS/WireGuard та інші системні порти (`XDP_PASS` за замовчуванням).
  - У режимі **Edge**: лімітує SYN-флуд, порожній/масовий UDP-флуд та приймає динамічні авто-бани сканерів з userspace.
  - У режимі **Node Guard (`--mode=node-guard`)**: дозволяє прийом трафіку на ігрові порти **виключно з IP-адрес ваших Edge-роутерів** (без необхідності гнати ігровий трафік через VPN!).
- **Zero-Copy `splice(2)` + `TCP_NODELAY` + `TCP_QUICKACK`:**
  - Після парсингу першого Minecraft `Handshake` пакету подальша сесія передається на рівні ядра Linux через `pipe2` + `splice`, без копіювання ігрових чанків у userspace.
- **HAProxy PROXY Protocol v2:**
  - Передає справжні IPv4/IPv6 адреси гравців на `Velocity` / `Paper` / `Purpur`.
- **Кешування Server List Ping (MOTD):**
  - Per-`(backend, protocol_version)` TTL-кеш миттєво відповідає на пінги зі списку серверів прямо на Edge.
- **Динамічний `routes.json` (сумісний з `itzg/mc-router`) + HTTP API `:8085`:**
  - Автоматичне гаряче перезавантаження без обриву активних з’єднань; підтримка exact, wildcard `*.domain.com` та Forge `\0FML...\0`.

## Збірка

Потрібні `rustc`/`cargo` (1.85+), `clang` (для таргета `bpf`) та `linux-libc-dev`:

```bash
cargo test
cargo build --release
```

Готовий бінарник: `target/release/yunexal-router` (байткод `xdp_shield.o` вшитий усередину).

## Запуск

### 1. Режим Edge-роутера (публічний вхід `play.example.com`)
```bash
sudo ./yunexal-router \
  --mode=edge \
  --port=25565 \
  --routes-config=/srv/mc-router/routes.json \
  --routes-config-watch \
  --api-binding=127.0.0.1:8085 \
  --connection-rate-limit=30
```

### 2. Робота БЕЗ VPN на ігровому потоці (анонімність вузлів + 0% VPN-оверхеду)
Щоб не платити CPU/MTU-оверхедом WireGuard на ігрових пакетах і при цьому не світити IP вузлів:
1. Edge-роутер шле трафік у `routes.json` безпосередньо на публічний IP:порт вузла (напр. `NODE_IP:31565`) з `proxyProtocol: true`.
2. **На Linux-вузлі** запускаєте `--mode=node-guard`:
   ```bash
   sudo ./yunexal-router \
     --mode=node-guard \
     --edge-allow=<EDGE_PUBLIC_IP_1>,<EDGE_PUBLIC_IP_2> \
     --ports=25565,24454 \
     --interface=eth0
   ```
   Або **на MikroTik RouterOS (обов’язково в Safe Mode — `Ctrl+X`)** приймаєте `dst-nat` на нестандартний ігровий порт виключно з `src-address-list=yunexal_edges` (`in-interface-list=WAN`) і дропаєте прямі спроби з WAN (не зачіпаючи локальну мережу чи VXLAN):
   ```rsc
   # На MikroTik спочатку увімкніть Safe Mode (Ctrl+X у терміналі або кнопка Safe Mode у WinBox)!
   /ip firewall address-list
   add list=yunexal_edges address=<EDGE_PUBLIC_IP> comment="Yunexal Edge Router"

   /ip firewall filter
   add chain=forward in-interface-list=WAN protocol=tcp dst-address=<NODE_LAN_IP> dst-port=25565 src-address-list=yunexal_edges action=accept place-before=0 comment="Allow MC TCP from Edge only"
   add chain=forward in-interface-list=WAN protocol=udp dst-address=<NODE_LAN_IP> dst-port=24454 src-address-list=yunexal_edges action=accept place-before=1 comment="Allow VoiceChat UDP from Edge only"
   add chain=forward in-interface-list=WAN protocol=tcp dst-address=<NODE_LAN_IP> dst-port=25565 action=drop place-before=2 comment="Drop direct WAN MC TCP"
   add chain=forward in-interface-list=WAN protocol=udp dst-address=<NODE_LAN_IP> dst-port=24454 action=drop place-before=3 comment="Drop direct WAN VoiceChat"

   /ip firewall nat
   add chain=dstnat in-interface-list=WAN protocol=tcp dst-port=31565 src-address-list=yunexal_edges action=dst-nat to-addresses=<NODE_LAN_IP> to-ports=25565 comment="Yunexal Edge MC TCP"
   add chain=dstnat in-interface-list=WAN protocol=udp dst-port=31454 src-address-list=yunexal_edges action=dst-nat to-addresses=<NODE_LAN_IP> to-ports=24454 comment="Yunexal Edge VoiceChat UDP"
   ```

## HTTP API (`127.0.0.1:8085`)
- `GET /health` — статус та активний XDP-режим
- `GET /metrics` — лічильники TCP/UDP, кешу MOTD та XDP (`xdp_passed`, `xdp_dropped_*`)
- `GET /routes`, `POST /routes`, `DELETE /routes/<host>`

## Ліцензія
MIT License — [LICENSE](./LICENSE)
