#!/usr/bin/env bash
#
# setup.sh — Настройка и запуск прототипа туннеля.
# Запускать от root или через sudo.
#
set -euo pipefail

PSK_HEX="${PSK_HEX:-$(openssl rand -hex 32)}"
SERVER_PORT="${SERVER_PORT:-51820}"
SERVER_TUN_IP="${SERVER_TUN_IP:-10.200.0.1/24}"
CLIENT_TUN_IP="${CLIENT_TUN_IP:-10.200.0.2/24}"
TUN_NAME="${TUN_NAME:-tun0}"

echo "=== Прототип защищённого туннеля ==="
echo ""
echo "PSK (hex): $PSK_HEX"
echo "Порт:      $SERVER_PORT"
echo "TUN IP:    сервер=$SERVER_TUN_IP клиент=$CLIENT_TUN_IP"
echo ""

# Сборка
echo "[1/3] Сборка..."
make clean && make
echo ""

# Тесты
echo "[2/3] Модульные тесты..."
make test
echo ""

# Запуск сервера (в фоне)
echo "[3/3] Запуск сервера..."
sudo ./tunnel_server \
    --port "$SERVER_PORT" \
    --tun "$TUN_NAME" \
    --tun-ip "$SERVER_TUN_IP" \
    --psk "$PSK_HEX" &
SERVER_PID=$!
sleep 1

echo ""
echo "Сервер запущен (PID=$SERVER_PID)"
echo ""
echo "Для запуска клиента (в отдельном терминале):"
echo "  sudo ./tunnel_client \\"
echo "      --server 127.0.0.1 \\"
echo "      --port $SERVER_PORT \\"
echo "      --tun $TUN_NAME \\"
echo "      --tun-ip $CLIENT_TUN_IP \\"
echo "      --psk $PSK_HEX"
echo ""
echo "После установки сессии проверить:"
echo "  ping 10.200.0.1   # с клиента"
echo "  ping 10.200.0.2   # с сервера"
echo ""
echo "Остановка: kill $SERVER_PID"
