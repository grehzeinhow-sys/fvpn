/*
 * client.c — Клиент защищённого туннеля.
 */
#include "tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>

static struct tunnel_ctx g_ctx;

/* ── Обработчик сигналов ──────────────────────────────────────────── */
static void signal_handler(int sig)
{
    (void)sig;
    g_ctx.running = false;
}

/* ── Отправка UDP-датаграммы ──────────────────────────────────────── */
static int udp_send(const struct sockaddr_in *dst,
                    const uint8_t *data, size_t len)
{
    ssize_t n = sendto(g_ctx.udp_fd, data, len, 0,
                       (const struct sockaddr *)dst, sizeof(*dst));
    if (n < 0) {
        perror("sendto");
        return -1;
    }
    return 0;
}

/* ── Отправка MSG_DATA ────────────────────────────────────────────── */
static int send_data_packet(const uint8_t *ip_pkt, size_t len)
{
    struct session *s = &g_ctx.sess;
    if (s->state != SESS_ESTABLISHED) return -1;

    uint8_t buf[MAX_UDP_PACKET];
    size_t offset = 0;

    /* Заголовок */
    proto_write_header(buf, MSG_DATA, s->session_id, s->tx_seq);
    offset += HEADER_SIZE;

    /* Шифрование */
    uint8_t *nonce = buf + offset;
    size_t ct_len = 0;

    if (crypto_aead_encrypt(s, ip_pkt, len,
        buf, HEADER_SIZE,
        nonce,
        buf + HEADER_SIZE + NONCE_SIZE,
        &ct_len) != 0) {
        log_msg("ERROR: encryption failed");
    return -1;
        }

        offset += NONCE_SIZE + ct_len;

        if (udp_send(&s->peer_addr, buf, offset) != 0) return -1;

        s->tx_seq++;
    s->last_activity = time(NULL);
    g_ctx.pkts_tx++;
    g_ctx.bytes_tx += len;
    return 0;
}

/* ── Отправка служебного сообщения ────────────────────────────────── */
static int send_control(uint8_t type)
{
    struct session *s = &g_ctx.sess;
    if (s->state != SESS_ESTABLISHED && type != MSG_CLOSE) return -1;

    uint8_t buf[HEADER_SIZE + NONCE_SIZE + TAG_SIZE];
    proto_write_header(buf, type, s->session_id, s->tx_seq);

    uint8_t *nonce = buf + HEADER_SIZE;
    size_t ct_len = 0;

    if (crypto_aead_encrypt(s, NULL, 0,
        buf, HEADER_SIZE,
        nonce,
        buf + HEADER_SIZE + NONCE_SIZE,
        &ct_len) != 0) {
        return -1;
        }

        size_t total = HEADER_SIZE + NONCE_SIZE + ct_len;
    if (udp_send(&s->peer_addr, buf, total) != 0) return -1;

    s->tx_seq++;
    s->last_activity = time(NULL);
    return 0;
}

/* ── Обработка входящего UDP ──────────────────────────────────────── */
static void handle_udp_recv(void)
{
    uint8_t buf[MAX_UDP_PACKET];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    ssize_t n = recvfrom(g_ctx.udp_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &from_len);
    if (n <= 0) return;

    /* Разбор заголовка */
    struct packet_header hdr;
    if (proto_parse_header(buf, (size_t)n, &hdr) != 0) {
        log_msg("WARN: invalid packet header");
        g_ctx.pkts_dropped++;
        return;
    }

    struct session *s = &g_ctx.sess;

    /* Обработка рукопожатия */
    if (hdr.type == MSG_INIT_ACK && s->state == SESS_WAIT_ACK) {
        handshake_client_process_ack(&g_ctx, buf, (size_t)n);
        return;
    }

    /* Проверка сессии */
    if (s->state != SESS_ESTABLISHED) return;
    if (hdr.session_id != s->session_id) return;

    /* Анти-повтор */
    if (replay_check(&s->rx_window, hdr.seq) != 0) {
        log_msg("WARN: replay detected, seq=%lu", hdr.seq);
        g_ctx.pkts_dropped++;
        return;
    }

    /* Расшифровка */
    const uint8_t *nonce = buf + HEADER_SIZE;
    const uint8_t *ct = buf + HEADER_SIZE + NONCE_SIZE;
    size_t ct_len = (size_t)n - HEADER_SIZE - NONCE_SIZE;

    uint8_t plaintext[MAX_IP_PACKET];
    size_t pt_len = 0;

    if (crypto_aead_decrypt(s, ct, ct_len,
        buf, HEADER_SIZE,
        nonce,
        plaintext, &pt_len) != 0) {
        log_msg("WARN: decryption failed (bad tag?)");
    g_ctx.pkts_dropped++;
    return;
        }

        replay_update(&s->rx_window, hdr.seq);
        s->last_activity = time(NULL);
        g_ctx.pkts_rx++;
        g_ctx.bytes_rx += pt_len;

        switch (hdr.type) {
            case MSG_DATA:
                if (pt_len > 0) {
                    tun_write(g_ctx.tun_fd, plaintext, pt_len);
                }
                break;
            case MSG_KEEPALIVE:
                log_msg("Keepalive received");
                break;
            case MSG_CLOSE:
                log_msg("Session closed by peer");
                s->state = SESS_CLOSING;
                g_ctx.running = false;
                break;
            case MSG_REKEY:
                log_msg("Rekey requested by peer");
                /* В прототипе: просто логируем */
                break;
            default:
                log_msg("WARN: unknown message type %d", hdr.type);
                break;
        }
}

/* ── Обработка TUN (чтение → шифрование → отправка) ──────────────── */
static void handle_tun_read(void)
{
    uint8_t buf[MAX_IP_PACKET];
    ssize_t n = tun_read(g_ctx.tun_fd, buf, sizeof(buf));
    if (n <= 0) return;

    if (g_ctx.sess.state == SESS_ESTABLISHED) {
        send_data_packet(buf, (size_t)n);
    }
}

/* ── Рукопожатие: отправка INIT ───────────────────────────────────── */
int handshake_client_init(struct tunnel_ctx *ctx,
                          const struct sockaddr_in *server_addr)
{
    struct session *s = &ctx->sess;

    /* Генерация ключей X25519 */
    crypto_scalarmult_keypair(s->my_x25519_pub, s->my_x25519_priv);
    randombytes_buf(s->my_random, RANDOM_SIZE);

    /* Генерация session_id */
    randombytes_buf(&s->session_id, sizeof(s->session_id));

    /* Формирование полезной нагрузки INIT */
    uint8_t payload[100];
    memcpy(payload + 0,  s->my_x25519_pub, 32);
    memcpy(payload + 32, s->my_random, 32);

    uint32_t suites = htole32(SUITE_BIT_CHACHA);
    if (crypto_aead_aes256gcm_is_available())
        suites |= htole32(SUITE_BIT_AESGCM);
    memcpy(payload + 64, &suites, 4);

    /* HMAC поверх данных */
    crypto_hmac(ctx->psk, payload, 68, payload + 68);

    /* Шифрование ключом из PSK */
    uint8_t psk_key[KEY_SIZE];
    crypto_derive_psk_key(ctx->psk, psk_key);

    uint8_t buf[MAX_UDP_PACKET];
    proto_write_header(buf, MSG_INIT, s->session_id, 0);

    uint8_t *nonce = buf + HEADER_SIZE;
    size_t ct_len = 0;

    if (crypto_handshake_encrypt(psk_key, payload, sizeof(payload),
        nonce,
        buf + HEADER_SIZE + NONCE_SIZE,
        &ct_len) != 0) {
        log_msg("ERROR: handshake encryption failed");
    return -1;
        }

        size_t total = HEADER_SIZE + NONCE_SIZE + ct_len;
        if (udp_send(server_addr, buf, total) != 0) return -1;

        s->state = SESS_WAIT_ACK;
    s->peer_addr = *server_addr;
    s->peer_addr_valid = true;
    s->last_activity = time(NULL);

    log_msg("INIT sent, session_id=0x%016lx, waiting for ACK...",
            s->session_id);
    return 0;
}

/* ── Рукопожатие: обработка INIT_ACK ──────────────────────────────── */
int handshake_client_process_ack(struct tunnel_ctx *ctx,
                                 const uint8_t *buf, size_t len)
{
    struct session *s = &ctx->sess;

    /* Разбор заголовка уже выполнен вызывающим */
    struct packet_header hdr;
    if (proto_parse_header(buf, len, &hdr) != 0) return -1;

    /* Расшифровка */
    uint8_t psk_key[KEY_SIZE];
    crypto_derive_psk_key(ctx->psk, psk_key);

    const uint8_t *nonce = buf + HEADER_SIZE;
    const uint8_t *ct = buf + HEADER_SIZE + NONCE_SIZE;
    size_t ct_len = len - HEADER_SIZE - NONCE_SIZE;

    uint8_t payload[98];
    size_t pt_len = 0;

    if (crypto_handshake_decrypt(psk_key, ct, ct_len,
        nonce, payload, &pt_len) != 0) {
        log_msg("ERROR: INIT_ACK decryption failed");
    return -1;
        }

        if (pt_len < 98) {
            log_msg("ERROR: INIT_ACK too short (%zu)", pt_len);
            return -1;
        }

        /* Проверка HMAC */
        if (!crypto_hmac_verify(ctx->psk, payload, 66, payload + 66)) {
            log_msg("ERROR: INIT_ACK HMAC verification failed");
            return -1;
        }

        /* Извлечение данных сервера */
        uint8_t server_pub[X25519_PUB_SIZE];
        uint8_t server_random[RANDOM_SIZE];
        uint16_t chosen_suite;

        memcpy(server_pub, payload + 0, 32);
        memcpy(server_random, payload + 32, 32);
        memcpy(&chosen_suite, payload + 64, 2);
        chosen_suite = le16toh(chosen_suite);

        /* Вычисление общего секрета */
        uint8_t shared[X25519_PUB_SIZE];
        if (crypto_scalarmult(shared, s->my_x25519_priv, server_pub) != 0) {
            log_msg("ERROR: X25519 shared secret computation failed");
            return -1;
        }

        /* Выбор набора шифров */
        s->suite = (enum cipher_suite)chosen_suite;

        /* Вывод сессионных ключей */
        crypto_derive_session_keys(shared, s->my_random, server_random,
                                   ctx->psk, false, s);

        /* Очистка */
        sodium_memzero(shared, sizeof(shared));
        sodium_memzero(s->my_x25519_priv, sizeof(s->my_x25519_priv));

        s->state = SESS_ESTABLISHED;
        s->tx_seq = 1;
        s->established_at = time(NULL);
        s->last_activity = time(NULL);
        replay_init(&s->rx_window);

        log_msg("Session established: id=0x%016lx suite=0x%04x",
                s->session_id, s->suite);
        return 0;
}

/* ── Главный цикл ─────────────────────────────────────────────────── */
static void event_loop(void)
{
    time_t last_keepalive = time(NULL);

    while (g_ctx.running) {
        struct pollfd fds[2];
        fds[0].fd = g_ctx.tun_fd;
        fds[0].events = POLLIN;
        fds[1].fd = g_ctx.udp_fd;
        fds[1].events = POLLIN;

        int ret = poll(fds, 2, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if (ret > 0) {
            if (fds[0].revents & POLLIN) handle_tun_read();
            if (fds[1].revents & POLLIN) handle_udp_recv();
        }

        /* Keepalive */
        time_t now = time(NULL);
        if (g_ctx.sess.state == SESS_ESTABLISHED &&
            now - last_keepalive >= KEEPALIVE_INTERVAL_SEC) {
            send_control(MSG_KEEPALIVE);
        last_keepalive = now;
            }

            /* Таймаут сессии */
            if (g_ctx.sess.state == SESS_ESTABLISHED &&
                now - g_ctx.sess.last_activity > SESSION_TIMEOUT_SEC) {
                log_msg("Session timeout, closing");
            send_control(MSG_CLOSE);
            g_ctx.running = false;
                }
    }
}

/* ── main ─────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    const char *server_ip = "127.0.0.1";
    int server_port = 51820;
    const char *tun_name = "tun0";
    const char *tun_ip = "10.200.0.2/24";
    const char *psk_hex = NULL;

    static struct option long_opts[] = {
        {"server",  required_argument, 0, 's'},
        {"port",    required_argument, 0, 'p'},
        {"tun",     required_argument, 0, 't'},
        {"tun-ip",  required_argument, 0, 'i'},
        {"psk",     required_argument, 0, 'k'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "s:p:t:i:k:", long_opts, NULL)) != -1) {
        switch (opt) {
            case 's': server_ip = optarg; break;
            case 'p': server_port = atoi(optarg); break;
            case 't': tun_name = optarg; break;
            case 'i': tun_ip = optarg; break;
            case 'k': psk_hex = optarg; break;
            default:
                fprintf(stderr, "Usage: %s -s <server_ip> [-p port] "
                "[-t tun_name] [-i tun_ip] -k <psk_hex>\n", argv[0]);
                return 1;
        }
    }

    if (!psk_hex) {
        fprintf(stderr, "ERROR: PSK is required (-k)\n");
        return 1;
    }

    /* Инициализация */
    if (crypto_init() != 0) return 1;

    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.is_server = false;
    g_ctx.running = true;

    /* Парсинг PSK из hex */
    if (sodium_hex2bin(g_ctx.psk, PSK_SIZE, psk_hex, strlen(psk_hex),
        NULL, NULL, NULL) != 0) {
        fprintf(stderr, "ERROR: invalid PSK hex\n");
    return 1;
        }

        /* Сигналы */
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        /* TUN */
        g_ctx.tun_fd = tun_alloc(tun_name);
        if (g_ctx.tun_fd < 0) return 1;
        if (tun_set_ip(g_ctx.tun_fd, tun_ip) != 0) return 1;

        /* UDP-сокет */
        g_ctx.udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (g_ctx.udp_fd < 0) {
            perror("socket");
            return 1;
        }

        /* Адрес сервера */
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons((uint16_t)server_port);
        if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) != 1) {
            fprintf(stderr, "ERROR: invalid server IP '%s'\n", server_ip);
            return 1;
        }

        /* Привязка к локальному порту */
        struct sockaddr_in bind_addr = {0};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind_addr.sin_port = 0;
        if (bind(g_ctx.udp_fd, (struct sockaddr *)&bind_addr,
            sizeof(bind_addr)) < 0) {
            perror("bind");
        return 1;
            }

            log_msg("Client starting: server=%s:%d tun=%s tun_ip=%s",
                    server_ip, server_port, tun_name, tun_ip);

            /* Рукопожатие */
            if (handshake_client_init(&g_ctx, &server_addr) != 0) {
                fprintf(stderr, "ERROR: handshake init failed\n");
                return 1;
            }

            /* Главный цикл */
            event_loop();

            /* Завершение */
            log_msg("Client shutting down. TX=%lu RX=%lu dropped=%lu",
                    g_ctx.pkts_tx, g_ctx.pkts_rx, g_ctx.pkts_dropped);
            close(g_ctx.tun_fd);
            close(g_ctx.udp_fd);
            return 0;
}
