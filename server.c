/*
 * server.c — Сервер защищённого туннеля.
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
#include <time.h>          /* ← ДОБАВЛЕНО */

static struct tunnel_ctx g_ctx;

static void signal_handler(int sig)
{
    (void)sig;
    g_ctx.running = false;
}

static int udp_send_to(const struct sockaddr_in *dst,
                       const uint8_t *data, size_t len)
{
    ssize_t n = sendto(g_ctx.udp_fd, data, len, 0,
                       (const struct sockaddr *)dst, sizeof(*dst));
    return (n < 0) ? -1 : 0;
}

static int send_data_packet(const uint8_t *ip_pkt, size_t len)
{
    struct session *s = &g_ctx.sess;
    if (s->state != SESS_ESTABLISHED) return -1;

    uint8_t buf[MAX_UDP_PACKET];
    proto_write_header(buf, MSG_DATA, s->session_id, s->tx_seq);

    uint8_t *nonce = buf + HEADER_SIZE;
    size_t ct_len = 0;

    if (crypto_aead_encrypt(s, ip_pkt, len,
        buf, HEADER_SIZE,
        nonce,
        buf + HEADER_SIZE + NONCE_SIZE,
        &ct_len) != 0) {
        return -1;
        }

        size_t total = HEADER_SIZE + NONCE_SIZE + ct_len;
    if (udp_send_to(&s->peer_addr, buf, total) != 0) return -1;

    s->tx_seq++;
    s->last_activity = time(NULL);
    g_ctx.pkts_tx++;
    g_ctx.bytes_tx += len;
    return 0;
}

static int send_control(uint8_t type)
{
    struct session *s = &g_ctx.sess;
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
    if (udp_send_to(&s->peer_addr, buf, total) != 0) return -1;
    s->tx_seq++;
    return 0;
}

/* ── Обработка INIT ───────────────────────────────────────────────── */
int handshake_server_process_init(struct tunnel_ctx *ctx,
                                  const uint8_t *buf, size_t len,
                                  const struct sockaddr_in *client_addr)
{
    struct session *s = &ctx->sess;

    struct packet_header hdr;
    if (proto_parse_header(buf, len, &hdr) != 0) return -1;
    if (hdr.type != MSG_INIT) return -1;

    /* Расшифровка */
    uint8_t psk_key[KEY_SIZE];
    crypto_derive_psk_key(ctx->psk, psk_key);

    const uint8_t *nonce = buf + HEADER_SIZE;
    const uint8_t *ct = buf + HEADER_SIZE + NONCE_SIZE;
    size_t ct_len = len - HEADER_SIZE - NONCE_SIZE;

    uint8_t payload[100];
    size_t pt_len = 0;

    if (crypto_handshake_decrypt(psk_key, ct, ct_len,
        nonce, payload, &pt_len) != 0) {
        log_msg("ERROR: INIT decryption failed (wrong PSK?)");
    return -1;
        }

        if (pt_len < 100) {
            log_msg("ERROR: INIT payload too short (%zu)", pt_len);
            return -1;
        }

        /* Проверка HMAC */
        if (!crypto_hmac_verify(ctx->psk, payload, 68, payload + 68)) {
            log_msg("ERROR: INIT HMAC verification failed");
            return -1;
        }

        /* Извлечение данных клиента */
        uint8_t client_pub[X25519_PUB_SIZE];
        uint8_t client_random[RANDOM_SIZE];
        uint32_t client_suites;

        memcpy(client_pub, payload + 0, 32);
        memcpy(client_random, payload + 32, 32);
        memcpy(&client_suites, payload + 64, 4);
        client_suites = le32toh(client_suites);

        /* Выбор набора шифров */
        uint16_t chosen = SUITE_CHACHA20_POLY1305;
        if ((client_suites & SUITE_BIT_AESGCM) &&
            crypto_aead_aes256gcm_is_available()) {
            chosen = SUITE_AES_256_GCM;
            } else if (!(client_suites & SUITE_BIT_CHACHA)) {
                log_msg("ERROR: no common cipher suite");
                return -1;
            }

            /* ── ИСПРАВЛЕНИЕ: генерация пары X25519 ── */
            randombytes_buf(s->my_x25519_priv, X25519_PRIV_SIZE);
        crypto_scalarmult_base(s->my_x25519_pub, s->my_x25519_priv);
        randombytes_buf(s->my_random, RANDOM_SIZE);

        /* Общий секрет */
        uint8_t shared[X25519_PUB_SIZE];
        if (crypto_scalarmult(shared, s->my_x25519_priv, client_pub) != 0) {
            log_msg("ERROR: X25519 failed");
            return -1;
        }

        /* Session ID из запроса клиента */
        s->session_id = hdr.session_id;
        s->suite = (enum cipher_suite)chosen;

        /* Вывод ключей */
        crypto_derive_session_keys(shared, client_random, s->my_random,
                                   ctx->psk, true, s);

        sodium_memzero(shared, sizeof(shared));
        sodium_memzero(s->my_x25519_priv, sizeof(s->my_x25519_priv));

        /* Формирование INIT_ACK */
        uint8_t ack_payload[98];
        memcpy(ack_payload + 0,  s->my_x25519_pub, 32);
        memcpy(ack_payload + 32, s->my_random, 32);
        uint16_t cs = htole16(chosen);
        memcpy(ack_payload + 64, &cs, 2);
        crypto_hmac(ctx->psk, ack_payload, 66, ack_payload + 66);

        uint8_t ack_buf[MAX_UDP_PACKET];
        proto_write_header(ack_buf, MSG_INIT_ACK, s->session_id, 0);

        uint8_t *ack_nonce = ack_buf + HEADER_SIZE;
        size_t ack_ct_len = 0;

        if (crypto_handshake_encrypt(psk_key, ack_payload, sizeof(ack_payload),
            ack_nonce,
            ack_buf + HEADER_SIZE + NONCE_SIZE,
            &ack_ct_len) != 0) {
            return -1;
            }

            size_t total = HEADER_SIZE + NONCE_SIZE + ack_ct_len;
        if (udp_send_to(client_addr, ack_buf, total) != 0) return -1;

        /* Сессия установлена */
        s->state = SESS_ESTABLISHED;
        s->tx_seq = 1;
        s->peer_addr = *client_addr;
        s->peer_addr_valid = true;
        s->established_at = time(NULL);
        s->last_activity = time(NULL);
        replay_init(&s->rx_window);

        log_msg("Session established: id=0x%016lx suite=0x%04x client=%s:%d",
                s->session_id, s->suite,
                inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
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

    struct packet_header hdr;
    if (proto_parse_header(buf, (size_t)n, &hdr) != 0) {
        g_ctx.pkts_dropped++;
        return;
    }

    struct session *s = &g_ctx.sess;

    /* INIT — новое рукопожатие */
    if (hdr.type == MSG_INIT) {
        handshake_server_process_init(&g_ctx, buf, (size_t)n, &from);
        return;
    }

    /* Остальное — только для установленной сессии */
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
        nonce, plaintext, &pt_len) != 0) {
        log_msg("WARN: decryption failed");
    g_ctx.pkts_dropped++;
    return;
        }

        replay_update(&s->rx_window, hdr.seq);
        s->last_activity = time(NULL);
        g_ctx.pkts_rx++;
        g_ctx.bytes_rx += pt_len;

        switch (hdr.type) {
            case MSG_DATA:
                if (pt_len > 0) tun_write(g_ctx.tun_fd, plaintext, pt_len);
                break;
            case MSG_KEEPALIVE:
                break;
            case MSG_CLOSE:
                log_msg("Session closed by client");
                s->state = SESS_IDLE;
                break;
            default:
                break;
        }
}

static void handle_tun_read(void)
{
    uint8_t buf[MAX_IP_PACKET];
    ssize_t n = tun_read(g_ctx.tun_fd, buf, sizeof(buf));
    if (n <= 0) return;

    if (g_ctx.sess.state == SESS_ESTABLISHED) {
        send_data_packet(buf, (size_t)n);
    }
}

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

        time_t now = time(NULL);
        if (g_ctx.sess.state == SESS_ESTABLISHED &&
            now - last_keepalive >= KEEPALIVE_INTERVAL_SEC) {
            send_control(MSG_KEEPALIVE);
        last_keepalive = now;
            }

            if (g_ctx.sess.state == SESS_ESTABLISHED &&
                now - g_ctx.sess.last_activity > SESSION_TIMEOUT_SEC) {
                log_msg("Session timeout");
            send_control(MSG_CLOSE);
            g_ctx.sess.state = SESS_IDLE;
                }
    }
}

int main(int argc, char *argv[])
{
    const char *tun_name = "tun0";
    const char *tun_ip = "10.200.0.1/24";
    const char *psk_hex = NULL;
    int listen_port = 51820;

    static struct option long_opts[] = {
        {"port",   required_argument, 0, 'p'},
        {"tun",    required_argument, 0, 't'},
        {"tun-ip", required_argument, 0, 'i'},
        {"psk",    required_argument, 0, 'k'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:t:i:k:", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': listen_port = atoi(optarg); break;
            case 't': tun_name = optarg; break;
            case 'i': tun_ip = optarg; break;
            case 'k': psk_hex = optarg; break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-t tun] [-i ip] -k <psk_hex>\n",
                        argv[0]);
                return 1;
        }
    }

    if (!psk_hex) {
        fprintf(stderr, "ERROR: PSK is required (-k)\n");
        return 1;
    }

    if (crypto_init() != 0) return 1;

    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.is_server = true;
    g_ctx.running = true;

    if (sodium_hex2bin(g_ctx.psk, PSK_SIZE, psk_hex, strlen(psk_hex),
        NULL, NULL, NULL) != 0) {
        fprintf(stderr, "ERROR: invalid PSK hex\n");
    return 1;
        }

        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        g_ctx.tun_fd = tun_alloc(tun_name);
        if (g_ctx.tun_fd < 0) return 1;
        if (tun_set_ip(g_ctx.tun_fd, tun_ip) != 0) return 1;

        g_ctx.udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_ctx.udp_fd < 0) {
        perror("socket");
        return 1;
    }

    int reuse = 1;
    setsockopt(g_ctx.udp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons((uint16_t)listen_port);

    if (bind(g_ctx.udp_fd, (struct sockaddr *)&bind_addr,
        sizeof(bind_addr)) < 0) {
        perror("bind");
    return 1;
        }

        log_msg("Server listening on port %d, tun=%s tun_ip=%s",
                listen_port, tun_name, tun_ip);

        event_loop();

        log_msg("Server shutting down. TX=%lu RX=%lu dropped=%lu",
                g_ctx.pkts_tx, g_ctx.pkts_rx, g_ctx.pkts_dropped);
        close(g_ctx.tun_fd);
        close(g_ctx.udp_fd);
        return 0;
}
