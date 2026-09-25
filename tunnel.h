/*
 * tunnel.h — Общие определения прототипа защищённого туннеля.
 * Протокол, константы, структуры данных.
 */
#ifndef TUNNEL_H
#define TUNNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sodium.h>

/* ── Версия и магическое число ────────────────────────────────────── */
#define PROTO_MAGIC      0x544E4C53u  /* "TNLS" */
#define PROTO_VERSION    1

/* ── Типы сообщений ───────────────────────────────────────────────── */
enum msg_type {
    MSG_INIT      = 0x01,
    MSG_INIT_ACK  = 0x02,
    MSG_DATA      = 0x03,
    MSG_CLOSE     = 0x04,
    MSG_ERROR     = 0x05,
    MSG_KEEPALIVE = 0x06,
    MSG_REKEY     = 0x07,
};

/* ── Наборы шифров ────────────────────────────────────────────────── */
enum cipher_suite {
    SUITE_CHACHA20_POLY1305 = 0x0001,
    SUITE_AES_256_GCM       = 0x0002,
};

#define SUITE_BIT_CHACHA  (1u << 0)
#define SUITE_BIT_AESGCM  (1u << 1)

/* ── Размеры ──────────────────────────────────────────────────────── */
#define HEADER_SIZE       24   /* заголовок на проводе */
#define NONCE_SIZE        12   /* IETF ChaCha20 / AES-GCM */
#define TAG_SIZE          16   /* AEAD-тег */
#define KEY_SIZE          32   /* размер ключа */
#define PSK_SIZE          32   /* размер PSK */
#define SESSION_ID_SIZE   8
#define MAX_IP_PACKET     65535
#define MAX_PAYLOAD       (MAX_IP_PACKET + TAG_SIZE)
#define MAX_UDP_PACKET    (HEADER_SIZE + NONCE_SIZE + MAX_PAYLOAD)

#define HANDSHAKE_KEY_SIZE  KEY_SIZE
#define X25519_PUB_SIZE     crypto_scalarmult_BYTES   /* 32 */
#define X25519_PRIV_SIZE    crypto_scalarmult_BYTES   /* 32 */
#define RANDOM_SIZE         32
#define HMAC_SIZE           crypto_auth_hmacsha256_BYTES  /* 32 */
#define BLAKE2B_SIZE        crypto_generichash_BYTES      /* 32 */

/* ── Таймауты ─────────────────────────────────────────────────────── */
#define SESSION_TIMEOUT_SEC   120   /* таймаут неактивности */
#define KEEPALIVE_INTERVAL_SEC 30   /* период keepalive */
#define REKEY_INTERVAL_SEC   3600   /* периодический rekey */

/* ── Заголовок на проводе ─────────────────────────────────────────── */
struct packet_header {
    uint32_t magic;
    uint8_t  version;
    uint8_t  type;
    uint8_t  flags;
    uint8_t  reserved;
    uint64_t session_id;
    uint64_t seq;
} __attribute__((packed));

_Static_assert(sizeof(struct packet_header) == HEADER_SIZE,
               "packet_header must be 24 bytes");

/* ── Флаги в заголовке ────────────────────────────────────────────── */
#define FLAG_REKEY  0x01

/* ── Скользящее окно анти-повтора ─────────────────────────────────── */
struct replay_window {
    uint64_t last_seq;
    uint64_t bitmap;   /* бит i → seq = last_seq - i */
};

/* ── Состояние сессии ─────────────────────────────────────────────── */
enum session_state {
    SESS_IDLE = 0,
    SESS_WAIT_ACK,      /* клиент ждёт INIT_ACK */
    SESS_ESTABLISHED,   /* сессия активна */
    SESS_CLOSING,       /* отправлен CLOSE */
};

struct session {
    uint64_t session_id;
    enum session_state state;
    enum cipher_suite suite;

    /* Ключи направлений */
    uint8_t write_key[KEY_SIZE];     /* ключ для исходящих */
    uint8_t read_key[KEY_SIZE];      /* ключ для входящих */
    uint8_t write_salt[NONCE_SIZE];  /* соль nonce для исходящих */
    uint8_t read_salt[NONCE_SIZE];   /* соль nonce для входящих */

    /* Последовательности */
    uint64_t tx_seq;                 /* следующий исходящий seq */
    struct replay_window rx_window;  /* окно входящих */

    /* Временные данные рукопожатия */
    uint8_t my_x25519_priv[X25519_PRIV_SIZE];
    uint8_t my_x25519_pub[X25519_PUB_SIZE];
    uint8_t my_random[RANDOM_SIZE];

    /* Таймеры */
    time_t last_activity;
    time_t established_at;

    /* Адрес пира (для сервера — адрес клиента) */
    struct sockaddr_in peer_addr;
    bool peer_addr_valid;
};

/* ── Глобальный контекст ──────────────────────────────────────────── */
struct tunnel_ctx {
    int tun_fd;
    int udp_fd;
    uint8_t psk[PSK_SIZE];
    struct session sess;
    bool is_server;
    volatile bool running;

    /* Статистика */
    uint64_t pkts_tx;
    uint64_t pkts_rx;
    uint64_t pkts_dropped;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
};

/* ── Функции криптографического слоя (crypto.c) ───────────────────── */
int  crypto_init(void);
void crypto_derive_psk_key(const uint8_t psk[PSK_SIZE],
                           uint8_t out[KEY_SIZE]);
void crypto_derive_session_keys(const uint8_t shared[X25519_PUB_SIZE],
                                const uint8_t client_random[RANDOM_SIZE],
                                const uint8_t server_random[RANDOM_SIZE],
                                const uint8_t psk[PSK_SIZE],
                                bool is_server,
                                struct session *sess);
int  crypto_aead_encrypt(const struct session *sess,
                         const uint8_t *plaintext, size_t pt_len,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *nonce_out,
                         uint8_t *ciphertext, size_t *ct_len);
int  crypto_aead_decrypt(const struct session *sess,
                         const uint8_t *ciphertext, size_t ct_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *nonce,
                         uint8_t *plaintext, size_t *pt_len);
int  crypto_handshake_encrypt(const uint8_t key[KEY_SIZE],
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *nonce_out,
                              uint8_t *ciphertext, size_t *ct_len);
int  crypto_handshake_decrypt(const uint8_t key[KEY_SIZE],
                              const uint8_t *ciphertext, size_t ct_len,
                              const uint8_t *nonce,
                              uint8_t *plaintext, size_t *pt_len);
void crypto_hmac(const uint8_t key[KEY_SIZE],
                 const uint8_t *data, size_t len,
                 uint8_t out[HMAC_SIZE]);
bool crypto_hmac_verify(const uint8_t key[KEY_SIZE],
                        const uint8_t *data, size_t len,
                        const uint8_t expected[HMAC_SIZE]);

/* ── Функции протокола (proto.c) ──────────────────────────────────── */
void proto_write_header(uint8_t *buf, uint8_t type, uint64_t session_id,
                        uint64_t seq);
int  proto_parse_header(const uint8_t *buf, size_t len,
                        struct packet_header *hdr);
void proto_compute_nonce(const uint8_t salt[NONCE_SIZE], uint64_t seq,
                         uint8_t nonce_out[NONCE_SIZE]);

/* ── Функции анти-повтора (внутри proto.c) ────────────────────────── */
void replay_init(struct replay_window *w);
int  replay_check(const struct replay_window *w, uint64_t seq);
void replay_update(struct replay_window *w, uint64_t seq);

/* ── Функции TUN (tun.c) ──────────────────────────────────────────── */
int  tun_alloc(const char *name);
int  tun_set_ip(int tun_fd, const char *ip_cidr);
ssize_t tun_read(int fd, uint8_t *buf, size_t len);
ssize_t tun_write(int fd, const uint8_t *buf, size_t len);

/* ── Функции рукопожатия (внутри client.c / server.c) ─────────────── */
int  handshake_client_init(struct tunnel_ctx *ctx,
                           const struct sockaddr_in *server_addr);
int  handshake_client_process_ack(struct tunnel_ctx *ctx,
                                  const uint8_t *buf, size_t len);
int  handshake_server_process_init(struct tunnel_ctx *ctx,
                                   const uint8_t *buf, size_t len,
                                   const struct sockaddr_in *client_addr);

/* ── Утилиты ──────────────────────────────────────────────────────── */
void log_msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_hex(const char *label, const uint8_t *data, size_t len);

#endif /* TUNNEL_H */
