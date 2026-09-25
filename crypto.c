/*
 * crypto.c — Криптографический слой на базе libsodium.
 * X25519, ChaCha20-Poly1305, AES-256-GCM, BLAKE2b, HMAC-SHA256.
 */
#include "tunnel.h"
#include <string.h>
#include <stdio.h>

/* ── Инициализация libsodium ──────────────────────────────────────── */
int crypto_init(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init() failed\n");
        return -1;
    }
    return 0;
}

/* ── Вывод ключа для шифрования рукопожатия из PSK ────────────────── */
void crypto_derive_psk_key(const uint8_t psk[PSK_SIZE],
                           uint8_t out[KEY_SIZE])
{
    const char *ctx = "handshake_encryption";
    crypto_generichash(out, KEY_SIZE,
                       psk, PSK_SIZE,
                       (const uint8_t *)ctx, strlen(ctx));
}

/* ── Вывод сессионных ключей через BLAKE2b ────────────────────────── */
void crypto_derive_session_keys(const uint8_t shared[X25519_PUB_SIZE],
                                const uint8_t client_random[RANDOM_SIZE],
                                const uint8_t server_random[RANDOM_SIZE],
                                const uint8_t psk[PSK_SIZE],
                                bool is_server,
                                struct session *sess)
{
    uint8_t master[BLAKE2B_SIZE];

    /* Шаг 1: мастер-секрет */
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, BLAKE2B_SIZE);
    crypto_generichash_update(&st, shared, X25519_PUB_SIZE);
    crypto_generichash_update(&st, client_random, RANDOM_SIZE);
    crypto_generichash_update(&st, server_random, RANDOM_SIZE);
    crypto_generichash_update(&st, psk, PSK_SIZE);
    crypto_generichash_final(&st, master, BLAKE2B_SIZE);

    /* Шаг 2: ключи направлений */
    const char *ck = "client_write_key";
    const char *sk = "server_write_key";
    const char *cs = "client_write_salt";
    const char *ss = "server_write_salt";

    uint8_t client_key[KEY_SIZE], server_key[KEY_SIZE];
    uint8_t client_salt[BLAKE2B_SIZE], server_salt[BLAKE2B_SIZE];

    crypto_generichash(client_key, KEY_SIZE,
                       master, BLAKE2B_SIZE,
                       (const uint8_t *)ck, strlen(ck));
    crypto_generichash(server_key, KEY_SIZE,
                       master, BLAKE2B_SIZE,
                       (const uint8_t *)sk, strlen(sk));
    crypto_generichash(client_salt, BLAKE2B_SIZE,
                       master, BLAKE2B_SIZE,
                       (const uint8_t *)cs, strlen(cs));
    crypto_generichash(server_salt, BLAKE2B_SIZE,
                       master, BLAKE2B_SIZE,
                       (const uint8_t *)ss, strlen(ss));

    /* Назначаем в зависимости от роли */
    if (is_server) {
        memcpy(sess->write_key, server_key, KEY_SIZE);
        memcpy(sess->read_key,  client_key, KEY_SIZE);
        memcpy(sess->write_salt, server_salt, NONCE_SIZE);
        memcpy(sess->read_salt,  client_salt, NONCE_SIZE);
    } else {
        memcpy(sess->write_key, client_key, KEY_SIZE);
        memcpy(sess->read_key,  server_key, KEY_SIZE);
        memcpy(sess->write_salt, client_salt, NONCE_SIZE);
        memcpy(sess->read_salt,  server_salt, NONCE_SIZE);
    }

    sodium_memzero(master, sizeof(master));
    sodium_memzero(client_key, sizeof(client_key));
    sodium_memzero(server_key, sizeof(server_key));
}

/* ── AEAD-шифрование данных сессии ────────────────────────────────── */
int crypto_aead_encrypt(const struct session *sess,
                        const uint8_t *plaintext, size_t pt_len,
                        const uint8_t *aad, size_t aad_len,
                        uint8_t *nonce_out,
                        uint8_t *ciphertext, size_t *ct_len)
{
    /* Вычисляем nonce из соли и последовательности */
    proto_compute_nonce(sess->write_salt, sess->tx_seq, nonce_out);

    unsigned long long out_len = 0;
    int ret;

    switch (sess->suite) {
        case SUITE_CHACHA20_POLY1305:
            ret = crypto_aead_chacha20poly1305_ietf_encrypt(
                ciphertext, &out_len,
                plaintext, pt_len,
                aad, aad_len,
                NULL, nonce_out, sess->write_key);
            break;
        case SUITE_AES_256_GCM:
            if (!crypto_aead_aes256gcm_is_available()) {
                fprintf(stderr, "AES-256-GCM not available (no AES-NI)\n");
                return -1;
            }
            ret = crypto_aead_aes256gcm_encrypt(
                ciphertext, &out_len,
                plaintext, pt_len,
                aad, aad_len,
                NULL, nonce_out, sess->write_key);
            break;
        default:
            return -1;
    }

    if (ret != 0) return -1;
    *ct_len = (size_t)out_len;
    return 0;
}

/* ── AEAD-расшифровка данных сессии ───────────────────────────────── */
int crypto_aead_decrypt(const struct session *sess,
                        const uint8_t *ciphertext, size_t ct_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *nonce,
                        uint8_t *plaintext, size_t *pt_len)
{
    unsigned long long out_len = 0;
    int ret;

    switch (sess->suite) {
        case SUITE_CHACHA20_POLY1305:
            ret = crypto_aead_chacha20poly1305_ietf_decrypt(
                plaintext, &out_len,
                NULL,
                ciphertext, ct_len,
                aad, aad_len,
                nonce, sess->read_key);
            break;
        case SUITE_AES_256_GCM:
            if (!crypto_aead_aes256gcm_is_available()) return -1;
            ret = crypto_aead_aes256gcm_decrypt(
                plaintext, &out_len,
                NULL,
                ciphertext, ct_len,
                aad, aad_len,
                nonce, sess->read_key);
            break;
        default:
            return -1;
    }

    if (ret != 0) return -1;
    *pt_len = (size_t)out_len;
    return 0;
}

/* ── Шифрование рукопожатия (ключ из PSK) ─────────────────────────── */
int crypto_handshake_encrypt(const uint8_t key[KEY_SIZE],
                             const uint8_t *plaintext, size_t pt_len,
                             uint8_t *nonce_out,
                             uint8_t *ciphertext, size_t *ct_len)
{
    randombytes_buf(nonce_out, NONCE_SIZE);
    unsigned long long out_len = 0;
    int ret = crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, &out_len,
        plaintext, pt_len,
        NULL, 0, NULL, nonce_out, key);
    if (ret != 0) return -1;
    *ct_len = (size_t)out_len;
    return 0;
}

int crypto_handshake_decrypt(const uint8_t key[KEY_SIZE],
                             const uint8_t *ciphertext, size_t ct_len,
                             const uint8_t *nonce,
                             uint8_t *plaintext, size_t *pt_len)
{
    unsigned long long out_len = 0;
    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext, &out_len,
        NULL,
        ciphertext, ct_len,
        NULL, 0, nonce, key);
    if (ret != 0) return -1;
    *pt_len = (size_t)out_len;
    return 0;
}

/* ── HMAC-SHA256 ──────────────────────────────────────────────────── */
void crypto_hmac(const uint8_t key[KEY_SIZE],
                 const uint8_t *data, size_t len,
                 uint8_t out[HMAC_SIZE])
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, KEY_SIZE);
    crypto_auth_hmacsha256_update(&st, data, len);
    crypto_auth_hmacsha256_final(&st, out);
}

bool crypto_hmac_verify(const uint8_t key[KEY_SIZE],
                        const uint8_t *data, size_t len,
                        const uint8_t expected[HMAC_SIZE])
{
    uint8_t computed[HMAC_SIZE];
    crypto_hmac(key, data, len, computed);
    return crypto_verify_32(computed, expected) == 0;
}
