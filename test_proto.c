/*
 * test_proto.c — Модульные тесты для критичных компонентов.
 * Сборка: gcc -o test_proto test_proto.c proto.c crypto.c common.c
 *         -lsodium -Wall -Wextra
 */
#include "tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
printf("  TEST: %-50s ", #name); \
if (test_##name()) { printf("PASS\n"); tests_passed++; } \
    else { printf("FAIL\n"); tests_failed++; } \
} while(0)

/* ── Тест заголовка ───────────────────────────────────────────────── */
static int test_header_roundtrip(void)
{
    uint8_t buf[HEADER_SIZE];
    proto_write_header(buf, MSG_DATA, 0xDEADBEEF12345678ULL, 42);

    struct packet_header hdr;
    if (proto_parse_header(buf, HEADER_SIZE, &hdr) != 0) return 0;
    if (hdr.magic != PROTO_MAGIC) return 0;
    if (hdr.version != PROTO_VERSION) return 0;
    if (hdr.type != MSG_DATA) return 0;
    if (hdr.session_id != 0xDEADBEEF12345678ULL) return 0;
    if (hdr.seq != 42) return 0;
    return 1;
}

/* ── Тест неверного magic ─────────────────────────────────────────── */
static int test_header_bad_magic(void)
{
    uint8_t buf[HEADER_SIZE];
    proto_write_header(buf, MSG_DATA, 1, 1);
    buf[0] = 0xFF;  /* ломаем magic */

    struct packet_header hdr;
    return proto_parse_header(buf, HEADER_SIZE, &hdr) != 0;
}

/* ── Тест анти-повтора ────────────────────────────────────────────── */
static int test_replay_window(void)
{
    struct replay_window w;
    replay_init(&w);

    /* Первый пакет */
    if (replay_check(&w, 1) != 0) return 0;
    replay_update(&w, 1);

    /* Повтор */
    if (replay_check(&w, 1) != -1) return 0;

    /* Новый */
    if (replay_check(&w, 2) != 0) return 0;
    replay_update(&w, 2);

    /* Старый в пределах окна */
    if (replay_check(&w, 1) != -1) return 0;  /* уже виден */

        /* Скачок вперёд */
        if (replay_check(&w, 100) != 0) return 0;
        replay_update(&w, 100);

    /* Пакет за пределами окна */
    if (replay_check(&w, 10) != -1) return 0;  /* diff = 90 > 64 */

        return 1;
}

/* ── Тест nonce ───────────────────────────────────────────────────── */
static int test_nonce_computation(void)
{
    uint8_t salt[NONCE_SIZE] = {0};
    uint8_t nonce1[NONCE_SIZE], nonce2[NONCE_SIZE];

    proto_compute_nonce(salt, 1, nonce1);
    proto_compute_nonce(salt, 2, nonce2);

    /* Разные seq → разные nonce */
    if (memcmp(nonce1, nonce2, NONCE_SIZE) == 0) return 0;

    /* Нулевой nonce при нулевом соли и seq=0 */
    uint8_t nonce0[NONCE_SIZE];
    proto_compute_nonce(salt, 0, nonce0);
    for (int i = 0; i < NONCE_SIZE; i++)
        if (nonce0[i] != 0) return 0;

        return 1;
}

/* ── Тест AEAD шифрование/расшифровка ─────────────────────────────── */
static int test_aead_roundtrip(void)
{
    if (crypto_init() != 0) return 0;

    struct session sess;
    memset(&sess, 0, sizeof(sess));
    sess.suite = SUITE_CHACHA20_POLY1305;
    sess.tx_seq = 1;

    /* Генерируем случайные ключи */
    randombytes_buf(sess.write_key, KEY_SIZE);
    randombytes_buf(sess.read_key, KEY_SIZE);
    randombytes_buf(sess.write_salt, NONCE_SIZE);
    randombytes_buf(sess.read_salt, NONCE_SIZE);

    /* Для теста: ключ чтения = ключ записи */
    memcpy(sess.read_key, sess.write_key, KEY_SIZE);
    memcpy(sess.read_salt, sess.write_salt, NONCE_SIZE);

    const char *msg = "Hello, secure tunnel!";
    size_t msg_len = strlen(msg);

    uint8_t aad[HEADER_SIZE];
    proto_write_header(aad, MSG_DATA, 12345, sess.tx_seq);

    uint8_t nonce[NONCE_SIZE];
    uint8_t ct[msg_len + TAG_SIZE];
    size_t ct_len = 0;

    if (crypto_aead_encrypt(&sess, (const uint8_t *)msg, msg_len,
        aad, HEADER_SIZE, nonce, ct, &ct_len) != 0)
        return 0;

    if (ct_len != msg_len + TAG_SIZE) return 0;

    /* Расшифровка */
    uint8_t pt[msg_len + 1];
    size_t pt_len = 0;

    if (crypto_aead_decrypt(&sess, ct, ct_len,
        aad, HEADER_SIZE, nonce,
        pt, &pt_len) != 0)
        return 0;

    if (pt_len != msg_len) return 0;
    if (memcmp(pt, msg, msg_len) != 0) return 0;

    return 1;
}

/* ── Тест повреждённого тега ──────────────────────────────────────── */
static int test_aead_tampered(void)
{
    struct session sess;
    memset(&sess, 0, sizeof(sess));
    sess.suite = SUITE_CHACHA20_POLY1305;
    sess.tx_seq = 1;

    randombytes_buf(sess.write_key, KEY_SIZE);
    randombytes_buf(sess.read_key, KEY_SIZE);
    randombytes_buf(sess.write_salt, NONCE_SIZE);
    randombytes_buf(sess.read_salt, NONCE_SIZE);
    memcpy(sess.read_key, sess.write_key, KEY_SIZE);
    memcpy(sess.read_salt, sess.write_salt, NONCE_SIZE);

    const char *msg = "test data";
    uint8_t aad[HEADER_SIZE];
    proto_write_header(aad, MSG_DATA, 1, sess.tx_seq);

    uint8_t nonce[NONCE_SIZE];
    uint8_t ct[strlen(msg) + TAG_SIZE];
    size_t ct_len = 0;

    crypto_aead_encrypt(&sess, (const uint8_t *)msg, strlen(msg),
                        aad, HEADER_SIZE, nonce, ct, &ct_len);

    /* Повреждаем один байт шифртекста */
    ct[0] ^= 0xFF;

    uint8_t pt[64];
    size_t pt_len = 0;

    /* Должно вернуть ошибку */
    return crypto_aead_decrypt(&sess, ct, ct_len,
                               aad, HEADER_SIZE, nonce,
                               pt, &pt_len) != 0;
}

/* ── Тест KDF ─────────────────────────────────────────────────────── */
static int test_kdf_derivation(void)
{
    uint8_t shared[X25519_PUB_SIZE];
    uint8_t cr[RANDOM_SIZE], sr[RANDOM_SIZE];
    uint8_t psk[PSK_SIZE];

    randombytes_buf(shared, sizeof(shared));
    randombytes_buf(cr, sizeof(cr));
    randombytes_buf(sr, sizeof(sr));
    randombytes_buf(psk, sizeof(psk));

    struct session client_sess, server_sess;
    memset(&client_sess, 0, sizeof(client_sess));
    memset(&server_sess, 0, sizeof(server_sess));

    crypto_derive_session_keys(shared, cr, sr, psk, false, &client_sess);
    crypto_derive_session_keys(shared, cr, sr, psk, true, &server_sess);

    /* write_key клиента = read_key сервера */
    if (memcmp(client_sess.write_key, server_sess.read_key, KEY_SIZE) != 0)
        return 0;

    /* write_key сервера = read_key клиента */
    if (memcmp(server_sess.write_key, client_sess.read_key, KEY_SIZE) != 0)
        return 0;

    /* write_salt клиента = read_salt сервера */
    if (memcmp(client_sess.write_salt, server_sess.read_salt, NONCE_SIZE) != 0)
        return 0;

    return 1;
}

/* ── Тест HMAC ────────────────────────────────────────────────────── */
static int test_hmac(void)
{
    uint8_t key[KEY_SIZE];
    randombytes_buf(key, sizeof(key));

    const char *data = "authentication test";
    uint8_t mac[HMAC_SIZE];

    crypto_hmac(key, (const uint8_t *)data, strlen(data), mac);

    if (!crypto_hmac_verify(key, (const uint8_t *)data, strlen(data), mac))
        return 0;

    /* Повреждённые данные */
    if (crypto_hmac_verify(key, (const uint8_t *)"tampered data", 13, mac))
        return 0;

    return 1;
}

/* ── main ─────────────────────────────────────────────────────────── */
int main(void)
{
    printf("=== Tunnel Protocol Unit Tests ===\n\n");

    if (crypto_init() != 0) {
        fprintf(stderr, "FATAL: crypto_init failed\n");
        return 1;
    }

    printf("[Protocol]\n");
    TEST(header_roundtrip);
    TEST(header_bad_magic);
    TEST(nonce_computation);

    printf("\n[Anti-Replay]\n");
    TEST(replay_window);

    printf("\n[AEAD Encryption]\n");
    TEST(aead_roundtrip);
    TEST(aead_tampered);

    printf("\n[Key Derivation]\n");
    TEST(kdf_derivation);

    printf("\n[HMAC]\n");
    TEST(hmac);

    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
