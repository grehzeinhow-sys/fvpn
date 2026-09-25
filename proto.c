/*
 * proto.c — Сериализация/десериализация пакетов, анти-повтор.
 */
#include "tunnel.h"
#include <string.h>
#include <arpa/inet.h>

/* ── Запись заголовка в буфер ─────────────────────────────────────── */
void proto_write_header(uint8_t *buf, uint8_t type, uint64_t session_id,
                        uint64_t seq)
{
    uint32_t magic = htole32(PROTO_MAGIC);
    memcpy(buf + 0, &magic, 4);
    buf[4] = PROTO_VERSION;
    buf[5] = type;
    buf[6] = 0;  /* flags */
    buf[7] = 0;  /* reserved */
    uint64_t sid = htole64(session_id);
    memcpy(buf + 8, &sid, 8);
    uint64_t s = htole64(seq);
    memcpy(buf + 16, &s, 8);
}

/* ── Разбор заголовка ─────────────────────────────────────────────── */
int proto_parse_header(const uint8_t *buf, size_t len,
                       struct packet_header *hdr)
{
    if (len < HEADER_SIZE) return -1;

    uint32_t magic;
    memcpy(&magic, buf + 0, 4);
    hdr->magic = le32toh(magic);
    hdr->version = buf[4];
    hdr->type = buf[5];
    hdr->flags = buf[6];
    hdr->reserved = buf[7];

    uint64_t sid;
    memcpy(&sid, buf + 8, 8);
    hdr->session_id = le64toh(sid);

    uint64_t s;
    memcpy(&s, buf + 16, 8);
    hdr->seq = le64toh(s);

    if (hdr->magic != PROTO_MAGIC) return -1;
    if (hdr->version != PROTO_VERSION) return -1;

    return 0;
}

/* ── Вычисление nonce из соли и последовательности ────────────────── */
void proto_compute_nonce(const uint8_t salt[NONCE_SIZE], uint64_t seq,
                         uint8_t nonce_out[NONCE_SIZE])
{
    /* nonce = salt XOR seq (последние 8 байт) */
    memcpy(nonce_out, salt, NONCE_SIZE);
    uint8_t seq_bytes[8];
    uint64_t s = htole64(seq);
    memcpy(seq_bytes, &s, 8);
    for (int i = 0; i < 8; i++) {
        nonce_out[NONCE_SIZE - 8 + i] ^= seq_bytes[i];
    }
}

/* ── Анти-повтор: инициализация ───────────────────────────────────── */
void replay_init(struct replay_window *w)
{
    w->last_seq = 0;
    w->bitmap = 0;
}

/* ── Анти-повтор: проверка ────────────────────────────────────────── */
int replay_check(const struct replay_window *w, uint64_t seq)
{
    if (seq == 0) return -1;  /* seq 0 не используется */
        if (seq > w->last_seq) return 0;  /* новый пакет */

            uint64_t diff = w->last_seq - seq;
    if (diff >= 64) return -1;  /* слишком старый */
        if (w->bitmap & (1ULL << diff)) return -1;  /* дубликат */
            return 0;
}

/* ── Анти-повтор: обновление окна ─────────────────────────────────── */
void replay_update(struct replay_window *w, uint64_t seq)
{
    if (seq == 0) return;

    if (seq > w->last_seq) {
        uint64_t shift = seq - w->last_seq;
        if (w->last_seq == 0) {
            w->bitmap = 1;
        } else if (shift < 64) {
            w->bitmap <<= shift;
            w->bitmap |= 1;
        } else {
            w->bitmap = 1;
        }
        w->last_seq = seq;
    } else {
        uint64_t diff = w->last_seq - seq;
        if (diff < 64) {
            w->bitmap |= (1ULL << diff);
        }
    }
}
