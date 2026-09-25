/*
 * tun.c — Создание и работа с TUN-интерфейсом.
 */
#include "tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ── Создание TUN-интерфейса ──────────────────────────────────────── */
int tun_alloc(const char *name)
{
    struct ifreq ifr;
    int fd;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }

    log_msg("TUN interface '%s' created (fd=%d)", ifr.ifr_name, fd);
    return fd;
}

/* ── Назначение IP-адреса через ioctl ─────────────────────────────── */
int tun_set_ip(int tun_fd, const char *ip_cidr)
{
    /* Используем системный вызов ip(8) для простоты прототипа.
     * В продакшене лучше через netlink. */
    char cmd[256];

    /* Получаем имя интерфейса */
    struct ifreq ifr;
    if (ioctl(tun_fd, TUNGETIFF, &ifr) < 0) {
        perror("ioctl TUNGETIFF");
        return -1;
    }

    /* Парсим IP и маску из CIDR */
    char ip[64];
    int prefix = 24;
    strncpy(ip, ip_cidr, sizeof(ip) - 1);
    ip[sizeof(ip) - 1] = '\0';
    char *slash = strchr(ip, '/');
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }

    /* ip addr add */
    snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev %s 2>/dev/null",
             ip, prefix, ifr.ifr_name);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: failed to add IP %s/%d to %s\n",
                ip, prefix, ifr.ifr_name);
    }

    /* ip link set up */
    snprintf(cmd, sizeof(cmd), "ip link set %s up", ifr.ifr_name);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: failed to bring up %s\n", ifr.ifr_name);
        return -1;
    }

    log_msg("TUN '%s' configured: %s/%d", ifr.ifr_name, ip, prefix);
    return 0;
}

/* ── Чтение из TUN ────────────────────────────────────────────────── */
ssize_t tun_read(int fd, uint8_t *buf, size_t len)
{
    return read(fd, buf, len);
}

/* ── Запись в TUN ─────────────────────────────────────────────────── */
ssize_t tun_write(int fd, const uint8_t *buf, size_t len)
{
    return write(fd, buf, len);
}
