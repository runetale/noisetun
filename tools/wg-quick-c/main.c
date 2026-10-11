/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * wg-quick-c: WireGuard quick configuration tool (Linux).
 *
 * Usage: wg-quick-c up|down <config-file-or-interface>
 *
 * Equivalent to wg-quick(8) from wireguard-tools:
 *   - Parses .conf files ([Interface] + [Peer] sections)
 *   - Launches wg-c daemon
 *   - Configures addresses, routes, DNS, fwmark, MTU
 *   - Executes PostUp/PreDown/PostDown hooks
 *
 * Not implemented: PreUp, SaveConfig.
 * Linux only. Requires: wg-c in PATH (or WGC_BIN env), ip, resolvconf (optional).
 */

#ifdef __linux__

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>

#define MAX_PEERS 256
#define MAX_ADDRESSES 16
#define MAX_DNS 8
#define MAX_ALLOWED_IPS 64
#define MAX_LINE 4096
#define MAX_HOOKS 16

typedef struct {
    char public_key[64];
    char preshared_key[64];
    char endpoint[256];
    char allowed_ips[MAX_ALLOWED_IPS][64];
    int num_allowed_ips;
    int persistent_keepalive;
} peer_config_t;

typedef struct {
    char private_key[64];
    int listen_port;
    int fwmark;
    int mtu;
    char addresses[MAX_ADDRESSES][64];
    int num_addresses;
    char dns[MAX_DNS][256];
    int num_dns;
    char post_up[MAX_HOOKS][MAX_LINE];
    int num_post_up;
    char pre_down[MAX_HOOKS][MAX_LINE];
    int num_pre_down;
    char post_down[MAX_HOOKS][MAX_LINE];
    int num_post_down;
    char table[64];
    peer_config_t peers[MAX_PEERS];
    int num_peers;
} wg_config_t;

static bool g_verbose = false;

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static void msg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[#] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static char *strip(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
    return s;
}

static int run_cmd(const char *cmd)
{
    if (g_verbose)
        msg("%s", cmd);
    int ret = system(cmd);
    if (ret == -1)
        return -1;
    return WIFEXITED(ret) ? WEXITSTATUS(ret) : -1;
}

static int run_cmd_fmt(const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return run_cmd(buf);
}

static void replace_iface(char *dst, size_t dst_size, const char *src, const char *iface)
{
    dst[0] = '\0';
    size_t ilen = strlen(iface);
    size_t dlen = 0;
    for (const char *p = src; *p; p++) {
        if (p[0] == '%' && p[1] == 'i') {
            if (dlen + ilen >= dst_size)
                break;
            memcpy(dst + dlen, iface, ilen);
            dlen += ilen;
            p++;
        } else {
            if (dlen + 1 >= dst_size)
                break;
            dst[dlen++] = *p;
        }
    }
    dst[dlen] = '\0';
}

static void run_hooks(const char hooks[][MAX_LINE], int count, const char *iface)
{
    char expanded[MAX_LINE];
    for (int i = 0; i < count; i++) {
        replace_iface(expanded, sizeof(expanded), hooks[i], iface);
        int ret = run_cmd(expanded);
        if (ret != 0)
            fprintf(stderr, "Warning: hook failed (exit %d): %s\n", ret, expanded);
    }
}

static bool parse_config(const char *path, wg_config_t *cfg)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open config: %s: %s\n", path, strerror(errno));
        return false;
    }

    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->table, sizeof(cfg->table), "auto");

    enum { SEC_NONE, SEC_INTERFACE, SEC_PEER } section = SEC_NONE;
    char line[MAX_LINE];

    while (fgets(line, sizeof(line), f)) {
        char *s = strip(line);
        if (*s == '\0' || *s == '#')
            continue;

        if (*s == '[') {
            if (strncasecmp(s, "[Interface]", 11) == 0) {
                section = SEC_INTERFACE;
            } else if (strncasecmp(s, "[Peer]", 6) == 0) {
                section = SEC_PEER;
                if (cfg->num_peers >= MAX_PEERS) {
                    fprintf(stderr, "Too many peers\n");
                    fclose(f);
                    return false;
                }
                cfg->num_peers++;
            } else {
                fprintf(stderr, "Unknown section: %s\n", s);
                fclose(f);
                return false;
            }
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = strip(s);
        char *val = strip(eq + 1);

        if (section == SEC_INTERFACE) {
            if (strcasecmp(key, "PrivateKey") == 0) {
                snprintf(cfg->private_key, sizeof(cfg->private_key), "%s", val);
            } else if (strcasecmp(key, "ListenPort") == 0) {
                cfg->listen_port = atoi(val);
            } else if (strcasecmp(key, "FwMark") == 0) {
                cfg->fwmark = (int)strtol(val, NULL, 0);
            } else if (strcasecmp(key, "MTU") == 0) {
                cfg->mtu = atoi(val);
            } else if (strcasecmp(key, "Table") == 0) {
                snprintf(cfg->table, sizeof(cfg->table), "%s", val);
            } else if (strcasecmp(key, "Address") == 0) {
                char *saveptr;
                char *tok = strtok_r(val, ",", &saveptr);
                while (tok && cfg->num_addresses < MAX_ADDRESSES) {
                    char *a = strip(tok);
                    if (*a)
                        snprintf(cfg->addresses[cfg->num_addresses++],
                                 sizeof(cfg->addresses[0]), "%s", a);
                    tok = strtok_r(NULL, ",", &saveptr);
                }
            } else if (strcasecmp(key, "DNS") == 0) {
                char *saveptr;
                char *tok = strtok_r(val, ",", &saveptr);
                while (tok && cfg->num_dns < MAX_DNS) {
                    char *d = strip(tok);
                    if (*d)
                        snprintf(cfg->dns[cfg->num_dns++],
                                 sizeof(cfg->dns[0]), "%s", d);
                    tok = strtok_r(NULL, ",", &saveptr);
                }
            } else if (strcasecmp(key, "PostUp") == 0) {
                if (cfg->num_post_up < MAX_HOOKS)
                    snprintf(cfg->post_up[cfg->num_post_up++],
                             MAX_LINE, "%s", val);
            } else if (strcasecmp(key, "PreDown") == 0) {
                if (cfg->num_pre_down < MAX_HOOKS)
                    snprintf(cfg->pre_down[cfg->num_pre_down++],
                             MAX_LINE, "%s", val);
            } else if (strcasecmp(key, "PostDown") == 0) {
                if (cfg->num_post_down < MAX_HOOKS)
                    snprintf(cfg->post_down[cfg->num_post_down++],
                             MAX_LINE, "%s", val);
            }
        } else if (section == SEC_PEER) {
            peer_config_t *peer = &cfg->peers[cfg->num_peers - 1];
            if (strcasecmp(key, "PublicKey") == 0) {
                snprintf(peer->public_key, sizeof(peer->public_key), "%s", val);
            } else if (strcasecmp(key, "PresharedKey") == 0) {
                snprintf(peer->preshared_key, sizeof(peer->preshared_key), "%s", val);
            } else if (strcasecmp(key, "Endpoint") == 0) {
                snprintf(peer->endpoint, sizeof(peer->endpoint), "%s", val);
            } else if (strcasecmp(key, "PersistentKeepalive") == 0) {
                peer->persistent_keepalive = atoi(val);
            } else if (strcasecmp(key, "AllowedIPs") == 0) {
                char *saveptr;
                char *tok = strtok_r(val, ",", &saveptr);
                while (tok && peer->num_allowed_ips < MAX_ALLOWED_IPS) {
                    char *a = strip(tok);
                    if (*a)
                        snprintf(peer->allowed_ips[peer->num_allowed_ips++],
                                 sizeof(peer->allowed_ips[0]), "%s", a);
                    tok = strtok_r(NULL, ",", &saveptr);
                }
            }
        }
    }

    fclose(f);

    if (cfg->private_key[0] == '\0') {
        fprintf(stderr, "Missing PrivateKey in [Interface]\n");
        return false;
    }

    return true;
}

static bool has_default_route(const wg_config_t *cfg)
{
    for (int i = 0; i < cfg->num_peers; i++) {
        for (int j = 0; j < cfg->peers[i].num_allowed_ips; j++) {
            const char *ip = cfg->peers[i].allowed_ips[j];
            if (strcmp(ip, "0.0.0.0/0") == 0 || strcmp(ip, "::/0") == 0)
                return true;
        }
    }
    return false;
}

static int cmd_up(const char *iface, const char *config_path)
{
    wg_config_t cfg;
    if (!parse_config(config_path, &cfg))
        return 1;

    const char *wgc_bin = getenv("WGC_BIN");
    if (!wgc_bin)
        wgc_bin = "wg-c";

    msg("Starting wg-c for %s", iface);

    /* Start wg-c daemon in background */
    pid_t pid = fork();
    if (pid < 0)
        die("fork: %s", strerror(errno));

    if (pid == 0) {
        setsid();
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO)
                close(devnull);
        }
        execlp(wgc_bin, wgc_bin, "-f", iface, (char *)NULL);
        fprintf(stderr, "Failed to exec %s: %s\n", wgc_bin, strerror(errno));
        _exit(127);
    }

    /* Wait for UAPI socket to appear */
    char sock_path[PATH_MAX];
    snprintf(sock_path, sizeof(sock_path), "/var/run/wireguard/%s.sock", iface);
    for (int i = 0; i < 40; i++) {
        usleep(100000);
        struct stat st;
        if (stat(sock_path, &st) == 0)
            goto socket_ready;
    }
    die("Timeout waiting for %s (wg-c failed to start?)", sock_path);

socket_ready:;
    /* Write private key to temp file (O_CREAT|O_TRUNC with 0600 avoids TOCTOU) */
    char keyfile[PATH_MAX];
    snprintf(keyfile, sizeof(keyfile), "/tmp/.wg-quick-c-%s.key", iface);
    int key_fd = open(keyfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (key_fd < 0)
        die("Cannot write key file: %s", strerror(errno));
    FILE *kf = fdopen(key_fd, "w");
    if (!kf) {
        close(key_fd);
        die("fdopen key file: %s", strerror(errno));
    }
    fprintf(kf, "%s\n", cfg.private_key);
    fclose(kf);

    /* Configure interface via wg */
    char wg_cmd[4096];
    int off = snprintf(wg_cmd, sizeof(wg_cmd),
                       "wg set %s private-key %s", iface, keyfile);

    if (cfg.listen_port > 0)
        off += snprintf(wg_cmd + off, sizeof(wg_cmd) - off,
                        " listen-port %d", cfg.listen_port);
    if (cfg.fwmark > 0)
        off += snprintf(wg_cmd + off, sizeof(wg_cmd) - off,
                        " fwmark %d", cfg.fwmark);

    if (run_cmd(wg_cmd) != 0) {
        unlink(keyfile);
        die("Failed to configure interface");
    }

    /* Add peers */
    for (int i = 0; i < cfg.num_peers; i++) {
        peer_config_t *p = &cfg.peers[i];
        char peer_cmd[4096];
        int poff = snprintf(peer_cmd, sizeof(peer_cmd),
                            "wg set %s peer %s", iface, p->public_key);

        if (p->endpoint[0])
            poff += snprintf(peer_cmd + poff, sizeof(peer_cmd) - poff,
                             " endpoint %s", p->endpoint);

        if (p->num_allowed_ips > 0) {
            poff += snprintf(peer_cmd + poff, sizeof(peer_cmd) - poff,
                             " allowed-ips ");
            for (int j = 0; j < p->num_allowed_ips; j++) {
                if (j > 0)
                    poff += snprintf(peer_cmd + poff, sizeof(peer_cmd) - poff, ",");
                poff += snprintf(peer_cmd + poff, sizeof(peer_cmd) - poff,
                                 "%s", p->allowed_ips[j]);
            }
        }

        if (p->persistent_keepalive > 0)
            poff += snprintf(peer_cmd + poff, sizeof(peer_cmd) - poff,
                             " persistent-keepalive %d", p->persistent_keepalive);

        if (p->preshared_key[0]) {
            char pskfile[PATH_MAX];
            snprintf(pskfile, sizeof(pskfile), "/tmp/.wg-quick-c-%s-psk-%d.key", iface, i);
            int psk_fd = open(pskfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (psk_fd >= 0) {
                FILE *psk_fp = fdopen(psk_fd, "w");
                if (psk_fp) {
                    fprintf(psk_fp, "%s\n", p->preshared_key);
                    fclose(psk_fp);
                    poff += snprintf(peer_cmd + poff, sizeof(peer_cmd) - poff,
                                     " preshared-key %s", pskfile);
                } else {
                    close(psk_fd);
                }
            }
        }

        if (run_cmd(peer_cmd) != 0)
            fprintf(stderr, "Warning: failed to add peer %s\n", p->public_key);
    }

    unlink(keyfile);

    /* Add addresses */
    for (int i = 0; i < cfg.num_addresses; i++) {
        run_cmd_fmt("ip addr add %s dev %s", cfg.addresses[i], iface);
    }

    /* Set MTU */
    if (cfg.mtu > 0) {
        run_cmd_fmt("ip link set mtu %d dev %s", cfg.mtu, iface);
    } else {
        run_cmd_fmt("ip link set mtu 1420 dev %s", iface);
    }

    /* Bring interface up */
    run_cmd_fmt("ip link set %s up", iface);

    /* Add routes */
    bool use_table = (strcmp(cfg.table, "off") != 0);
    bool auto_table = (strcmp(cfg.table, "auto") == 0);
    int table_num = 0;

    if (use_table && auto_table && has_default_route(&cfg)) {
        table_num = 51820;
        run_cmd_fmt("ip rule add not fwmark %d table %d",
                    cfg.fwmark ? cfg.fwmark : 51820, table_num);
        run_cmd_fmt("ip rule add table main suppress_prefixlength 0");
    }

    for (int i = 0; i < cfg.num_peers; i++) {
        peer_config_t *p = &cfg.peers[i];
        for (int j = 0; j < p->num_allowed_ips; j++) {
            const char *aip = p->allowed_ips[j];
            if (table_num > 0)
                run_cmd_fmt("ip route add %s dev %s table %d", aip, iface, table_num);
            else if (use_table)
                run_cmd_fmt("ip route add %s dev %s", aip, iface);
        }
    }

    /* Set fwmark if routing table is used */
    if (table_num > 0 && cfg.fwmark == 0) {
        run_cmd_fmt("wg set %s fwmark 51820", iface);
    }

    /* DNS via resolvconf */
    if (cfg.num_dns > 0) {
        char dns_cmd[2048];
        int doff = snprintf(dns_cmd, sizeof(dns_cmd), "printf '");
        for (int i = 0; i < cfg.num_dns; i++) {
            doff += snprintf(dns_cmd + doff, sizeof(dns_cmd) - doff,
                             "nameserver %s\\n", cfg.dns[i]);
        }
        doff += snprintf(dns_cmd + doff, sizeof(dns_cmd) - doff,
                         "' | resolvconf -a tun.%s -m 0 -x", iface);
        if (run_cmd(dns_cmd) != 0)
            fprintf(stderr, "Warning: DNS setup failed (resolvconf not available?)\n");
    }

    /* Save PID for down */
    char pidfile[PATH_MAX];
    snprintf(pidfile, sizeof(pidfile), "/var/run/wireguard/%s.pid", iface);
    FILE *pf = fopen(pidfile, "w");
    if (pf) {
        fprintf(pf, "%d\n", pid);
        fclose(pf);
    }

    /* Save config path for down */
    char cfgref[PATH_MAX];
    snprintf(cfgref, sizeof(cfgref), "/var/run/wireguard/%s.conf", iface);
    FILE *cf = fopen(cfgref, "w");
    if (cf) {
        fprintf(cf, "%s\n", config_path);
        fclose(cf);
    }

    /* PostUp hooks */
    run_hooks((const char (*)[MAX_LINE])cfg.post_up, cfg.num_post_up, iface);

    msg("%s is up", iface);
    return 0;
}

static int cmd_down(const char *iface, const char *config_path)
{
    /* Try to load config for hooks */
    wg_config_t cfg;
    bool have_cfg = false;

    if (config_path) {
        have_cfg = parse_config(config_path, &cfg);
    } else {
        char cfgref[PATH_MAX];
        snprintf(cfgref, sizeof(cfgref), "/var/run/wireguard/%s.conf", iface);
        FILE *f = fopen(cfgref, "r");
        if (f) {
            char saved_path[PATH_MAX];
            if (fgets(saved_path, sizeof(saved_path), f)) {
                saved_path[strcspn(saved_path, "\n")] = '\0';
                have_cfg = parse_config(saved_path, &cfg);
            }
            fclose(f);
        }
    }

    /* PreDown hooks */
    if (have_cfg)
        run_hooks((const char (*)[MAX_LINE])cfg.pre_down, cfg.num_pre_down, iface);

    /* Remove DNS */
    run_cmd_fmt("resolvconf -d tun.%s 2>/dev/null", iface);

    /* Remove policy routing rules only if this interface used them */
    if (have_cfg && has_default_route(&cfg) &&
        strcmp(cfg.table, "off") != 0 &&
        (strcmp(cfg.table, "auto") == 0 || strcmp(cfg.table, "") == 0)) {
        run_cmd_fmt("ip rule del table 51820 2>/dev/null");
        run_cmd_fmt("ip rule del table main suppress_prefixlength 0 2>/dev/null");
    }

    /* Bring interface down */
    run_cmd_fmt("ip link set %s down 2>/dev/null", iface);

    /* Kill wg-c daemon */
    char pidfile[PATH_MAX];
    snprintf(pidfile, sizeof(pidfile), "/var/run/wireguard/%s.pid", iface);
    FILE *pf = fopen(pidfile, "r");
    if (pf) {
        int pid;
        if (fscanf(pf, "%d", &pid) == 1 && pid > 0) {
            kill(pid, SIGTERM);
            usleep(500000);
            kill(pid, SIGKILL);
        }
        fclose(pf);
        unlink(pidfile);
    } else {
        run_cmd_fmt("pkill -f 'wg-c -f %s' 2>/dev/null", iface);
    }

    /* Remove interface (wg-c should have done this, but be safe) */
    run_cmd_fmt("ip link del %s 2>/dev/null", iface);

    /* Clean up runtime files */
    char sock_path[PATH_MAX];
    snprintf(sock_path, sizeof(sock_path), "/var/run/wireguard/%s.sock", iface);
    unlink(sock_path);

    char cfgref[PATH_MAX];
    snprintf(cfgref, sizeof(cfgref), "/var/run/wireguard/%s.conf", iface);
    unlink(cfgref);

    /* Clean up PSK files */
    for (int i = 0; i < MAX_PEERS; i++) {
        char pskfile[PATH_MAX];
        snprintf(pskfile, sizeof(pskfile), "/tmp/.wg-quick-c-%s-psk-%d.key", iface, i);
        unlink(pskfile);
    }

    /* PostDown hooks */
    if (have_cfg)
        run_hooks((const char (*)[MAX_LINE])cfg.post_down, cfg.num_post_down, iface);

    msg("%s is down", iface);
    return 0;
}

static void print_usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [up|down] [CONFIG_FILE|INTERFACE]\n"
            "\n"
            "  CONFIG_FILE is a .conf file path (e.g., /etc/wireguard/wg0.conf)\n"
            "  INTERFACE is the name (searched in /etc/wireguard/<name>.conf)\n"
            "\n"
            "Environment:\n"
            "  WGC_BIN  Path to wg-c binary (default: wg-c in PATH)\n",
            argv0);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *target = argv[2];

    if (getenv("WG_QUICK_VERBOSE"))
        g_verbose = true;

    /* Determine interface name and config path */
    char config_path[PATH_MAX];
    char iface[256];

    bool have_config_file = false;
    struct stat target_st;
    if (stat(target, &target_st) == 0 && S_ISREG(target_st.st_mode)) {
        snprintf(config_path, sizeof(config_path), "%s", target);
        const char *base = strrchr(target, '/');
        base = base ? base + 1 : target;
        snprintf(iface, sizeof(iface), "%s", base);
        char *dot = strrchr(iface, '.');
        if (dot)
            *dot = '\0';
        have_config_file = true;
    } else {
        snprintf(iface, sizeof(iface), "%s", target);
        snprintf(config_path, sizeof(config_path),
                 "/etc/wireguard/%s.conf", target);
        struct stat etc_st;
        if (stat(config_path, &etc_st) == 0 && S_ISREG(etc_st.st_mode))
            have_config_file = true;
    }

    if (strlen(iface) >= IFNAMSIZ)
        die("Interface name too long (max %d): %s", IFNAMSIZ - 1, iface);

    if (geteuid() != 0)
        die("Must run as root");

    if (strcmp(cmd, "up") == 0) {
        if (!have_config_file)
            die("Config not found: %s", config_path);
        return cmd_up(iface, config_path);
    } else if (strcmp(cmd, "down") == 0) {
        return cmd_down(iface, have_config_file ? config_path : NULL);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}

#else /* !__linux__ */

#include <stdio.h>

int main(void)
{
    fprintf(stderr, "wg-quick-c currently supports Linux only\n");
    return 1;
}

#endif
