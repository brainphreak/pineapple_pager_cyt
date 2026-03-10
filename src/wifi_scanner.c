/*
 * wifi_scanner.c — WiFi Probe Request Capture for Chasing Your Tail
 *
 * Puts a WiFi interface into monitor mode and captures 802.11 probe
 * request frames (management type=0, subtype=4).  Logs to SQLite.
 *
 * Approach: raw socket on the monitor interface, reads 802.11 radiotap
 * frames.  Extracts source MAC, SSID from the probe request body, and
 * RSSI from the radiotap header.
 *
 * Usage:
 *   wifi_scanner [options]
 *   Options:
 *     --db PATH       SQLite database (required)
 *     --iface IFACE   Monitor interface (default: wlan0mon, tries wlan0/wlan1)
 *     --daemon        Fork to background
 *     --pidfile PATH  Write PID file
 *     --verbose       Print sightings to stdout
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "db.h"

/* ------------------------------------------------------------------ */
/*  802.11 constants                                                    */
/* ------------------------------------------------------------------ */
#define WLAN_FC_TYPE_MGMT       0
#define WLAN_FC_SUBTYPE_PROBE   4

/* Radiotap header present flags */
#define RADIOTAP_TSFT           (1 << 0)
#define RADIOTAP_FLAGS          (1 << 1)
#define RADIOTAP_RATE           (1 << 2)
#define RADIOTAP_CHANNEL        (1 << 3)
#define RADIOTAP_FHSS           (1 << 4)
#define RADIOTAP_DBM_ANTSIGNAL  (1 << 5)
#define RADIOTAP_DBM_ANTNOISE   (1 << 6)
#define RADIOTAP_LOCK_QUALITY   (1 << 7)
#define RADIOTAP_TX_ATTENUATION (1 << 8)
#define RADIOTAP_DBM_TX_POWER   (1 << 10)
#define RADIOTAP_ANTENNA        (1 << 11)
#define RADIOTAP_DB_ANTSIGNAL   (1 << 12)

/* ------------------------------------------------------------------ */
/*  Radiotap header                                                     */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((packed)) radiotap_hdr_t;

/* ------------------------------------------------------------------ */
/*  802.11 frame header                                                 */
/* ------------------------------------------------------------------ */
typedef struct {
    uint16_t fc;         /* Frame control */
    uint16_t duration;
    uint8_t  addr1[6];   /* Destination */
    uint8_t  addr2[6];   /* Source */
    uint8_t  addr3[6];   /* BSSID */
    uint16_t seq_ctrl;
} __attribute__((packed)) ieee80211_hdr_t;

/* ------------------------------------------------------------------ */
/*  Globals                                                             */
/* ------------------------------------------------------------------ */
static volatile sig_atomic_t g_running = 1;
static void sig_handler(int sig) { (void)sig; g_running = 0; }

/* ------------------------------------------------------------------ */
/*  MAC formatting                                                      */
/* ------------------------------------------------------------------ */
static void format_mac(const uint8_t *addr, char *out) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

/* ------------------------------------------------------------------ */
/*  Put interface into monitor mode using system commands               */
/* ------------------------------------------------------------------ */
static int setup_monitor_mode(const char *iface) {
    char cmd[256];

    /* Try iw first (preferred on OpenWrt) */
    snprintf(cmd, sizeof(cmd),
             "ip link set %s down 2>/dev/null && "
             "iw dev %s set type monitor 2>/dev/null && "
             "ip link set %s up 2>/dev/null",
             iface, iface, iface);
    int rc = system(cmd);
    if (rc == 0) return 0;

    /* Fall back to iwconfig */
    snprintf(cmd, sizeof(cmd),
             "ifconfig %s down 2>/dev/null && "
             "iwconfig %s mode monitor 2>/dev/null && "
             "ifconfig %s up 2>/dev/null",
             iface, iface, iface);
    rc = system(cmd);
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Try to create a monitor interface via iw                           */
/* ------------------------------------------------------------------ */
static int create_monitor_iface(const char *base, char *mon_out, size_t mon_sz) {
    char cmd[256];

    /* Try wlan1mon first (Pineapple usually has wlan1 for monitor) */
    const char *candidates[] = { "wlan1", "wlan0", "wlan2", NULL };

    for (int i = 0; candidates[i]; i++) {
        snprintf(mon_out, mon_sz, "%smon", candidates[i]);

        /* Delete if exists */
        snprintf(cmd, sizeof(cmd), "iw dev %s del 2>/dev/null", mon_out);
        system(cmd);

        /* Create */
        snprintf(cmd, sizeof(cmd),
                 "iw dev %s interface add %s type monitor 2>/dev/null",
                 candidates[i], mon_out);
        if (system(cmd) == 0) {
            snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", mon_out);
            system(cmd);
            fprintf(stderr, "[wifi] Created monitor interface: %s\n", mon_out);
            return 0;
        }
    }

    (void)base;
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Parse RSSI from radiotap header                                     */
/* ------------------------------------------------------------------ */
static int8_t parse_radiotap_rssi(const uint8_t *buf, int len) {
    if (len < (int)sizeof(radiotap_hdr_t)) return -100;

    const radiotap_hdr_t *rt = (const radiotap_hdr_t *)buf;
    uint32_t present = le32toh(rt->it_present);
    uint16_t rt_len  = le16toh(rt->it_len);

    if (rt_len > len) return -100;

    /* Walk the radiotap fields to find DBM_ANTSIGNAL */
    int offset = sizeof(radiotap_hdr_t);

    /* Handle extended present bitmaps */
    uint32_t p = present;
    while ((p & (1 << 31)) && offset + 4 <= rt_len) {
        offset += 4;
        p = *(uint32_t *)(buf + offset - 4);
    }

    /* Now walk fields in order of bits in `present` */
    if (present & RADIOTAP_TSFT) {
        offset = (offset + 7) & ~7; /* 8-byte align */
        offset += 8;
    }
    if (present & RADIOTAP_FLAGS) {
        offset += 1;
    }
    if (present & RADIOTAP_RATE) {
        offset += 1;
    }
    if (present & RADIOTAP_CHANNEL) {
        offset = (offset + 1) & ~1; /* 2-byte align */
        offset += 4; /* freq + flags */
    }
    if (present & RADIOTAP_FHSS) {
        offset += 2;
    }
    if (present & RADIOTAP_DBM_ANTSIGNAL) {
        if (offset < rt_len) {
            return (int8_t)buf[offset];
        }
    }

    return -100;
}

/* ------------------------------------------------------------------ */
/*  Parse 802.11 probe request                                          */
/* ------------------------------------------------------------------ */
static void parse_probe_request(const uint8_t *buf, int len,
                                  int8_t rssi, sqlite3 *db, int verbose) {
    if (len < (int)sizeof(ieee80211_hdr_t)) return;

    const ieee80211_hdr_t *hdr = (const ieee80211_hdr_t *)buf;
    uint16_t fc = le16toh(hdr->fc);

    uint8_t type    = (fc >> 2)  & 0x3;
    uint8_t subtype = (fc >> 4)  & 0xF;

    if (type != WLAN_FC_TYPE_MGMT || subtype != WLAN_FC_SUBTYPE_PROBE)
        return;

    cyt_sighting_t s;
    memset(&s, 0, sizeof(s));

    format_mac(hdr->addr2, s.mac);
    strncpy(s.source, "wifi", sizeof(s.source)-1);
    s.rssi      = (int)rssi;
    s.timestamp = (int64_t)time(NULL);

    /* Parse information elements (start after fixed fields: 24 bytes) */
    const uint8_t *ie = buf + sizeof(ieee80211_hdr_t);
    int ie_len = len - (int)sizeof(ieee80211_hdr_t);
    int i = 0;
    char ssids[256] = {0};
    int ssid_pos = 0;

    while (i + 2 <= ie_len) {
        uint8_t ie_type = ie[i];
        uint8_t ie_size = ie[i+1];
        if (i + 2 + ie_size > ie_len) break;

        if (ie_type == 0 && ie_size > 0) {
            /* SSID element */
            char ssid_buf[34] = {0};
            int copy = ie_size < 32 ? ie_size : 32;
            memcpy(ssid_buf, &ie[i+2], copy);

            /* Only add non-empty, printable SSIDs */
            int printable = 1;
            for (int j = 0; j < copy; j++) {
                if (ssid_buf[j] < 0x20 || ssid_buf[j] > 0x7E) {
                    printable = 0; break;
                }
            }

            if (printable && copy > 0) {
                if (ssid_pos + copy + 2 < (int)sizeof(ssids)) {
                    if (ssid_pos > 0) ssids[ssid_pos++] = ',';
                    memcpy(&ssids[ssid_pos], ssid_buf, copy);
                    ssid_pos += copy;
                }
            }
        }

        i += 2 + ie_size;
    }

    if (ssid_pos > 0) {
        strncpy(s.ssid_probes, ssids, sizeof(s.ssid_probes)-1);
        strncpy(s.name, ssids, sizeof(s.name)-1); /* use first SSID as name */
    }

    if (db) db_insert_sighting(db, &s);

    if (verbose) {
        printf("[wifi] %-17s  rssi=%4d  %s\n",
               s.mac, s.rssi, s.ssid_probes[0] ? s.ssid_probes : "(wildcard)");
        fflush(stdout);
    }
}

/* ------------------------------------------------------------------ */
/*  Daemonize                                                           */
/* ------------------------------------------------------------------ */
static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0);
    setsid();
    pid = fork();
    if (pid < 0) { perror("fork2"); exit(1); }
    if (pid > 0) exit(0);
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);
    }
    umask(0);
}

static void write_pidfile(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
}

/* ------------------------------------------------------------------ */
/*  Usage                                                               */
/* ------------------------------------------------------------------ */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --db PATH       SQLite database (required)\n"
        "  --iface IFACE   Monitor interface (auto-detect if not specified)\n"
        "  --daemon        Fork to background\n"
        "  --pidfile PATH  Write PID file\n"
        "  --verbose       Print sightings to stdout\n",
        prog);
}

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[]) {
    const char *db_path  = NULL;
    const char *iface    = NULL;
    const char *pidfile  = NULL;
    int do_daemon        = 0;
    int verbose          = 0;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--db")      && i+1 < argc) db_path = argv[++i];
        else if (!strcmp(argv[i], "--iface")   && i+1 < argc) iface   = argv[++i];
        else if (!strcmp(argv[i], "--pidfile") && i+1 < argc) pidfile = argv[++i];
        else if (!strcmp(argv[i], "--daemon"))   do_daemon = 1;
        else if (!strcmp(argv[i], "--verbose"))  verbose   = 1;
        else if (!strcmp(argv[i], "--help"))  { usage(argv[0]); return 0; }
        else {
            fprintf(stderr, "[wifi] Unknown option: %s\n", argv[i]);
            usage(argv[0]); return 1;
        }
    }

    if (!db_path) {
        fprintf(stderr, "[wifi] Error: --db PATH is required\n");
        usage(argv[0]); return 1;
    }

    /* Open database */
    sqlite3 *db = NULL;
    if (db_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "[wifi] Failed to open database: %s\n", db_path);
        return 1;
    }

    /* Set up monitor interface */
    char mon_iface[64];

    if (iface) {
        strncpy(mon_iface, iface, sizeof(mon_iface)-1);
        setup_monitor_mode(mon_iface);
    } else {
        /* Try to auto-detect / create monitor interface */
        if (create_monitor_iface(NULL, mon_iface, sizeof(mon_iface)) < 0) {
            /* Last resort: try wlan1mon as-is */
            strncpy(mon_iface, "wlan1mon", sizeof(mon_iface)-1);
        }
    }

    fprintf(stderr, "[wifi] Using monitor interface: %s\n", mon_iface);

    /* Open raw packet socket */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("[wifi] socket");
        db_close(db);
        return 1;
    }

    /* Bind to the monitor interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, mon_iface, IFNAMSIZ-1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "[wifi] Cannot find interface '%s': %s\n",
                mon_iface, strerror(errno));
        close(sock);
        db_close(db);
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("[wifi] bind");
        close(sock);
        db_close(db);
        return 1;
    }

    if (do_daemon) daemonize();
    if (pidfile) write_pidfile(pidfile);

    signal(SIGTERM, sig_handler);
    signal(SIGINT,  sig_handler);

    if (!do_daemon)
        fprintf(stderr, "[wifi] Capturing on %s → %s\n", mon_iface, db_path);

    /* Receive loop */
    uint8_t buf[4096];
    while (g_running) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("[wifi] recv");
            break;
        }
        if (n < (ssize_t)sizeof(radiotap_hdr_t)) continue;

        /* Parse radiotap header to get length and RSSI */
        const radiotap_hdr_t *rt = (const radiotap_hdr_t *)buf;
        uint16_t rt_len = le16toh(rt->it_len);
        if (rt_len >= n) continue;

        int8_t rssi = parse_radiotap_rssi(buf, (int)rt_len);

        /* 802.11 frame starts after radiotap */
        parse_probe_request(buf + rt_len, (int)(n - rt_len),
                            rssi, db, verbose);
    }

    close(sock);
    db_close(db);
    return 0;
}
