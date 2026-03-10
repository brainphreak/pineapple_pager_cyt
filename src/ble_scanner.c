/*
 * ble_scanner.c — Passive BLE Advertisement Scanner for Chasing Your Tail
 *
 * Opens a raw HCI socket on the specified adapter (default hci1 = MT7921U),
 * enables passive LE scanning, and logs every advertisement to SQLite.
 *
 * Usage:
 *   ble_scanner [options]
 *   Options:
 *     --db PATH       Path to SQLite database (required)
 *     --hci N         HCI device number (default: 1)
 *     --daemon        Daemonize (fork to background)
 *     --pidfile PATH  Write PID to file (useful with --daemon)
 *     --verbose       Print each sighting to stdout
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
#include <sys/types.h>
#include <sys/stat.h>

/* Bluetooth headers — available in musl / glibc on Linux */
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "db.h"
#include "manufacturers.h"

/* ------------------------------------------------------------------ */
/*  HCI constants not always in musl bluetooth headers                  */
/* ------------------------------------------------------------------ */
#ifndef HCI_LE_META_EVENT
#define HCI_LE_META_EVENT       0x3E
#endif

#ifndef EVT_LE_ADVERTISING_REPORT
#define EVT_LE_ADVERTISING_REPORT  0x02
#endif

#ifndef LE_SCAN_PASSIVE
#define LE_SCAN_PASSIVE  0x00
#endif
#ifndef LE_SCAN_ACTIVE
#define LE_SCAN_ACTIVE   0x01
#endif

/* AD type constants */
#define AD_TYPE_FLAGS            0x01
#define AD_TYPE_UUID16_INCOMPLETE 0x02
#define AD_TYPE_UUID16_COMPLETE   0x03
#define AD_TYPE_UUID32_INCOMPLETE 0x04
#define AD_TYPE_UUID32_COMPLETE   0x05
#define AD_TYPE_UUID128_INCOMPLETE 0x06
#define AD_TYPE_UUID128_COMPLETE  0x07
#define AD_TYPE_SHORT_NAME       0x08
#define AD_TYPE_COMPLETE_NAME    0x09
#define AD_TYPE_TX_POWER         0x0A
#define AD_TYPE_CLASS_OF_DEVICE  0x0D
#define AD_TYPE_SLAVE_CONN_INTERVAL 0x12
#define AD_TYPE_SERVICE_DATA     0x16
#define AD_TYPE_APPEARANCE       0x19
#define AD_TYPE_MANUFACTURER     0xFF

/* ------------------------------------------------------------------ */
/*  Globals                                                             */
/* ------------------------------------------------------------------ */
static volatile sig_atomic_t g_running = 1;
static int   g_hci_sock = -1;
static char  g_pidfile[256] = {0};

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* ------------------------------------------------------------------ */
/*  Daemonize                                                           */
/* ------------------------------------------------------------------ */
static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0); /* parent exits */

    setsid();
    pid = fork();
    if (pid < 0) { perror("fork2"); exit(1); }
    if (pid > 0) exit(0);

    /* Redirect stdio to /dev/null */
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
/*  MAC formatting                                                      */
/* ------------------------------------------------------------------ */
static void format_mac(const uint8_t *addr, char *out) {
    /* BLE MAC bytes come LSB-first in HCI events */
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
}

/* ------------------------------------------------------------------ */
/*  HCI socket setup                                                    */
/* ------------------------------------------------------------------ */
static int hci_open_scanner(int dev_id) {
    int sock = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
    if (sock < 0) {
        perror("[ble] socket");
        return -1;
    }

    /* Bind to specific HCI device */
    struct sockaddr_hci addr = {0};
    addr.hci_family  = AF_BLUETOOTH;
    addr.hci_dev     = (uint16_t)dev_id;
    addr.hci_channel = HCI_CHANNEL_RAW;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[ble] bind");
        close(sock);
        return -1;
    }

    /* Filter: only receive HCI events (type 0x04) */
    struct hci_filter flt;
    hci_filter_clear(&flt);
    hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
    hci_filter_set_event(HCI_LE_META_EVENT, &flt);
    /* Also let through command complete so we can verify scan enable */
    hci_filter_set_event(EVT_CMD_COMPLETE, &flt);

    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        perror("[ble] setsockopt HCI_FILTER");
        close(sock);
        return -1;
    }

    return sock;
}

/* ------------------------------------------------------------------ */
/*  Send HCI LE Set Scan Parameters                                     */
/* ------------------------------------------------------------------ */
static int hci_le_set_scan_params(int sock, int dev_id,
                                   uint8_t type,       /* LE_SCAN_PASSIVE */
                                   uint16_t interval,  /* 0x0010 */
                                   uint16_t window,    /* 0x0010 */
                                   uint8_t own_addr_type, /* 0=public */
                                   uint8_t filter)     /* 0=all */
{
    int ret = hci_le_set_scan_parameters(sock, type, htobs(interval),
                                          htobs(window), own_addr_type,
                                          filter, 2000);
    if (ret < 0) {
        fprintf(stderr, "[ble] hci_le_set_scan_parameters: %s\n",
                strerror(errno));
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Send HCI LE Set Scan Enable                                         */
/* ------------------------------------------------------------------ */
static int hci_le_scan_enable(int sock, uint8_t enable, uint8_t filter_dup) {
    int ret = hci_le_set_scan_enable(sock, enable, filter_dup, 2000);
    if (ret < 0) {
        fprintf(stderr, "[ble] hci_le_set_scan_enable(%d): %s\n",
                enable, strerror(errno));
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Parse AD structures from advertisement payload                     */
/* ------------------------------------------------------------------ */
static void parse_ad_structures(const uint8_t *data, int len,
                                  cyt_sighting_t *s) {
    int i = 0;
    while (i < len) {
        if (i + 1 >= len) break;
        uint8_t ad_len  = data[i];
        if (ad_len == 0) break;
        if (i + ad_len >= len) break; /* bounds check */

        uint8_t ad_type = data[i + 1];
        const uint8_t *ad_data = &data[i + 2];
        int ad_data_len = ad_len - 1;

        switch (ad_type) {
            case AD_TYPE_SHORT_NAME:
            case AD_TYPE_COMPLETE_NAME:
                if (s->name[0] == '\0' && ad_data_len > 0) {
                    int copy = ad_data_len < (int)sizeof(s->name)-1
                               ? ad_data_len : (int)sizeof(s->name)-1;
                    memcpy(s->name, ad_data, copy);
                    s->name[copy] = '\0';
                }
                break;

            case AD_TYPE_MANUFACTURER:
                if (ad_data_len >= 2) {
                    uint16_t cid = (uint16_t)(ad_data[0] | (ad_data[1] << 8));
                    const char *mfr = ble_manufacturer_name(cid);
                    if (mfr) {
                        strncpy(s->manufacturer, mfr, sizeof(s->manufacturer)-1);
                    } else {
                        snprintf(s->manufacturer, sizeof(s->manufacturer),
                                 "0x%04X", cid);
                    }
                    /* Apple sub-type identification */
                    if (cid == 0x004C && ad_data_len >= 3) {
                        uint8_t apple_type = ad_data[2];
                        const char *aname = apple_adv_type_name(apple_type);
                        snprintf(s->manufacturer, sizeof(s->manufacturer),
                                 "Apple/%s", aname);
                    }
                    /* Store raw manufacturer data in adv_data field */
                    int copy = ad_data_len < (int)sizeof(s->adv_data)
                               ? ad_data_len : (int)sizeof(s->adv_data);
                    memcpy(s->adv_data, ad_data, copy);
                    s->adv_data_len = copy;
                }
                break;

            case AD_TYPE_UUID16_INCOMPLETE:
            case AD_TYPE_UUID16_COMPLETE:
                /* Check for notable service UUIDs */
                for (int j = 0; j + 1 < ad_data_len; j += 2) {
                    uint16_t uuid = (uint16_t)(ad_data[j] | (ad_data[j+1] << 8));
                    const char *sname = service_uuid16_name(uuid);
                    if (sname && s->manufacturer[0] == '\0') {
                        strncpy(s->manufacturer, sname, sizeof(s->manufacturer)-1);
                    }
                }
                break;

            default:
                break;
        }

        i += 1 + ad_len;
    }
}

/* ------------------------------------------------------------------ */
/*  Process LE Advertising Report                                       */
/* ------------------------------------------------------------------ */
static void process_le_adv_report(sqlite3 *db, const uint8_t *buf, int len,
                                    int verbose) {
    if (len < 2) return;

    uint8_t num_reports = buf[0];
    int offset = 1;

    for (int r = 0; r < num_reports; r++) {
        /* Each report: event_type(1), addr_type(1), addr(6), data_len(1),
         *              data(N), rssi(1) */
        if (offset + 9 > len) break;

        /* uint8_t event_type = buf[offset]; */  offset++;
        uint8_t addr_type   = buf[offset];        offset++;
        const uint8_t *addr = &buf[offset];       offset += 6;
        uint8_t data_len    = buf[offset];        offset++;

        if (offset + data_len + 1 > len) break;
        const uint8_t *adv_payload = &buf[offset]; offset += data_len;
        int8_t  rssi               = (int8_t)buf[offset]; offset++;

        cyt_sighting_t s;
        memset(&s, 0, sizeof(s));

        format_mac(addr, s.mac);
        strncpy(s.source, "ble", sizeof(s.source)-1);
        s.rssi      = (int)rssi;
        s.timestamp = (int64_t)time(NULL);

        /* Note address type (random MACs are very common) */
        (void)addr_type; /* addr_type 0=public, 1=random */

        /* Parse advertisement payload */
        parse_ad_structures(adv_payload, data_len, &s);

        /* Skip insert if DB not available */
        if (!db) {
            if (verbose) {
                printf("[ble] %-17s  rssi=%4d  %-20s  %s\n",
                       s.mac, s.rssi, s.manufacturer, s.name);
            }
            continue;
        }

        db_insert_sighting(db, &s);

        if (verbose) {
            printf("[ble] %-17s  rssi=%4d  %-30s  %s\n",
                   s.mac, s.rssi, s.manufacturer, s.name);
            fflush(stdout);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Main receive loop                                                   */
/* ------------------------------------------------------------------ */
static void scan_loop(int sock, sqlite3 *db, int verbose) {
    uint8_t buf[HCI_MAX_EVENT_SIZE + 1];

    while (g_running) {
        ssize_t n = read(sock, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000);
                continue;
            }
            perror("[ble] read");
            break;
        }
        if (n < 3) continue;

        /* buf[0] = HCI packet type (0x04 for event) */
        if (buf[0] != HCI_EVENT_PKT) continue;

        uint8_t event_code = buf[1];
        /* uint8_t param_len  = buf[2]; */
        const uint8_t *params = &buf[3];
        int params_len = (int)n - 3;

        if (event_code != HCI_LE_META_EVENT) continue;
        if (params_len < 1) continue;

        uint8_t subevent = params[0];
        if (subevent != EVT_LE_ADVERTISING_REPORT) continue;

        process_le_adv_report(db, params + 1, params_len - 1, verbose);
    }
}

/* ------------------------------------------------------------------ */
/*  Usage                                                               */
/* ------------------------------------------------------------------ */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --db PATH       SQLite database path (required)\n"
        "  --hci N         HCI device number (default: 1)\n"
        "  --daemon        Fork to background\n"
        "  --pidfile PATH  Write PID file\n"
        "  --verbose       Print sightings to stdout\n"
        "  --help          Show this help\n",
        prog);
}

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[]) {
    const char *db_path  = NULL;
    int         hci_id   = 1;
    int         do_daemon = 0;
    int         verbose  = 0;
    const char *pidfile  = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--db") && i+1 < argc) {
            db_path = argv[++i];
        } else if (!strcmp(argv[i], "--hci") && i+1 < argc) {
            hci_id = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--daemon")) {
            do_daemon = 1;
        } else if (!strcmp(argv[i], "--pidfile") && i+1 < argc) {
            pidfile = argv[++i];
        } else if (!strcmp(argv[i], "--verbose")) {
            verbose = 1;
        } else if (!strcmp(argv[i], "--help")) {
            usage(argv[0]); return 0;
        } else {
            fprintf(stderr, "[ble] Unknown option: %s\n", argv[i]);
            usage(argv[0]); return 1;
        }
    }

    if (!db_path) {
        fprintf(stderr, "[ble] Error: --db PATH is required\n");
        usage(argv[0]); return 1;
    }

    /* Bring hci device up via hciconfig (best-effort) */
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "hciconfig hci%d up 2>/dev/null", hci_id);
    system(cmd);
    usleep(200000); /* 200ms for adapter to come up */

    /* Open HCI socket */
    g_hci_sock = hci_open_scanner(hci_id);
    if (g_hci_sock < 0) {
        fprintf(stderr, "[ble] Failed to open HCI socket on hci%d\n", hci_id);
        return 1;
    }

    /* Configure passive scan:
     * type=0 (passive), interval=0x0010 (10ms), window=0x0010 (10ms)
     * own_addr=0 (public), filter=0 (all) */
    if (hci_le_set_scan_params(g_hci_sock, hci_id,
                                LE_SCAN_PASSIVE, 0x0010, 0x0010,
                                0x00, 0x00) < 0) {
        fprintf(stderr, "[ble] Warning: could not set scan params, continuing anyway\n");
    }

    /* Enable scanning, no duplicate filter so we see all advertisements */
    if (hci_le_scan_enable(g_hci_sock, 0x01, 0x00) < 0) {
        fprintf(stderr, "[ble] Warning: could not enable scanning, continuing anyway\n");
    }

    /* Open database */
    sqlite3 *db = NULL;
    if (db_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "[ble] Failed to open database: %s\n", db_path);
        hci_le_scan_enable(g_hci_sock, 0x00, 0x00);
        close(g_hci_sock);
        return 1;
    }

    /* Daemonize after all setup is done */
    if (do_daemon) {
        daemonize();
    }

    if (pidfile) {
        write_pidfile(pidfile);
    }

    /* Signal handling */
    signal(SIGTERM, sig_handler);
    signal(SIGINT,  sig_handler);
    signal(SIGHUP,  sig_handler);

    if (!do_daemon)
        fprintf(stderr, "[ble] Scanning on hci%d → %s\n", hci_id, db_path);

    /* Main loop */
    scan_loop(g_hci_sock, db, verbose);

    /* Cleanup */
    fprintf(stderr, "[ble] Shutting down\n");
    hci_le_scan_enable(g_hci_sock, 0x00, 0x00);
    close(g_hci_sock);
    db_close(db);

    if (g_pidfile[0])
        unlink(g_pidfile);

    return 0;
}
