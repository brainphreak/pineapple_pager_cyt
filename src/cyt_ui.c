/*
 * cyt_ui.c — Display UI for Chasing Your Tail
 *
 * When compiled with -DHAVE_PAGERCTL: full pagerctl LCD display on the
 * Hak5 WiFi Pineapple Pager (480x222 framebuffer).
 *
 * When compiled WITHOUT -DHAVE_PAGERCTL (headless mode): reads the DB and
 * writes a text threat summary to stdout + periodically refreshes.
 * This is also useful for testing on any Linux machine.
 *
 * Usage:
 *   cyt_ui [options]
 *   Options:
 *     --db PATH        SQLite database path (required)
 *     --status PATH    JSON status file (written by analyzer, read here)
 *     --refresh N      Refresh interval in seconds (default: 3)
 *     --limit N        Max devices shown (default: 20)
 *     --filter SOURCE  Show only 'ble', 'wifi', or 'all' (default: all)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#include "db.h"

#ifdef HAVE_PAGERCTL
#include "pagerctl.h"
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */
#define DISPLAY_W       480
#define DISPLAY_H       222
#define MAX_LIST        64
#define DEFAULT_REFRESH 3

/* Colors (RGB565) */
#define COLOR_BLACK     0x0000
#define COLOR_WHITE     0xFFFF
#define COLOR_RED       0xF800
#define COLOR_ORANGE    0xFC60
#define COLOR_YELLOW    0xFFE0
#define COLOR_GREEN     0x07E0
#define COLOR_DARKGREEN 0x03E0
#define COLOR_BLUE      0x001F
#define COLOR_CYAN      0x07FF
#define COLOR_GRAY      0x4208
#define COLOR_DARKGRAY  0x2104
#define COLOR_HEADER_BG 0x0010  /* Dark blue */

/* Bar sizes */
#define BAR_H           18      /* Height of each device row */
#define STATUS_BAR_H    20      /* Top status bar */
#define CTRL_BAR_H      18      /* Bottom controls bar */
#define LIST_START_Y    (STATUS_BAR_H + 1)
#define LIST_H          (DISPLAY_H - STATUS_BAR_H - CTRL_BAR_H - 2)
#define ROWS_VISIBLE    (LIST_H / BAR_H)

/* ------------------------------------------------------------------ */
/*  Globals                                                             */
/* ------------------------------------------------------------------ */
static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig) { (void)sig; g_running = 0; }

/* ------------------------------------------------------------------ */
/*  Threat coloring                                                     */
/* ------------------------------------------------------------------ */
static uint32_t threat_color(double score) {
    if (score >= 0.80) return COLOR_RED;
    if (score >= 0.60) return COLOR_ORANGE;
    if (score >= 0.40) return COLOR_YELLOW;
    if (score >= 0.20) return COLOR_GREEN;
    return COLOR_GRAY;
}

static const char *threat_label(double score) {
    if (score >= 0.80) return "CRIT";
    if (score >= 0.60) return "HIGH";
    if (score >= 0.40) return " MED";
    if (score >= 0.20) return " LOW";
    return "  OK";
}

/* ------------------------------------------------------------------ */
/*  Text-mode display (no pagerctl)                                    */
/* ------------------------------------------------------------------ */
#ifndef HAVE_PAGERCTL

static void clear_screen(void) {
    /* ANSI clear screen + home cursor */
    printf("\033[2J\033[H");
}

static void text_display(const cyt_persistence_t *devices, int count,
                          int scroll, int sel, const char *filter,
                          int ble_total, int wifi_total) {
    clear_screen();

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);

    /* Count threats */
    int threats = 0;
    for (int i = 0; i < count; i++)
        if (devices[i].threat_score >= 0.40) threats++;

    printf("\033[1;37;44m"  /* bold white on blue */
           " CYT  BLE:%-4d WiFi:%-4d  %-8s  Threats:%-3d  %s "
           "\033[0m\n",
           ble_total, wifi_total, filter, threats, timebuf);

    printf("%-4s %-17s %-6s %5s %5s %4s  %-30s %-20s\n",
           "LVL", "MAC", "SRC", "SCORE", "RSSI", "SEEN", "MANUFACTURER", "NAME");
    printf("%-4s %-17s %-6s %5s %5s %4s  %-30s %-20s\n",
           "----", "-----------------", "------", "-----", "-----", "----",
           "------------------------------", "--------------------");

    int end = count < ROWS_VISIBLE + scroll ? count : ROWS_VISIBLE + scroll;

    for (int i = scroll; i < end; i++) {
        const cyt_persistence_t *p = &devices[i];
        const char *lvl = threat_label(p->threat_score);

        /* Color based on threat */
        const char *color = "\033[0m";
        if (p->threat_score >= 0.80)      color = "\033[1;31m"; /* red */
        else if (p->threat_score >= 0.60) color = "\033[1;33m"; /* yellow */
        else if (p->threat_score >= 0.40) color = "\033[1;35m"; /* magenta */
        else if (p->threat_score >= 0.20) color = "\033[0;32m"; /* green */
        else                               color = "\033[0;90m"; /* dark */

        if (i == sel) printf("\033[7m"); /* reverse video for selection */

        printf("%s%s  %-17s %-6s %5.2f %5d %4d  %-30s %-20s\033[0m\n",
               color, lvl, p->mac, p->source, p->threat_score,
               p->avg_rssi, p->sighting_count,
               p->manufacturer[0] ? p->manufacturer : "Unknown",
               p->name[0]         ? p->name         : "");
    }

    printf("\n\033[2;37m[Ctrl+C] Exit  [Auto-refresh every %ds]\033[0m\n",
           DEFAULT_REFRESH);
    fflush(stdout);
}

#else /* HAVE_PAGERCTL */

/* ------------------------------------------------------------------ */
/*  pagerctl display (full GUI mode)                                   */
/* ------------------------------------------------------------------ */

static void draw_device_row(int y, const cyt_persistence_t *p, int selected) {
    uint32_t bg = selected ? COLOR_DARKGRAY : COLOR_BLACK;
    uint32_t fg = threat_color(p->threat_score);

    /* Background for row */
    pager_draw_rect(0, y, DISPLAY_W, BAR_H, bg);

    /* Threat score bar (left 6px) */
    int bar_h = (int)(p->threat_score * BAR_H);
    pager_draw_rect(0, y + (BAR_H - bar_h), 5, bar_h, fg);

    /* Threat label */
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", threat_label(p->threat_score));
    pager_draw_text(7, y + 2, buf, fg, bg, 10);

    /* MAC address */
    pager_draw_text(42, y + 2, p->mac, COLOR_WHITE, bg, 10);

    /* Source tag */
    pager_draw_text(185, y + 2, p->source, COLOR_CYAN, bg, 10);

    /* Manufacturer + name */
    snprintf(buf, sizeof(buf), "%-22s %s",
             p->manufacturer[0] ? p->manufacturer : "Unknown",
             p->name[0]         ? p->name         : "");
    pager_draw_text(225, y + 2, buf, fg, bg, 10);

    /* RSSI + duration on right */
    int64_t dur_min = (p->last_seen - p->first_seen) / 60;
    snprintf(buf, sizeof(buf), "%ddB %dm", p->avg_rssi, (int)dur_min);
    int tw = (int)strlen(buf) * 7;
    pager_draw_text(DISPLAY_W - tw - 4, y + 2, buf, COLOR_GRAY, bg, 10);
}

static void draw_status_bar(int ble_total, int wifi_total, int threat_count) {
    pager_draw_rect(0, 0, DISPLAY_W, STATUS_BAR_H, COLOR_HEADER_BG);

    char buf[128];
    snprintf(buf, sizeof(buf), " CYT  BLE:%-3d WiFi:%-3d",
             ble_total, wifi_total);
    pager_draw_text(0, 2, buf, COLOR_WHITE, COLOR_HEADER_BG, 12);

    if (threat_count > 0) {
        snprintf(buf, sizeof(buf), "! %d THREATS !", threat_count);
        pager_draw_text(280, 2, buf, COLOR_RED, COLOR_HEADER_BG, 12);
    }

    /* Time */
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(buf, sizeof(buf), "%H:%M:%S", tm);
    pager_draw_text(420, 2, buf, COLOR_GRAY, COLOR_HEADER_BG, 10);
}

static void draw_controls_bar(const char *filter) {
    int y = DISPLAY_H - CTRL_BAR_H;
    pager_draw_rect(0, y, DISPLAY_W, CTRL_BAR_H, COLOR_DARKGRAY);
    char buf[128];
    snprintf(buf, sizeof(buf), "[A]Details [B]Exit [<>]%s", filter);
    pager_draw_text(4, y + 2, buf, COLOR_WHITE, COLOR_DARKGRAY, 10);
}

static void draw_divider(void) {
    /* Thin line between status bar and list */
    pager_draw_rect(0, STATUS_BAR_H, DISPLAY_W, 1, COLOR_GRAY);
    /* Thin line above controls */
    pager_draw_rect(0, DISPLAY_H - CTRL_BAR_H - 1, DISPLAY_W, 1, COLOR_GRAY);
}

static void update_leds(double max_score) {
    if (max_score >= 0.80) {
        /* Critical: red flash on all LEDs */
        pager_set_led(LED_UP,    255, 0,   0);
        pager_set_led(LED_DOWN,  255, 0,   0);
        pager_set_led(LED_LEFT,  255, 0,   0);
        pager_set_led(LED_RIGHT, 255, 0,   0);
        pager_set_led(LED_A,     255, 0,   0);
        pager_set_led(LED_B,     255, 0,   0);
    } else if (max_score >= 0.60) {
        /* High: orange */
        pager_set_led(LED_UP,    255, 100, 0);
        pager_set_led(LED_DOWN,  255, 100, 0);
        pager_set_led(LED_LEFT,  255, 100, 0);
        pager_set_led(LED_RIGHT, 255, 100, 0);
        pager_set_led(LED_A,     255, 100, 0);
        pager_set_led(LED_B,     255, 100, 0);
    } else if (max_score >= 0.40) {
        /* Medium: yellow */
        pager_set_led(LED_UP,    255, 255, 0);
        pager_set_led(LED_DOWN,  255, 255, 0);
        pager_set_led(LED_LEFT,  0,   0,   0);
        pager_set_led(LED_RIGHT, 0,   0,   0);
        pager_set_led(LED_A,     255, 255, 0);
        pager_set_led(LED_B,     0,   0,   0);
    } else {
        /* Normal/Low: LEDs off */
        pager_set_led(LED_UP,    0, 0, 0);
        pager_set_led(LED_DOWN,  0, 0, 0);
        pager_set_led(LED_LEFT,  0, 0, 0);
        pager_set_led(LED_RIGHT, 0, 0, 0);
        pager_set_led(LED_A,     0, 0, 0);
        pager_set_led(LED_B,     0, 0, 0);
    }
}

static void show_detail(const cyt_persistence_t *p) {
    pager_clear(COLOR_BLACK);

    int y = 4;
    char buf[256];

    snprintf(buf, sizeof(buf), "Device Detail");
    pager_draw_text(4, y, buf, COLOR_WHITE, COLOR_BLACK, 14);
    y += 20;

    pager_draw_rect(0, y, DISPLAY_W, 1, COLOR_GRAY);
    y += 6;

    snprintf(buf, sizeof(buf), "MAC:    %s  (%s)", p->mac, p->source);
    pager_draw_text(4, y, buf, COLOR_WHITE, COLOR_BLACK, 10);
    y += 14;

    snprintf(buf, sizeof(buf), "Score:  %.2f  [%s]",
             p->threat_score, p->threat_score >= 0.40 ? "ALERT" : "OK");
    pager_draw_text(4, y, buf, threat_color(p->threat_score), COLOR_BLACK, 10);
    y += 14;

    if (p->name[0]) {
        snprintf(buf, sizeof(buf), "Name:   %s", p->name);
        pager_draw_text(4, y, buf, COLOR_CYAN, COLOR_BLACK, 10);
        y += 14;
    }

    if (p->manufacturer[0]) {
        snprintf(buf, sizeof(buf), "Device: %s", p->manufacturer);
        pager_draw_text(4, y, buf, COLOR_CYAN, COLOR_BLACK, 10);
        y += 14;
    }

    snprintf(buf, sizeof(buf), "RSSI:   %d dBm", p->avg_rssi);
    pager_draw_text(4, y, buf, COLOR_WHITE, COLOR_BLACK, 10);
    y += 14;

    snprintf(buf, sizeof(buf), "Seen:   %d times", p->sighting_count);
    pager_draw_text(4, y, buf, COLOR_WHITE, COLOR_BLACK, 10);
    y += 14;

    time_t fs = (time_t)p->first_seen;
    time_t ls = (time_t)p->last_seen;
    struct tm *tm;
    char tmbuf[32];

    tm = localtime(&fs);
    strftime(tmbuf, sizeof(tmbuf), "%H:%M:%S", tm);
    snprintf(buf, sizeof(buf), "First:  %s", tmbuf);
    pager_draw_text(4, y, buf, COLOR_WHITE, COLOR_BLACK, 10);
    y += 14;

    tm = localtime(&ls);
    strftime(tmbuf, sizeof(tmbuf), "%H:%M:%S", tm);
    snprintf(buf, sizeof(buf), "Last:   %s", tmbuf);
    pager_draw_text(4, y, buf, COLOR_WHITE, COLOR_BLACK, 10);
    y += 14;

    int64_t dur = (p->last_seen - p->first_seen) / 60;
    snprintf(buf, sizeof(buf), "Duration: %d min", (int)dur);
    pager_draw_text(4, y, buf, COLOR_WHITE, COLOR_BLACK, 10);
    y += 14;

    if (p->locations_seen > 1) {
        snprintf(buf, sizeof(buf), "Locations: %d  *** MULTI-LOCATION ***",
                 p->locations_seen);
        pager_draw_text(4, y, buf, COLOR_RED, COLOR_BLACK, 10);
        y += 14;
    }

    y = DISPLAY_H - 18;
    pager_draw_rect(0, y, DISPLAY_W, 1, COLOR_GRAY);
    pager_draw_text(4, y+2, "[A/B] Back", COLOR_WHITE, COLOR_BLACK, 10);

    pager_flip();

    /* Wait for button press */
    int btn;
    do {
        btn = pager_wait_button(1000);
    } while (btn == 0 && g_running);
}

#endif /* HAVE_PAGERCTL */

/* ------------------------------------------------------------------ */
/*  Main loop logic (shared between pagerctl and text mode)           */
/* ------------------------------------------------------------------ */
static void run_ui(sqlite3 *db, const char *filter_src,
                    int refresh_sec, int limit) {
    int scroll  = 0;
    int sel     = 0;
    double prev_max = 0.0;

#ifdef HAVE_PAGERCTL
    pager_init();
    pager_set_rotation(270);  /* Landscape mode */
#endif

    while (g_running) {
        /* Fetch current persistence data */
        cyt_persistence_t *devices = NULL;
        int count = db_query_persistence(db, &devices, limit * 3);

        /* Apply source filter */
        int fcount = 0;
        static cyt_persistence_t filtered[MAX_LIST];
        for (int i = 0; i < count && fcount < MAX_LIST; i++) {
            if (!strcmp(filter_src, "all") ||
                !strcmp(devices[i].source, filter_src)) {
                filtered[fcount++] = devices[i];
            }
        }
        free(devices);
        devices = NULL;

        /* Find max threat score */
        double max_score = 0.0;
        int threat_count = 0;
        for (int i = 0; i < fcount; i++) {
            if (filtered[i].threat_score > max_score)
                max_score = filtered[i].threat_score;
            if (filtered[i].threat_score >= 0.40) threat_count++;
        }

        int ble_total  = db_count_unique_macs(db, 3600, "ble");
        int wifi_total = db_count_unique_macs(db, 3600, "wifi");

#ifdef HAVE_PAGERCTL
        /* Read input (non-blocking) */
        int btn = pager_poll_input();

        if (btn == BTN_DOWN) {
            sel++;
            if (sel >= fcount) sel = fcount > 0 ? fcount - 1 : 0;
            if (sel >= scroll + ROWS_VISIBLE) scroll = sel - ROWS_VISIBLE + 1;
        } else if (btn == BTN_UP) {
            sel--;
            if (sel < 0) sel = 0;
            if (sel < scroll) scroll = sel;
        } else if (btn == BTN_B) {
            break;  /* Exit */
        } else if (btn == BTN_A && fcount > 0 && sel < fcount) {
            show_detail(&filtered[sel]);
            continue;
        } else if (btn == BTN_LEFT || btn == BTN_RIGHT) {
            /* Cycle filter */
            if (!strcmp(filter_src, "all"))        filter_src = "ble";
            else if (!strcmp(filter_src, "ble"))   filter_src = "wifi";
            else                                    filter_src = "all";
            scroll = 0; sel = 0;
        }

        /* Draw frame */
        pager_clear(COLOR_BLACK);
        draw_status_bar(ble_total, wifi_total, threat_count);
        draw_divider();

        for (int i = 0; i < ROWS_VISIBLE && (scroll + i) < fcount; i++) {
            int idx = scroll + i;
            int y   = LIST_START_Y + i * BAR_H;
            draw_device_row(y, &filtered[idx], idx == sel);
        }

        draw_controls_bar(filter_src);
        pager_flip();

        /* LED alerts on threat change */
        if (max_score != prev_max) {
            update_leds(max_score);
            if (max_score >= 0.80 && max_score > prev_max) {
                /* Critical: vibration burst */
                pager_buzzer(100, 800, 50);
                usleep(200000);
                pager_buzzer(100, 800, 50);
            } else if (max_score >= 0.60 && max_score > prev_max) {
                pager_buzzer(80, 600, 30);
            }
            prev_max = max_score;
        }

        usleep(100000); /* 100ms poll rate */

#else /* text mode */
        text_display(filtered, fcount, scroll, sel, filter_src,
                     ble_total, wifi_total);
        sleep(refresh_sec);
#endif
    }

#ifdef HAVE_PAGERCTL
    /* Turn off LEDs before exit */
    update_leds(0.0);
    pager_clear(COLOR_BLACK);
    pager_draw_text(4, 4, "CYT Stopped.", COLOR_WHITE, COLOR_BLACK, 14);
    pager_flip();
    sleep(1);
    pager_cleanup();
#endif
}

/* ------------------------------------------------------------------ */
/*  Usage                                                               */
/* ------------------------------------------------------------------ */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --db PATH        SQLite database (required)\n"
        "  --refresh N      Refresh interval seconds (default: 3)\n"
        "  --limit N        Max devices to show (default: 20)\n"
        "  --filter SRC     'ble', 'wifi', or 'all' (default: all)\n",
        prog);
}

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[]) {
    const char *db_path    = NULL;
    const char *filter_src = "all";
    int refresh_sec        = DEFAULT_REFRESH;
    int limit              = 20;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--db")      && i+1 < argc) db_path    = argv[++i];
        else if (!strcmp(argv[i], "--refresh") && i+1 < argc) refresh_sec = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--limit")   && i+1 < argc) limit      = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--filter")  && i+1 < argc) filter_src = argv[++i];
        else if (!strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else {
            fprintf(stderr, "[ui] Unknown option: %s\n", argv[i]);
            usage(argv[0]); return 1;
        }
    }

    if (!db_path) {
        fprintf(stderr, "[ui] Error: --db PATH is required\n");
        usage(argv[0]); return 1;
    }

    sqlite3 *db = NULL;
    if (db_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "[ui] Failed to open database: %s\n", db_path);
        return 1;
    }

    signal(SIGTERM, sig_handler);
    signal(SIGINT,  sig_handler);

    run_ui(db, filter_src, refresh_sec, limit);

    db_close(db);
    return 0;
}
