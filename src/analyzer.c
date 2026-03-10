/*
 * analyzer.c — Threat Scoring Engine for Chasing Your Tail
 *
 * Runs periodically, aggregates sightings from SQLite, computes threat scores,
 * updates the persistence table, and writes alerts to alerts.log.
 *
 * Usage:
 *   analyzer [options]
 *   Options:
 *     --db PATH        Path to SQLite database (required)
 *     --log PATH       Alert log file (default: alerts.log next to db)
 *     --status PATH    JSON status file to write (for headless monitoring)
 *     --interval N     Analysis interval in seconds (default: 30)
 *     --window N       Sighting window in seconds (default: 3600 = 1 hour)
 *     --daemon         Fork to background
 *     --pidfile PATH   Write PID file
 *     --once           Run once and exit (don't loop)
 *     --verbose        Print analysis results to stdout
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "db.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */
#define MAX_DEVICES     1024    /* Max devices to analyze at once */
#define ALERT_COOLDOWN  300     /* Only re-alert same MAC after 5 min */

/* Threat levels */
#define THREAT_NORMAL   0.20
#define THREAT_LOW      0.40
#define THREAT_MEDIUM   0.60
#define THREAT_HIGH     0.80

/* ------------------------------------------------------------------ */
/*  Globals                                                             */
/* ------------------------------------------------------------------ */
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_do_analysis = 0;

static void sig_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) g_running = 0;
    if (sig == SIGUSR1) g_do_analysis = 1; /* Manual trigger */
    if (sig == SIGHUP)  g_do_analysis = 1;
}

/* ------------------------------------------------------------------ */
/*  Threat scoring algorithm                                            */
/* ------------------------------------------------------------------ */
static double compute_threat_score(const cyt_persistence_t *p) {
    double score = 0.0;
    int64_t now = (int64_t)time(NULL);

    /* How long has this device been visible? */
    int64_t duration = p->last_seen - p->first_seen;

    /* Recency: if last seen > 10 min ago, it's gone — ignore */
    int64_t since_last = now - p->last_seen;
    if (since_last > 600) return 0.0;

    double duration_min = (double)duration / 60.0;

    /* Duration score: up to 0.60 */
    if (duration_min >  5.0) score += 0.15;
    if (duration_min > 10.0) score += 0.15;
    if (duration_min > 15.0) score += 0.15;
    if (duration_min > 20.0) score += 0.15;

    /* Frequency score: up to 0.10 */
    double denom = duration_min > 1.0 ? duration_min : 1.0;
    double sightings_per_min = (double)p->sighting_count / denom;
    if (sightings_per_min > 0.5) score += 0.10;

    /* Multi-location correlation: up to 0.30 (if GPS available) */
    if (p->locations_seen > 1) score += 0.20;
    if (p->locations_seen > 2) score += 0.10;

    /* Proximity: up to 0.20 */
    if (p->avg_rssi > -60) score += 0.10;  /* moderately close (<10m) */
    if (p->avg_rssi > -50) score += 0.05;  /* close (<3m) */
    if (p->avg_rssi > -40) score += 0.05;  /* very close (<1m) */

    /* Cap at 1.0 */
    if (score > 1.0) score = 1.0;

    return score;
}

/* ------------------------------------------------------------------ */
/*  Threat level string                                                 */
/* ------------------------------------------------------------------ */
static const char *threat_level_str(double score) {
    if (score >= THREAT_HIGH)   return "CRITICAL";
    if (score >= THREAT_MEDIUM) return "HIGH";
    if (score >= THREAT_LOW)    return "MEDIUM";
    if (score >= THREAT_NORMAL) return "LOW";
    return "NORMAL";
}

/* ------------------------------------------------------------------ */
/*  Alert tracking (avoid duplicate alerts within cooldown period)     */
/* ------------------------------------------------------------------ */
#define MAX_ALERT_TRACK 256

typedef struct {
    char    mac[18];
    double  last_score;
    int64_t last_alerted;
} alert_track_t;

static alert_track_t g_alerts[MAX_ALERT_TRACK];
static int g_alert_count = 0;

static int should_alert(const char *mac, double score, double threshold) {
    if (score < threshold) return 0;

    int64_t now = (int64_t)time(NULL);

    /* Find existing entry */
    for (int i = 0; i < g_alert_count; i++) {
        if (strcmp(g_alerts[i].mac, mac) == 0) {
            /* Alert if score increased significantly or cooldown expired */
            double delta = score - g_alerts[i].last_score;
            int64_t age  = now - g_alerts[i].last_alerted;
            if (delta >= 0.15 || age >= ALERT_COOLDOWN) {
                g_alerts[i].last_score   = score;
                g_alerts[i].last_alerted = now;
                return 1;
            }
            return 0;
        }
    }

    /* New MAC — add to tracker */
    if (g_alert_count < MAX_ALERT_TRACK) {
        strncpy(g_alerts[g_alert_count].mac, mac, 17);
        g_alerts[g_alert_count].mac[17] = '\0';
        g_alerts[g_alert_count].last_score   = score;
        g_alerts[g_alert_count].last_alerted = now;
        g_alert_count++;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Write alert to log                                                  */
/* ------------------------------------------------------------------ */
static void write_alert(FILE *logf, const cyt_persistence_t *p) {
    if (!logf) return;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

    int64_t duration_sec = p->last_seen - p->first_seen;
    int     duration_min = (int)(duration_sec / 60);

    fprintf(logf,
        "[%s] %s  %s  %-17s  %-30s  %-20s  "
        "score=%.2f  rssi=%d  seen=%d  dur=%dm\n",
        timebuf,
        threat_level_str(p->threat_score),
        p->source,
        p->mac,
        p->manufacturer[0] ? p->manufacturer : "Unknown",
        p->name[0]         ? p->name         : "",
        p->threat_score,
        p->avg_rssi,
        p->sighting_count,
        duration_min);
    fflush(logf);
}

/* ------------------------------------------------------------------ */
/*  Write JSON status file                                              */
/* ------------------------------------------------------------------ */
static void write_status_json(const char *path,
                               const cyt_persistence_t *devices, int count,
                               int ble_total, int wifi_total) {
    if (!path) return;

    /* Write to temp file then rename for atomic update */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    FILE *f = fopen(tmp, "w");
    if (!f) return;

    time_t now = time(NULL);

    fprintf(f, "{\n");
    fprintf(f, "  \"updated\": %lld,\n", (long long)now);
    fprintf(f, "  \"ble_devices\": %d,\n", ble_total);
    fprintf(f, "  \"wifi_devices\": %d,\n", wifi_total);
    fprintf(f, "  \"devices\": [\n");

    for (int i = 0; i < count; i++) {
        const cyt_persistence_t *p = &devices[i];
        int64_t dur = p->last_seen - p->first_seen;

        /* Escape strings for JSON */
        char name_esc[128], mfr_esc[128];
        int j = 0;
        for (int k = 0; p->name[k] && j < 127; k++) {
            char c = p->name[k];
            if (c == '"' || c == '\\') name_esc[j++] = '\\';
            name_esc[j++] = c;
        }
        name_esc[j] = '\0';

        j = 0;
        for (int k = 0; p->manufacturer[k] && j < 127; k++) {
            char c = p->manufacturer[k];
            if (c == '"' || c == '\\') mfr_esc[j++] = '\\';
            mfr_esc[j++] = c;
        }
        mfr_esc[j] = '\0';

        fprintf(f,
            "    {\"mac\":\"%s\",\"source\":\"%s\","
            "\"score\":%.3f,\"level\":\"%s\","
            "\"rssi\":%d,\"seen\":%d,\"duration\":%lld,"
            "\"name\":\"%s\",\"manufacturer\":\"%s\","
            "\"first_seen\":%lld,\"last_seen\":%lld}%s\n",
            p->mac, p->source,
            p->threat_score, threat_level_str(p->threat_score),
            p->avg_rssi, p->sighting_count, (long long)dur,
            name_esc, mfr_esc,
            (long long)p->first_seen, (long long)p->last_seen,
            (i < count-1) ? "," : "");
    }

    fprintf(f, "  ]\n}\n");
    fclose(f);

    rename(tmp, path);
}

/* ------------------------------------------------------------------ */
/*  Run one analysis pass                                               */
/* ------------------------------------------------------------------ */
static void run_analysis(sqlite3 *db, FILE *logf, const char *status_path,
                          int window_sec, int verbose) {
    int64_t since = (int64_t)time(NULL) - window_sec;

    static cyt_persistence_t raw[MAX_DEVICES];
    int count = db_aggregate_sightings(db, since, raw, MAX_DEVICES);

    if (verbose)
        fprintf(stdout, "[analyzer] Analyzing %d devices...\n", count);

    int high_count = 0;

    for (int i = 0; i < count; i++) {
        cyt_persistence_t *p = &raw[i];

        /* Skip whitelisted */
        if (db_is_whitelisted(db, p->mac)) {
            p->threat_score = 0.0;
            continue;
        }

        p->threat_score = compute_threat_score(p);

        if (verbose && p->threat_score >= THREAT_NORMAL) {
            printf("[analyzer]  %-17s  %-6s  score=%.2f (%s)  "
                   "rssi=%d  seen=%d  %s\n",
                   p->mac, p->source, p->threat_score,
                   threat_level_str(p->threat_score),
                   p->avg_rssi, p->sighting_count,
                   p->manufacturer[0] ? p->manufacturer : "");
        }

        /* Update persistence table */
        db_upsert_persistence(db, p);

        /* Alert if above LOW threshold */
        if (p->threat_score >= THREAT_LOW) {
            high_count++;
            if (logf && should_alert(p->mac, p->threat_score, THREAT_LOW)) {
                write_alert(logf, p);
            }
        }
    }

    if (verbose)
        printf("[analyzer] Done. %d devices above LOW threshold.\n", high_count);

    /* Write JSON status file */
    if (status_path) {
        int ble_total  = db_count_unique_macs(db, window_sec, "ble");
        int wifi_total = db_count_unique_macs(db, window_sec, "wifi");
        write_status_json(status_path, raw, count, ble_total, wifi_total);
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
        "  --db PATH        SQLite database (required)\n"
        "  --log PATH       Alert log file\n"
        "  --status PATH    JSON status output file\n"
        "  --interval N     Analysis interval seconds (default: 30)\n"
        "  --window N       Sighting window seconds (default: 3600)\n"
        "  --daemon         Fork to background\n"
        "  --pidfile PATH   Write PID file\n"
        "  --once           Run once and exit\n"
        "  --verbose        Print analysis to stdout\n",
        prog);
}

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[]) {
    const char *db_path     = NULL;
    const char *log_path    = NULL;
    const char *status_path = NULL;
    const char *pidfile     = NULL;
    int interval            = 30;
    int window_sec          = 3600;
    int do_daemon           = 0;
    int run_once            = 0;
    int verbose             = 0;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--db")       && i+1 < argc) db_path     = argv[++i];
        else if (!strcmp(argv[i], "--log")      && i+1 < argc) log_path    = argv[++i];
        else if (!strcmp(argv[i], "--status")   && i+1 < argc) status_path = argv[++i];
        else if (!strcmp(argv[i], "--interval") && i+1 < argc) interval    = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--window")   && i+1 < argc) window_sec  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--daemon"))   do_daemon = 1;
        else if (!strcmp(argv[i], "--once"))     run_once  = 1;
        else if (!strcmp(argv[i], "--verbose"))  verbose   = 1;
        else if (!strcmp(argv[i], "--pidfile") && i+1 < argc) pidfile = argv[++i];
        else if (!strcmp(argv[i], "--help"))  { usage(argv[0]); return 0; }
        else {
            fprintf(stderr, "[analyzer] Unknown option: %s\n", argv[i]);
            usage(argv[0]); return 1;
        }
    }

    if (!db_path) {
        fprintf(stderr, "[analyzer] Error: --db PATH is required\n");
        usage(argv[0]); return 1;
    }

    /* Derive default log path from db path */
    char log_buf[512];
    if (!log_path) {
        snprintf(log_buf, sizeof(log_buf), "%s", db_path);
        /* Replace .db with .log, or append .log */
        char *dot = strrchr(log_buf, '.');
        if (dot) strcpy(dot, ".log");
        else strcat(log_buf, ".log");
        log_path = log_buf;
    }

    if (do_daemon) daemonize();
    if (pidfile) write_pidfile(pidfile);

    signal(SIGTERM, sig_handler);
    signal(SIGINT,  sig_handler);
    signal(SIGUSR1, sig_handler);
    signal(SIGHUP,  sig_handler);

    sqlite3 *db = NULL;
    if (db_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "[analyzer] Failed to open database: %s\n", db_path);
        return 1;
    }

    FILE *logf = fopen(log_path, "a");
    if (!logf) {
        fprintf(stderr, "[analyzer] Warning: cannot open log '%s': %s\n",
                log_path, strerror(errno));
    } else {
        /* Write session start marker */
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        char timebuf[32];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
        fprintf(logf, "--- CYT analyzer started %s ---\n", timebuf);
        fflush(logf);
    }

    if (!do_daemon)
        fprintf(stderr, "[analyzer] Running every %ds on %s\n", interval, db_path);

    if (run_once) {
        run_analysis(db, logf, status_path, window_sec, verbose);
    } else {
        while (g_running) {
            run_analysis(db, logf, status_path, window_sec, verbose);
            /* Sleep in 1-second increments so SIGTERM is responsive */
            for (int t = 0; t < interval && g_running; t++) {
                if (g_do_analysis) { g_do_analysis = 0; break; }
                sleep(1);
            }
        }
    }

    if (logf) fclose(logf);
    db_close(db);
    return 0;
}
