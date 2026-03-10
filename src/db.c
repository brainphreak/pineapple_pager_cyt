#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/*  Schema                                                              */
/* ------------------------------------------------------------------ */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS sightings ("
    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  mac         TEXT    NOT NULL,"
    "  source      TEXT    NOT NULL,"
    "  rssi        INTEGER,"
    "  name        TEXT,"
    "  manufacturer TEXT,"
    "  adv_data    BLOB,"
    "  ssid_probes TEXT,"
    "  lat         REAL,"
    "  lon         REAL,"
    "  timestamp   INTEGER NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_sightings_mac  ON sightings(mac);"
    "CREATE INDEX IF NOT EXISTS idx_sightings_time ON sightings(timestamp);"
    "CREATE TABLE IF NOT EXISTS persistence ("
    "  mac           TEXT NOT NULL,"
    "  source        TEXT NOT NULL,"
    "  first_seen    INTEGER,"
    "  last_seen     INTEGER,"
    "  sighting_count INTEGER,"
    "  avg_rssi      INTEGER,"
    "  locations_seen INTEGER,"
    "  threat_score  REAL,"
    "  name          TEXT,"
    "  manufacturer  TEXT,"
    "  PRIMARY KEY (mac, source)"
    ");"
    "CREATE TABLE IF NOT EXISTS whitelist ("
    "  mac   TEXT PRIMARY KEY,"
    "  name  TEXT,"
    "  added INTEGER"
    ");";

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */
static int exec_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[db] SQL error: %s\n", err ? err : "?");
        sqlite3_free(err);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Open / Close                                                        */
/* ------------------------------------------------------------------ */
int db_open(const char *path, sqlite3 **db) {
    int rc = sqlite3_open(path, db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[db] Cannot open '%s': %s\n", path,
                sqlite3_errmsg(*db));
        return rc;
    }

    /* Performance tuning for embedded use */
    exec_sql(*db, "PRAGMA journal_mode=WAL;");
    exec_sql(*db, "PRAGMA synchronous=NORMAL;");
    exec_sql(*db, "PRAGMA temp_store=MEMORY;");
    exec_sql(*db, "PRAGMA cache_size=500;");

    rc = exec_sql(*db, SCHEMA_SQL);
    return rc;
}

void db_close(sqlite3 *db) {
    sqlite3_close(db);
}

/* ------------------------------------------------------------------ */
/*  Insert sighting                                                     */
/* ------------------------------------------------------------------ */
int db_insert_sighting(sqlite3 *db, const cyt_sighting_t *s) {
    static const char *SQL =
        "INSERT INTO sightings"
        "(mac,source,rssi,name,manufacturer,adv_data,ssid_probes,lat,lon,timestamp)"
        " VALUES (?,?,?,?,?,?,?,?,?,?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return rc;

    sqlite3_bind_text(stmt,  1, s->mac,          -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt,  2, s->source,        -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt,  3, s->rssi);
    sqlite3_bind_text(stmt,  4, s->name[0]        ? s->name        : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt,  5, s->manufacturer[0]? s->manufacturer: NULL, -1, SQLITE_STATIC);
    if (s->adv_data_len > 0)
        sqlite3_bind_blob(stmt, 6, s->adv_data, s->adv_data_len, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 6);
    sqlite3_bind_text(stmt,  7, s->ssid_probes[0] ? s->ssid_probes : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 8, s->lat);
    sqlite3_bind_double(stmt, 9, s->lon);
    sqlite3_bind_int64(stmt, 10, s->timestamp);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

/* ------------------------------------------------------------------ */
/*  Upsert persistence                                                  */
/* ------------------------------------------------------------------ */
int db_upsert_persistence(sqlite3 *db, const cyt_persistence_t *p) {
    static const char *SQL =
        "INSERT INTO persistence"
        "(mac,source,first_seen,last_seen,sighting_count,avg_rssi,"
        " locations_seen,threat_score,name,manufacturer)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(mac,source) DO UPDATE SET"
        "  first_seen     = excluded.first_seen,"
        "  last_seen      = excluded.last_seen,"
        "  sighting_count = excluded.sighting_count,"
        "  avg_rssi       = excluded.avg_rssi,"
        "  locations_seen = excluded.locations_seen,"
        "  threat_score   = excluded.threat_score,"
        "  name           = CASE WHEN excluded.name IS NOT NULL"
        "                        THEN excluded.name ELSE persistence.name END,"
        "  manufacturer   = CASE WHEN excluded.manufacturer IS NOT NULL"
        "                        THEN excluded.manufacturer"
        "                        ELSE persistence.manufacturer END;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return rc;

    sqlite3_bind_text  (stmt,  1, p->mac,          -1, SQLITE_STATIC);
    sqlite3_bind_text  (stmt,  2, p->source,        -1, SQLITE_STATIC);
    sqlite3_bind_int64 (stmt,  3, p->first_seen);
    sqlite3_bind_int64 (stmt,  4, p->last_seen);
    sqlite3_bind_int   (stmt,  5, p->sighting_count);
    sqlite3_bind_int   (stmt,  6, p->avg_rssi);
    sqlite3_bind_int   (stmt,  7, p->locations_seen);
    sqlite3_bind_double(stmt,  8, p->threat_score);
    sqlite3_bind_text  (stmt,  9, p->name[0]        ? p->name        : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text  (stmt, 10, p->manufacturer[0]? p->manufacturer: NULL, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

/* ------------------------------------------------------------------ */
/*  Query persistence (ordered by threat score)                        */
/* ------------------------------------------------------------------ */
int db_query_persistence(sqlite3 *db, cyt_persistence_t **out, int limit) {
    static const char *SQL =
        "SELECT mac,source,first_seen,last_seen,sighting_count,avg_rssi,"
        "       locations_seen,threat_score,name,manufacturer"
        " FROM persistence"
        " ORDER BY threat_score DESC"
        " LIMIT ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, limit);

    /* First pass: count rows */
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) count++;
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        *out = NULL;
        return 0;
    }

    *out = calloc(count, sizeof(cyt_persistence_t));
    if (!*out) {
        sqlite3_finalize(stmt);
        return -1;
    }

    int i = 0;
    while (i < count && sqlite3_step(stmt) == SQLITE_ROW) {
        cyt_persistence_t *p = &(*out)[i++];
        const char *v;

        v = (const char *)sqlite3_column_text(stmt, 0);
        if (v) strncpy(p->mac, v, sizeof(p->mac)-1);
        v = (const char *)sqlite3_column_text(stmt, 1);
        if (v) strncpy(p->source, v, sizeof(p->source)-1);
        p->first_seen     = sqlite3_column_int64(stmt, 2);
        p->last_seen      = sqlite3_column_int64(stmt, 3);
        p->sighting_count = sqlite3_column_int  (stmt, 4);
        p->avg_rssi       = sqlite3_column_int  (stmt, 5);
        p->locations_seen = sqlite3_column_int  (stmt, 6);
        p->threat_score   = sqlite3_column_double(stmt, 7);
        v = (const char *)sqlite3_column_text(stmt, 8);
        if (v) strncpy(p->name, v, sizeof(p->name)-1);
        v = (const char *)sqlite3_column_text(stmt, 9);
        if (v) strncpy(p->manufacturer, v, sizeof(p->manufacturer)-1);
    }

    sqlite3_finalize(stmt);
    return count;
}

/* ------------------------------------------------------------------ */
/*  Aggregate raw sightings since `since`                              */
/* ------------------------------------------------------------------ */
int db_aggregate_sightings(sqlite3 *db, int64_t since,
                            cyt_persistence_t *out, int max) {
    static const char *SQL =
        "SELECT mac, source,"
        "       MIN(timestamp) AS first_seen,"
        "       MAX(timestamp) AS last_seen,"
        "       COUNT(*) AS cnt,"
        "       AVG(rssi) AS avg_rssi,"
        "       COUNT(DISTINCT CASE WHEN lat != 0 OR lon != 0"
        "             THEN CAST(lat*100 AS INTEGER)||','||CAST(lon*100 AS INTEGER)"
        "             ELSE NULL END) AS locs,"
        "       MAX(name) AS name,"
        "       MAX(manufacturer) AS mfr"
        " FROM sightings"
        " WHERE timestamp >= ?"
        " GROUP BY mac, source"
        " ORDER BY cnt DESC"
        " LIMIT ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, since);
    sqlite3_bind_int  (stmt, 2, max);

    int count = 0;
    while (count < max && sqlite3_step(stmt) == SQLITE_ROW) {
        cyt_persistence_t *p = &out[count++];
        memset(p, 0, sizeof(*p));

        const char *v;
        v = (const char *)sqlite3_column_text(stmt, 0);
        if (v) strncpy(p->mac, v, sizeof(p->mac)-1);
        v = (const char *)sqlite3_column_text(stmt, 1);
        if (v) strncpy(p->source, v, sizeof(p->source)-1);
        p->first_seen     = sqlite3_column_int64(stmt, 2);
        p->last_seen      = sqlite3_column_int64(stmt, 3);
        p->sighting_count = sqlite3_column_int  (stmt, 4);
        p->avg_rssi       = (int)sqlite3_column_double(stmt, 5);
        p->locations_seen = sqlite3_column_int  (stmt, 6);
        v = (const char *)sqlite3_column_text(stmt, 7);
        if (v) strncpy(p->name, v, sizeof(p->name)-1);
        v = (const char *)sqlite3_column_text(stmt, 8);
        if (v) strncpy(p->manufacturer, v, sizeof(p->manufacturer)-1);
    }

    sqlite3_finalize(stmt);
    return count;
}

/* ------------------------------------------------------------------ */
/*  Whitelist                                                           */
/* ------------------------------------------------------------------ */
int db_is_whitelisted(sqlite3 *db, const char *mac) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT 1 FROM whitelist WHERE mac=? LIMIT 1;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_text(stmt, 1, mac, -1, SQLITE_STATIC);
    int found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

int db_whitelist_add(sqlite3 *db, const char *mac, const char *name) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO whitelist(mac,name,added) VALUES(?,?,?);",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return rc;

    sqlite3_bind_text (stmt, 1, mac,  -1, SQLITE_STATIC);
    sqlite3_bind_text (stmt, 2, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

/* ------------------------------------------------------------------ */
/*  Count unique MACs                                                   */
/* ------------------------------------------------------------------ */
int db_count_unique_macs(sqlite3 *db, int window_sec, const char *source) {
    int64_t since = (int64_t)time(NULL) - window_sec;
    const char *SQL = source
        ? "SELECT COUNT(DISTINCT mac) FROM sightings WHERE timestamp>=? AND source=?;"
        : "SELECT COUNT(DISTINCT mac) FROM sightings WHERE timestamp>=?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, since);
    if (source) sqlite3_bind_text(stmt, 2, source, -1, SQLITE_STATIC);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}
