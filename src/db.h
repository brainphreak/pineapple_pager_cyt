#ifndef CYT_DB_H
#define CYT_DB_H

#include "sqlite3.h"
#include <stdint.h>

/* ------------------------------------------------------------------ */
/*  Sighting record                                                     */
/* ------------------------------------------------------------------ */
typedef struct {
    char    mac[18];        /* "AA:BB:CC:DD:EE:FF\0" */
    char    source[8];      /* "ble" or "wifi" */
    int     rssi;
    char    name[64];
    char    manufacturer[64];
    uint8_t adv_data[64];
    int     adv_data_len;
    char    ssid_probes[256]; /* wifi only, comma-separated */
    double  lat;
    double  lon;
    int64_t timestamp;      /* unix epoch */
} cyt_sighting_t;

/* ------------------------------------------------------------------ */
/*  Persistence record (computed by analyzer)                          */
/* ------------------------------------------------------------------ */
typedef struct {
    char    mac[18];
    char    source[8];
    int64_t first_seen;
    int64_t last_seen;
    int     sighting_count;
    int     avg_rssi;
    int     locations_seen;
    double  threat_score;
    char    name[64];
    char    manufacturer[64];
} cyt_persistence_t;

/* ------------------------------------------------------------------ */
/*  Database API                                                        */
/* ------------------------------------------------------------------ */

/* Open (or create) the database and ensure schema exists.
   Returns 0 on success, non-zero on error. */
int  db_open(const char *path, sqlite3 **db);

/* Close database */
void db_close(sqlite3 *db);

/* Insert a sighting.  Returns 0 on success. */
int  db_insert_sighting(sqlite3 *db, const cyt_sighting_t *s);

/* Retrieve all persistence records ordered by threat_score DESC.
   Caller must free the returned array.
   Returns number of records, or -1 on error. */
int  db_query_persistence(sqlite3 *db, cyt_persistence_t **out, int limit);

/* Update/insert a persistence record */
int  db_upsert_persistence(sqlite3 *db, const cyt_persistence_t *p);

/* Return 1 if mac is in whitelist, 0 otherwise */
int  db_is_whitelisted(sqlite3 *db, const char *mac);

/* Add mac to whitelist */
int  db_whitelist_add(sqlite3 *db, const char *mac, const char *name);

/* Count sightings since `since` epoch, grouped by mac+source.
   Fills out[] with at most `max` persistence records (raw aggregate,
   no threat score).  Returns count. */
int  db_aggregate_sightings(sqlite3 *db, int64_t since,
                             cyt_persistence_t *out, int max);

/* Count total unique MACs seen in last window_sec seconds */
int  db_count_unique_macs(sqlite3 *db, int window_sec, const char *source);

#endif /* CYT_DB_H */
