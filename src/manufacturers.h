#ifndef CYT_MANUFACTURERS_H
#define CYT_MANUFACTURERS_H

#include <stdint.h>
#include <string.h>

/* BLE Company ID → manufacturer name lookup.
   Source: Bluetooth Assigned Numbers (https://www.bluetooth.com/specifications/assigned-numbers/)
   Common entries for surveillance detection use-cases. */

typedef struct {
    uint16_t    id;
    const char *name;
} ble_company_t;

static const ble_company_t BLE_COMPANIES[] = {
    { 0x0000, "Ericsson" },
    { 0x0001, "Nokia" },
    { 0x0002, "Intel" },
    { 0x0003, "IBM" },
    { 0x0004, "Toshiba" },
    { 0x0006, "Microsoft" },
    { 0x0007, "Lucent" },
    { 0x0008, "Motorola" },
    { 0x000F, "Broadcom" },
    { 0x0046, "Zeevo" },
    { 0x004C, "Apple" },
    { 0x0057, "Harman" },
    { 0x005D, "Nordic Semiconductor" },
    { 0x0060, "Tencent" },
    { 0x0075, "Samsung" },
    { 0x0087, "Garmin" },
    { 0x008A, "Misfit Wearables" },
    { 0x0092, "Jawbone" },
    { 0x00A0, "Google" },
    { 0x00B3, "Qualcomm" },
    { 0x00C1, "MediaTek" },
    { 0x00C4, "Plantronics" },
    { 0x00D2, "Xiaomi" },
    { 0x00D7, "Polar Electro" },
    { 0x00DA, "Qualcomm ASSA ABLOY" },
    { 0x00E0, "Google (Alt)" },
    { 0x00F0, "Samsung (Alt)" },
    { 0x0100, "Fitbit" },
    { 0x0105, "Logitech" },
    { 0x0118, "Amazon" },
    { 0x0131, "Withings" },
    { 0x013A, "Xiaomi (Alt)" },
    { 0x0157, "Huawei" },
    { 0x015D, "Sony" },
    { 0x0171, "GoPro" },
    { 0x01A0, "Tile" },
    { 0x01FF, "Xiaomi (Alt2)" },
    { 0x0205, "Vizio" },
    { 0x0217, "Bose" },
    { 0x0220, "OnePlus" },
    { 0x0256, "Belkin" },
    { 0x0278, "Motorola (Alt)" },
    { 0x02D0, "Sony (Alt)" },
    { 0x02E5, "Espressif" },
    { 0x038F, "Govee" },
    { 0x03DA, "Sony (Alt2)" },
    { 0x048F, "Meta/Facebook" },
    { 0x04B3, "LG Electronics" },
    { 0x04C6, "SONOS" },
    { 0x053A, "Jabra" },
    { 0x058C, "Realtek" },
    { 0x05C7, "Ring" },
    { 0x06D6, "Wyze" },
    { 0x0756, "Tile (Alt)" },
    { 0x076E, "Nothing" },
    { 0x07D0, "JBL" },
    { 0x0884, "TP-Link" },
    { 0xFFFF, "Unknown" },
};

#define BLE_COMPANIES_COUNT (sizeof(BLE_COMPANIES) / sizeof(BLE_COMPANIES[0]))

/* Lookup company name by ID. Returns pointer to static string. */
static inline const char *ble_manufacturer_name(uint16_t company_id) {
    for (size_t i = 0; i < BLE_COMPANIES_COUNT; i++) {
        if (BLE_COMPANIES[i].id == company_id)
            return BLE_COMPANIES[i].name;
    }
    return NULL; /* Unknown */
}

/* ------------------------------------------------------------------ */
/*  Apple BLE fingerprinting                                            */
/*  Apple uses company ID 0x004C; the first byte of manufacturer data  */
/*  indicates what kind of Apple device/feature is advertising.        */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t     type;
    const char *name;
} apple_adv_type_t;

static const apple_adv_type_t APPLE_ADV_TYPES[] = {
    { 0x01, "AirDrop" },
    { 0x02, "iBeacon" },
    { 0x03, "AirPrint" },
    { 0x05, "AirPlay" },
    { 0x07, "Apple HomeKit" },
    { 0x08, "Siri Remote" },
    { 0x09, "Apple TV" },
    { 0x0A, "Apple Nearby" },
    { 0x0B, "Apple Watch" },
    { 0x0C, "Apple Handoff" },
    { 0x0D, "Apple Nearby (0x0D)" },
    { 0x0E, "Apple Nearby (0x0E)" },
    { 0x0F, "Nearby Action" },
    { 0x10, "Find My" },
    { 0x12, "Apple Continuity" },
    { 0x1E, "AirPods" },
};

#define APPLE_ADV_TYPES_COUNT (sizeof(APPLE_ADV_TYPES)/sizeof(APPLE_ADV_TYPES[0]))

static inline const char *apple_adv_type_name(uint8_t type) {
    for (size_t i = 0; i < APPLE_ADV_TYPES_COUNT; i++) {
        if (APPLE_ADV_TYPES[i].type == type)
            return APPLE_ADV_TYPES[i].name;
    }
    return "Apple Device";
}

/* ------------------------------------------------------------------ */
/*  Google Fast Pair service UUID: 0xFE2C                              */
/*  Microsoft Swift Pair: 0xFFFE in manufacturer data prefix 0x0006    */
/*  Samsung: company ID 0x0075                                         */
/* ------------------------------------------------------------------ */

/* Service UUIDs worth noting */
#define UUID16_GOOGLE_FAST_PAIR    0xFE2C
#define UUID16_APPLE_IBEACON       0xFE9A
#define UUID16_EDDYSTONE           0xFEAA
#define UUID16_TILE_FIND_ME        0xFEED
#define UUID16_BATTERY_SERVICE     0x180F
#define UUID16_HEART_RATE          0x180D
#define UUID16_GENERIC_ACCESS      0x1800
#define UUID16_DEVICE_INFO         0x180A
#define UUID16_FIND_MY_NETWORK     0xFD6F  /* Apple Find My Network */

static inline const char *service_uuid16_name(uint16_t uuid) {
    switch (uuid) {
        case UUID16_GOOGLE_FAST_PAIR:  return "Google Fast Pair";
        case UUID16_APPLE_IBEACON:     return "Apple iBeacon";
        case UUID16_EDDYSTONE:         return "Google Eddystone";
        case UUID16_TILE_FIND_ME:      return "Tile";
        case UUID16_BATTERY_SERVICE:   return "Battery Service";
        case UUID16_HEART_RATE:        return "Heart Rate";
        case UUID16_DEVICE_INFO:       return "Device Info";
        case UUID16_FIND_MY_NETWORK:   return "Find My Network";
        default:                       return NULL;
    }
}

#endif /* CYT_MANUFACTURERS_H */
