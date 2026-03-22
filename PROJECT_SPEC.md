# Arduino OTA Update Server

A lightweight HTTP server written in Go that serves OTA firmware updates to ESP8266 devices, following the [Arduino ESP8266 HTTP OTA protocol](https://arduino-esp8266.readthedocs.io/en/3.0.0/ota_updates/readme.html#http-server).

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | HTTP listen port |
| `--root` | `.` | Root directory containing firmware files |
| `--no-parse-version` | `false` | Disable parsing `__DATE__ __TIME__` format from the version header |
| `--client-log` | _(disabled)_ | Path to a TSV file recording the latest request from each client |

## How It Works

1. A device sends an OTA request with `x-ESP8266-STA-MAC` and `x-ESP8266-version` headers.
2. The MAC address is sanitized (lowercased, non-hex characters replaced with `-`, truncated to 17 chars) and used to locate a device-specific directory under `<root>/<sanitized-mac>/`.
3. The version string is sanitized similarly (truncated to 32 chars). Unless `--no-parse-version` is set, it is also parsed from C/C++ `__DATE__ __TIME__` format into `YYYYMMDD-hhmmss`.
4. The server lists `*.bin` files in the device directory whose filenames are alphanumerically greater than the current version.
5. If a newer version exists, the next sequential version is served (HTTP 200). This ensures devices upgrade one version at a time, which is important for devices that lack space to download a full release and must first install a smaller intermediate OTA-only build.
6. If no newer version exists, the server responds with HTTP 304.

All `x-ESP8266-*` request headers, the resolved directory, current version, selected file, and skipped version count are logged to stdout.

## Client Log

When `--client-log` is set, the server maintains a TSV file with one line per known client, keyed by sanitized MAC address. Each line contains:

```
<sanitized-mac>\t<YYYYMMDD-hhmmss>\t<client-ip>\t<version>\t<offered-file or <NONE>>
```

Subsequent requests from the same MAC overwrite that client's existing line. The version column is the raw `x-ESP8266-version` header value with control characters stripped.

## Example Arduino Client

```cpp
t_httpUpdate_return ret = ESPhttpUpdate.update("192.168.0.2", 80, "/ota", "__DATE__ __TIME__");
switch (ret) {
    case HTTP_UPDATE_FAILED:    Serial.println("[update] Failed.");    break;
    case HTTP_UPDATE_NO_UPDATES: Serial.println("[update] No update."); break;
    case HTTP_UPDATE_OK:         Serial.println("[update] OK.");        break;
}
```
