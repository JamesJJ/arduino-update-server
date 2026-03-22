# Arduino OTA Update Server

A lightweight HTTP server written in Go that serves OTA firmware updates to ESP8266 devices, following the [Arduino ESP8266 HTTP OTA protocol](https://arduino-esp8266.readthedocs.io/en/3.0.0/ota_updates/readme.html#http-server).

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | HTTP listen port |
| `--root` | _(required)_ | Root directory containing firmware files |
| `--no-parse-version` | `false` | Disable parsing `\|D:__DATE__\|T:__TIME__\|` format from the version header |
| `--client-log` | _(disabled)_ | Path to a TSV file recording the latest request from each client |

## HTTP Endpoints

| Path | Description |
|------|-------------|
| `/ota` | OTA update endpoint for ESP8266 devices |
| `/health` | Returns HTTP 200 with no body or logging |
| `/clients` | HTML table of all clients from the client log, ordered by most recent first |
| `/metrics` | JSON metrics aggregated from the client log (last 30 days) |

## OTA Update Flow

1. A device sends a request to `/ota` with `x-ESP8266-STA-MAC` and `x-ESP8266-version` headers.
2. The MAC address is validated (after lowercasing, only `0-9`, `a-f`, and `:` are permitted) and normalised to `aa-bb-cc-dd-ee-ff` format (exactly 6 hex pairs). Invalid MACs are rejected with HTTP 304 and an error log. The sanitised MAC is used to locate a device-specific directory under `<root>/<sanitized-mac>/`.
3. The version string is sanitized for filename compatibility (characters outside `a-zA-Z0-9._-` replaced with `-`, truncated to 32 chars). Unless `--no-parse-version` is set, versions starting with `|D:__DATE__|T:__TIME__|` are parsed into `YYYYMMDD-hhmmss` format, with any trailing optional string appended as `-<sanitized-suffix>`.
4. The server lists `*.bin` files in the device directory whose filenames are alphanumerically greater than the current version.
5. If a newer version exists, the next sequential version is served (HTTP 200). This ensures devices upgrade one version at a time, which is important for devices that lack space to download a full release and must first install a smaller intermediate OTA-only build.
6. If no newer version exists, the server responds with HTTP 304.

All `x-ESP8266-*` request headers, the resolved directory, current version, selected file, and skipped version count are logged to stdout.

## Client Log

When `--client-log` is set, the server maintains a TSV file with one line per known client, keyed by sanitized MAC address. Each line contains:

```
<mac>\t<YYYYMMDD-hhmmss>\t<ip>\t<version>\t<offered-file or <NONE>>\t<fail-count>
```

- Subsequent requests from the same MAC overwrite that client's existing line.
- The version column is the raw `x-ESP8266-version` header value with control characters stripped.
- The fail count tracks consecutive requests where the same MAC sends the same version while an update is available. It resets to 0 when no update is offered, or when the version changes.

## Metrics

`/metrics` returns JSON with counts derived from client log records within the last 30 days:

```json
{
  "total_clients": 10,
  "offered_update": 4,
  "up_to_date": 5,
  "apparently_failing": 1
}
```

A client is counted as "apparently failing" when its fail count is 3 or more.

## Example Arduino Client

```cpp
t_httpUpdate_return ret = ESPhttpUpdate.update("192.168.0.2", 80, "/ota", "|D:" __DATE__ "|T:" __TIME__ "|");
switch (ret) {
    case HTTP_UPDATE_FAILED:    Serial.println("[update] Failed.");    break;
    case HTTP_UPDATE_NO_UPDATES: Serial.println("[update] No update."); break;
    case HTTP_UPDATE_OK:         Serial.println("[update] OK.");        break;
}
```
