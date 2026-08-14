# Shell integration

This integration is explicitly opt-in and sends events only after it is sourced **and** `AIR_RECORDER_ENABLED=1`. It records a command, working directory, source timestamp and exit code. Commands that look as though they may contain inline credentials are reduced to metadata; their command and working directory are not sent. It does not inspect shell history or masked prompt input.

Use the project ID and **shell-only** pairing token shown by the desktop application. Create and keep a stable random source ID for this shell installation:

```zsh
export AIR_RECORDER_PROJECT_ID='current project ID'
export AIR_RECORDER_SOURCE_ID='a locally generated UUID'
export AIR_RECORDER_TOKEN='shell-only pairing token'
export AIR_RECORDER_ENABLED=1
source /absolute/path/to/integrations/shell/air-recorder.zsh
```

Each message carries the project ID, source identity, UUID message ID, source timestamp, canonical payload SHA-256 and an HMAC-SHA-256 signature. The desktop rejects a wrong project, wrong source token, duplicate message ID, stale/future time or altered payload.

Set `AIR_RECORDER_ENABLED=0`, remove the `source` line, and unset the three pairing variables to disable it.
