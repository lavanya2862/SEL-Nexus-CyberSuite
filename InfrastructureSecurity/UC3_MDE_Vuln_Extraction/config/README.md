# config/

| File | What it controls |
|---|---|
| `settings.example.env` | Template for `.env` (Defender API address, folders, login details). Copy it to `../.env`; you type the secret there yourself. |
| `opco_mapping.csv` | Maps Defender devices to OpCos (business units). `match_type` is `rbac_group` (Defender device group), `tag` (device tag, e.g. `OpCo A`) or `name_pattern` (device name). `pattern` accepts `*` wildcards and ignores upper/lower case. Rules are tried **top to bottom and the first match wins**; unmatched devices become `UNMAPPED` (flagged by the quality checks). |
| `sla_policy.csv` | Days allowed to fix a vulnerability per severity. PoC assumptions, not a client policy. |
