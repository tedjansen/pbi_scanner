# Local Power BI Desktop smoke test (Windows)

This is the Windows runtime check for the local Desktop work. It needs:

- Windows with Power BI Desktop and a `.pbix`/`.pbip` model open;
- the DuckDB `v1.5.6` CLI for Windows (`duckdb.exe`);
- a `windows_amd64` build of this branch.

## 1. Get the extension build

1. Open the fork's **Actions** tab and pick the latest green
   *Main Extension Distribution Pipeline* run for this branch.
2. Under **Artifacts**, download the `windows_amd64` artifact for DuckDB
   `v1.5.6` (the name looks like `pbi_scanner-v1.5.6-extension-windows_amd64`)
   and unzip it. It contains `pbi_scanner.duckdb_extension`.
3. Download the DuckDB `v1.5.6` Windows CLI (`duckdb_cli-windows-amd64.zip`)
   from the DuckDB GitHub releases page and unzip `duckdb.exe` next to it.

## 2. Find the open models and their ports

Have one or more models open in Desktop. Then run:

```powershell
$ext = (Resolve-Path .\pbi_scanner.duckdb_extension).Path
.\duckdb.exe -unsigned -c "LOAD '$ext'; COPY (SELECT * FROM pbi_local_instances()) TO 'instances.csv' (HEADER);"
Get-Content instances.csv
```

`pbi_local_instances()` returns one row per running `msmdsrv.exe`:

| column | meaning |
| --- | --- |
| `report_name` | Taken from the `PBIDesktop.exe` window title: `<name> - Power BI Desktop`, or just `<name>` on newer builds. |
| `port` | The listening TCP port of `msmdsrv.exe`. |
| `catalog` | The database GUID, from `DBSCHEMA_CATALOGS`. |
| `connection_string` | `Data Source=localhost:<port>;Initial Catalog=<guid>;`, ready for `dax_query`. |
| `host_process` | The parent process: `PBIDesktop.exe` for Desktop, `devenv.exe` for a Visual Studio workspace. |
| `msmdsrv_pid`, `host_pid` | The process IDs. |
| `window_title` | The raw window title. |
| `workspace_path` | The workspace folder whose `msmdsrv.port.txt` holds this port. |
| `detail` | Problems such as a failed catalog lookup, or more than one catalog. |

Options:

- `discover_catalog := false` skips the TCP/SSPI lookup.
- `protection := 'privacy'` (default) sets message protection. Desktop rejects `none` and `integrity`.
- `timeout_ms := 10000` sets the timeout in milliseconds.

Compare the result with what you see. Is every open report listed? Are the
report names correct? Do the ports match `msmdsrv.port.txt`? The manual
fallback is below. Note that the port file is UTF-16.

```powershell
$roots = @(
  "$env:LOCALAPPDATA\Microsoft\Power BI Desktop\AnalysisServicesWorkspaces",
  "$env:USERPROFILE\Microsoft\Power BI Desktop Store App\AnalysisServicesWorkspaces"
)
$ws = Get-ChildItem $roots -Directory -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
$port = (Get-Content -Encoding Unicode "$($ws.FullName)\Data\msmdsrv.port.txt").Trim()
$port
```

## 3. Spike run: `pbi_local_probe`

Run this once from the folder that holds `duckdb.exe` and the extension. Set
`$port` to a port from step 2. It writes two files that answer every spike
question in one go.

```powershell
$port = 60790   # replace with a port from instances.csv
$env:PBI_SCANNER_LOCAL_TRACE = "1"
$ext = (Resolve-Path .\pbi_scanner.duckdb_extension).Path
.\duckdb.exe -unsigned -c "LOAD '$ext'; COPY (SELECT * FROM pbi_local_probe('Data Source=localhost:$port;')) TO 'probe.csv' (HEADER);" 2> probe_trace.txt
Get-Content probe.csv
```

The probe makes four attempts:

| attempt | protection | what it checks |
| --- | --- | --- |
| 1 | `skip` | requests without SSPI authentication |
| 2 | `none` | SSPI authentication, no message signing or encryption |
| 3 | `integrity` | SSPI authentication with signed messages |
| 4 | `privacy` | SSPI authentication with encrypted messages |

Each attempt reports these steps:

- `tcp_connect`;
- `sspi_round_N` and `sspi_context` (package, user, negotiated attributes);
- `discover_catalogs`, which should list one GUID;
- `execute_plain` and `execute_sx_xpress`, which return columns, types and the
  first row of a typed `EVALUATE ROW(...)`.

Failures show up as `ok = false` with the server or SSPI message. A failure
does not stop the later attempts.

Send back `instances.csv`, `probe.csv` and `probe_trace.txt`. `instances.csv`
contains report names and local paths. **Privacy note:** `sspi_context`
contains your Windows user name, and the trace contains hex previews of the
SSPI tokens, which include your user, domain and machine names. Redact them if
you like. The rest is protocol metadata.

Useful variations if something fails:

```sql
SELECT * FROM pbi_local_probe('Data Source=localhost:<port>;', protection := 'none', package := 'NTLM');
SELECT * FROM pbi_local_probe('Data Source=localhost:<port>;', protection := 'none', target_name := 'MSOLAPSvc.3/localhost');
SELECT * FROM pbi_local_probe('Data Source=localhost:<port>;', protection := 'none', dax_text := 'EVALUATE TOPN(5, INFO.VIEW.TABLES())');
```

## 4. Full smoke: `dax_query` and `pbi_*` against Desktop

Paste these blocks into PowerShell one at a time. The examples use
`C:\git` and the report `Uren`; adjust both. Queries avoid non-ASCII
characters, because Windows PowerShell may re-encode piped text.

**4a. Setup.** The helper loads the extension and runs SQL through stdin.

```powershell
cd C:\git
$ext = (Resolve-Path .\pbi_scanner.duckdb_extension).Path
Remove-Item Env:PBI_SCANNER_LOCAL_TRACE, Env:PBI_SCANNER_XMLA_TRANSPORT, Env:PBI_SCANNER_LOCAL_DUMP_DIR -ErrorAction SilentlyContinue
function Invoke-Duck([string]$sql) { ("LOAD '$ext';`n" + $sql) | .\duckdb.exe -unsigned }
```

**4b. Discovery.** Expect `catalog` to be filled and `detail` to be empty.

```powershell
Invoke-Duck @"
.mode line
SELECT * FROM pbi_local_instances();
"@
$cs = (Invoke-Duck @"
.mode list
.headers off
SELECT connection_string FROM pbi_local_instances() WHERE report_name = 'Uren' LIMIT 1;
"@ | Select-Object -Last 1).Trim()
$port = [regex]::Match($cs, 'localhost:(\d+)').Groups[1].Value
$cs; $port
```

**4c. First queries.** Run one with the discovered catalog and one without
`Initial Catalog`.

```powershell
Invoke-Duck @"
.mode box
SELECT * FROM dax_query('$cs', 'EVALUATE ROW("probe_ok", 1)');
SELECT * FROM dax_query('Data Source=localhost:$port;', 'EVALUATE ROW("probe_ok", 2)');
"@
```

**4d. Types and values on every transport.** The rows should be identical.

```powershell
$typed = 'EVALUATE ROW("i", 42, "c", CURRENCY(12.34), "f", DIVIDE(1, 3), "d", DATE(2024, 1, 31), "dt", DATE(2024, 1, 31) + TIME(13, 45, 0), "s", "h" & UNICHAR(233) & "llo", "t", TRUE(), "fa", FALSE(), "b", BLANK())'
Invoke-Duck @"
.mode box
DESCRIBE SELECT * FROM dax_query('$cs', '$typed');
"@
foreach ($t in 'sx_xpress', 'xpress', 'plain') {
  $env:PBI_SCANNER_XMLA_TRANSPORT = $t
  Invoke-Duck @"
.mode line
SELECT '$t' AS transport, * FROM dax_query('$cs', '$typed');
"@
}
Remove-Item Env:PBI_SCANNER_XMLA_TRANSPORT
```

**4e. Metadata functions.**

```powershell
Invoke-Duck @"
.mode box
SELECT (SELECT count(*) FROM pbi_tables('$cs')) AS tables,
       (SELECT count(*) FROM pbi_columns('$cs')) AS columns,
       (SELECT count(*) FROM pbi_measures('$cs')) AS measures,
       (SELECT count(*) FROM pbi_relationships('$cs')) AS relationships;
SELECT * FROM pbi_tables('$cs') LIMIT 5;
SELECT * FROM pbi_tables('$cs', normalize_dax_column_names := true) LIMIT 3;
"@
```

**4f. A real table on every transport.** Expect the same row count everywhere
and a reasonable time for `sx_xpress`.

```powershell
$table = 'Medewerkers'
foreach ($t in 'sx_xpress', 'xpress', 'plain') {
  $env:PBI_SCANNER_XMLA_TRANSPORT = $t
  Invoke-Duck @"
.timer on
.mode box
SELECT '$t' AS transport, count(*) AS row_count FROM dax_query('$cs', 'EVALUATE ''$table''');
"@
}
Remove-Item Env:PBI_SCANNER_XMLA_TRANSPORT
Invoke-Duck @"
.mode box
SELECT * FROM dax_query('$cs', 'EVALUATE TOPN(5, ''$table'')');
"@
```

**4g. Error messages.** Each statement should fail with a clear message.

```powershell
Invoke-Duck @"
SELECT * FROM dax_query('Data Source=localhost:1;', 'EVALUATE ROW("x", 1)');
SELECT * FROM dax_query('$cs', 'EVALUATE ROW("x", 1)', access_token := 'abc');
SELECT * FROM dax_query('$cs', 'EVALUATE NOSUCHFUNCTION()');
"@
```

**4h. Optional: capture fixtures.** Use this if 4d differs between transports.
The output is hex for the synthetic `EVALUATE ROW` only, with no model data.

```powershell
New-Item -ItemType Directory -Force C:\git\pbi_dump | Out-Null
Remove-Item C:\git\pbi_dump\* -ErrorAction SilentlyContinue
$env:PBI_SCANNER_LOCAL_DUMP_DIR = 'C:\git\pbi_dump'
Invoke-Duck "SELECT * FROM dax_query('$cs', '$typed');" | Out-Null
Remove-Item Env:PBI_SCANNER_LOCAL_DUMP_DIR
Get-ChildItem C:\git\pbi_dump | ForEach-Object { $_.Name; ([BitConverter]::ToString([IO.File]::ReadAllBytes($_.FullName)) -replace '-', '') }
```

Expected results:

- 4b: `catalog` is the model GUID.
- 4c: `probe_ok` is 1 and 2; the second query discovers the catalog itself.
- 4d: `i` BIGINT, `c` and `f` DOUBLE, `d` DATE, `dt` TIMESTAMP, `s` VARCHAR,
  `t`/`fa` BOOLEAN. An all-`BLANK()` column is left out of the schema by the
  server. The values match across transports.
- 4e: counts match what Desktop shows in the model view.
- 4f: the same row count on all transports.
- 4g: a connect error, the `access_token is not supported ...` error, and a
  DAX error from the server.
