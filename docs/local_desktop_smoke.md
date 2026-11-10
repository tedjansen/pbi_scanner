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

## 2. Find the Desktop port

Run this in PowerShell with the model open in Desktop. It covers the regular
and the Microsoft Store installs. The port file is UTF-16.

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

Run this once from the folder that holds `duckdb.exe` and the extension. It
writes two files that answer every spike question in one go.

```powershell
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

Send back `probe.csv` and `probe_trace.txt`. **Privacy note:** `sspi_context`
contains your Windows user name, and the trace contains hex previews of the
SSPI tokens, which include your user, domain and machine names. Redact them if
you like. The rest is protocol metadata.

Useful variations if something fails:

```sql
SELECT * FROM pbi_local_probe('Data Source=localhost:<port>;', protection := 'none', package := 'NTLM');
SELECT * FROM pbi_local_probe('Data Source=localhost:<port>;', protection := 'none', target_name := 'MSOLAPSvc.3/localhost');
SELECT * FROM pbi_local_probe('Data Source=localhost:<port>;', protection := 'none', dax_text := 'EVALUATE TOPN(5, INFO.VIEW.TABLES())');
```

## 4. Full smoke (after `dax_query` supports local targets)

These checks run once local targets are wired into `dax_query`. They are not
available in the spike build yet.

```sql
LOAD '<path>\pbi_scanner.duckdb_extension';
SELECT * FROM dax_query('Data Source=localhost:<port>;', 'EVALUATE ROW("probe_ok", 1)');
SELECT * FROM pbi_tables('Data Source=localhost:<port>;');
SELECT * FROM dax_query('Data Source=localhost:<port>;',
  'EVALUATE ROW("d", DATE(2024, 1, 31), "c", CURRENCY(12.34), "f", DIVIDE(1, 3), "b", BLANK())');
DESCRIBE SELECT * FROM dax_query('Data Source=localhost:<port>;',
  'EVALUATE ROW("d", DATE(2024, 1, 31), "c", CURRENCY(12.34), "f", DIVIDE(1, 3), "b", BLANK())');
```

Expected results:

- `probe_ok = 1`;
- `pbi_tables` lists the model's tables;
- `d` is `DATE` or `TIMESTAMP` as on the service path, `c` is `DECIMAL`/`DOUBLE`
  as on the service path, and `b` is `NULL`.

Compare the types with the same query against the published model.
