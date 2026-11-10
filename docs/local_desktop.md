# Local Power BI Desktop (Windows): design notes

Status: **implemented, awaiting Windows validation**. `dax_query` and the
`pbi_*` metadata functions accept `Data Source=localhost:<port>`. Discovery
(`pbi_local_instances`) and diagnostics (`pbi_local_probe`) are available. The
handshake, encryption and decoding were verified against Power BI Desktop with
the probe. The full `dax_query` path still needs the Windows smoke test in
[local_desktop_smoke.md](local_desktop_smoke.md), step 4.

Tracking issue: crazy-treyn/pbi_scanner#19.

## Problem

Power BI Desktop hosts the open model in a local Analysis Services instance
(`msmdsrv.exe`). It listens on `localhost:<random port>` and writes the port to
`...\AnalysisServicesWorkspaces\<id>\Data\msmdsrv.port.txt`. That instance does
not serve XMLA over HTTP. It speaks the native Analysis Services TCP protocol
and uses Windows integrated authentication. `pbi_scanner` today only sends XMLA
over HTTP(S) with a Bearer token.

## Protocol (from [MS-SSAS])

All of this comes from the Open Specifications document
[MS-SSAS] *SQL Server Analysis Services Protocol*:

| Topic | Section | Summary |
| --- | --- | --- |
| Transport | 2.1 | TCP or HTTP(S). SOAP XML or binary XML, optionally compressed. Network byte order unless stated otherwise. DIME is used on TCP. |
| Framing | 2.1.1 | Each SOAP message is a DIME message of one or more records. Record header: `VERSION(5)=1, MB, ME, CF, TYPE_T(4), RESERVED(4), OPTIONS_LENGTH(16), ID_LENGTH(16), TYPE_LENGTH(16), DATA_LENGTH(32)`, then OPTIONS/ID/TYPE/DATA, each padded to 4 bytes. TYPE is `text/xml`, `application/sx`, `application/xml+xpress` or `application/sx+xpress`. |
| Negotiation | 2.1.1, 3.2.3 | The 4-byte OPTIONS field carries flags (LSB first): `NEGO, REQ_SX, REQ_XPRESS, RESP_SX, RESP_XPRESS`. The first request and its response are always text XML with `NEGO=0`. The server keeps no negotiation state, so both sides send the flags on every message. These are the same five flags as the HTTP `X-Transport-Caps-Negotiation-Flags` header the extension already sends. |
| Authentication | 3.2.2, 3.1.4.1 | GSS-API (SPNEGO). Tokens travel base64-encoded in the XMLA `Authenticate` method (`<Authenticate xmlns="http://schemas.microsoft.com/analysisservices/2003/ext"><SspiHandshake>…`), answered by `AuthenticateResponse/return/SspiHandshake`, until GSS-API reports completion. |
| Message protection | 2.1.3 | If signing or encryption was negotiated, the payload is a sequence of blocks `DATA_SIZE(16, LE), TOKEN_SIZE(16, LE), DATA, TOKEN`. A block can span DIME records. |
| Compression | 2.1.4, 3.2.5 | Blocks of `ORIGINAL_SIZE(32, LE), COMPRESSED_SIZE(32, LE), DATA`. This is the same Xpress framing the HTTP path already decodes (`src/xpress.cpp`). |
| Binary XML | 2.1.5 | [MS-BINXML], already parsed by `src/xmla.cpp`. |
| Layering | 3.2.4 | Send: SOAP → binary XML (optional) → compress (optional) → encrypt/sign (optional) → DIME. Receive: the reverse. |
| Product defaults | Appendix A <1>–<3> | Analysis Services splits messages into several DIME records and uses `application/sx+xpress` by default. |

The only new pieces compared with the HTTP path are DIME, the `Authenticate`
loop and the optional GSS-API wrap layer. The envelopes, `ProtocolCapabilities`,
Xpress decompression and the plain/binary XML parsers are reused unchanged.

## Code layout (spike)

- `src/xmla_tcp.cpp` / `src/include/xmla_tcp.hpp`: platform-independent pieces.
  This covers the DIME encoder and incremental reader, the GSS-API wrap block
  codec, the `Authenticate` envelope and response parser, the
  `DBSCHEMA_CATALOGS` envelope and parser, and `localhost:<port>` recognition.
  Offline tests live in `test/cpp/pbi_scanner_unit_tests.cpp` (`[xmla_tcp]`).
- `src/xmla_tcp_client.cpp` / `src/include/xmla_tcp_client.hpp`:
  `LocalXmlaTcpClient`. On Windows it uses Winsock, SSPI (`secur32`:
  `AcquireCredentialsHandleW`, `InitializeSecurityContextW`, and
  `EncryptMessage`/`MakeSignature` with their counterparts), DIME round trips
  and optional message protection. On other platforms, including WASM, it
  throws `InvalidInputException`.
- `src/local_probe.cpp`: the `pbi_local_probe(connection_string, ...)` table
  function, for the spike only. Each attempt (protection `skip`, `none`,
  `integrity`, `privacy`) does the following:
  - connects;
  - authenticates, unless the protection is `skip`;
  - discovers the catalog;
  - runs a typed `EVALUATE ROW(...)` once as plain XML and once with
    `sx+xpress`.

  It returns one row per step. `PBI_SCANNER_LOCAL_TRACE=1` adds hex previews
  of every message on stderr.
- `src/local_instances.cpp`: the `pbi_local_instances()` table function
  (Windows only). It builds the list as follows:
  - lists `msmdsrv.exe` processes (Toolhelp snapshot). Instances whose
    parent is `services.exe` (an SSAS service) or `RSHostingService.exe`
    (Power BI Report Server) are skipped;
  - gets their listening ports (`GetExtendedTcpTable`, IPv4 and IPv6). This
    is more reliable than port files, which stay behind after a crash. Some
    Windows 11 builds (KB5127936) report the listener with state 0, so an
    unconnected socket on a loopback or wildcard address also counts;
  - finds the parent process and its top-level window title for the report
    name. The title is `<report> - Power BI Desktop`, or just `<report>`.
    The separator varies with the UI language (hyphen, minus sign, en/em
    dash, and so on);
  - matches ports to `AnalysisServicesWorkspaces\*\Data\msmdsrv.port.txt`
    (UTF-16) for the workspace folder;
  - optionally discovers the catalog GUID over TCP;
  - returns a ready `connection_string`.

  The port file parser and the title parsing are tested offline.

## Prior art

- [DAX Studio](https://github.com/DaxStudio/DaxStudio) does not implement the
  protocol itself. It connects through Microsoft's closed-source ADOMD.NET
  (`Microsoft.AnalysisServices.AdomdClient`) with `Data Source=localhost:<port>`
  and integrated security. Its instance discovery
  (`src/DaxStudio.Core/Utils/PowerBIHelper.cs`, `ManagedIpHelper.cs`) uses the
  same approach as `pbi_local_instances`: `msmdsrv` processes, their parent
  process and window title, and the TCP table. The parent filtering, the
  localized title separators and the state-0 listener workaround are taken
  from it as behaviour, not as code.
- Tabular Editor, Bravo and pyadomd also wrap Microsoft's AMO/TOM or
  ADOMD.NET client libraries. No open-source native implementation of the TCP
  protocol turned up, so `[MS-SSAS]` stays the reference for the wire format.

## Findings from the first Windows run

These come from Power BI Desktop, Microsoft Store install:

- TCP connect and DIME framing work. The server answers `Authenticate` with a
  `text/xml` DIME message.
- Authentication is required. Sending `Discover` without `Authenticate`
  makes the server reset the connection (WSA error 10054).
- Negotiate (SPNEGO) carries NTLM on loopback. The first round returns an
  SPNEGO `negTokenResp` with an NTLM challenge.
- The server wraps the base64 `SspiHandshake` in 76-character lines with
  line breaks. The parser now strips whitespace before decoding.
- The window title can be just the report name, without the
  ` - Power BI Desktop` suffix. `report_name` now uses the title itself in
  that case.

## Findings from the second Windows run

- **Encryption is required.** With `none` or `integrity`, Desktop resets the
  connection after the first NTLM round. With `privacy`, the handshake
  completes in two rounds: NTLM, with `CONFIDENTIALITY|INTEGRITY` and a
  16-byte trailer. After that, every message is a sequence of wrap blocks as
  specified in [MS-SSAS] 2.1.3. Our layout (DATA, then TOKEN, sizes
  little-endian, `SECBUFFER_DATA` + `SECBUFFER_TOKEN`) is accepted in both
  directions. `privacy` is now the default.
- Encrypted `DBSCHEMA_CATALOGS` returns the single GUID catalog.
- A plain-XML `Execute` returns real column names and the expected types.
  `CURRENCY` comes back as `DOUBLE`, and a column that is entirely `BLANK()`
  is absent from the schema. Both should be compared with the service path.
- With `RESP_SX|RESP_XPRESS`, the server answers `application/sx+xpress`.
  The existing Xpress and binary-XML decoders read it. As on the service path,
  sx responses carry positional names (`C0`, `C1`, ...), which is why
  `dax_query` probes the schema with `xpress` first. The probe's stand-alone
  sx decode misreads the last column after the blank one. The real
  `dax_query` path decodes sx against the probed schema, so this needs
  checking once local targets are wired in.
- Desktop advertises `REQ_SX|REQ_XPRESS` in every response. Requests stay
  plain text XML.
- `EVALUATE TOPN(5, INFO.VIEW.TABLES())` works over plain XML, with real
  names and types (BIGINT, VARCHAR, BOOLEAN). That response arrived in two
  DIME records, which the reader reassembles. A column that is entirely
  `BLANK()` is left out of the schema.
- The probe's stand-alone sx decode, which has no known schema, drops or
  `NULL`s BOOLEAN columns. Examples are `C4`/`C8` in `INFO.VIEW.TABLES`, and
  `TRUE()` in `EVALUATE ROW`. `dax_query` decodes sx against the schema it
  probed with `xpress`, so booleans must be checked through `dax_query` once
  local targets are wired in.

## Open questions the Windows probe answers

1. Does Desktop's `msmdsrv` accept requests without `Authenticate` (attempt
   `skip`)?
2. Which SSPI package actually runs for loopback: Negotiate falling back to
   NTLM, or Kerberos. How many rounds does it take?
3. Does the server require signing or encryption, or does it accept
   `protection=none`? Do our wrap-block layout and SSPI buffer order match the
   server for `integrity` and `privacy`?
4. Does the server honour `RESP_SX|RESP_XPRESS` on TCP? Which TYPE and OPTIONS
   does it send back? Do the existing parsers decode the payload?
5. Does `DBSCHEMA_CATALOGS` return exactly one GUID-named catalog?
6. Does `pbi_local_instances()` find every open report? Are the window title
   heuristics right for the installed Desktop version and language? This
   covers unsaved reports ("Untitled") and the Microsoft Store install.

## Public surface

- `Data Source=localhost:<port>` (also `127.0.0.1:<port>`, `[::1]:<port>`),
  with no scheme. `Initial Catalog` is optional for local targets. When it is
  omitted, the extension discovers it through `DBSCHEMA_CATALOGS`; if there
  is more than one database, it asks for `Initial Catalog`.
- No token resolution for local targets. Authentication is always the current
  Windows user (SSPI Negotiate, which is NTLM on loopback), with an encrypted
  session. `auth_mode`, `access_token`, `secret_name`, `tenant_id`,
  `client_id`, `client_secret` and `Secret=` are rejected with
  `<name> is not supported for local Power BI Desktop connections ...`.
- Same column naming (`normalize_dax_column_names`), schema probe, transports
  (`PBI_SCANNER_XMLA_TRANSPORT`) and type coercion as the service path,
  because the same parsers are used.
- Local targets are not stored in the metadata cache: the port changes on
  every Desktop start, and the model changes while it is being developed.
- Clear `InvalidInputException` on non-Windows and WASM builds:
  `Local Power BI Desktop connections (Data Source=localhost:<port>) are only
  supported in native Windows builds of pbi_scanner`.
- `PBI_SCANNER_LOCAL_TRACE=1` traces each message on stderr.
  `PBI_SCANNER_LOCAL_DUMP_DIR=<folder>` writes decrypted response bodies to
  files, for offline fixtures.

## Implementation

- `PowerBIConnectionConfig::is_local_instance` with `local_host` and
  `local_port`, set by `ParsePowerBIConnectionString`.
- `XmlaExecutor::PostXmla` sends HTTP requests through `HttpClient` and local
  requests through `LocalXmlaTcpClient::RoundTripStream`. For local requests,
  the DIME TYPE becomes the response `Content-Type`, so `ProbeSchema`,
  `ExecuteStreaming` and every decoder are unchanged. Transport errors become
  `request failed` errors, exactly as on HTTP.
- `XmlaTcpResponseReader` (portable, unit tested) decrypts wrap blocks as DIME
  records arrive, so results stream instead of being buffered.
- `dax_query` bind skips the resolver, token resolution and caches for local
  targets. It discovers the catalog when needed, and hands the authenticated
  connection from the schema probe to execution. Cancellation shuts the
  socket down (`LocalXmlaTcpClient::Abort`).

## Next steps

1. Windows smoke test (step 4 of the smoke doc). Compare types and values
   across the `sx_xpress`, `xpress` and `plain` transports, and against the
   published model.
2. If BOOLEAN or other sx tokens decode differently from `xpress`, capture
   the bodies with `PBI_SCANNER_LOCAL_DUMP_DIR` and turn them into Catch
   fixtures.
3. Decide whether to keep `pbi_local_probe` as a documented diagnostic.
4. Upstream PR (crazy-treyn/pbi_scanner#19), once the maintainer agrees.

## Out of scope (follow-ups)

- RLS testing against Desktop (`Roles=`, `EffectiveUserName`).
- Resolving `Data Source=<report name>` automatically inside `dax_query`.
  Callers select a `connection_string` from `pbi_local_instances()`.
- On-premises SSAS over the network, Kerberos delegation, and explicit
  credentials.
