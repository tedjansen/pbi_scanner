#include "local_probe.hpp"

#include "pbi_duckdb_compat.hpp"
#include "pbi_scanner_util.hpp"
#include "xmla.hpp"
#include "xmla_tcp.hpp"
#include "xmla_tcp_client.hpp"
#include "xpress.hpp"

#include "duckdb/common/error_data.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/table_function.hpp"

#include <chrono>

namespace duckdb {

namespace {

//! Exercises the types the smoke test cares about in one round trip.
static constexpr const char *DEFAULT_PROBE_DAX =
    "EVALUATE ROW(\"probe_ok\", 1, \"int_col\", 42, \"currency_col\", "
    "CURRENCY(12.34), \"double_col\", DIVIDE(1, 3), \"date_col\", "
    "DATE(2024, 1, 31), \"datetime_col\", DATE(2024, 1, 31) + TIME(13, 45, 0), "
    "\"text_col\", \"héllo\", \"blank_col\", BLANK(), \"bool_col\", TRUE())";

struct ProbeRow {
  int32_t attempt;
  string protection;
  string step;
  bool ok;
  int64_t elapsed_ms;
  string detail;
};

struct LocalProbeBindData : public TableFunctionData {
  vector<ProbeRow> rows;
};

struct LocalProbeState : public GlobalTableFunctionState {
  idx_t offset = 0;
};

static string ExtractDataSource(const string &input, string &catalog_out) {
  auto trimmed = Trimmed(input);
  if (trimmed.find('=') == string::npos) {
    return trimmed;
  }
  string data_source;
  for (auto &segment : StringUtil::Split(trimmed, ';')) {
    auto equals = segment.find('=');
    if (equals == string::npos) {
      continue;
    }
    auto key = Trimmed(segment.substr(0, equals));
    auto value = Trimmed(segment.substr(equals + 1));
    if (StringUtil::CIEquals(key, "Data Source")) {
      data_source = value;
    } else if (StringUtil::CIEquals(key, "Initial Catalog")) {
      catalog_out = value;
    }
  }
  return data_source;
}

static string DescribeResult(const XmlaParseTestResult &result) {
  if (!result.fault_message.empty()) {
    return "fault: " + result.fault_message;
  }
  vector<string> columns;
  for (auto &column : result.columns) {
    columns.push_back(column.name + " " + column.duckdb_type.ToString() + " (" +
                      column.source_type + ")");
  }
  string detail =
      StringUtil::Format("%llu columns, %llu rows; columns: %s",
                         static_cast<unsigned long long>(result.columns.size()),
                         static_cast<unsigned long long>(result.rows.size()),
                         StringUtil::Join(columns, ", ").c_str());
  if (!result.rows.empty()) {
    vector<string> values;
    for (auto &value : result.rows[0]) {
      values.push_back(value.IsNull() ? "NULL" : value.ToString());
    }
    detail += "; first row: " + StringUtil::Join(values, " | ");
  }
  return detail;
}

static XmlaParseTestResult DecodeResponse(const LocalXmlaResponse &response) {
  auto type = StringUtil::Lower(response.content_type);
  auto body = response.body;
  if (type.find("xpress") != string::npos) {
    body = DecompressXpressLz77Framed(body);
  }
  if (StringUtil::StartsWith(type, "application/sx")) {
    return ParseBinXmlForTesting(body);
  }
  return ParseXmlaChunksForTesting({body});
}

static string ResponseSummary(const LocalXmlaResponse &response) {
  return StringUtil::Format(
      "type=%s caps=%s records=%llu wire=%llu bytes body=%llu bytes",
      response.content_type.c_str(),
      response.has_caps_flags
          ? DescribeXmlaTcpCapsFlags(response.caps_flags).c_str()
          : "none",
      static_cast<unsigned long long>(response.dime_records),
      static_cast<unsigned long long>(response.wire_bytes),
      static_cast<unsigned long long>(response.body.size()));
}

class ProbeRecorder {
public:
  ProbeRecorder(vector<ProbeRow> &rows, int32_t attempt, string protection)
      : rows(rows), attempt(attempt), protection(std::move(protection)),
        last(std::chrono::steady_clock::now()) {}

  void Add(const string &step, bool ok, const string &detail) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - last)
            .count();
    last = now;
    rows.push_back(ProbeRow{attempt, protection, step, ok,
                            static_cast<int64_t>(elapsed), detail});
  }

private:
  vector<ProbeRow> &rows;
  int32_t attempt;
  string protection;
  std::chrono::steady_clock::time_point last;
};

static void RunAttempt(vector<ProbeRow> &rows, int32_t attempt,
                       const string &host, uint16_t port,
                       const LocalXmlaAuthOptions &auth, bool authenticate,
                       string catalog, const string &dax_text,
                       int64_t timeout_ms) {
  ProbeRecorder recorder(rows, attempt,
                         authenticate ? auth.protection : "skip");
  string current = "tcp_connect";
  try {
    LocalXmlaTcpClient client(
        timeout_ms, [&](const string &step, bool ok, const string &detail) {
          recorder.Add(step, ok, detail);
        });
    client.Connect(host, port);
    if (authenticate) {
      current = "authenticate";
      client.Authenticate(auth);
    }

    current = "discover_catalogs";
    auto discover =
        client.RoundTrip(BuildXmlaDiscoverCatalogsEnvelope(),
                         authenticate ? XMLA_TCP_CAPS_NEGO : uint8_t(0));
    auto names = ParseXmlaCatalogNames(discover.body);
    recorder.Add(current, !names.empty(),
                 ResponseSummary(discover) +
                     "; catalogs: " + StringUtil::Join(names, ", ") +
                     (names.empty() ? "; body: " + discover.body.substr(0, 400)
                                    : string()));
    if (catalog.empty() && !names.empty()) {
      catalog = names[0];
    }

    current = "execute_plain";
    auto plain =
        client.RoundTrip(BuildXmlaExecuteEnvelopeForMode(
                             catalog, dax_text, "", XmlaTransportMode::PLAIN),
                         XMLA_TCP_CAPS_NEGO);
    auto plain_result = DecodeResponse(plain);
    recorder.Add(current, plain_result.fault_message.empty(),
                 ResponseSummary(plain) + "; " + DescribeResult(plain_result));

    current = "execute_sx_xpress";
    auto sx = client.RoundTrip(
        BuildXmlaExecuteEnvelopeForMode(catalog, dax_text, "",
                                        XmlaTransportMode::SX_XPRESS),
        XMLA_TCP_CAPS_NEGO | XMLA_TCP_CAPS_RESP_SX | XMLA_TCP_CAPS_RESP_XPRESS);
    string sx_detail =
        ResponseSummary(sx) + "; head=" + HexPreview(sx.body, 24);
    try {
      auto sx_result = DecodeResponse(sx);
      recorder.Add(current, sx_result.fault_message.empty(),
                   sx_detail + "; " + DescribeResult(sx_result));
    } catch (const std::exception &ex) {
      recorder.Add(current, false, sx_detail + "; decode error: " + ex.what());
    }
    recorder.Add("done", true, "catalog=" + catalog);
  } catch (const std::exception &ex) {
    ErrorData error(ex);
    recorder.Add(current, false, error.RawMessage());
  }
}

#ifdef PBI_DUCKDB_MAIN_SIGNATURES
static void AddName(vector<Identifier> &names, const char *name) {
  names.emplace_back(name);
}
#else
static void AddName(vector<string> &names, const char *name) {
  names.emplace_back(name);
}
#endif

static unique_ptr<FunctionData>
LocalProbeBind(ClientContext &, TableFunctionBindInput &input,
               vector<LogicalType> &return_types,
#ifdef PBI_DUCKDB_MAIN_SIGNATURES
               vector<Identifier> &names) {
#else
               vector<string> &names) {
#endif
  auto named_parameters =
      pbi_compat::CopyBindNamedParameters(input.named_parameters);
  string catalog;
  auto data_source =
      ExtractDataSource(input.inputs[0].GetValue<string>(), catalog);
  string host;
  uint16_t port = 0;
  if (!TryParseLocalInstanceDataSource(data_source, host, port)) {
    throw InvalidInputException(
        "pbi_local_probe expects Data Source=localhost:<port>");
  }

  LocalXmlaAuthOptions auth;
  string protection = "all";
  string dax_text = DEFAULT_PROBE_DAX;
  int64_t timeout_ms = 30000;
  for (auto &entry : named_parameters) {
    auto key = StringUtil::Lower(pbi_compat::IdentifierName(entry.first));
    if (entry.second.IsNull()) {
      continue;
    }
    if (key == "package") {
      auth.package = entry.second.GetValue<string>();
    } else if (key == "protection") {
      protection = StringUtil::Lower(entry.second.GetValue<string>());
    } else if (key == "target_name") {
      auth.target_name = entry.second.GetValue<string>();
    } else if (key == "dax_text") {
      dax_text = entry.second.GetValue<string>();
    } else if (key == "timeout_ms") {
      timeout_ms = entry.second.GetValue<int64_t>();
    }
  }
  vector<string> levels;
  if (protection == "all") {
    levels = {"skip", "none", "integrity", "privacy"};
  } else if (protection == "skip" || protection == "none" ||
             protection == "integrity" || protection == "privacy") {
    levels = {protection};
  } else {
    throw InvalidInputException(
        "protection must be all, skip, none, integrity, or privacy");
  }

  if (!LocalXmlaTcpClient::IsSupported()) {
    throw InvalidInputException(
        "Local Power BI Desktop connections (Data Source=localhost:<port>) are "
        "only supported in native Windows builds of pbi_scanner");
  }

  auto result = make_uniq<LocalProbeBindData>();
  int32_t attempt = 0;
  for (auto &level : levels) {
    attempt++;
    auto attempt_auth = auth;
    attempt_auth.protection = level == "skip" ? "none" : level;
    RunAttempt(result->rows, attempt, host, port, attempt_auth, level != "skip",
               catalog, dax_text, timeout_ms);
  }

  return_types = {LogicalType::INTEGER, LogicalType::VARCHAR,
                  LogicalType::VARCHAR, LogicalType::BOOLEAN,
                  LogicalType::BIGINT,  LogicalType::VARCHAR};
  AddName(names, "attempt");
  AddName(names, "protection");
  AddName(names, "step");
  AddName(names, "ok");
  AddName(names, "elapsed_ms");
  AddName(names, "detail");
  return std::move(result);
}

static unique_ptr<GlobalTableFunctionState>
LocalProbeInit(ClientContext &, TableFunctionInitInput &) {
  return make_uniq<LocalProbeState>();
}

static void LocalProbeExecute(ClientContext &, TableFunctionInput &input,
                              DataChunk &output) {
  auto &bind_data = input.bind_data->Cast<LocalProbeBindData>();
  auto &state = input.global_state->Cast<LocalProbeState>();
  idx_t count = 0;
  while (state.offset < bind_data.rows.size() && count < STANDARD_VECTOR_SIZE) {
    auto &row = bind_data.rows[state.offset++];
    output.SetValue(0, count, Value::INTEGER(row.attempt));
    output.SetValue(1, count, Value(row.protection));
    output.SetValue(2, count, Value(row.step));
    output.SetValue(3, count, Value::BOOLEAN(row.ok));
    output.SetValue(4, count, Value::BIGINT(row.elapsed_ms));
    output.SetValue(5, count, Value(row.detail));
    count++;
  }
  output.SetCardinality(count);
}

} // namespace

vector<string> LocalProbeNamedParameterNames() {
  return {"package", "protection", "target_name", "dax_text", "timeout_ms"};
}

TableFunction CreatePbiLocalProbeFunction() {
  TableFunction function("pbi_local_probe", {LogicalType::VARCHAR},
                         LocalProbeExecute, LocalProbeBind, LocalProbeInit);
#ifdef PBI_DUCKDB_MAIN_SIGNATURES
  // Keep this order in sync with LocalProbeNamedParameterNames().
  function.GetSignature().WithTypedKwargs("options", [](TypedKwargs &kwargs) {
    kwargs.Add("package", LogicalType::VARCHAR);
    kwargs.Add("protection", LogicalType::VARCHAR);
    kwargs.Add("target_name", LogicalType::VARCHAR);
    kwargs.Add("dax_text", LogicalType::VARCHAR);
    kwargs.Add("timeout_ms", LogicalType::BIGINT);
  });
  function.GetSignature().GetParameter(0).SetName(
      Identifier("connection_string"));
#else
  function.named_parameters["package"] = LogicalType::VARCHAR;
  function.named_parameters["protection"] = LogicalType::VARCHAR;
  function.named_parameters["target_name"] = LogicalType::VARCHAR;
  function.named_parameters["dax_text"] = LogicalType::VARCHAR;
  function.named_parameters["timeout_ms"] = LogicalType::BIGINT;
#endif
  return function;
}

} // namespace duckdb
