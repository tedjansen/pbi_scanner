#pragma once

#include "http_client.hpp"
#include "xmla_tcp_client.hpp"
#include "xmla_transport.hpp"

#include "duckdb/common/types/value.hpp"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace duckdb {

enum class XmlaCoercionKind : uint8_t {
  INFER,
  VARCHAR,
  BOOLEAN,
  BIGINT,
  UBIGINT,
  DOUBLE,
  DATE,
  TIME,
  TIMESTAMP,
  TIMESTAMP_TZ
};

struct XmlaColumn {
  std::string name;
  std::string source_type;
  LogicalType duckdb_type;
  XmlaCoercionKind coercion_kind = XmlaCoercionKind::INFER;
  bool nullable = true;
  bool nullable_known = false;
};

struct XmlaRequest {
  std::string url;
  std::string catalog;
  std::string auth_scheme = "Bearer";
  std::string access_token;
  std::string xmla_server;
  std::string xmla_workspace_id;
  std::string statement;
  std::string effective_user_name;
  int64_t timeout_ms = 300000;
  //! Set for a local Analysis Services instance (Power BI Desktop): the
  //! request goes over the native TCP protocol instead of HTTP.
  std::string local_host;
  uint16_t local_port = 0;
  std::string local_protection = "privacy";

  bool IsLocal() const { return local_port != 0; }
};

struct XmlaParseTestResult {
  std::vector<XmlaColumn> columns;
  std::vector<std::vector<Value>> rows;
  std::string fault_message;
  bool stopped_early = false;
};

std::string BuildXmlaExecuteEnvelope(const std::string &catalog,
                                     const std::string &statement,
                                     const std::string &effective_user_name);
//! Same envelope for an explicit transport mode (ProtocolCapabilities header).
std::string BuildXmlaExecuteEnvelopeForMode(
    const std::string &catalog, const std::string &statement,
    const std::string &effective_user_name, XmlaTransportMode transport_mode);
XmlaParseTestResult
ParseXmlaChunksForTesting(const std::vector<std::string> &chunks,
                          bool stop_after_schema = false);
XmlaParseTestResult ParseBinXmlForTesting(const std::string &payload,
                                          bool stop_after_schema = false);
XmlaParseTestResult
ParseBinXmlWithColumnsForTesting(const std::string &payload,
                                 const std::vector<XmlaColumn> &columns);
XmlaParseTestResult ParseStreamingSxRowsForTesting(const std::string &payload,
                                                   idx_t chunk_size);
Value CoerceXmlValueForTesting(const std::string &raw_value,
                               XmlaCoercionKind coercion_kind);
std::string EffectiveExecutionTransportForTesting(const std::string &statement);

class XmlaExecutor {
public:
  explicit XmlaExecutor(int64_t timeout_ms);
  //! Reuses the same HTTP connection (keep-alive) across ProbeSchema + execute.
  XmlaExecutor(int64_t timeout_ms, std::shared_ptr<HttpClient> shared_http);
  //! Reuses the same authenticated local TCP connection across calls.
  XmlaExecutor(int64_t timeout_ms, std::shared_ptr<HttpClient> shared_http,
               std::shared_ptr<LocalXmlaTcpClient> shared_local);

  //! Local targets only: returns the CATALOG_NAME values from
  //! DBSCHEMA_CATALOGS (Power BI Desktop hosts exactly one).
  vector<string> DiscoverLocalCatalogs(const XmlaRequest &request);

  std::vector<XmlaColumn> ProbeSchema(const XmlaRequest &request);
  void ExecuteStreaming(
      const XmlaRequest &request, const std::vector<XmlaColumn> *known_columns,
      const std::function<void(const std::vector<XmlaColumn> &columns)>
          &on_schema,
      const std::function<bool(const std::vector<Value> &row)> &on_row,
      const std::function<bool()> &should_stop);
  void Stop();

private:
  HttpResponse
  PostXmla(const XmlaRequest &request, XmlaTransportMode transport_mode,
           const std::string &envelope,
           const std::function<bool(const_data_ptr_t, idx_t)> &receiver,
           bool disconnect_after_response);
  LocalXmlaTcpClient &EnsureLocalConnection(const XmlaRequest &request);

  int64_t timeout_ms;
  std::shared_ptr<HttpClient> http;
  std::shared_ptr<LocalXmlaTcpClient> local;
};

} // namespace duckdb
