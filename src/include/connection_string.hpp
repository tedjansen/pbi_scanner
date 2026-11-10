#pragma once

#include <cstdint>
#include <string>

namespace duckdb {

struct PowerBIEndpoint {
  std::string raw;
  std::string host;
  std::string workspace_name;
};

struct PowerBIConnectionConfig {
  std::string raw;
  std::string data_source;
  std::string initial_catalog;
  bool is_direct_xmla = false;
  //! Data Source=localhost:<port>: a local Analysis Services instance such as
  //! Power BI Desktop, reached over the native TCP protocol (Windows only).
  bool is_local_instance = false;
  std::string local_host;
  uint16_t local_port = 0;
  std::string secret_name;
  std::string effective_user_name;
  int64_t timeout_ms = 0;
  bool has_timeout_ms = false;
  PowerBIEndpoint endpoint;
};

PowerBIEndpoint ParsePowerBIEndpoint(const std::string &raw);
PowerBIConnectionConfig ParsePowerBIConnectionString(const std::string &raw);

} // namespace duckdb
