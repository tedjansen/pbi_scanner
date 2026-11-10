#pragma once

#include "duckdb/function/table_function.hpp"

#include <cstdint>
#include <string>

namespace duckdb {

//! Windows only: lists running Power BI Desktop Analysis Services instances
//! (msmdsrv.exe) with port, report name, workspace folder and catalog.
TableFunction CreatePbiLocalInstancesFunction();
//! Named parameters in catalog (signature) order.
vector<string> LocalInstancesNamedParameterNames();

//! Parses msmdsrv.port.txt. Desktop writes it as UTF-16LE (optionally with a
//! BOM); UTF-8/ASCII content is accepted too. Returns false when the content is
//! not a port number between 1 and 65535.
bool ParseMsmdsrvPortFile(const std::string &bytes, uint16_t &port_out);

//! Report name from a PBIDesktop.exe window title: strips a
//! " - Power BI Desktop" suffix when present, otherwise returns the trimmed
//! title. Returns an empty string for an empty title or the bare product name.
bool DesktopWindowTitleHasSuffix(const std::string &title);

//! TCP table row filter for an Analysis Services listener: LISTEN, or (as
//! some Windows 11 builds report state 0) an unconnected socket on a loopback
//! or wildcard local address.
bool IsTcpListenerCandidate(uint32_t state, bool local_loopback_or_any,
                            bool remote_unspecified);
std::string ReportNameFromDesktopWindowTitle(const std::string &title);

std::string BuildLocalConnectionString(uint16_t port,
                                       const std::string &catalog);

} // namespace duckdb
