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

//! Strips the " - Power BI Desktop" suffix from a PBIDesktop.exe window title.
//! Returns an empty string for titles without the suffix.
std::string ReportNameFromDesktopWindowTitle(const std::string &title);

std::string BuildLocalConnectionString(uint16_t port,
                                       const std::string &catalog);

} // namespace duckdb
