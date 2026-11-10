#pragma once

#include "duckdb/function/table_function.hpp"

namespace duckdb {

//! Experimental spike diagnostics for local Power BI Desktop (Windows):
//! connects to localhost:<port> over the native Analysis Services TCP protocol
//! and reports every handshake step as a row.
TableFunction CreatePbiLocalProbeFunction();
//! Named parameters in catalog (signature) order.
vector<string> LocalProbeNamedParameterNames();

} // namespace duckdb
