#include "local_instances.hpp"

#include "pbi_duckdb_compat.hpp"
#include "pbi_scanner_util.hpp"
#include "xmla_tcp.hpp"
#include "xmla_tcp_client.hpp"

#include "duckdb/common/error_data.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#endif

namespace duckdb {

static constexpr const char *DESKTOP_TITLE_SUFFIXES[] = {
    " - Power BI Desktop", " \xE2\x80\x93 Power BI Desktop"};

bool ParseMsmdsrvPortFile(const std::string &bytes, uint16_t &port_out) {
  std::string text;
  idx_t start = 0;
  bool utf16 = false;
  if (bytes.size() >= 2 && static_cast<uint8_t>(bytes[0]) == 0xFF &&
      static_cast<uint8_t>(bytes[1]) == 0xFE) {
    utf16 = true;
    start = 2;
  } else if (bytes.size() >= 2 && bytes[1] == '\0') {
    utf16 = true;
  } else if (bytes.size() >= 3 && static_cast<uint8_t>(bytes[0]) == 0xEF &&
             static_cast<uint8_t>(bytes[1]) == 0xBB &&
             static_cast<uint8_t>(bytes[2]) == 0xBF) {
    start = 3;
  }
  if (utf16) {
    for (idx_t i = start; i + 1 < bytes.size(); i += 2) {
      if (bytes[i + 1] != '\0') {
        return false;
      }
      text.push_back(bytes[i]);
    }
  } else {
    text = bytes.substr(start);
  }
  // Trailing NULs and whitespace are tolerated.
  while (!text.empty() &&
         (text.back() == '\0' || StringUtil::CharacterIsSpace(text.back()))) {
    text.pop_back();
  }
  text = Trimmed(text);
  if (text.empty() || text.size() > 5) {
    return false;
  }
  for (auto ch : text) {
    if (ch < '0' || ch > '9') {
      return false;
    }
  }
  auto value = std::strtoul(text.c_str(), nullptr, 10);
  if (value == 0 || value > 65535) {
    return false;
  }
  port_out = static_cast<uint16_t>(value);
  return true;
}

std::string ReportNameFromDesktopWindowTitle(const std::string &title) {
  auto trimmed = Trimmed(title);
  for (auto *suffix : DESKTOP_TITLE_SUFFIXES) {
    if (StringUtil::EndsWith(trimmed, suffix)) {
      return Trimmed(trimmed.substr(0, trimmed.size() - std::strlen(suffix)));
    }
  }
  return std::string();
}

std::string BuildLocalConnectionString(uint16_t port,
                                       const std::string &catalog) {
  auto result =
      StringUtil::Format("Data Source=localhost:%d;", static_cast<int>(port));
  if (!catalog.empty()) {
    result += "Initial Catalog=" + catalog + ";";
  }
  return result;
}

namespace {

struct LocalInstanceRow {
  int64_t pid = 0;
  int64_t desktop_pid = 0;
  uint16_t port = 0;
  std::string report_name;
  std::string window_title;
  std::string workspace_path;
  std::string catalog;
  std::string detail;
};

struct LocalInstancesBindData : public TableFunctionData {
  vector<LocalInstanceRow> rows;
};

struct LocalInstancesState : public GlobalTableFunctionState {
  idx_t offset = 0;
};

#ifdef _WIN32

static std::string NarrowWide(const std::wstring &value) {
  if (value.empty()) {
    return std::string();
  }
  auto length = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                    static_cast<int>(value.size()), nullptr, 0,
                                    nullptr, nullptr);
  std::string result(static_cast<size_t>(length), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      &result[0], length, nullptr, nullptr);
  return result;
}

struct ProcessInfo {
  std::wstring exe;
  DWORD parent = 0;
};

static std::map<DWORD, ProcessInfo> SnapshotProcesses() {
  std::map<DWORD, ProcessInfo> processes;
  auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    throw IOException("CreateToolhelp32Snapshot failed (%lu)", GetLastError());
  }
  PROCESSENTRY32W entry;
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      processes[entry.th32ProcessID] =
          ProcessInfo{entry.szExeFile, entry.th32ParentProcessID};
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return processes;
}

static bool IsExe(const std::wstring &exe, const wchar_t *name) {
  return _wcsicmp(exe.c_str(), name) == 0;
}

static std::vector<char> ReadTcpTable(ULONG family) {
  DWORD size = 0;
  std::vector<char> buffer;
  for (int attempt = 0; attempt < 5; attempt++) {
    auto result =
        GetExtendedTcpTable(buffer.empty() ? nullptr : buffer.data(), &size,
                            FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (result == NO_ERROR) {
      return buffer;
    }
    if (result != ERROR_INSUFFICIENT_BUFFER) {
      return std::vector<char>();
    }
    buffer.assign(size, '\0');
  }
  return std::vector<char>();
}

//! pid -> listening TCP ports (IPv4 and IPv6, de-duplicated).
static std::map<DWORD, std::set<uint16_t>> ListeningPortsByPid() {
  std::map<DWORD, std::set<uint16_t>> ports;
  auto v4 = ReadTcpTable(AF_INET);
  if (!v4.empty()) {
    auto table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(v4.data());
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
      ports[table->table[i].dwOwningPid].insert(
          ntohs(static_cast<u_short>(table->table[i].dwLocalPort)));
    }
  }
  auto v6 = ReadTcpTable(AF_INET6);
  if (!v6.empty()) {
    auto table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(v6.data());
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
      ports[table->table[i].dwOwningPid].insert(
          ntohs(static_cast<u_short>(table->table[i].dwLocalPort)));
    }
  }
  return ports;
}

struct WindowSearch {
  DWORD pid;
  std::string best_title;
};

static BOOL CALLBACK CollectDesktopWindowTitle(HWND window, LPARAM param) {
  auto &search = *reinterpret_cast<WindowSearch *>(param);
  DWORD window_pid = 0;
  GetWindowThreadProcessId(window, &window_pid);
  if (window_pid != search.pid || !IsWindowVisible(window) ||
      GetWindow(window, GW_OWNER) != nullptr) {
    return TRUE;
  }
  wchar_t title[1024];
  auto length = GetWindowTextW(window, title, 1024);
  if (length <= 0) {
    return TRUE;
  }
  auto text = NarrowWide(std::wstring(title, static_cast<size_t>(length)));
  if (!ReportNameFromDesktopWindowTitle(text).empty()) {
    search.best_title = text;
    return FALSE;
  }
  if (search.best_title.empty()) {
    search.best_title = text;
  }
  return TRUE;
}

static std::string DesktopWindowTitle(DWORD pid) {
  WindowSearch search{pid, std::string()};
  EnumWindows(CollectDesktopWindowTitle, reinterpret_cast<LPARAM>(&search));
  return search.best_title;
}

static std::wstring EnvW(const wchar_t *name) {
  wchar_t buffer[MAX_PATH * 2];
  auto length = GetEnvironmentVariableW(name, buffer, MAX_PATH * 2);
  if (length == 0 || length >= MAX_PATH * 2) {
    return std::wstring();
  }
  return std::wstring(buffer, length);
}

static bool ReadSmallFile(const std::wstring &path, std::string &out) {
  auto handle =
      CreateFileW(path.c_str(), GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return false;
  }
  char buffer[256];
  DWORD read = 0;
  auto ok = ReadFile(handle, buffer, sizeof(buffer), &read, nullptr);
  CloseHandle(handle);
  if (!ok) {
    return false;
  }
  out.assign(buffer, read);
  return true;
}

//! port -> workspace folder, read from Data/msmdsrv.port.txt under each
//! AnalysisServicesWorkspaces folder (regular and Microsoft Store installs).
static std::map<uint16_t, std::string> WorkspacesByPort() {
  std::map<uint16_t, std::string> result;
  std::vector<std::wstring> roots;
  auto local_app_data = EnvW(L"LOCALAPPDATA");
  if (!local_app_data.empty()) {
    roots.push_back(
        local_app_data +
        L"\\Microsoft\\Power BI Desktop\\AnalysisServicesWorkspaces");
  }
  auto user_profile = EnvW(L"USERPROFILE");
  if (!user_profile.empty()) {
    roots.push_back(user_profile + L"\\Microsoft\\Power BI Desktop Store "
                                   L"App\\AnalysisServicesWorkspaces");
  }
  for (auto &root : roots) {
    WIN32_FIND_DATAW find_data;
    auto find = FindFirstFileW((root + L"\\*").c_str(), &find_data);
    if (find == INVALID_HANDLE_VALUE) {
      continue;
    }
    do {
      if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
          wcscmp(find_data.cFileName, L".") == 0 ||
          wcscmp(find_data.cFileName, L"..") == 0) {
        continue;
      }
      auto workspace = root + L"\\" + find_data.cFileName;
      std::string bytes;
      uint16_t port = 0;
      if (ReadSmallFile(workspace + L"\\Data\\msmdsrv.port.txt", bytes) &&
          ParseMsmdsrvPortFile(bytes, port)) {
        result[port] = NarrowWide(workspace);
      }
    } while (FindNextFileW(find, &find_data));
    FindClose(find);
  }
  return result;
}

static vector<LocalInstanceRow> DiscoverLocalInstances() {
  vector<LocalInstanceRow> rows;
  auto processes = SnapshotProcesses();
  auto ports = ListeningPortsByPid();
  auto workspaces = WorkspacesByPort();
  for (auto &entry : processes) {
    if (!IsExe(entry.second.exe, L"msmdsrv.exe")) {
      continue;
    }
    LocalInstanceRow base;
    base.pid = entry.first;
    auto parent = processes.find(entry.second.parent);
    if (parent != processes.end() &&
        IsExe(parent->second.exe, L"PBIDesktop.exe")) {
      base.desktop_pid = parent->first;
      base.window_title = DesktopWindowTitle(parent->first);
      base.report_name = ReportNameFromDesktopWindowTitle(base.window_title);
    }
    auto pid_ports = ports.find(entry.first);
    if (pid_ports == ports.end() || pid_ports->second.empty()) {
      base.detail = "msmdsrv.exe has no listening TCP port (still starting?)";
      rows.push_back(base);
      continue;
    }
    for (auto port : pid_ports->second) {
      auto row = base;
      row.port = port;
      auto workspace = workspaces.find(port);
      if (workspace != workspaces.end()) {
        row.workspace_path = workspace->second;
      }
      rows.push_back(row);
    }
  }
  return rows;
}

static void DiscoverCatalog(LocalInstanceRow &row,
                            const LocalXmlaAuthOptions &auth,
                            int64_t timeout_ms) {
  try {
    LocalXmlaTcpClient client(timeout_ms, nullptr);
    client.Connect("localhost", row.port);
    client.Authenticate(auth);
    auto response = client.RoundTrip(BuildXmlaDiscoverCatalogsEnvelope(),
                                     XMLA_TCP_CAPS_NEGO);
    auto names = ParseXmlaCatalogNames(response.body);
    if (names.empty()) {
      row.detail = "DBSCHEMA_CATALOGS returned no catalogs";
    } else {
      row.catalog = names[0];
      if (names.size() > 1) {
        row.detail =
            StringUtil::Format("%llu catalogs; using the first: %s",
                               static_cast<unsigned long long>(names.size()),
                               StringUtil::Join(names, ", ").c_str());
      }
    }
  } catch (const std::exception &ex) {
    ErrorData error(ex);
    row.detail = "catalog discovery failed: " + error.RawMessage();
  }
}

#endif

#ifdef PBI_DUCKDB_MAIN_SIGNATURES
static void AddName(vector<Identifier> &names, const char *name) {
  names.emplace_back(name);
}
#else
static void AddName(vector<string> &names, const char *name) {
  names.emplace_back(name);
}
#endif

static Value OptionalText(const std::string &value) {
  return value.empty() ? Value(LogicalType::VARCHAR) : Value(value);
}

static unique_ptr<FunctionData>
LocalInstancesBind(ClientContext &, TableFunctionBindInput &input,
                   vector<LogicalType> &return_types,
#ifdef PBI_DUCKDB_MAIN_SIGNATURES
                   vector<Identifier> &names) {
#else
                   vector<string> &names) {
#endif
  auto named_parameters =
      pbi_compat::CopyBindNamedParameters(input.named_parameters);
  bool discover_catalog = true;
  int64_t timeout_ms = 10000;
  LocalXmlaAuthOptions auth;
  for (auto &entry : named_parameters) {
    auto key = StringUtil::Lower(entry.first);
    if (entry.second.IsNull()) {
      continue;
    }
    if (key == "discover_catalog") {
      discover_catalog = entry.second.GetValue<bool>();
    } else if (key == "timeout_ms") {
      timeout_ms = entry.second.GetValue<int64_t>();
      if (timeout_ms <= 0) {
        throw InvalidInputException("timeout_ms must be greater than zero");
      }
    } else if (key == "protection") {
      auth.protection = StringUtil::Lower(entry.second.GetValue<string>());
      if (auth.protection != "none" && auth.protection != "integrity" &&
          auth.protection != "privacy") {
        throw InvalidInputException(
            "protection must be none, integrity, or privacy");
      }
    }
  }

  auto result = make_uniq<LocalInstancesBindData>();
#ifdef _WIN32
  result->rows = DiscoverLocalInstances();
  if (discover_catalog) {
    for (auto &row : result->rows) {
      if (row.port != 0) {
        DiscoverCatalog(row, auth, timeout_ms);
      }
    }
  }
#else
  (void)discover_catalog;
  throw InvalidInputException(
      "pbi_local_instances is only supported in native Windows builds of "
      "pbi_scanner");
#endif

  return_types = {
      LogicalType::VARCHAR, LogicalType::INTEGER, LogicalType::VARCHAR,
      LogicalType::VARCHAR, LogicalType::BIGINT,  LogicalType::BIGINT,
      LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};
  AddName(names, "report_name");
  AddName(names, "port");
  AddName(names, "catalog");
  AddName(names, "connection_string");
  AddName(names, "msmdsrv_pid");
  AddName(names, "desktop_pid");
  AddName(names, "window_title");
  AddName(names, "workspace_path");
  AddName(names, "detail");
  return std::move(result);
}

static unique_ptr<GlobalTableFunctionState>
LocalInstancesInit(ClientContext &, TableFunctionInitInput &) {
  return make_uniq<LocalInstancesState>();
}

static void LocalInstancesExecute(ClientContext &, TableFunctionInput &input,
                                  DataChunk &output) {
  auto &bind_data = input.bind_data->Cast<LocalInstancesBindData>();
  auto &state = input.global_state->Cast<LocalInstancesState>();
  idx_t count = 0;
  while (state.offset < bind_data.rows.size() && count < STANDARD_VECTOR_SIZE) {
    auto &row = bind_data.rows[state.offset++];
    output.SetValue(0, count, OptionalText(row.report_name));
    output.SetValue(1, count,
                    row.port == 0 ? Value(LogicalType::INTEGER)
                                  : Value::INTEGER(row.port));
    output.SetValue(2, count, OptionalText(row.catalog));
    output.SetValue(3, count,
                    row.port == 0 ? Value(LogicalType::VARCHAR)
                                  : Value(BuildLocalConnectionString(
                                        row.port, row.catalog)));
    output.SetValue(4, count, Value::BIGINT(row.pid));
    output.SetValue(5, count,
                    row.desktop_pid == 0 ? Value(LogicalType::BIGINT)
                                         : Value::BIGINT(row.desktop_pid));
    output.SetValue(6, count, OptionalText(row.window_title));
    output.SetValue(7, count, OptionalText(row.workspace_path));
    output.SetValue(8, count, OptionalText(row.detail));
    count++;
  }
  output.SetCardinality(count);
}

} // namespace

vector<string> LocalInstancesNamedParameterNames() {
  return {"discover_catalog", "protection", "timeout_ms"};
}

TableFunction CreatePbiLocalInstancesFunction() {
  TableFunction function("pbi_local_instances", {}, LocalInstancesExecute,
                         LocalInstancesBind, LocalInstancesInit);
#ifdef PBI_DUCKDB_MAIN_SIGNATURES
  // Keep this order in sync with LocalInstancesNamedParameterNames().
  function.GetSignature().WithTypedKwargs("options", [](TypedKwargs &kwargs) {
    kwargs.Add("discover_catalog", LogicalType::BOOLEAN);
    kwargs.Add("protection", LogicalType::VARCHAR);
    kwargs.Add("timeout_ms", LogicalType::BIGINT);
  });
#else
  function.named_parameters["discover_catalog"] = LogicalType::BOOLEAN;
  function.named_parameters["protection"] = LogicalType::VARCHAR;
  function.named_parameters["timeout_ms"] = LogicalType::BIGINT;
#endif
  return function;
}

} // namespace duckdb
