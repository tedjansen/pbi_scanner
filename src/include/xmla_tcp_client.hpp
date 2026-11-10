#pragma once

#include "duckdb/common/types.hpp"
#include "duckdb/common/unique_ptr.hpp"

#include <cstdint>
#include <functional>
#include <string>

namespace duckdb {

//! SSPI settings for a local Analysis Services TCP connection.
struct LocalXmlaAuthOptions {
  //! SSPI package: Negotiate (default), NTLM or Kerberos.
  std::string package = "Negotiate";
  //! none, integrity (signed messages) or privacy (encrypted messages).
  //! Power BI Desktop resets the connection unless privacy is negotiated.
  std::string protection = "privacy";
  //! Optional SPN; empty lets SSPI pick (NTLM for loopback).
  std::string target_name;
};

struct LocalXmlaResponse {
  std::string content_type;
  uint8_t caps_flags = 0;
  bool has_caps_flags = false;
  std::string body;
  idx_t dime_records = 0;
  idx_t wire_bytes = 0;
};

using LocalXmlaTrace = std::function<void(const std::string &step, bool ok,
                                          const std::string &detail)>;

//! XMLA over the native Analysis Services TCP protocol ([MS-SSAS] 2.1.1,
//! 3.2): DIME framing, SSPI authentication through the XMLA Authenticate
//! method and optional GSS-API message protection. Windows only; on other
//! platforms Connect throws InvalidInputException.
class LocalXmlaTcpClient {
public:
  LocalXmlaTcpClient(int64_t timeout_ms, LocalXmlaTrace trace);
  ~LocalXmlaTcpClient();

  static bool IsSupported();

  void Connect(const std::string &host, uint16_t port);
  void Authenticate(const LocalXmlaAuthOptions &options);
  //! Sends one SOAP envelope as a text/xml DIME message with the given
  //! [MS-SSAS] 2.1.1 OPTIONS flags and returns the full response message.
  LocalXmlaResponse RoundTrip(const std::string &envelope, uint8_t caps_flags);
  //! Like RoundTrip, but streams the decrypted response body to on_data and
  //! leaves LocalXmlaResponse::body empty. When on_data returns false the
  //! read stops early, stopped_out is set and the connection must be closed.
  LocalXmlaResponse
  RoundTripStream(const std::string &envelope, uint8_t caps_flags,
                  const std::function<bool(const_data_ptr_t, idx_t)> &on_data,
                  bool &stopped_out);
  //! Connected and authenticated.
  bool IsConnected() const;
  //! Thread-safe interrupt of a blocked read (used for query cancellation).
  void Abort();
  void Close();

private:
  struct Impl;
  unique_ptr<Impl> impl;
};

} // namespace duckdb
