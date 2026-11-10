#include "xmla_tcp_client.hpp"

#include "xmla_tcp.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

#include <cstdio>
#include <atomic>
#include <cstdlib>
#include <functional>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <security.h>
#include <sspi.h>
#endif

namespace duckdb {

#ifdef _WIN32

namespace {

static bool LocalTraceToStderr() {
  auto *value = std::getenv("PBI_SCANNER_LOCAL_TRACE");
  return value && *value && std::string(value) != "0";
}

static std::wstring Widen(const std::string &value) {
  if (value.empty()) {
    return std::wstring();
  }
  auto length = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                    static_cast<int>(value.size()), nullptr, 0);
  std::wstring result(static_cast<size_t>(length), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      &result[0], length);
  return result;
}

static std::string Narrow(const wchar_t *value) {
  if (!value) {
    return std::string();
  }
  auto length =
      WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
  if (length <= 1) {
    return std::string();
  }
  std::string result(static_cast<size_t>(length - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value, -1, &result[0], length, nullptr,
                      nullptr);
  return result;
}

static std::string SecurityStatusText(SECURITY_STATUS status) {
  return StringUtil::Format("0x%08x", static_cast<unsigned int>(status));
}

static std::string ContextAttributesText(unsigned long attrs) {
  vector<string> names;
  if (attrs & ISC_RET_MUTUAL_AUTH) {
    names.emplace_back("MUTUAL_AUTH");
  }
  if (attrs & ISC_RET_REPLAY_DETECT) {
    names.emplace_back("REPLAY_DETECT");
  }
  if (attrs & ISC_RET_SEQUENCE_DETECT) {
    names.emplace_back("SEQUENCE_DETECT");
  }
  if (attrs & ISC_RET_CONFIDENTIALITY) {
    names.emplace_back("CONFIDENTIALITY");
  }
  if (attrs & ISC_RET_INTEGRITY) {
    names.emplace_back("INTEGRITY");
  }
  if (attrs & ISC_RET_CONNECTION) {
    names.emplace_back("CONNECTION");
  }
  return StringUtil::Format("0x%08lx", attrs) +
         (names.empty() ? std::string()
                        : " (" + StringUtil::Join(names, "|") + ")");
}

} // namespace

struct LocalXmlaTcpClient::Impl {
  int64_t timeout_ms = 0;
  LocalXmlaTrace trace;
  SOCKET socket_handle = INVALID_SOCKET;
  bool wsa_started = false;
  CredHandle credentials{};
  bool has_credentials = false;
  CtxtHandle context{};
  bool has_context = false;
  bool wrap_messages = false;
  bool encrypt_messages = false;
  SecPkgContext_Sizes sizes{};

  void Trace(const std::string &step, bool ok, const std::string &detail) {
    if (trace) {
      trace(step, ok, detail);
    }
    if (LocalTraceToStderr()) {
      std::fprintf(stderr, "[pbi_scanner local] %s %s: %s\n", step.c_str(),
                   ok ? "ok" : "FAILED", detail.c_str());
    }
  }

  void SendAll(const std::string &bytes) {
    idx_t offset = 0;
    while (offset < bytes.size()) {
      auto chunk =
          static_cast<int>(std::min<idx_t>(bytes.size() - offset, 1024 * 1024));
      auto sent = send(socket_handle, bytes.data() + offset, chunk, 0);
      if (sent == SOCKET_ERROR) {
        throw IOException("Local XMLA TCP send failed (WSA error %d)",
                          WSAGetLastError());
      }
      offset += static_cast<idx_t>(sent);
    }
  }

  std::string Wrap(const std::string &plain) {
    std::string out;
    static constexpr idx_t BLOCK = 32 * 1024;
    for (idx_t offset = 0; offset < plain.size() || offset == 0;
         offset += BLOCK) {
      auto data = plain.substr(offset, BLOCK);
      std::string token(encrypt_messages ? sizes.cbSecurityTrailer
                                         : sizes.cbMaxSignature,
                        '\0');
      std::string padding(encrypt_messages ? sizes.cbBlockSize : 0, '\0');
      SecBuffer buffers[3];
      buffers[0].BufferType = SECBUFFER_TOKEN;
      buffers[0].cbBuffer = static_cast<unsigned long>(token.size());
      buffers[0].pvBuffer = token.empty() ? nullptr : &token[0];
      buffers[1].BufferType = SECBUFFER_DATA;
      buffers[1].cbBuffer = static_cast<unsigned long>(data.size());
      buffers[1].pvBuffer = data.empty() ? nullptr : &data[0];
      buffers[2].BufferType = SECBUFFER_PADDING;
      buffers[2].cbBuffer = static_cast<unsigned long>(padding.size());
      buffers[2].pvBuffer = padding.empty() ? nullptr : &padding[0];
      SecBufferDesc desc;
      desc.ulVersion = SECBUFFER_VERSION;
      desc.cBuffers = encrypt_messages && !padding.empty() ? 3 : 2;
      desc.pBuffers = buffers;
      auto status = encrypt_messages ? EncryptMessage(&context, 0, &desc, 0)
                                     : MakeSignature(&context, 0, &desc, 0);
      if (status != SEC_E_OK) {
        throw IOException("SSPI %s failed with %s",
                          encrypt_messages ? "EncryptMessage" : "MakeSignature",
                          SecurityStatusText(status).c_str());
      }
      token.resize(buffers[0].cbBuffer);
      data.resize(buffers[1].cbBuffer);
      if (desc.cBuffers == 3) {
        data.append(padding.data(), buffers[2].cbBuffer);
      }
      out += EncodeGssWrapBlock(data, token);
      if (offset + BLOCK >= plain.size()) {
        break;
      }
    }
    return out;
  }

  std::string UnwrapBlock(const std::string &data_p,
                          const std::string &token_p) {
    auto data = data_p;
    auto token = token_p;
    SecBuffer buffers[2];
    buffers[0].BufferType = SECBUFFER_DATA;
    buffers[0].cbBuffer = static_cast<unsigned long>(data.size());
    buffers[0].pvBuffer = data.empty() ? nullptr : &data[0];
    buffers[1].BufferType = SECBUFFER_TOKEN;
    buffers[1].cbBuffer = static_cast<unsigned long>(token.size());
    buffers[1].pvBuffer = token.empty() ? nullptr : &token[0];
    SecBufferDesc desc;
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 2;
    desc.pBuffers = buffers;
    unsigned long qop = 0;
    auto status = encrypt_messages ? DecryptMessage(&context, &desc, 0, &qop)
                                   : VerifySignature(&context, &desc, 0, &qop);
    if (status != SEC_E_OK) {
      throw IOException("SSPI %s failed with %s",
                        encrypt_messages ? "DecryptMessage" : "VerifySignature",
                        SecurityStatusText(status).c_str());
    }
    return std::string(static_cast<const char *>(buffers[0].pvBuffer),
                       buffers[0].cbBuffer);
  }

  LocalXmlaResponse
  RoundTripStream(const std::string &envelope, uint8_t caps_flags,
                  bool allow_wrap,
                  const std::function<bool(const_data_ptr_t, idx_t)> &on_data,
                  bool &stopped_out) {
    stopped_out = false;
    if (socket_handle == INVALID_SOCKET) {
      throw IOException("Local XMLA TCP client is not connected");
    }
    auto wrap = allow_wrap && wrap_messages;
    auto payload = wrap ? Wrap(envelope) : envelope;
    auto message = EncodeDimeMessage("text/xml", caps_flags, payload);
    if (LocalTraceToStderr()) {
      std::fprintf(stderr, "[pbi_scanner local] send %llu bytes: %s\n",
                   static_cast<unsigned long long>(message.size()),
                   HexPreview(message, 96).c_str());
    }
    SendAll(message);

    LocalXmlaResponse response;
    FILE *dump = OpenDumpFile();
    std::string preview;
    XmlaTcpResponseReader reader(
        wrap ? XmlaTcpResponseReader::Unwrap(
                   [this](const std::string &data, const std::string &token) {
                     return UnwrapBlock(data, token);
                   })
             : XmlaTcpResponseReader::Unwrap(),
        [&](const_data_ptr_t data, idx_t size) {
          if (preview.size() < 96) {
            preview.append(reinterpret_cast<const char *>(data),
                           std::min<idx_t>(size, 96 - preview.size()));
          }
          if (dump) {
            std::fwrite(data, 1, size, dump);
          }
          return on_data ? on_data(data, size) : true;
        });
    char buffer[64 * 1024];
    try {
      while (!reader.MessageComplete() && !reader.Stopped()) {
        auto received = recv(socket_handle, buffer, sizeof(buffer), 0);
        if (received == 0) {
          throw IOException(
              "Local XMLA server closed the TCP connection after %llu bytes",
              static_cast<unsigned long long>(response.wire_bytes));
        }
        if (received == SOCKET_ERROR) {
          auto error = WSAGetLastError();
          if (error == WSAETIMEDOUT) {
            throw IOException("Local XMLA TCP receive timed out after %lld ms",
                              static_cast<long long>(timeout_ms));
          }
          if (error == WSAECONNRESET) {
            throw IOException(
                "Local XMLA server reset the TCP connection (WSA error %d). "
                "Power BI Desktop requires an encrypted (privacy) connection",
                error);
          }
          throw IOException("Local XMLA TCP receive failed (WSA error %d)",
                            error);
        }
        response.wire_bytes += static_cast<idx_t>(received);
        auto consumed = reader.Feed(const_data_ptr_cast(buffer),
                                    static_cast<idx_t>(received));
        if (reader.MessageComplete() &&
            consumed < static_cast<idx_t>(received)) {
          // A request/response protocol: nothing may follow the response.
          throw IOException(
              "Local XMLA server sent %llu unexpected bytes after the DIME "
              "response message",
              static_cast<unsigned long long>(received - consumed));
        }
      }
      if (!reader.Stopped()) {
        reader.Finish();
      }
    } catch (...) {
      if (dump) {
        std::fclose(dump);
      }
      throw;
    }
    if (dump) {
      std::fclose(dump);
    }
    stopped_out = reader.Stopped();
    response.content_type = reader.ContentType();
    response.caps_flags = reader.CapsFlags();
    response.has_caps_flags = reader.HasCapsFlags();
    response.dime_records = reader.RecordCount();
    if (LocalTraceToStderr()) {
      std::fprintf(stderr,
                   "[pbi_scanner local] recv type=%s caps=%s records=%llu "
                   "wire=%llu plain=%llu: %s\n",
                   response.content_type.c_str(),
                   DescribeXmlaTcpCapsFlags(response.caps_flags).c_str(),
                   static_cast<unsigned long long>(response.dime_records),
                   static_cast<unsigned long long>(response.wire_bytes),
                   static_cast<unsigned long long>(reader.PlainBytes()),
                   HexPreview(preview, 96).c_str());
    }
    return response;
  }

  LocalXmlaResponse RoundTrip(const std::string &envelope, uint8_t caps_flags,
                              bool allow_wrap) {
    std::string body;
    bool stopped = false;
    auto response = RoundTripStream(
        envelope, caps_flags, allow_wrap,
        [&](const_data_ptr_t data, idx_t size) {
          body.append(reinterpret_cast<const char *>(data), size);
          return true;
        },
        stopped);
    response.body = std::move(body);
    return response;
  }

  //! PBI_SCANNER_LOCAL_DUMP_DIR=<folder> writes every decrypted response body
  //! to <folder>/pbi_local_<n>.bin, for building offline test fixtures.
  FILE *OpenDumpFile() {
    auto *dir = std::getenv("PBI_SCANNER_LOCAL_DUMP_DIR");
    if (!dir || !*dir) {
      return nullptr;
    }
    static std::atomic<unsigned long long> counter{0};
    auto path = std::string(dir) + "\\pbi_local_" +
                std::to_string(GetCurrentProcessId()) + "_" +
                std::to_string(++counter) + ".bin";
    return std::fopen(path.c_str(), "wb");
  }

  void Close() {
    if (has_context) {
      DeleteSecurityContext(&context);
      has_context = false;
    }
    if (has_credentials) {
      FreeCredentialsHandle(&credentials);
      has_credentials = false;
    }
    if (socket_handle != INVALID_SOCKET) {
      closesocket(socket_handle);
      socket_handle = INVALID_SOCKET;
    }
    if (wsa_started) {
      WSACleanup();
      wsa_started = false;
    }
    wrap_messages = false;
    encrypt_messages = false;
  }
};

LocalXmlaTcpClient::LocalXmlaTcpClient(int64_t timeout_ms, LocalXmlaTrace trace)
    : impl(make_uniq<Impl>()) {
  impl->timeout_ms = timeout_ms > 0 ? timeout_ms : 300000;
  impl->trace = std::move(trace);
}

LocalXmlaTcpClient::~LocalXmlaTcpClient() {
  if (impl) {
    impl->Close();
  }
}

bool LocalXmlaTcpClient::IsSupported() { return true; }

void LocalXmlaTcpClient::Connect(const std::string &host, uint16_t port) {
  impl->Close();
  WSADATA wsa_data;
  auto wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
  if (wsa_result != 0) {
    throw IOException("WSAStartup failed (%d)", wsa_result);
  }
  impl->wsa_started = true;

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo *addresses = nullptr;
  auto port_text = std::to_string(port);
  auto gai = getaddrinfo(host.c_str(), port_text.c_str(), &hints, &addresses);
  if (gai != 0 || !addresses) {
    throw IOException("Could not resolve local XMLA host %s (%d)", host.c_str(),
                      gai);
  }
  int last_error = 0;
  for (auto *address = addresses; address; address = address->ai_next) {
    auto candidate =
        socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (candidate == INVALID_SOCKET) {
      last_error = WSAGetLastError();
      continue;
    }
    if (connect(candidate, address->ai_addr,
                static_cast<int>(address->ai_addrlen)) == 0) {
      impl->socket_handle = candidate;
      break;
    }
    last_error = WSAGetLastError();
    closesocket(candidate);
  }
  freeaddrinfo(addresses);
  if (impl->socket_handle == INVALID_SOCKET) {
    throw IOException("Could not connect to local Analysis Services at %s:%d "
                      "(WSA error %d). Is Power BI Desktop running with the "
                      "model open, and is the port current?",
                      host.c_str(), static_cast<int>(port), last_error);
  }
  DWORD timeout = static_cast<DWORD>(impl->timeout_ms);
  setsockopt(impl->socket_handle, SOL_SOCKET, SO_RCVTIMEO,
             reinterpret_cast<const char *>(&timeout), sizeof(timeout));
  setsockopt(impl->socket_handle, SOL_SOCKET, SO_SNDTIMEO,
             reinterpret_cast<const char *>(&timeout), sizeof(timeout));
  BOOL no_delay = TRUE;
  setsockopt(impl->socket_handle, IPPROTO_TCP, TCP_NODELAY,
             reinterpret_cast<const char *>(&no_delay), sizeof(no_delay));
  impl->Trace(
      "tcp_connect", true,
      StringUtil::Format("%s:%d", host.c_str(), static_cast<int>(port)));
}

void LocalXmlaTcpClient::Authenticate(const LocalXmlaAuthOptions &options) {
  auto protection = StringUtil::Lower(options.protection);
  unsigned long request_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION;
  if (protection == "integrity" || protection == "privacy") {
    request_flags |=
        ISC_REQ_INTEGRITY | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT;
  }
  if (protection == "privacy") {
    request_flags |= ISC_REQ_CONFIDENTIALITY;
  } else if (protection != "none" && protection != "integrity") {
    throw InvalidInputException(
        "protection must be none, integrity, or privacy");
  }

  auto package = Widen(options.package.empty() ? "Negotiate" : options.package);
  auto target = Widen(options.target_name);
  TimeStamp expiry;
  auto status = AcquireCredentialsHandleW(
      nullptr, &package[0], SECPKG_CRED_OUTBOUND, nullptr, nullptr, nullptr,
      nullptr, &impl->credentials, &expiry);
  if (status != SEC_E_OK) {
    throw IOException("SSPI AcquireCredentialsHandle(%s) failed with %s",
                      options.package.c_str(),
                      SecurityStatusText(status).c_str());
  }
  impl->has_credentials = true;

  std::string server_token;
  unsigned long context_attrs = 0;
  for (idx_t round = 1;; round++) {
    if (round > 16) {
      throw IOException("SSPI handshake did not complete after 16 rounds");
    }
    SecBuffer in_buffer;
    in_buffer.BufferType = SECBUFFER_TOKEN;
    in_buffer.cbBuffer = static_cast<unsigned long>(server_token.size());
    in_buffer.pvBuffer = server_token.empty() ? nullptr : &server_token[0];
    SecBufferDesc in_desc;
    in_desc.ulVersion = SECBUFFER_VERSION;
    in_desc.cBuffers = 1;
    in_desc.pBuffers = &in_buffer;
    SecBuffer out_buffer;
    out_buffer.BufferType = SECBUFFER_TOKEN;
    out_buffer.cbBuffer = 0;
    out_buffer.pvBuffer = nullptr;
    SecBufferDesc out_desc;
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = &out_buffer;

    status = InitializeSecurityContextW(
        &impl->credentials, impl->has_context ? &impl->context : nullptr,
        target.empty() ? nullptr : &target[0], request_flags, 0,
        SECURITY_NATIVE_DREP, impl->has_context ? &in_desc : nullptr, 0,
        &impl->context, &out_desc, &context_attrs, &expiry);
    if (status == SEC_I_COMPLETE_NEEDED ||
        status == SEC_I_COMPLETE_AND_CONTINUE) {
      CompleteAuthToken(&impl->context, &out_desc);
    }
    if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED &&
        status != SEC_I_COMPLETE_NEEDED &&
        status != SEC_I_COMPLETE_AND_CONTINUE) {
      if (out_buffer.pvBuffer) {
        FreeContextBuffer(out_buffer.pvBuffer);
      }
      impl->Trace("sspi_initialize", false, SecurityStatusText(status));
      throw IOException("SSPI InitializeSecurityContext failed with %s",
                        SecurityStatusText(status).c_str());
    }
    impl->has_context = true;
    std::string client_token;
    if (out_buffer.pvBuffer && out_buffer.cbBuffer > 0) {
      client_token.assign(static_cast<const char *>(out_buffer.pvBuffer),
                          out_buffer.cbBuffer);
    }
    if (out_buffer.pvBuffer) {
      FreeContextBuffer(out_buffer.pvBuffer);
    }
    auto done = status == SEC_E_OK || status == SEC_I_COMPLETE_NEEDED;
    if (client_token.empty()) {
      if (!done) {
        throw IOException("SSPI requested another round without a token");
      }
      impl->Trace(StringUtil::Format("sspi_round_%llu",
                                     static_cast<unsigned long long>(round)),
                  true, "complete without a final client token");
      break;
    }
    // [MS-SSAS] 3.2.3: the first request on a connection is text XML with
    // NEGO=0; the server does not keep negotiation state.
    auto response =
        impl->RoundTrip(BuildXmlaAuthenticateEnvelope(client_token), 0, false);
    try {
      server_token = ParseXmlaAuthenticateResponse(response.body);
    } catch (const Exception &) {
      impl->Trace(StringUtil::Format("sspi_round_%llu",
                                     static_cast<unsigned long long>(round)),
                  false,
                  StringUtil::Format(
                      "status=%s client_token=%llu bytes; response "
                      "type=%s body=%s",
                      SecurityStatusText(status).c_str(),
                      static_cast<unsigned long long>(client_token.size()),
                      response.content_type.c_str(),
                      response.body.substr(0, 400).c_str()));
      throw;
    }
    impl->Trace(StringUtil::Format("sspi_round_%llu",
                                   static_cast<unsigned long long>(round)),
                true,
                StringUtil::Format(
                    "status=%s client_token=%llu bytes server_token=%llu bytes "
                    "response_type=%s response_caps=%s",
                    SecurityStatusText(status).c_str(),
                    static_cast<unsigned long long>(client_token.size()),
                    static_cast<unsigned long long>(server_token.size()),
                    response.content_type.c_str(),
                    DescribeXmlaTcpCapsFlags(response.caps_flags).c_str()));
    if (done) {
      break;
    }
  }

  std::string package_name;
  SecPkgContext_PackageInfoW package_info{};
  if (QueryContextAttributesW(&impl->context, SECPKG_ATTR_PACKAGE_INFO,
                              &package_info) == SEC_E_OK &&
      package_info.PackageInfo) {
    package_name = Narrow(package_info.PackageInfo->Name);
    FreeContextBuffer(package_info.PackageInfo);
  }
  std::string user_name;
  SecPkgContext_NamesW names{};
  if (QueryContextAttributesW(&impl->context, SECPKG_ATTR_NAMES, &names) ==
          SEC_E_OK &&
      names.sUserName) {
    user_name = Narrow(names.sUserName);
    FreeContextBuffer(names.sUserName);
  }
  QueryContextAttributesW(&impl->context, SECPKG_ATTR_SIZES, &impl->sizes);
  impl->encrypt_messages = (context_attrs & ISC_RET_CONFIDENTIALITY) != 0;
  impl->wrap_messages =
      impl->encrypt_messages || (context_attrs & ISC_RET_INTEGRITY) != 0;
  impl->Trace(
      "sspi_context", true,
      StringUtil::Format(
          "package=%s user=%s attrs=%s wrap=%s encrypt=%s max_token=%lu "
          "max_signature=%lu trailer=%lu block=%lu",
          package_name.c_str(), user_name.c_str(),
          ContextAttributesText(context_attrs).c_str(),
          impl->wrap_messages ? "yes" : "no",
          impl->encrypt_messages ? "yes" : "no", impl->sizes.cbMaxToken,
          impl->sizes.cbMaxSignature, impl->sizes.cbSecurityTrailer,
          impl->sizes.cbBlockSize));
}

LocalXmlaResponse LocalXmlaTcpClient::RoundTrip(const std::string &envelope,
                                                uint8_t caps_flags) {
  if (impl->socket_handle == INVALID_SOCKET) {
    throw IOException("Local XMLA TCP client is not connected");
  }
  return impl->RoundTrip(envelope, caps_flags, true);
}

LocalXmlaResponse LocalXmlaTcpClient::RoundTripStream(
    const std::string &envelope, uint8_t caps_flags,
    const std::function<bool(const_data_ptr_t, idx_t)> &on_data,
    bool &stopped_out) {
  return impl->RoundTripStream(envelope, caps_flags, true, on_data,
                               stopped_out);
}

bool LocalXmlaTcpClient::IsConnected() const {
  return impl->socket_handle != INVALID_SOCKET && impl->has_context;
}

void LocalXmlaTcpClient::Abort() {
  auto handle = impl->socket_handle;
  if (handle != INVALID_SOCKET) {
    // Unblocks a recv() on the worker thread; Close() releases the socket.
    shutdown(handle, SD_BOTH);
  }
}

void LocalXmlaTcpClient::Close() { impl->Close(); }

#else // !_WIN32

static constexpr const char *LOCAL_XMLA_UNSUPPORTED_MESSAGE =
    "Local Power BI Desktop connections (Data Source=localhost:<port>) are "
    "only supported in native Windows builds of pbi_scanner";

struct LocalXmlaTcpClient::Impl {};

LocalXmlaTcpClient::LocalXmlaTcpClient(int64_t timeout_ms,
                                       LocalXmlaTrace trace) {
  (void)timeout_ms;
  (void)trace;
}

LocalXmlaTcpClient::~LocalXmlaTcpClient() = default;

bool LocalXmlaTcpClient::IsSupported() { return false; }

void LocalXmlaTcpClient::Connect(const std::string &host, uint16_t port) {
  (void)host;
  (void)port;
  throw InvalidInputException("%s", LOCAL_XMLA_UNSUPPORTED_MESSAGE);
}

void LocalXmlaTcpClient::Authenticate(const LocalXmlaAuthOptions &options) {
  (void)options;
  throw InvalidInputException("%s", LOCAL_XMLA_UNSUPPORTED_MESSAGE);
}

LocalXmlaResponse LocalXmlaTcpClient::RoundTrip(const std::string &envelope,
                                                uint8_t caps_flags) {
  (void)envelope;
  (void)caps_flags;
  throw InvalidInputException("%s", LOCAL_XMLA_UNSUPPORTED_MESSAGE);
}

LocalXmlaResponse LocalXmlaTcpClient::RoundTripStream(
    const std::string &envelope, uint8_t caps_flags,
    const std::function<bool(const_data_ptr_t, idx_t)> &on_data,
    bool &stopped_out) {
  (void)envelope;
  (void)caps_flags;
  (void)on_data;
  stopped_out = false;
  throw InvalidInputException("%s", LOCAL_XMLA_UNSUPPORTED_MESSAGE);
}

bool LocalXmlaTcpClient::IsConnected() const { return false; }

void LocalXmlaTcpClient::Abort() {}

void LocalXmlaTcpClient::Close() {}

#endif

} // namespace duckdb
