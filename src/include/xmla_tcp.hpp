#pragma once

#include "duckdb/common/types.hpp"
#include "duckdb/common/unique_ptr.hpp"
#include "duckdb/common/vector.hpp"

#include <cstdint>
#include <functional>
#include <string>

namespace duckdb {

//! Wire format pieces for XMLA over native Analysis Services TCP, as specified
//! in [MS-SSAS] 2.1.1 (DIME records), 2.1.3 (GSS-API wrap blocks) and 3.1.4.1
//! (Authenticate). Everything here is platform independent so it can be
//! covered by offline tests; the socket and SSPI code lives in
//! xmla_tcp_windows.cpp.

//! [MS-SSAS] 2.1.1 OPTIONS flag bits (first OPTIONS byte, LSB first).
static constexpr uint8_t XMLA_TCP_CAPS_NEGO = 0x01;
static constexpr uint8_t XMLA_TCP_CAPS_REQ_SX = 0x02;
static constexpr uint8_t XMLA_TCP_CAPS_REQ_XPRESS = 0x04;
static constexpr uint8_t XMLA_TCP_CAPS_RESP_SX = 0x08;
static constexpr uint8_t XMLA_TCP_CAPS_RESP_XPRESS = 0x10;

static constexpr idx_t DIME_HEADER_SIZE = 12;
static constexpr uint8_t DIME_VERSION = 1;

struct DimeRecordHeader {
  uint8_t version = 0;
  bool message_begin = false;
  bool message_end = false;
  bool chunked = false;
  uint8_t type_format = 0;
  uint16_t options_length = 0;
  uint16_t id_length = 0;
  uint16_t type_length = 0;
  uint32_t data_length = 0;
};

//! Encodes one DIME message. The first record carries TYPE and the 4-byte
//! OPTIONS field with the content-type negotiation flags; payloads larger than
//! max_record_data are split into chunked records (CF=1) as allowed by
//! [MS-SSAS] 2.1.1.
std::string EncodeDimeMessage(const std::string &content_type,
                              uint8_t caps_flags, const std::string &payload,
                              idx_t max_record_data = 0x7FFFFFFF);

//! Incremental DIME message decoder. Feed raw socket bytes; record payload
//! bytes are forwarded to on_data as soon as they arrive.
class DimeMessageReader {
public:
  using DataCallback = std::function<bool(const_data_ptr_t, idx_t)>;

  explicit DimeMessageReader(DataCallback on_data);

  //! Returns the number of bytes consumed from data. Consumption stops at the
  //! end of the message (ME record fully read) or when on_data returns false.
  idx_t Feed(const_data_ptr_t data, idx_t size);
  bool MessageComplete() const { return message_complete; }
  bool Stopped() const { return stopped; }
  const std::string &ContentType() const { return content_type; }
  //! First OPTIONS byte from the first record (negotiated caps), or 0.
  uint8_t CapsFlags() const { return caps_flags; }
  bool HasCapsFlags() const { return has_caps_flags; }
  idx_t RecordCount() const { return record_count; }
  idx_t DataBytes() const { return data_bytes; }

private:
  enum class State : uint8_t { HEADER, OPTIONS, ID, TYPE, DATA, PADDING };

  void BeginRecord();
  void Advance();

  DataCallback on_data;
  State state = State::HEADER;
  std::string pending;
  DimeRecordHeader header;
  idx_t field_remaining = 0;
  idx_t padding_remaining = 0;
  State after_padding = State::HEADER;
  std::string field;
  std::string content_type;
  uint8_t caps_flags = 0;
  bool has_caps_flags = false;
  bool message_complete = false;
  bool stopped = false;
  idx_t record_count = 0;
  idx_t data_bytes = 0;
};

DimeRecordHeader DecodeDimeRecordHeader(const_data_ptr_t data);

//! [MS-SSAS] 2.1.3 encryption/hashing data block:
//! DATA_SIZE (16-bit LE), TOKEN_SIZE (16-bit LE), DATA, TOKEN.
std::string EncodeGssWrapBlock(const std::string &data,
                               const std::string &token);

class GssWrapBlockReader {
public:
  using BlockCallback =
      std::function<void(const std::string &data, const std::string &token)>;
  explicit GssWrapBlockReader(BlockCallback on_block);
  void Feed(const_data_ptr_t data, idx_t size);
  //! Throws IOException if a partial block is left over.
  void Finish() const;

private:
  BlockCallback on_block;
  std::string buffer;
};

//! Reads one response message from the socket byte stream: DIME records, and
//! when GSS-API protection is active ([MS-SSAS] 2.1.3) the wrap blocks inside
//! them. Plaintext is forwarded to on_plain as soon as each block (or record
//! chunk, when unprotected) is complete, so large results stream.
class XmlaTcpResponseReader {
public:
  using Unwrap = std::function<std::string(const std::string &data,
                                           const std::string &token)>;
  using DataCallback = std::function<bool(const_data_ptr_t, idx_t)>;

  //! unwrap may be empty for an unprotected connection.
  XmlaTcpResponseReader(Unwrap unwrap, DataCallback on_plain);

  //! Returns the number of bytes consumed; stops at the end of the message or
  //! when on_plain returns false.
  idx_t Feed(const_data_ptr_t data, idx_t size);
  //! Throws IOException when a protected message ends mid-block.
  void Finish() const;
  bool MessageComplete() const { return dime.MessageComplete(); }
  bool Stopped() const { return stopped; }
  const std::string &ContentType() const { return dime.ContentType(); }
  uint8_t CapsFlags() const { return dime.CapsFlags(); }
  bool HasCapsFlags() const { return dime.HasCapsFlags(); }
  idx_t RecordCount() const { return dime.RecordCount(); }
  idx_t PlainBytes() const { return plain_bytes; }

private:
  Unwrap unwrap;
  DataCallback on_plain;
  bool stopped = false;
  idx_t plain_bytes = 0;
  unique_ptr<GssWrapBlockReader> wrap_reader;
  DimeMessageReader dime;
};

//! [MS-SSAS] 2.1.1 OPTIONS flags for an XMLA transport mode: requests stay
//! text XML, responses use binary XML and/or compression as requested.
uint8_t XmlaTcpCapsForTransport(bool response_sx, bool response_xpress);

//! [MS-SSAS] 3.1.4.1.2.1 Authenticate request carrying a base64 SSPI token.
std::string BuildXmlaAuthenticateEnvelope(const std::string &sspi_token);
//! Extracts and base64-decodes the SspiHandshake from an AuthenticateResponse.
//! Throws IOException with the SOAP fault text when the server returned one.
std::string ParseXmlaAuthenticateResponse(const std::string &xml);

std::string BuildXmlaDiscoverCatalogsEnvelope();
//! Returns CATALOG_NAME values from a DBSCHEMA_CATALOGS text/xml response.
vector<string> ParseXmlaCatalogNames(const std::string &xml);

//! Recognizes a local Analysis Services instance data source:
//! "localhost:<port>", "127.0.0.1:<port>", "[::1]:<port>" or "::1:<port>", with
//! no URL scheme. Returns false for anything else (including powerbi:// and
//! http(s)://). Throws InvalidInputException for a loopback host with a missing
//! or invalid port.
bool TryParseLocalInstanceDataSource(const std::string &data_source,
                                     std::string &host_out, uint16_t &port_out);

std::string DescribeXmlaTcpCapsFlags(uint8_t flags);
std::string HexPreview(const std::string &bytes, idx_t max_bytes);

} // namespace duckdb
