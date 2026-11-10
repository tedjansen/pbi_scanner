#include "xmla_tcp.hpp"

#include "pbi_scanner_util.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/blob.hpp"

#include <algorithm>
#include <cstdlib>

namespace duckdb {

namespace {

static idx_t DimePadding(idx_t length) { return (4 - (length % 4)) % 4; }

static void AppendBigEndian16(std::string &out, uint16_t value) {
  out.push_back(static_cast<char>((value >> 8) & 0xFF));
  out.push_back(static_cast<char>(value & 0xFF));
}

static void AppendBigEndian32(std::string &out, uint32_t value) {
  out.push_back(static_cast<char>((value >> 24) & 0xFF));
  out.push_back(static_cast<char>((value >> 16) & 0xFF));
  out.push_back(static_cast<char>((value >> 8) & 0xFF));
  out.push_back(static_cast<char>(value & 0xFF));
}

static void AppendLittleEndian16(std::string &out, uint16_t value) {
  out.push_back(static_cast<char>(value & 0xFF));
  out.push_back(static_cast<char>((value >> 8) & 0xFF));
}

static void AppendPadded(std::string &out, const std::string &field) {
  out += field;
  out.append(DimePadding(field.size()), '\0');
}

static void AppendDimeRecord(std::string &out, bool message_begin,
                             bool message_end, bool chunked,
                             uint8_t type_format, const std::string &options,
                             const std::string &type, const_data_ptr_t data,
                             idx_t data_length) {
  // [MS-SSAS] 2.1.1: VERSION (5) MB (1) ME (1) CF (1) | TYPE_T (4) RESERVED (4)
  // followed by OPTIONS_LENGTH, ID_LENGTH, TYPE_LENGTH (16 bits each) and
  // DATA_LENGTH (32 bits), all big-endian ([MS-SSAS] 2.1).
  uint8_t first = static_cast<uint8_t>(DIME_VERSION << 3);
  if (message_begin) {
    first |= 0x04;
  }
  if (message_end) {
    first |= 0x02;
  }
  if (chunked) {
    first |= 0x01;
  }
  out.push_back(static_cast<char>(first));
  out.push_back(static_cast<char>((type_format & 0x0F) << 4));
  AppendBigEndian16(out, static_cast<uint16_t>(options.size()));
  AppendBigEndian16(out, 0);
  AppendBigEndian16(out, static_cast<uint16_t>(type.size()));
  AppendBigEndian32(out, static_cast<uint32_t>(data_length));
  AppendPadded(out, options);
  AppendPadded(out, type);
  out.append(reinterpret_cast<const char *>(data), data_length);
  out.append(DimePadding(data_length), '\0');
}

static std::string ExtractFirstElementText(const std::string &xml,
                                           const std::string &local_name,
                                           idx_t start, idx_t &end_out) {
  // Matches <name>, <prefix:name> and tags with attributes. Analysis Services
  // responses are machine generated, so this narrow scan is sufficient for
  // the handful of fields the TCP handshake needs.
  idx_t pos = start;
  while (true) {
    pos = xml.find('<', pos);
    if (pos == std::string::npos) {
      end_out = std::string::npos;
      return std::string();
    }
    auto name_start = pos + 1;
    if (name_start >= xml.size() || xml[name_start] == '/' ||
        xml[name_start] == '?' || xml[name_start] == '!') {
      pos = name_start;
      continue;
    }
    auto name_end = xml.find_first_of(" \t\r\n/>", name_start);
    if (name_end == std::string::npos) {
      end_out = std::string::npos;
      return std::string();
    }
    auto qualified = xml.substr(name_start, name_end - name_start);
    auto colon = qualified.find(':');
    auto name =
        colon == std::string::npos ? qualified : qualified.substr(colon + 1);
    auto tag_close = xml.find('>', name_end);
    if (tag_close == std::string::npos) {
      end_out = std::string::npos;
      return std::string();
    }
    if (name != local_name) {
      pos = tag_close + 1;
      continue;
    }
    if (xml[tag_close - 1] == '/') {
      end_out = tag_close + 1;
      return std::string();
    }
    auto closing = "</" + qualified + ">";
    auto close_pos = xml.find(closing, tag_close + 1);
    if (close_pos == std::string::npos) {
      end_out = std::string::npos;
      return std::string();
    }
    end_out = close_pos + closing.size();
    return xml.substr(tag_close + 1, close_pos - tag_close - 1);
  }
}

static std::string UnescapeXmlText(const std::string &text) {
  std::string result;
  result.reserve(text.size());
  for (idx_t i = 0; i < text.size(); i++) {
    if (text[i] != '&') {
      result.push_back(text[i]);
      continue;
    }
    auto semi = text.find(';', i);
    if (semi == std::string::npos) {
      result.push_back(text[i]);
      continue;
    }
    auto entity = text.substr(i + 1, semi - i - 1);
    if (entity == "lt") {
      result.push_back('<');
    } else if (entity == "gt") {
      result.push_back('>');
    } else if (entity == "amp") {
      result.push_back('&');
    } else if (entity == "quot") {
      result.push_back('"');
    } else if (entity == "apos") {
      result.push_back('\'');
    } else {
      result += text.substr(i, semi - i + 1);
    }
    i = semi;
  }
  return result;
}

static void ThrowIfSoapFault(const std::string &xml, const char *context) {
  idx_t end = 0;
  auto fault = ExtractFirstElementText(xml, "Fault", 0, end);
  if (end == std::string::npos) {
    return;
  }
  idx_t ignored = 0;
  auto fault_string = Trimmed(UnescapeXmlText(
      ExtractFirstElementText(fault, "faultstring", 0, ignored)));
  // Analysis Services puts the user-facing text on <Error Description="...">.
  auto description_pos = fault.find("Description=\"");
  if (description_pos != std::string::npos) {
    auto value_start = description_pos + 13;
    auto value_end = fault.find('"', value_start);
    if (value_end != std::string::npos) {
      auto description =
          UnescapeXmlText(fault.substr(value_start, value_end - value_start));
      if (!description.empty()) {
        fault_string = fault_string.empty() ? description
                                            : fault_string + ": " + description;
      }
    }
  }
  if (fault_string.empty()) {
    fault_string = "unknown SOAP fault";
  }
  throw IOException("%s failed: %s", context, fault_string.c_str());
}

static bool ParsePort(const std::string &text, uint16_t &port_out) {
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

} // namespace

DimeRecordHeader DecodeDimeRecordHeader(const_data_ptr_t data) {
  DimeRecordHeader header;
  header.version = static_cast<uint8_t>(data[0] >> 3);
  header.message_begin = (data[0] & 0x04) != 0;
  header.message_end = (data[0] & 0x02) != 0;
  header.chunked = (data[0] & 0x01) != 0;
  header.type_format = static_cast<uint8_t>(data[1] >> 4);
  header.options_length = static_cast<uint16_t>((data[2] << 8) | data[3]);
  header.id_length = static_cast<uint16_t>((data[4] << 8) | data[5]);
  header.type_length = static_cast<uint16_t>((data[6] << 8) | data[7]);
  header.data_length = (static_cast<uint32_t>(data[8]) << 24) |
                       (static_cast<uint32_t>(data[9]) << 16) |
                       (static_cast<uint32_t>(data[10]) << 8) |
                       static_cast<uint32_t>(data[11]);
  return header;
}

std::string EncodeDimeMessage(const std::string &content_type,
                              uint8_t caps_flags, const std::string &payload,
                              idx_t max_record_data) {
  if (max_record_data == 0) {
    throw InvalidInputException("DIME record size must be greater than zero");
  }
  std::string options(4, '\0');
  options[0] = static_cast<char>(caps_flags);

  std::string out;
  out.reserve(payload.size() + 64);
  auto data = const_data_ptr_cast(payload.data());
  idx_t offset = 0;
  bool first = true;
  do {
    auto chunk = std::min<idx_t>(max_record_data, payload.size() - offset);
    auto last = offset + chunk >= payload.size();
    // TYPE_T is 1 (media type) on the first record and 0 (unchanged) on
    // continuation records ([MS-SSAS] 2.1.1).
    AppendDimeRecord(
        out, first, last, !last, first ? 1 : 0, first ? options : std::string(),
        first ? content_type : std::string(), data + offset, chunk);
    offset += chunk;
    first = false;
  } while (offset < payload.size());
  return out;
}

DimeMessageReader::DimeMessageReader(DataCallback on_data_p)
    : on_data(std::move(on_data_p)) {}

void DimeMessageReader::BeginRecord() {
  state = State::HEADER;
  pending.clear();
}

void DimeMessageReader::Advance() {
  // Moves to the next non-empty field after the current one completed.
  switch (state) {
  case State::HEADER:
    state = State::OPTIONS;
    field_remaining = header.options_length;
    break;
  case State::OPTIONS:
    if (record_count == 1 && field.size() >= 1) {
      caps_flags = static_cast<uint8_t>(field[0]);
      has_caps_flags = true;
    }
    state = State::ID;
    field_remaining = header.id_length;
    break;
  case State::ID:
    state = State::TYPE;
    field_remaining = header.type_length;
    break;
  case State::TYPE:
    if (!field.empty()) {
      content_type = field;
    }
    state = State::DATA;
    field_remaining = header.data_length;
    break;
  default:
    break;
  }
  field.clear();
}

idx_t DimeMessageReader::Feed(const_data_ptr_t data, idx_t size) {
  idx_t offset = 0;
  while (!message_complete && !stopped) {
    if (state == State::HEADER) {
      auto needed = DIME_HEADER_SIZE - pending.size();
      auto take = std::min<idx_t>(needed, size - offset);
      pending.append(reinterpret_cast<const char *>(data + offset), take);
      offset += take;
      if (pending.size() < DIME_HEADER_SIZE) {
        return offset;
      }
      header = DecodeDimeRecordHeader(const_data_ptr_cast(pending.data()));
      if (header.version != DIME_VERSION) {
        throw IOException("Unsupported DIME record version %d (expected %d)",
                          static_cast<int>(header.version),
                          static_cast<int>(DIME_VERSION));
      }
      if (record_count == 0 && !header.message_begin) {
        throw IOException("DIME message does not start with an MB record");
      }
      if (record_count > 0 && header.message_begin) {
        throw IOException("Unexpected DIME MB record inside a message");
      }
      record_count++;
      Advance();
      continue;
    }

    if (state == State::PADDING) {
      auto take = std::min<idx_t>(padding_remaining, size - offset);
      offset += take;
      padding_remaining -= take;
      if (padding_remaining > 0) {
        return offset;
      }
      state = after_padding;
      if (state == State::HEADER) {
        // DATA (and its padding) finished: the record is complete.
        if (header.message_end && !header.chunked) {
          message_complete = true;
          return offset;
        }
        BeginRecord();
      }
      continue;
    }

    if (field_remaining > 0 && offset >= size) {
      return offset;
    }
    auto take = std::min<idx_t>(field_remaining, size - offset);
    if (state == State::DATA) {
      if (take > 0) {
        data_bytes += take;
        if (on_data && !on_data(data + offset, take)) {
          stopped = true;
          return offset + take;
        }
      }
    } else {
      field.append(reinterpret_cast<const char *>(data + offset), take);
    }
    offset += take;
    field_remaining -= take;
    if (field_remaining > 0) {
      return offset;
    }

    idx_t field_length = 0;
    switch (state) {
    case State::OPTIONS:
      field_length = header.options_length;
      break;
    case State::ID:
      field_length = header.id_length;
      break;
    case State::TYPE:
      field_length = header.type_length;
      break;
    case State::DATA:
      field_length = header.data_length;
      break;
    default:
      break;
    }
    padding_remaining = DimePadding(field_length);
    if (state == State::DATA) {
      after_padding = State::HEADER;
    } else {
      Advance();
      after_padding = state;
    }
    state = State::PADDING;
  }
  return offset;
}

std::string EncodeGssWrapBlock(const std::string &data,
                               const std::string &token) {
  if (data.size() > 0xFFFF || token.size() > 0xFFFF) {
    throw InvalidInputException(
        "GSS-API wrap block exceeds the 16-bit size limit");
  }
  std::string out;
  out.reserve(4 + data.size() + token.size());
  AppendLittleEndian16(out, static_cast<uint16_t>(data.size()));
  AppendLittleEndian16(out, static_cast<uint16_t>(token.size()));
  out += data;
  out += token;
  return out;
}

GssWrapBlockReader::GssWrapBlockReader(BlockCallback on_block_p)
    : on_block(std::move(on_block_p)) {}

void GssWrapBlockReader::Feed(const_data_ptr_t data, idx_t size) {
  buffer.append(reinterpret_cast<const char *>(data), size);
  idx_t offset = 0;
  while (buffer.size() - offset >= 4) {
    auto bytes = const_data_ptr_cast(buffer.data()) + offset;
    idx_t data_size = bytes[0] | (static_cast<idx_t>(bytes[1]) << 8);
    idx_t token_size = bytes[2] | (static_cast<idx_t>(bytes[3]) << 8);
    if (buffer.size() - offset < 4 + data_size + token_size) {
      break;
    }
    on_block(buffer.substr(offset + 4, data_size),
             buffer.substr(offset + 4 + data_size, token_size));
    offset += 4 + data_size + token_size;
  }
  buffer.erase(0, offset);
}

void GssWrapBlockReader::Finish() const {
  if (!buffer.empty()) {
    throw IOException("Truncated GSS-API wrap block (%llu trailing bytes)",
                      static_cast<unsigned long long>(buffer.size()));
  }
}

std::string BuildXmlaAuthenticateEnvelope(const std::string &sspi_token) {
  std::string envelope =
      "<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"><Body>"
      "<Authenticate "
      "xmlns=\"http://schemas.microsoft.com/analysisservices/2003/ext\">"
      "<SspiHandshake>";
  envelope += Blob::ToBase64(
      string_t(sspi_token.data(), static_cast<uint32_t>(sspi_token.size())));
  envelope += "</SspiHandshake></Authenticate></Body></Envelope>";
  return envelope;
}

std::string ParseXmlaAuthenticateResponse(const std::string &xml) {
  ThrowIfSoapFault(xml, "XMLA Authenticate");
  idx_t end = 0;
  ExtractFirstElementText(xml, "AuthenticateResponse", 0, end);
  if (end == std::string::npos) {
    throw IOException("XMLA Authenticate response is missing "
                      "AuthenticateResponse");
  }
  auto token = Trimmed(ExtractFirstElementText(xml, "SspiHandshake", 0, end));
  if (end == std::string::npos) {
    throw IOException("XMLA Authenticate response is missing SspiHandshake");
  }
  if (token.empty()) {
    return std::string();
  }
  // Analysis Services wraps the base64 text in MIME-style lines (76
  // characters plus CR/LF); the decoder only accepts the bare alphabet.
  std::string compact;
  compact.reserve(token.size());
  for (auto ch : token) {
    if (!StringUtil::CharacterIsSpace(ch)) {
      compact.push_back(ch);
    }
  }
  try {
    return Blob::FromBase64(
        string_t(compact.data(), static_cast<uint32_t>(compact.size())));
  } catch (const std::exception &) {
    throw IOException("XMLA Authenticate response has an invalid base64 "
                      "SspiHandshake");
  }
}

std::string BuildXmlaDiscoverCatalogsEnvelope() {
  return "<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"><Body>"
         "<Discover xmlns=\"urn:schemas-microsoft-com:xml-analysis\">"
         "<RequestType>DBSCHEMA_CATALOGS</RequestType>"
         "<Restrictions><RestrictionList/></Restrictions>"
         "<Properties><PropertyList><Format>Tabular</Format></PropertyList>"
         "</Properties></Discover></Body></Envelope>";
}

vector<string> ParseXmlaCatalogNames(const std::string &xml) {
  ThrowIfSoapFault(xml, "XMLA Discover DBSCHEMA_CATALOGS");
  vector<string> names;
  idx_t pos = 0;
  while (pos != std::string::npos && pos < xml.size()) {
    idx_t end = 0;
    auto row = ExtractFirstElementText(xml, "row", pos, end);
    if (end == std::string::npos) {
      break;
    }
    idx_t ignored = 0;
    auto name = UnescapeXmlText(
        Trimmed(ExtractFirstElementText(row, "CATALOG_NAME", 0, ignored)));
    if (!name.empty()) {
      names.push_back(name);
    }
    pos = end;
  }
  return names;
}

bool TryParseLocalInstanceDataSource(const std::string &data_source,
                                     std::string &host_out,
                                     uint16_t &port_out) {
  auto value = Trimmed(data_source);
  if (value.find("://") != std::string::npos) {
    return false;
  }
  std::string host;
  std::string port_text;
  bool has_port = false;
  if (!value.empty() && value.front() == '[') {
    auto close = value.find(']');
    if (close == std::string::npos) {
      return false;
    }
    host = value.substr(1, close - 1);
    auto rest = value.substr(close + 1);
    if (!rest.empty()) {
      if (rest.front() != ':') {
        return false;
      }
      port_text = rest.substr(1);
      has_port = true;
    }
  } else if (StringUtil::StartsWith(value, "::1")) {
    host = "::1";
    auto rest = value.substr(3);
    if (!rest.empty()) {
      if (rest.front() != ':') {
        return false;
      }
      port_text = rest.substr(1);
      has_port = true;
    }
  } else {
    auto colon = value.rfind(':');
    host = colon == std::string::npos ? value : value.substr(0, colon);
    if (colon != std::string::npos) {
      port_text = value.substr(colon + 1);
      has_port = true;
    }
  }
  auto lower_host = StringUtil::Lower(Trimmed(host));
  if (lower_host != "localhost" && lower_host != "127.0.0.1" &&
      lower_host != "::1") {
    return false;
  }
  if (!has_port || !ParsePort(Trimmed(port_text), port_out)) {
    throw InvalidInputException(
        "Local Data Source must be localhost:<port> with a port between 1 and "
        "65535");
  }
  host_out = lower_host;
  return true;
}

std::string DescribeXmlaTcpCapsFlags(uint8_t flags) {
  std::string result = StringUtil::Format("0x%02x", static_cast<int>(flags));
  vector<string> names;
  if (flags & XMLA_TCP_CAPS_NEGO) {
    names.emplace_back("NEGO");
  }
  if (flags & XMLA_TCP_CAPS_REQ_SX) {
    names.emplace_back("REQ_SX");
  }
  if (flags & XMLA_TCP_CAPS_REQ_XPRESS) {
    names.emplace_back("REQ_XPRESS");
  }
  if (flags & XMLA_TCP_CAPS_RESP_SX) {
    names.emplace_back("RESP_SX");
  }
  if (flags & XMLA_TCP_CAPS_RESP_XPRESS) {
    names.emplace_back("RESP_XPRESS");
  }
  if (flags & 0xE0) {
    names.emplace_back("RESERVED");
  }
  if (!names.empty()) {
    result += " (" + StringUtil::Join(names, "|") + ")";
  }
  return result;
}

std::string HexPreview(const std::string &bytes, idx_t max_bytes) {
  static constexpr const char *HEX = "0123456789abcdef";
  std::string out;
  auto count = std::min<idx_t>(bytes.size(), max_bytes);
  out.reserve(count * 2 + 4);
  for (idx_t i = 0; i < count; i++) {
    auto byte = static_cast<uint8_t>(bytes[i]);
    out.push_back(HEX[byte >> 4]);
    out.push_back(HEX[byte & 0x0F]);
  }
  if (bytes.size() > count) {
    out += "...";
  }
  return out;
}

} // namespace duckdb
