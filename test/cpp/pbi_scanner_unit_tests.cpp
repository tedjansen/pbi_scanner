#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "auth.hpp"
#include "connection_string.hpp"
#include "pbi_platform.hpp"
#include "dax_column_names.hpp"
#include "dax_probe.hpp"
#include "local_instances.hpp"
#include "metadata_cache.hpp"
#include "pbi_scanner_util.hpp"
#include "xmla.hpp"
#include "xmla_tcp.hpp"
#include "xmla_tcp_client.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension_helper.hpp"

#include <algorithm>
#include <string>

using namespace duckdb;

namespace {

// MS-BINXML SQL-MONEY (token 0x05) — SSAS / sx can emit scalar typed values
// from the BINXML grammar, not only the compact tokens observed in early tests.
constexpr const char *kBinXmlLegacyRate112_5 =
    "0f01010001ff0000000000040072006f006f00740000000201b40000000000060073006300"
    "680065006d006100000002419b00000000000b0063006f006d0070006c0065007800540079"
    "007000650000001900000006000004006e0061006d00650000000501030072006f00770002"
    "415b0000000000070065006c0065006d0065006e00740000004200000046000004006e0061"
    "006d006500000005010400520061007400650006000004007400790070006500000005010a"
    "007800730064003a0064006f00750062006c00650003040401310000000000030072006f00"
    "7700000002011e000000000004005200610074006500000002050105003100310032002e00"
    "350004040400";
constexpr const char *kBinXmlCompactRate112_5 =
    "dfff01b004f00472006f006f007400ef000001f801f00372006f007700ef000002f802f004"
    "5200610074006500ef000003f803040000000000205c40f7f7f7";
constexpr const char *kBinXmlSqlMoneyRate112_5 =
    "dfff01b004f00472006f006f007400ef000001f801f00372006f007700ef000002f802f004"
    "5200610074006500ef000003f80305882a110000000000f7f7f7";
constexpr const char *kBinXmlShortFirstText =
    "dfff01b004f00472006f006f007400ef000001f801f00372006f007700ef000002f802f004"
    "5200610074006500ef000003f80386f7f7f7";

static std::string DecodeHex(const std::string &hex) {
  if (hex.size() % 2 != 0) {
    throw InvalidInputException(
        "hex input must contain an even number of digits");
  }
  std::string result;
  result.reserve(hex.size() / 2);
  for (idx_t i = 0; i < hex.size(); i += 2) {
    auto high =
        DecodeHexDigit(hex[i], "hex input contained a non-hex character");
    auto low =
        DecodeHexDigit(hex[i + 1], "hex input contained a non-hex character");
    result.push_back(static_cast<char>((high << 4) | low));
  }
  return result;
}

static XmlaCoercionKind ParseCoercionKind(const string &kind_name) {
  auto normalized = StringUtil::Upper(Trimmed(kind_name));
  if (normalized == "INFER") {
    return XmlaCoercionKind::INFER;
  }
  if (normalized == "VARCHAR") {
    return XmlaCoercionKind::VARCHAR;
  }
  if (normalized == "BOOLEAN") {
    return XmlaCoercionKind::BOOLEAN;
  }
  if (normalized == "BIGINT") {
    return XmlaCoercionKind::BIGINT;
  }
  if (normalized == "UBIGINT") {
    return XmlaCoercionKind::UBIGINT;
  }
  if (normalized == "DOUBLE") {
    return XmlaCoercionKind::DOUBLE;
  }
  if (normalized == "DATE") {
    return XmlaCoercionKind::DATE;
  }
  if (normalized == "TIME") {
    return XmlaCoercionKind::TIME;
  }
  if (normalized == "TIMESTAMP") {
    return XmlaCoercionKind::TIMESTAMP;
  }
  if (normalized == "TIMESTAMP_TZ") {
    return XmlaCoercionKind::TIMESTAMP_TZ;
  }
  throw InvalidInputException("unknown XMLA coercion kind: " + kind_name);
}

static double RequireSingleDouble(const XmlaParseTestResult &parsed) {
  REQUIRE(parsed.fault_message.empty());
  REQUIRE(parsed.rows.size() == 1);
  REQUIRE(parsed.rows[0].size() == 1);
  return parsed.rows[0][0].GetValueUnsafe<double>();
}

static Value RequireSingleValue(const XmlaParseTestResult &parsed) {
  REQUIRE(parsed.fault_message.empty());
  REQUIRE(parsed.rows.size() == 1);
  REQUIRE(parsed.rows[0].size() == 1);
  return parsed.rows[0][0];
}

static std::string CoerceXmlTypeString(const std::string &raw_value,
                                       const std::string &kind_name) {
  auto kind = ParseCoercionKind(kind_name);
  auto value = CoerceXmlValueForTesting(raw_value, kind);
  return value.type().ToString();
}

static std::string CoerceXmlTextString(const std::string &raw_value,
                                       const std::string &kind_name) {
  auto kind = ParseCoercionKind(kind_name);
  auto value = CoerceXmlValueForTesting(raw_value, kind);
  if (value.IsNull()) {
    return "<NULL>";
  }
  return value.ToString();
}

static std::string JoinPipeDelimited(const std::vector<string> &values) {
  string joined;
  for (idx_t i = 0; i < values.size(); i++) {
    if (i > 0) {
      joined.push_back('|');
    }
    joined += values[i];
  }
  return joined;
}

static std::vector<string> SplitPipeDelimited(const string &input) {
  std::vector<string> values;
  idx_t start = 0;
  for (idx_t i = 0; i <= input.size(); i++) {
    if (i == input.size() || input[i] == '|') {
      values.push_back(input.substr(start, i - start));
      start = i + 1;
    }
  }
  return values;
}

} // namespace

TEST_CASE("XMLA chunked parse", "[xmla][smoke]") {
  auto parsed = ParseXmlaChunksForTesting(
      {"<?xml version=\"1.0\" encoding=\"utf-8\"?><root><schema "
       "xmlns:xsd=\"http://www.w3.org/2001/"
       "XMLSchema\"><xsd:schema><xsd:complexType "
       "name=\"row\"><xsd:sequence><xsd:element name=\"Rate\" "
       "type=\"xsd:double\" "
       "/></xsd:sequence></xsd:complexType></xsd:schema></"
       "schema><row><Rate>1.125E2</Ra",
       "te></row></root>"});
  REQUIRE(RequireSingleDouble(parsed) == Approx(112.5));
}

TEST_CASE("BINXML double parse", "[xmla]") {
  REQUIRE(RequireSingleDouble(ParseBinXmlForTesting(
              DecodeHex(kBinXmlLegacyRate112_5))) == Approx(112.5));
  REQUIRE(RequireSingleDouble(ParseBinXmlForTesting(
              DecodeHex(kBinXmlCompactRate112_5))) == Approx(112.5));
  REQUIRE(RequireSingleDouble(ParseBinXmlForTesting(
              DecodeHex(kBinXmlSqlMoneyRate112_5))) == Approx(112.5));
}

TEST_CASE("BINXML first text", "[xmla]") {
  auto short_text = RequireSingleValue(
      ParseBinXmlForTesting(DecodeHex(kBinXmlShortFirstText)));
  REQUIRE(short_text.ToString().size() == 4);

  auto money_text = RequireSingleValue(
      ParseBinXmlForTesting(DecodeHex(kBinXmlSqlMoneyRate112_5)));
  REQUIRE(money_text.ToString() == "112.5");
}

TEST_CASE("Streaming SX double parse", "[xmla]") {
  auto decoded = DecodeHex(kBinXmlCompactRate112_5);
  auto decoded_money = DecodeHex(kBinXmlSqlMoneyRate112_5);

  REQUIRE(RequireSingleDouble(ParseStreamingSxRowsForTesting(decoded, 1)) ==
          Approx(112.5));
  REQUIRE(RequireSingleDouble(ParseStreamingSxRowsForTesting(decoded, 7)) ==
          Approx(112.5));
  REQUIRE(RequireSingleDouble(ParseStreamingSxRowsForTesting(
              decoded_money, 3)) == Approx(112.5));
}

TEST_CASE("Metadata cache roundtrip", "[metadata_cache]") {
  REQUIRE(TestMetadataCacheRoundTrip());
}

TEST_CASE("DAX schema probe", "[dax_probe]") {
  REQUIRE(BuildDaxSchemaProbeForTesting("EVALUATE 'Fact Allocation'", 100) ==
          "EVALUATE TOPN(100, 'Fact Allocation')");
  REQUIRE(BuildDaxSchemaProbeForTesting("EVALUATE ROW(\"x\", 1) ORDER BY [x]",
                                        10) ==
          "EVALUATE TOPN(10, ROW(\"x\", 1))");

  auto summarizing = StringUtil::Replace(
      BuildDaxSchemaProbeForTesting(
          "DEFINE MEASURE T[m] = 1 EVALUATE SUMMARIZECOLUMNS(T[c], \"m\", [m])",
          5),
      "\n", "|");
  REQUIRE(summarizing == "DEFINE MEASURE T[m] = 1 |EVALUATE TOPN(5, "
                         "SUMMARIZECOLUMNS(T[c], \"m\", [m]))");

  REQUIRE(BuildDaxSchemaProbeForTesting(
              "EVALUATE ROW(\"text\", \"ORDER BY ignored\")", 3) ==
          "EVALUATE TOPN(3, ROW(\"text\", \"ORDER BY ignored\"))");
  REQUIRE(BuildDaxSchemaProbeForTesting(
              "EVALUATE VAR X = ROW(\"x\", 1) RETURN X", 100) ==
          "EVALUATE VAR X = ROW(\"x\", 1) RETURN X");
  REQUIRE(BuildDaxSchemaProbeForTesting("EVALUATE ROW(\"x\", 1)", 0) ==
          "EVALUATE ROW(\"x\", 1)");
}

TEST_CASE("Service principal error messages", "[auth]") {
  REQUIRE(TestServicePrincipalAuthErrorMessage("request_error") ==
          "service principal token request failed: simulated_request_error");
  REQUIRE(TestServicePrincipalAuthErrorMessage("http_error") ==
          "service principal token request http 401: denied");
  REQUIRE(TestServicePrincipalAuthErrorMessage("invalid_json") ==
          "service principal token response was not valid JSON");
  REQUIRE(TestServicePrincipalAuthErrorMessage("missing_access_token") ==
          "service principal token response did not include access_token");
}

TEST_CASE("XML coercion type", "[xmla]") {
  REQUIRE(CoerceXmlTypeString("1899-12-30T12:34:56", "TIMESTAMP") ==
          "TIMESTAMP");
  REQUIRE(CoerceXmlTypeString("1899-12-30T12:34:56+00:00", "TIMESTAMP_TZ") ==
          "TIMESTAMP WITH TIME ZONE");
  REQUIRE(CoerceXmlTypeString("1899-12-30T12:34:56", "TIME") == "TIME");
  REQUIRE(CoerceXmlTypeString("9223372036854775807", "BIGINT") == "BIGINT");
  REQUIRE(CoerceXmlTypeString("1234.5678", "DOUBLE") == "DOUBLE");
  REQUIRE(CoerceXmlTypeString("true", "BOOLEAN") == "BOOLEAN");
  REQUIRE(CoerceXmlTypeString("1f66ff01-d600-48d3-a967-28a87af540cf",
                              "INFER") == "VARCHAR");
}

TEST_CASE("XML coercion text", "[xmla]") {
  REQUIRE(CoerceXmlTextString("", "VARCHAR").size() == 0);
  REQUIRE(CoerceXmlTextString("", "INFER") == "<NULL>");
  REQUIRE(CoerceXmlTextString("1", "DATE") == "1899-12-31");
  REQUIRE(CoerceXmlTextString("0.5", "TIME") == "12:00:00");
  REQUIRE(CoerceXmlTextString("2.5", "TIMESTAMP") == "1900-01-01 12:00:00");
  REQUIRE(CoerceXmlTextString("0", "DATE") == "1899-12-30");
  REQUIRE(CoerceXmlTextString("-1", "DATE") == "1899-12-29");
  REQUIRE(CoerceXmlTextString("0.9999999", "TIME") == "23:59:59.99136");
  REQUIRE(CoerceXmlTextString("45292.25", "TIMESTAMP") ==
          "2024-01-01 06:00:00");
  REQUIRE(CoerceXmlTextString("not-a-timestamp", "INFER") == "not-a-timestamp");
}

TEST_CASE("Effective execution transport", "[xmla]") {
  REQUIRE(EffectiveExecutionTransportForTesting(
              "EVALUATE INFO.VIEW.TABLES()") == "sx_xpress");
}

TEST_CASE("DAX column name normalization", "[dax_column_names]") {
  REQUIRE(FormatDaxColumnNameForDuckDB("[x]", true) == "x");
  REQUIRE(FormatDaxColumnNameForDuckDB("[Total Sales]", true) == "Total Sales");
  REQUIRE(FormatDaxColumnNameForDuckDB("Fact[Amount]", true) == "Amount");
  REQUIRE(FormatDaxColumnNameForDuckDB("[Total Sales]", false) ==
          "[Total Sales]");
  REQUIRE(FormatDaxColumnNameForDuckDB("Rate", true) == "Rate");

  REQUIRE(JoinPipeDelimited(FormatDaxColumnNamesForDuckDB(
              SplitPipeDelimited("TableA[Amount]|TableB[Amount]"), true)) ==
          "TableA_Amount|TableB_Amount");
  REQUIRE(JoinPipeDelimited(FormatDaxColumnNamesForDuckDB(
              SplitPipeDelimited("TableA[Amount]|[Amount]|TableB[Amount]"),
              true)) == "TableA_Amount|Amount|TableB_Amount");
  REQUIRE(JoinPipeDelimited(FormatDaxColumnNamesForDuckDB(
              SplitPipeDelimited("[Amount]|[Amount]"), true)) ==
          "Amount|Amount_2");
  REQUIRE(JoinPipeDelimited(FormatDaxColumnNamesForDuckDB(
              SplitPipeDelimited("TableA[Amount]|TableA[Amount]"), true)) ==
          "TableA_Amount|TableA_Amount_2");
  REQUIRE(
      JoinPipeDelimited(FormatDaxColumnNamesForDuckDB(
          SplitPipeDelimited("TableA[Amount]|TableB[Amount]|[TableA_Amount]"),
          true)) == "TableA_Amount|TableB_Amount|TableA_Amount_2");
  REQUIRE(JoinPipeDelimited(FormatDaxColumnNamesForDuckDB(
              SplitPipeDelimited("[Amount]|[Amount]|[Amount]"), true)) ==
          "Amount|Amount_2|Amount_3");
}

TEST_CASE("Native platform capabilities", "[pbi_platform]") {
  REQUIRE(PbiSupportsNativeAuth());
  REQUIRE(PbiSupportsFilesystemMetadataCache());
  REQUIRE(PbiSupportsBackgroundThreads());
  REQUIRE(PbiSupportsSxStreamingExecution());
  REQUIRE(!PbiIsBrowserPlatform());
  REQUIRE_NOTHROW(RejectUnsupportedBrowserAuthForTesting(
      "azure_cli auth is not supported in DuckDB-Wasm"));
}

TEST_CASE("Parse direct XMLA connection strings", "[connection_string]") {
  auto https_direct = ParsePowerBIConnectionString(
      "Data "
      "Source=https://example.com/xmla?vs=sobe_wowvirtualserver&db=example_db;"
      "Initial Catalog=example_db;");
  REQUIRE(https_direct.is_direct_xmla);
  REQUIRE(https_direct.data_source.find("https://") == 0);

  auto loopback_http = ParsePowerBIConnectionString(
      "Data Source=http://127.0.0.1:8123/xmla;Initial Catalog=mock;");
  REQUIRE(loopback_http.is_direct_xmla);

  auto loopback_localhost = ParsePowerBIConnectionString(
      "Data Source=http://localhost/xmla;Initial Catalog=mock;");
  REQUIRE(loopback_localhost.is_direct_xmla);

  REQUIRE_THROWS_WITH(
      ParsePowerBIConnectionString(
          "Data Source=https://example.com/xmla;Initial Catalog=example_db;"),
      Catch::Matchers::Contains("powerbi://"));

  REQUIRE_THROWS_WITH(
      ParsePowerBIConnectionString(
          "Data Source=http://evil.example/xmla;Initial Catalog=mock;"),
      Catch::Matchers::Contains("powerbi://"));

  auto powerbi = ParsePowerBIConnectionString(
      "Data Source=powerbi://api.powerbi.com/v1.0/myorg/Example%20Workspace;"
      "Initial Catalog=example_semantic_model;");
  REQUIRE(!powerbi.is_direct_xmla);
  REQUIRE(powerbi.endpoint.workspace_name == "Example Workspace");
}

TEST_CASE("Resolve normalize dax column names setting", "[dax_column_names]") {
  DuckDB db(nullptr);
  ExtensionHelper::LoadExtension(db, "pbi_scanner");
  Connection con(db);
  auto &context = *con.context;

  named_parameter_map_t empty;
  REQUIRE(!ResolveNormalizeDaxColumnNames(context, empty));

  auto set_on_result = con.Query("SET normalize_dax_column_names = true");
  REQUIRE(!set_on_result->HasError());
  REQUIRE(ResolveNormalizeDaxColumnNames(context, empty));

  auto set_off_result = con.Query("SET normalize_dax_column_names = false");
  REQUIRE(!set_off_result->HasError());
  REQUIRE(!ResolveNormalizeDaxColumnNames(context, empty));

  named_parameter_map_t override_on;
  override_on["normalize_dax_column_names"] = Value::BOOLEAN(true);
  REQUIRE(ResolveNormalizeDaxColumnNames(context, override_on));

  named_parameter_map_t override_off;
  override_off["normalize_dax_column_names"] = Value::BOOLEAN(false);
  REQUIRE(!ResolveNormalizeDaxColumnNames(context, override_off));
}

namespace {

std::string DecodeHexForTcpTests(const std::string &hex) {
  std::string out;
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(
        static_cast<char>(std::strtoul(hex.substr(i, 2).c_str(), nullptr, 16)));
  }
  return out;
}

struct DecodedDimeMessage {
  std::string data;
  std::string content_type;
  uint8_t caps = 0;
  idx_t records = 0;
  idx_t consumed = 0;
};

DecodedDimeMessage DecodeDimeInSlices(const std::string &wire, idx_t slice) {
  DecodedDimeMessage result;
  DimeMessageReader reader([&](const_data_ptr_t data, idx_t size) {
    result.data.append(reinterpret_cast<const char *>(data), size);
    return true;
  });
  for (idx_t offset = 0; offset < wire.size() && !reader.MessageComplete();
       offset += slice) {
    auto size = std::min<idx_t>(slice, wire.size() - offset);
    result.consumed +=
        reader.Feed(const_data_ptr_cast(wire.data()) + offset, size);
  }
  REQUIRE(reader.MessageComplete());
  result.content_type = reader.ContentType();
  result.caps = reader.CapsFlags();
  result.records = reader.RecordCount();
  return result;
}

} // namespace

TEST_CASE("Encode DIME records per MS-SSAS 2.1.1", "[xmla_tcp]") {
  auto wire = EncodeDimeMessage("text/xml",
                                XMLA_TCP_CAPS_NEGO | XMLA_TCP_CAPS_RESP_SX |
                                    XMLA_TCP_CAPS_RESP_XPRESS,
                                "abc");
  // VERSION=1 MB ME | TYPE_T=1, OPTIONS_LENGTH=4, ID_LENGTH=0, TYPE_LENGTH=8,
  // DATA_LENGTH=3, OPTIONS, TYPE, DATA + 1 padding byte.
  REQUIRE(wire == DecodeHexForTcpTests("0e1000040000000800000003"
                                       "19000000"
                                       "746578742f786d6c"
                                       "61626300"));
  auto header = DecodeDimeRecordHeader(const_data_ptr_cast(wire.data()));
  REQUIRE(header.version == 1);
  REQUIRE(header.message_begin);
  REQUIRE(header.message_end);
  REQUIRE(!header.chunked);
  REQUIRE(header.type_format == 1);
  REQUIRE(header.data_length == 3);
}

TEST_CASE("Chunked DIME messages round-trip", "[xmla_tcp]") {
  std::string payload;
  for (int i = 0; i < 1000; i++) {
    payload.push_back(static_cast<char>('a' + (i % 26)));
  }
  auto wire = EncodeDimeMessage("application/sx+xpress", 0x19, payload, 333);
  auto first = DecodeDimeRecordHeader(const_data_ptr_cast(wire.data()));
  REQUIRE(first.message_begin);
  REQUIRE(!first.message_end);
  REQUIRE(first.chunked);
  REQUIRE(first.type_format == 1);
  REQUIRE(first.data_length == 333);

  for (idx_t slice : {idx_t(1), idx_t(5), idx_t(64), idx_t(4096)}) {
    auto decoded = DecodeDimeInSlices(wire, slice);
    REQUIRE(decoded.data == payload);
    REQUIRE(decoded.content_type == "application/sx+xpress");
    REQUIRE(decoded.caps == 0x19);
    REQUIRE(decoded.records == 4);
    REQUIRE(decoded.consumed == wire.size());
  }
}

TEST_CASE("DIME reader stops at the message boundary", "[xmla_tcp]") {
  auto wire = EncodeDimeMessage("text/xml", 0, "") +
              EncodeDimeMessage("text/xml", 0, "next");
  std::string data;
  DimeMessageReader reader([&](const_data_ptr_t bytes, idx_t size) {
    data.append(reinterpret_cast<const char *>(bytes), size);
    return true;
  });
  auto consumed = reader.Feed(const_data_ptr_cast(wire.data()), wire.size());
  REQUIRE(reader.MessageComplete());
  REQUIRE(data.empty());
  REQUIRE(consumed == 12 + 4 + 8);
}

TEST_CASE("DIME reader rejects malformed records", "[xmla_tcp]") {
  auto wire = EncodeDimeMessage("text/xml", 0, "abc");
  auto bad_version = wire;
  bad_version[0] = static_cast<char>((2 << 3) | 0x06);
  DimeMessageReader version_reader(nullptr);
  REQUIRE_THROWS_WITH(
      version_reader.Feed(const_data_ptr_cast(bad_version.data()),
                          bad_version.size()),
      Catch::Matchers::Contains("Unsupported DIME record version 2"));

  auto no_begin = wire;
  no_begin[0] = static_cast<char>((1 << 3) | 0x02);
  DimeMessageReader begin_reader(nullptr);
  REQUIRE_THROWS_WITH(
      begin_reader.Feed(const_data_ptr_cast(no_begin.data()), no_begin.size()),
      Catch::Matchers::Contains("MB record"));
}

TEST_CASE("GSS-API wrap blocks per MS-SSAS 2.1.3", "[xmla_tcp]") {
  auto block = EncodeGssWrapBlock("hello", "TK");
  REQUIRE(block == DecodeHexForTcpTests("05000200") + "helloTK");
  auto wire = block + EncodeGssWrapBlock("", "sig") +
              EncodeGssWrapBlock(std::string(300, 'x'), "");
  std::vector<std::pair<std::string, std::string>> blocks;
  GssWrapBlockReader reader(
      [&](const std::string &data, const std::string &token) {
        blocks.emplace_back(data, token);
      });
  for (size_t i = 0; i < wire.size(); i += 7) {
    reader.Feed(const_data_ptr_cast(wire.data()) + i,
                std::min<size_t>(7, wire.size() - i));
  }
  REQUIRE_NOTHROW(reader.Finish());
  REQUIRE(blocks.size() == 3);
  REQUIRE(blocks[0].first == "hello");
  REQUIRE(blocks[0].second == "TK");
  REQUIRE(blocks[1].first.empty());
  REQUIRE(blocks[1].second == "sig");
  REQUIRE(blocks[2].first == std::string(300, 'x'));

  GssWrapBlockReader truncated([](const std::string &, const std::string &) {});
  truncated.Feed(const_data_ptr_cast(block.data()), block.size() - 1);
  REQUIRE_THROWS_WITH(truncated.Finish(),
                      Catch::Matchers::Contains("Truncated GSS-API"));
}

TEST_CASE("XMLA Authenticate envelope and response", "[xmla_tcp]") {
  auto envelope = BuildXmlaAuthenticateEnvelope(std::string("NTLMSSP\0\1", 9));
  REQUIRE(envelope.find("<Authenticate "
                        "xmlns=\"http://schemas.microsoft.com/analysisservices/"
                        "2003/ext\"><SspiHandshake>TlRMTVNTUAAB</"
                        "SspiHandshake>") != std::string::npos);

  auto token = ParseXmlaAuthenticateResponse(
      "<soap:Envelope "
      "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>"
      "<AuthenticateResponse "
      "xmlns=\"http://schemas.microsoft.com/analysisservices/2003/ext\">"
      "<return><SspiHandshake>TlRMTVNTUAAC</SspiHandshake></return>"
      "</AuthenticateResponse></soap:Body></soap:Envelope>");
  REQUIRE(token == std::string("NTLMSSP\0\2", 9));

  // Observed from Power BI Desktop: MIME-style line breaks in the base64.
  REQUIRE(ParseXmlaAuthenticateResponse(
              "<soap:Envelope><soap:Body><AuthenticateResponse><return>"
              "<SspiHandshake>TlRM\r\nTVNT\nUAAC</SspiHandshake></return>"
              "</AuthenticateResponse></soap:Body></soap:Envelope>") ==
          std::string("NTLMSSP\0\2", 9));
  REQUIRE_THROWS_WITH(
      ParseXmlaAuthenticateResponse(
          "<AuthenticateResponse><return><SspiHandshake>@@@@</SspiHandshake>"
          "</return></AuthenticateResponse>"),
      Catch::Matchers::Contains("invalid base64"));

  REQUIRE(ParseXmlaAuthenticateResponse(
              "<Envelope><Body><AuthenticateResponse><return><SspiHandshake/>"
              "</return></AuthenticateResponse></Body></Envelope>")
              .empty());

  REQUIRE_THROWS_WITH(
      ParseXmlaAuthenticateResponse(
          "<soap:Envelope><soap:Body><soap:Fault><faultcode>XMLAnalysisError."
          "0xc1060000</faultcode><faultstring>Authentication failed"
          "</faultstring><detail><Error ErrorCode=\"1\" Description=\"The "
          "user &apos;x&apos; does not have permission\"/></detail>"
          "</soap:Fault></soap:Body></soap:Envelope>"),
      Catch::Matchers::Contains("Authentication failed: The user 'x' does not "
                                "have permission"));
  REQUIRE_THROWS_WITH(ParseXmlaAuthenticateResponse("<Envelope/>"),
                      Catch::Matchers::Contains("AuthenticateResponse"));
}

TEST_CASE("Parse DBSCHEMA_CATALOGS names", "[xmla_tcp]") {
  REQUIRE(BuildXmlaDiscoverCatalogsEnvelope().find(
              "<RequestType>DBSCHEMA_CATALOGS</RequestType>") !=
          std::string::npos);
  auto names = ParseXmlaCatalogNames(
      "<return><root xmlns=\"urn:schemas-microsoft-com:xml-analysis:rowset\">"
      "<xsd:schema/><row><CATALOG_NAME>0f1e2d3c-aaaa-bbbb-cccc-"
      "000000000001</CATALOG_NAME><DESCRIPTION/></row>"
      "<row><CATALOG_NAME>Sales &amp; Ops</CATALOG_NAME></row></root>"
      "</return>");
  REQUIRE(names.size() == 2);
  REQUIRE(names[0] == "0f1e2d3c-aaaa-bbbb-cccc-000000000001");
  REQUIRE(names[1] == "Sales & Ops");
}

TEST_CASE("Recognize local Analysis Services data sources", "[xmla_tcp]") {
  std::string host;
  uint16_t port = 0;
  REQUIRE(TryParseLocalInstanceDataSource("localhost:60790", host, port));
  REQUIRE(host == "localhost");
  REQUIRE(port == 60790);
  REQUIRE(TryParseLocalInstanceDataSource(" LocalHost:1 ", host, port));
  REQUIRE(port == 1);
  REQUIRE(TryParseLocalInstanceDataSource("127.0.0.1:65535", host, port));
  REQUIRE(host == "127.0.0.1");
  REQUIRE(TryParseLocalInstanceDataSource("[::1]:5132", host, port));
  REQUIRE(host == "::1");
  REQUIRE(port == 5132);
  REQUIRE(TryParseLocalInstanceDataSource("::1:5133", host, port));
  REQUIRE(port == 5133);

  REQUIRE(!TryParseLocalInstanceDataSource(
      "powerbi://api.powerbi.com/v1.0/myorg/Example", host, port));
  REQUIRE(!TryParseLocalInstanceDataSource("http://localhost:8123/xmla", host,
                                           port));
  REQUIRE(!TryParseLocalInstanceDataSource("example.com:443", host, port));

  for (auto bad : {"localhost", "localhost:", "localhost:0", "localhost:65536",
                   "127.0.0.1:12a", "[::1]"}) {
    REQUIRE_THROWS_WITH(TryParseLocalInstanceDataSource(bad, host, port),
                        Catch::Matchers::Contains(
                            "Local Data Source must be localhost:<port>"));
  }
}

TEST_CASE("Describe XMLA TCP negotiation flags", "[xmla_tcp]") {
  REQUIRE(DescribeXmlaTcpCapsFlags(0) == "0x00");
  REQUIRE(DescribeXmlaTcpCapsFlags(0x19) == "0x19 (NEGO|RESP_SX|RESP_XPRESS)");
  REQUIRE(HexPreview(std::string("\x01\xab", 2), 1) == "01...");
#ifndef _WIN32
  REQUIRE(!LocalXmlaTcpClient::IsSupported());
  LocalXmlaTcpClient client(1000, nullptr);
  REQUIRE_THROWS_WITH(
      client.Connect("localhost", 60790),
      Catch::Matchers::Contains("only supported in native Windows builds"));
#endif
}

TEST_CASE("Parse msmdsrv.port.txt", "[local_instances]") {
  uint16_t port = 0;
  // UTF-16LE with BOM, as Power BI Desktop writes it.
  REQUIRE(ParseMsmdsrvPortFile(std::string("\xFF\xFE"
                                           "6\0"
                                           "0\0"
                                           "7\0"
                                           "9\0"
                                           "0\0",
                                           12),
                               port));
  REQUIRE(port == 60790);
  // UTF-16LE without BOM, trailing CRLF and NUL.
  REQUIRE(ParseMsmdsrvPortFile(std::string("5\0"
                                           "1\0"
                                           "3\0"
                                           "2\0"
                                           "\r\0"
                                           "\n\0"
                                           "\0\0",
                                           14),
                               port));
  REQUIRE(port == 5132);
  REQUIRE(ParseMsmdsrvPortFile("\xEF\xBB\xBF"
                               "60791\n",
                               port));
  REQUIRE(port == 60791);
  REQUIRE(ParseMsmdsrvPortFile(" 1 ", port));
  REQUIRE(port == 1);

  REQUIRE(!ParseMsmdsrvPortFile("", port));
  REQUIRE(!ParseMsmdsrvPortFile("0", port));
  REQUIRE(!ParseMsmdsrvPortFile("65536", port));
  REQUIRE(!ParseMsmdsrvPortFile("60x90", port));
  REQUIRE(!ParseMsmdsrvPortFile(std::string("\xFF\xFE"
                                            "6\x01",
                                            4),
                                port));
}

TEST_CASE("Report name from Power BI Desktop window title",
          "[local_instances]") {
  REQUIRE(ReportNameFromDesktopWindowTitle("Sales Model - Power BI Desktop") ==
          "Sales Model");
  REQUIRE(ReportNameFromDesktopWindowTitle(
              "Finance - Q4 - Power BI Desktop  ") == "Finance - Q4");
  REQUIRE(ReportNameFromDesktopWindowTitle(
              "Ops \xE2\x80\x93 Power BI Desktop") == "Ops");
  // Observed on the Microsoft Store install: the title is just the report.
  REQUIRE(ReportNameFromDesktopWindowTitle("Uren") == "Uren");
  REQUIRE(!DesktopWindowTitleHasSuffix("Uren"));
  REQUIRE(DesktopWindowTitleHasSuffix("Sales Model - Power BI Desktop"));
  REQUIRE(ReportNameFromDesktopWindowTitle("Power BI Desktop").empty());
  // Localized separators (sql-bi/Bravo#476).
  for (auto dash :
       {"\xE2\x88\x92", "\xE2\x80\x91", "\xE2\x80\x94", "\xE2\x80\x95"}) {
    REQUIRE(ReportNameFromDesktopWindowTitle(std::string("Uren ") + dash +
                                             " Power BI Desktop") == "Uren");
  }

  REQUIRE(IsTcpListenerCandidate(2, false, false));
  REQUIRE(IsTcpListenerCandidate(0, true, true));
  REQUIRE(!IsTcpListenerCandidate(5, true, false));
  REQUIRE(!IsTcpListenerCandidate(0, false, true));
  REQUIRE(ReportNameFromDesktopWindowTitle("").empty());

  REQUIRE(BuildLocalConnectionString(60790, "") ==
          "Data Source=localhost:60790;");
  REQUIRE(BuildLocalConnectionString(60790, "abc-123") ==
          "Data Source=localhost:60790;Initial Catalog=abc-123;");
}

#ifndef _WIN32
TEST_CASE("Local Desktop functions are Windows only", "[local_instances]") {
  DuckDB db(nullptr);
  ExtensionHelper::LoadExtension(db, "pbi_scanner");
  Connection con(db);
  auto instances = con.Query("SELECT * FROM pbi_local_instances()");
  REQUIRE(instances->HasError());
  REQUIRE_THAT(instances->GetError(),
               Catch::Matchers::Contains(
                   "pbi_local_instances is only supported in native Windows "
                   "builds of pbi_scanner"));
  auto probe = con.Query(
      "SELECT * FROM pbi_local_probe('Data Source=localhost:60790;')");
  REQUIRE(probe->HasError());
  REQUIRE_THAT(probe->GetError(),
               Catch::Matchers::Contains("only supported in native Windows "
                                         "builds of pbi_scanner"));
}
#endif

TEST_CASE("Parse local Power BI Desktop connection strings",
          "[connection_string]") {
  auto local = ParsePowerBIConnectionString("Data Source=localhost:60790;");
  REQUIRE(local.is_local_instance);
  REQUIRE(!local.is_direct_xmla);
  REQUIRE(local.local_host == "localhost");
  REQUIRE(local.local_port == 60790);
  REQUIRE(local.initial_catalog.empty());

  auto with_catalog = ParsePowerBIConnectionString(
      "Data Source=127.0.0.1:5132;Initial Catalog=0f1e2d3c-aaaa-bbbb-cccc-"
      "000000000001;TimeoutMs=5000;");
  REQUIRE(with_catalog.is_local_instance);
  REQUIRE(with_catalog.local_host == "127.0.0.1");
  REQUIRE(with_catalog.local_port == 5132);
  REQUIRE(with_catalog.initial_catalog ==
          "0f1e2d3c-aaaa-bbbb-cccc-000000000001");
  REQUIRE(with_catalog.has_timeout_ms);

  REQUIRE_THROWS_WITH(
      ParsePowerBIConnectionString("Data Source=localhost;"),
      Catch::Matchers::Contains("Local Data Source must be localhost:<port>"));
  // Remote host:port stays unsupported (no on-premises SSAS over the network).
  REQUIRE_THROWS_WITH(
      ParsePowerBIConnectionString(
          "Data Source=server.example:2383;Initial Catalog=db;"),
      Catch::Matchers::Contains("powerbi://"));
  // Loopback HTTP XMLA keeps its existing meaning.
  REQUIRE(ParsePowerBIConnectionString(
              "Data Source=http://localhost:8123/xmla;Initial Catalog=mock;")
              .is_direct_xmla);
}

TEST_CASE("XMLA TCP response reader unwraps protected DIME messages",
          "[xmla_tcp]") {
  // Fake GSS-API wrap: the "ciphertext" is the reversed plaintext and the
  // token must be "TK". Real decryption is SSPI on Windows.
  std::string plain;
  for (int i = 0; i < 5000; i++) {
    plain.push_back(static_cast<char>('A' + (i % 23)));
  }
  std::string wrapped;
  for (size_t offset = 0; offset < plain.size(); offset += 700) {
    auto block = plain.substr(offset, 700);
    std::reverse(block.begin(), block.end());
    wrapped += EncodeGssWrapBlock(block, "TK");
  }
  auto wire = EncodeDimeMessage("application/sx+xpress", 0x1e, wrapped, 999);
  auto unwrap = [](const std::string &data, const std::string &token) {
    REQUIRE(token == "TK");
    return std::string(data.rbegin(), data.rend());
  };

  for (size_t slice : {size_t(1), size_t(17), size_t(4096)}) {
    std::string out;
    XmlaTcpResponseReader reader(unwrap, [&](const_data_ptr_t d, idx_t n) {
      out.append(reinterpret_cast<const char *>(d), n);
      return true;
    });
    idx_t consumed = 0;
    for (size_t i = 0; i < wire.size() && !reader.MessageComplete();
         i += slice) {
      consumed += reader.Feed(const_data_ptr_cast(wire.data()) + i,
                              std::min(slice, wire.size() - i));
    }
    REQUIRE(reader.MessageComplete());
    REQUIRE_NOTHROW(reader.Finish());
    REQUIRE(consumed == wire.size());
    REQUIRE(out == plain);
    REQUIRE(reader.PlainBytes() == plain.size());
    REQUIRE(reader.ContentType() == "application/sx+xpress");
    REQUIRE(reader.CapsFlags() == 0x1e);
  }

  // Stopping early (query cancelled) stops reading before the message ends.
  std::string first;
  XmlaTcpResponseReader stopping(unwrap, [&](const_data_ptr_t d, idx_t n) {
    first.append(reinterpret_cast<const char *>(d), n);
    return false;
  });
  stopping.Feed(const_data_ptr_cast(wire.data()), wire.size());
  REQUIRE(stopping.Stopped());
  REQUIRE(!stopping.MessageComplete());
  REQUIRE(first == plain.substr(0, 700));

  // Unprotected connections pass DIME data straight through.
  std::string clear;
  XmlaTcpResponseReader passthrough(
      XmlaTcpResponseReader::Unwrap(), [&](const_data_ptr_t d, idx_t n) {
        clear.append(reinterpret_cast<const char *>(d), n);
        return true;
      });
  auto clear_wire = EncodeDimeMessage("text/xml", 0x01, "<root/>");
  passthrough.Feed(const_data_ptr_cast(clear_wire.data()), clear_wire.size());
  REQUIRE(passthrough.MessageComplete());
  REQUIRE(clear == "<root/>");

  // A protected message that ends mid-block is an error.
  auto truncated_wire =
      EncodeDimeMessage("text/xml", 0x01, wrapped.substr(0, 100));
  XmlaTcpResponseReader truncated(unwrap, nullptr);
  truncated.Feed(const_data_ptr_cast(truncated_wire.data()),
                 truncated_wire.size());
  REQUIRE_THROWS_WITH(truncated.Finish(),
                      Catch::Matchers::Contains("Truncated GSS-API"));

  REQUIRE(XmlaTcpCapsForTransport(false, false) == XMLA_TCP_CAPS_NEGO);
  REQUIRE(XmlaTcpCapsForTransport(true, true) == 0x19);
  REQUIRE(XmlaTcpCapsForTransport(false, true) == 0x11);
}

#ifndef _WIN32
TEST_CASE("dax_query local targets are Windows only", "[local_instances]") {
  DuckDB db(nullptr);
  ExtensionHelper::LoadExtension(db, "pbi_scanner");
  Connection con(db);
  for (auto sql :
       {"SELECT * FROM dax_query('Data Source=localhost:60790;', "
        "'EVALUATE ROW(\"x\", 1)')",
        "SELECT * FROM pbi_tables('Data Source=localhost:60790;')"}) {
    auto result = con.Query(sql);
    REQUIRE(result->HasError());
    REQUIRE_THAT(result->GetError(),
                 Catch::Matchers::Contains(
                     "Local Power BI Desktop connections (Data "
                     "Source=localhost:<port>) are only supported in native "
                     "Windows builds of pbi_scanner"));
  }
}
#endif
