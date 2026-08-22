/** @file

  Catch-based unit tests for the well known HTTP method tokens, with an emphasis
  on the QUERY method added for RFC 10008 and on the layout invariants of the
  method block that the rest of the code base relies on.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "proxy/hdrs/HTTP.h"
#include "proxy/hdrs/HdrToken.h"

using namespace std::literals;

namespace
{

// Parse a request line and hand back the parsed header. The caller destroys it.
ParseResult
parse_request_line(HTTPHdr &hdr, std::string_view msg)
{
  HTTPParser parser;

  http_parser_init(&parser);
  hdr.create(HTTPType::REQUEST, HTTP_1_1, new_HdrHeap(HdrHeap::DEFAULT_SIZE + 64));

  char const *start  = msg.data();
  ParseResult result = hdr.parse_req(&parser, &start, msg.data() + msg.length(), true);

  http_parser_clear(&parser);
  return result;
}

} // end anonymous namespace

TEST_CASE("QUERY is a well known method", "[proxy][hdrtest][query]")
{
  SECTION("the request line tokenizes to HTTP_WKSIDX_QUERY")
  {
    HTTPHdr hdr;

    REQUIRE(parse_request_line(hdr, "QUERY /path HTTP/1.1\r\nHost: example.com\r\n\r\n"sv) == ParseResult::DONE);
    CHECK(hdr.method_get_wksidx() == HTTP_WKSIDX_QUERY);
    CHECK(hdr.method_get() == "QUERY"sv);
    hdr.destroy();
  }

  SECTION("HTTP_METHOD_QUERY is the well known string for that index")
  {
    REQUIRE(static_cast<std::string_view>(HTTP_METHOD_QUERY) == "QUERY"sv);
    CHECK(hdrtoken_wks_to_index(HTTP_METHOD_QUERY.c_str()) == HTTP_WKSIDX_QUERY);
    CHECK(std::string_view{hdrtoken_index_to_wks(HTTP_WKSIDX_QUERY)} == "QUERY"sv);
    CHECK(hdrtoken_index_to_length(HTTP_WKSIDX_QUERY) == 5);
  }

  SECTION("setting the method from the well known string round trips")
  {
    HTTPHdr hdr;

    hdr.create(HTTPType::REQUEST, HTTP_1_1, new_HdrHeap(HdrHeap::DEFAULT_SIZE + 64));
    hdr.method_set(static_cast<std::string_view>(HTTP_METHOD_QUERY));
    CHECK(hdr.method_get_wksidx() == HTTP_WKSIDX_QUERY);
    CHECK(hdr.method_get() == "QUERY"sv);
    hdr.destroy();
  }
}

// The well known index of a method is persisted inside cached request headers,
// so an object written by an older Traffic Server is read back with the index it
// was written with. Moving any of the existing methods -- for instance by
// inserting QUERY alphabetically between PUT and PUSH rather than appending it --
// silently reinterprets every cached request as a different method. That is why
// QUERY is appended at the end of the method block in _hdrtoken_strs[], and why
// this test pins the offsets. If you are here because this test failed after you
// added a method: append it, do not insert it.
TEST_CASE("HTTP method indices are stable", "[proxy][hdrtest][query]")
{
  static std::vector<std::pair<char const *, int>> const expected_offsets = {
    {"CONNECT", 0 },
    {"DELETE",  1 },
    {"GET",     2 },
    {"POST",    3 },
    {"HEAD",    4 },
    {"OPTIONS", 5 },
    {"PURGE",   6 },
    {"PUT",     7 },
    {"TRACE",   8 },
    {"PUSH",    9 },
    {"QUERY",   10}
  };

  SECTION("every method sits at its historical offset from HTTP_WKSIDX_CONNECT")
  {
    CHECK(HTTP_WKSIDX_DELETE - HTTP_WKSIDX_CONNECT == 1);
    CHECK(HTTP_WKSIDX_GET - HTTP_WKSIDX_CONNECT == 2);
    CHECK(HTTP_WKSIDX_POST - HTTP_WKSIDX_CONNECT == 3);
    CHECK(HTTP_WKSIDX_HEAD - HTTP_WKSIDX_CONNECT == 4);
    CHECK(HTTP_WKSIDX_OPTIONS - HTTP_WKSIDX_CONNECT == 5);
    CHECK(HTTP_WKSIDX_PURGE - HTTP_WKSIDX_CONNECT == 6);
    CHECK(HTTP_WKSIDX_PUT - HTTP_WKSIDX_CONNECT == 7);
    CHECK(HTTP_WKSIDX_TRACE - HTTP_WKSIDX_CONNECT == 8);
    CHECK(HTTP_WKSIDX_PUSH - HTTP_WKSIDX_CONNECT == 9);

    // QUERY is the new one, and it must be last so that nothing above it moved.
    CHECK(HTTP_WKSIDX_QUERY - HTTP_WKSIDX_CONNECT == 10);
    CHECK(HTTP_WKSIDX_METHODS_CNT == 11);
  }

  SECTION("the string table agrees with the index constants")
  {
    for (auto const &[name, offset] : expected_offsets) {
      INFO("method " << name << " expected at offset " << offset);
      REQUIRE(hdrtoken_is_valid_wks_idx(HTTP_WKSIDX_CONNECT + offset));
      CHECK(std::string_view{hdrtoken_index_to_wks(HTTP_WKSIDX_CONNECT + offset)} == std::string_view{name});
    }
  }

  // IPAllow::ACL::MethodIdxToMask() and remap's standard_method_lookup both index
  // straight off HTTP_WKSIDX_CONNECT for HTTP_WKSIDX_METHODS_CNT entries, so a
  // non-method token landing inside that window would be given a method bit.
  SECTION("the method block is contiguous and holds only methods")
  {
    for (int idx = HTTP_WKSIDX_CONNECT; idx < HTTP_WKSIDX_CONNECT + HTTP_WKSIDX_METHODS_CNT; ++idx) {
      INFO("wks index " << idx << " is '" << hdrtoken_index_to_wks(idx) << "'");
      REQUIRE(hdrtoken_is_valid_wks_idx(idx));
      CHECK(hdrtoken_index_to_token_type(idx) == HdrTokenType::METHOD);
    }

    // And the token just past the block is not a method, which is what makes the
    // count above exact rather than merely a lower bound.
    int const past_end = HTTP_WKSIDX_CONNECT + HTTP_WKSIDX_METHODS_CNT;

    REQUIRE(hdrtoken_is_valid_wks_idx(past_end));
    CHECK(hdrtoken_index_to_token_type(past_end) != HdrTokenType::METHOD);
  }
}

// Methods are case sensitive in the request line (RFC 9110 section 9.1), and
// hdrtoken_method_tokenize() enforces that by rejecting a case insensitive DFA
// match whose bytes differ. So a lower case "query" is a valid but unknown
// method, exactly like a lower case "get" has always been, and it must not pick
// up the QUERY well known index or any of the QUERY handling that hangs off it.
TEST_CASE("HTTP methods are matched case sensitively", "[proxy][hdrtest][query]")
{
  SECTION("lower case query is not the QUERY method")
  {
    HTTPHdr hdr;

    REQUIRE(parse_request_line(hdr, "query /path HTTP/1.1\r\nHost: example.com\r\n\r\n"sv) == ParseResult::DONE);
    CHECK(hdr.method_get_wksidx() != HTTP_WKSIDX_QUERY);
    CHECK(hdr.method_get_wksidx() == -1);
    CHECK(hdr.method_get() == "query"sv);
    hdr.destroy();
  }

  SECTION("mixed case Query is not the QUERY method")
  {
    HTTPHdr hdr;

    REQUIRE(parse_request_line(hdr, "Query /path HTTP/1.1\r\nHost: example.com\r\n\r\n"sv) == ParseResult::DONE);
    CHECK(hdr.method_get_wksidx() == -1);
    CHECK(hdr.method_get() == "Query"sv);
    hdr.destroy();
  }

  // The existing behaviour this is matched against.
  SECTION("lower case get is not the GET method either")
  {
    HTTPHdr hdr;

    REQUIRE(parse_request_line(hdr, "get /path HTTP/1.1\r\nHost: example.com\r\n\r\n"sv) == ParseResult::DONE);
    CHECK(hdr.method_get_wksidx() == -1);
    CHECK(hdr.method_get() == "get"sv);
    hdr.destroy();
  }

  // hdrtoken_method_tokenize() is what the request line parser uses; check it
  // directly too, since that is the function the case rule lives in.
  SECTION("hdrtoken_method_tokenize is case sensitive")
  {
    CHECK(hdrtoken_method_tokenize("QUERY", 5) == HTTP_WKSIDX_QUERY);
    CHECK(hdrtoken_method_tokenize("query", 5) == -1);
    CHECK(hdrtoken_method_tokenize("Query", 5) == -1);
  }
}
