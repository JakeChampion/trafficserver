/** @file

  Unit tests for the RFC 10008 QUERY cache key digest, HttpSM::compute_query_content_digest()
  and HttpSM::apply_query_cache_key().

  The property under test is a security property: two QUERY requests that are not
  byte for byte identical in the inputs the digest covers must never produce the
  same digest, because a collision hands one requester another requester's stored
  response.

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

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include "iocore/eventsystem/IOBuffer.h"
#include "proxy/hdrs/HTTP.h"
#include "proxy/hdrs/MIME.h"
#include "proxy/http/HttpConfig.h"
#include "proxy/http/HttpSM.h"

using namespace std::literals;

namespace
{

using Digest = std::remove_reference_t<decltype(std::declval<HttpTransact::State &>().query_content_digest)>;

/** A QUERY request just complete enough to drive HttpSM::compute_query_content_digest().

    compute_query_content_digest() reads only t_state (method, txn_conf, client
    request headers) and the buffered post body, so a state machine that never ran
    a transaction is enough.

    The state machine is deliberately leaked. ~HttpSM() calls HttpConfig::release(),
    which forwards to ConfigProcessor::release() with HttpConfig::m_id; this test
    binary never calls HttpConfig::startup(), so that id is still 0 and
    ConfigProcessor::release() ink_abort()s on it. The leak is a handful of state
    machines for the life of the test binary.
 */
class QueryRequest
{
public:
  QueryRequest() : _sm{new HttpSM}
  {
    _conf.cache_query_method = 1;

    _sm->t_state.txn_conf = &_conf;
    _sm->t_state.method   = HTTP_WKSIDX_QUERY;
    _sm->t_state.hdr_info.client_request.create(HTTPType::REQUEST);
    _sm->t_state.hdr_info.client_request.method_set(static_cast<std::string_view>(HTTP_METHOD_QUERY));
  }

  QueryRequest(QueryRequest const &)            = delete;
  QueryRequest &operator=(QueryRequest const &) = delete;

  ~QueryRequest()
  {
    if (_ua_buffer != nullptr) {
      free_MIOBuffer(_ua_buffer);
    }
  }

  /// Add a request header field. Called more than once with the same name it adds a duplicate field.
  QueryRequest &
  with_field(std::string_view name, std::string_view value)
  {
    HTTPHdr   *request = &_sm->t_state.hdr_info.client_request;
    MIMEField *field   = request->field_create(name);

    request->field_attach(field);
    request->field_value_set(field, value);
    return *this;
  }

  /// Buffer @a body as the request content, the way tunnel_handler_post() would have.
  QueryRequest &
  with_body(std::string_view body)
  {
    _ua_buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_4K);

    IOBufferReader *ua_reader = _ua_buffer->alloc_reader();

    if (!body.empty()) {
      _ua_buffer->write(body.data(), body.length());
    }
    // A real transaction always has this set by the time the body is buffered, and
    // the digest cross checks the buffered length against it before keying.
    _sm->t_state.hdr_info.request_content_length = static_cast<int64_t>(body.length());
    _sm->postbuf_init(ua_reader);
    _sm->postbuf_copy_partial_data(static_cast<int64_t>(body.length()));
    _sm->set_postbuf_done(true);
    return *this;
  }

  QueryRequest &
  with_cache_query_method(MgmtByte value)
  {
    _conf.cache_query_method = value;
    return *this;
  }

  QueryRequest &
  with_method(int method)
  {
    _sm->t_state.method = method;
    return *this;
  }

  /// Compute the digest and return it. Fails the test if the request bypassed the cache.
  Digest
  digest()
  {
    _sm->compute_query_content_digest();
    REQUIRE(_sm->t_state.query_content_digest_valid);
    REQUIRE_FALSE(_sm->t_state.query_cache_bypass);
    return _sm->t_state.query_content_digest;
  }

  HttpSM *
  sm()
  {
    return _sm;
  }

private:
  HttpSM                     *_sm        = nullptr;
  MIOBuffer                  *_ua_buffer = nullptr;
  OverridableHttpConfigParams _conf;
};

std::string_view constexpr CONTENT_TYPE     = "Content-Type"sv;
std::string_view constexpr CONTENT_ENCODING = "Content-Encoding"sv;
std::string_view constexpr CONTENT_LANGUAGE = "Content-Language"sv;

void
init_wks()
{
  url_init();
  mime_init();
  http_init();
}

} // end anonymous namespace

TEST_CASE("QUERY content digest is deterministic", "[http][query]")
{
  init_wks();

  SECTION("the same body and metadata digest the same")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_TYPE, "application/sparql-query"sv).with_body("SELECT * WHERE { ?s ?p ?o }"sv);
    b.with_field(CONTENT_TYPE, "application/sparql-query"sv).with_body("SELECT * WHERE { ?s ?p ?o }"sv);

    CHECK(a.digest() == b.digest());
  }

  SECTION("digesting twice gives the same answer")
  {
    QueryRequest a;

    a.with_field(CONTENT_TYPE, "text/plain"sv).with_body("q=hello"sv);

    Digest const first = a.digest();

    CHECK(a.digest() == first);
  }

  SECTION("a body spanning several IOBuffer blocks digests deterministically")
  {
    // BUFFER_SIZE_INDEX_4K blocks, so this is several blocks and exercises the
    // block walking loop rather than a single contiguous read.
    std::string const large(20 * 1024, 'x');
    std::string       nearly_large = large;

    nearly_large.back() = 'y';

    QueryRequest a;
    QueryRequest b;
    QueryRequest c;

    a.with_body(large);
    b.with_body(large);
    c.with_body(nearly_large);

    CHECK(a.digest() == b.digest());
    CHECK(a.digest() != c.digest());
  }
}

TEST_CASE("QUERY content digest separates distinct requests", "[http][query]")
{
  init_wks();

  SECTION("a different body with the same metadata digests differently")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_TYPE, "text/plain"sv).with_body("q=one"sv);
    b.with_field(CONTENT_TYPE, "text/plain"sv).with_body("q=two"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("the same body with a different Content-Type digests differently")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_TYPE, "text/plain"sv).with_body("q=one"sv);
    b.with_field(CONTENT_TYPE, "application/json"sv).with_body("q=one"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("Content-Type parameters participate")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_TYPE, "text/plain; charset=utf-8"sv).with_body("q=one"sv);
    b.with_field(CONTENT_TYPE, "text/plain; charset=iso-8859-1"sv).with_body("q=one"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("the same body with a different Content-Encoding digests differently")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_ENCODING, "gzip"sv).with_body("q=one"sv);
    b.with_field(CONTENT_ENCODING, "br"sv).with_body("q=one"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("the same body with a different Content-Language digests differently")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_LANGUAGE, "en"sv).with_body("q=one"sv);
    b.with_field(CONTENT_LANGUAGE, "de"sv).with_body("q=one"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("a value in one metadata field is not the same as that value in another")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_ENCODING, "en"sv).with_body("q=one"sv);
    b.with_field(CONTENT_LANGUAGE, "en"sv).with_body("q=one"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("the body is not confused with the metadata")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_TYPE, "text/plain"sv).with_body(""sv);
    b.with_body("text/plain"sv);

    CHECK(a.digest() != b.digest());
  }
}

// This is what the uint64_t length prefix in front of every digested field is
// for. Concatenating variable length fields without a length is ambiguous: the
// concatenation of ("ab", "c") equals that of ("a", "bc"), so two requests that
// differ only in where the boundary falls would share a cache entry and one
// requester would be served the other's stored response. Every adjacent pair in
// the digest order (method, Content-Type, Content-Encoding, Content-Language,
// body) is checked here, since the ambiguity is between neighbours.
TEST_CASE("QUERY content digest fields are unambiguously delimited", "[http][query]")
{
  init_wks();

  SECTION("body \"ab\" with Content-Type \"c\" does not collide with body \"a\" and Content-Type \"bc\"")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_TYPE, "c"sv).with_body("ab"sv);
    b.with_field(CONTENT_TYPE, "bc"sv).with_body("a"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("the Content-Type / Content-Encoding boundary is unambiguous")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_TYPE, "ab"sv).with_field(CONTENT_ENCODING, "c"sv).with_body("q"sv);
    b.with_field(CONTENT_TYPE, "a"sv).with_field(CONTENT_ENCODING, "bc"sv).with_body("q"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("the Content-Encoding / Content-Language boundary is unambiguous")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_ENCODING, "ab"sv).with_field(CONTENT_LANGUAGE, "c"sv).with_body("q"sv);
    b.with_field(CONTENT_ENCODING, "a"sv).with_field(CONTENT_LANGUAGE, "bc"sv).with_body("q"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("the Content-Language / body boundary is unambiguous")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_LANGUAGE, "ab"sv).with_body("c"sv);
    b.with_field(CONTENT_LANGUAGE, "a"sv).with_body("bc"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("shifting a byte across every field at once does not collide")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_TYPE, "ab"sv).with_field(CONTENT_ENCODING, "cd"sv).with_field(CONTENT_LANGUAGE, "ef"sv).with_body("gh"sv);
    b.with_field(CONTENT_TYPE, "a"sv).with_field(CONTENT_ENCODING, "bcd"sv).with_field(CONTENT_LANGUAGE, "ef"sv).with_body("gh"sv);

    CHECK(a.digest() != b.digest());
  }
}

TEST_CASE("QUERY content digest handles absent and empty metadata", "[http][query]")
{
  init_wks();

  SECTION("absent metadata is stable")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_body("q=one"sv);
    b.with_body("q=one"sv);

    CHECK(a.digest() == b.digest());
  }

  SECTION("an absent field is not the same as a present one")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_body("q=one"sv);
    b.with_field(CONTENT_TYPE, "text/plain"sv).with_body("q=one"sv);

    CHECK(a.digest() != b.digest());
  }

  SECTION("an empty body is not the same as a one byte body")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_body(""sv);
    b.with_body("\0"sv);

    CHECK(a.digest() != b.digest());
  }
}

TEST_CASE("QUERY without a buffered body bypasses the cache", "[http][query]")
{
  init_wks();

  SECTION("no post buffer means no digest")
  {
    QueryRequest a;

    a.with_field(CONTENT_TYPE, "text/plain"sv);
    a.sm()->compute_query_content_digest();

    CHECK_FALSE(a.sm()->t_state.query_content_digest_valid);
    CHECK(a.sm()->t_state.query_cache_bypass);
  }

  SECTION("cache_query_method off means no digest and no bypass flag")
  {
    QueryRequest a;

    a.with_cache_query_method(0).with_body("q=one"sv);
    a.sm()->compute_query_content_digest();

    CHECK_FALSE(a.sm()->t_state.query_content_digest_valid);
    CHECK_FALSE(a.sm()->t_state.query_cache_bypass);
  }

  SECTION("a non QUERY method is not digested")
  {
    QueryRequest a;

    a.with_method(HTTP_WKSIDX_POST).with_body("q=one"sv);
    a.sm()->compute_query_content_digest();

    CHECK_FALSE(a.sm()->t_state.query_content_digest_valid);
  }

  SECTION("an already bypassed QUERY stays bypassed")
  {
    QueryRequest a;

    a.with_body("q=one"sv);
    a.sm()->t_state.query_cache_bypass = true;
    a.sm()->compute_query_content_digest();

    CHECK_FALSE(a.sm()->t_state.query_content_digest_valid);
  }

  // The one failure this whole design exists to prevent is keying on part of a
  // body: two distinct queries sharing a prefix would collide on one entry and one
  // client would be served the other's answer. If the buffer holds less than the
  // request declared, there must be no key.
  SECTION("a body shorter than Content-Length is never keyed")
  {
    QueryRequest a;

    a.with_body("q=one"sv);
    a.sm()->t_state.hdr_info.request_content_length += 16;
    a.sm()->compute_query_content_digest();

    CHECK_FALSE(a.sm()->t_state.query_content_digest_valid);
    CHECK(a.sm()->t_state.query_cache_bypass);
  }

  SECTION("a body longer than Content-Length is never keyed")
  {
    QueryRequest a;

    a.with_body("q=one and then some more"sv);
    a.sm()->t_state.hdr_info.request_content_length = 5;
    a.sm()->compute_query_content_digest();

    CHECK_FALSE(a.sm()->t_state.query_content_digest_valid);
    CHECK(a.sm()->t_state.query_cache_bypass);
  }
}

// apply_query_cache_key() is what actually moves a QUERY off the URL derived key,
// and it runs on the lookup, write and delete paths, so all three must land on the
// same key for the same request and on different keys for different requests.
TEST_CASE("QUERY cache key folding", "[http][query]")
{
  init_wks();

  auto url_key = []() -> HttpCacheKey {
    HttpCacheKey key;

    key.hostname = "example.com"sv;
    for (unsigned i = 0; i < sizeof(key.hash.u8); ++i) {
      key.hash.u8[i] = static_cast<uint8_t>(i);
    }
    return key;
  };

  SECTION("a valid digest moves the key off the URL derived one")
  {
    QueryRequest a;

    a.with_field(CONTENT_TYPE, "text/plain"sv).with_body("q=one"sv);
    REQUIRE(a.digest() == a.sm()->t_state.query_content_digest);

    HttpCacheKey key      = url_key();
    HttpCacheKey original = url_key();

    a.sm()->apply_query_cache_key(&key);
    CHECK(key.hash != original.hash);
  }

  SECTION("the same request folds to the same key every time")
  {
    QueryRequest a;

    a.with_field(CONTENT_TYPE, "text/plain"sv).with_body("q=one"sv);
    a.digest();

    HttpCacheKey first  = url_key();
    HttpCacheKey second = url_key();

    a.sm()->apply_query_cache_key(&first);
    a.sm()->apply_query_cache_key(&second);
    CHECK(first.hash == second.hash);
  }

  SECTION("different bodies fold the same URL key to different cache keys")
  {
    QueryRequest a;
    QueryRequest b;

    a.with_field(CONTENT_TYPE, "text/plain"sv).with_body("q=one"sv);
    b.with_field(CONTENT_TYPE, "text/plain"sv).with_body("q=two"sv);
    a.digest();
    b.digest();

    HttpCacheKey a_key = url_key();
    HttpCacheKey b_key = url_key();

    a.sm()->apply_query_cache_key(&a_key);
    b.sm()->apply_query_cache_key(&b_key);
    CHECK(a_key.hash != b_key.hash);
  }

  SECTION("the same body under a different URL key stays different")
  {
    QueryRequest a;

    a.with_body("q=one"sv);
    a.digest();

    HttpCacheKey first  = url_key();
    HttpCacheKey second = url_key();

    second.hash.u8[0] ^= 0xff;

    a.sm()->apply_query_cache_key(&first);
    a.sm()->apply_query_cache_key(&second);
    CHECK(first.hash != second.hash);
  }

  SECTION("without a valid digest the key is left alone")
  {
    QueryRequest a;

    a.with_body("q=one"sv);

    HttpCacheKey key      = url_key();
    HttpCacheKey original = url_key();

    a.sm()->apply_query_cache_key(&key);
    CHECK(key.hash == original.hash);
  }

  SECTION("a non QUERY method leaves the key alone")
  {
    QueryRequest a;

    a.with_body("q=one"sv);
    a.digest();
    a.with_method(HTTP_WKSIDX_POST);

    HttpCacheKey key      = url_key();
    HttpCacheKey original = url_key();

    a.sm()->apply_query_cache_key(&key);
    CHECK(key.hash == original.hash);
  }
}

// KNOWN GAPS, reported rather than fixed here. Both are cases where two requests
// that are not byte for byte identical produce the same digest, and so share a
// cache entry:
//
//  1. An absent metadata field and a present one with an empty value are both fed
//     to the digest as a zero length value, so they are indistinguishable. A
//     distinguishing prefix for "absent" (a presence byte, or a reserved length)
//     would separate them.
//
//  2. Only the first of a repeated metadata field is digested, because the code
//     digests field_find(name)->value_get() and stops there. So "Content-Type: a"
//     and "Content-Type: a" plus "Content-Type: b" digest the same. Walking the
//     duplicate chain, with the count folded in, would separate them.
//
// Neither collision is reachable with a well formed request -- an empty
// Content-Type is not valid, and a repeated Content-Type is not either -- but the
// property this digest exists to provide is that distinct requests never collide,
// and an attacker controls these bytes.
//
// Both are now covered: the digest folds in the number of values for each metadata
// field and then every value, so absent, present-and-empty, and repeated all differ.
TEST_CASE("QUERY content digest distinguishes absent from empty metadata", "[http][query]")
{
  init_wks();

  QueryRequest absent;
  QueryRequest empty;

  absent.with_body("q=one"sv);
  empty.with_field(CONTENT_TYPE, ""sv).with_body("q=one"sv);

  CHECK(absent.digest() != empty.digest());
}

TEST_CASE("QUERY content digest covers repeated metadata fields", "[http][query]")
{
  init_wks();

  QueryRequest single;
  QueryRequest repeated;

  single.with_field(CONTENT_TYPE, "a"sv).with_body("q=one"sv);
  repeated.with_field(CONTENT_TYPE, "a"sv).with_field(CONTENT_TYPE, "b"sv).with_body("q=one"sv);

  CHECK(single.digest() != repeated.digest());
}
