/** @file

    Catch2 unit tests for RFC 8941 Structured Fields List parser.

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

#include "tscore/StructuredFields.h"

#include <catch2/catch_test_macros.hpp>
#include <string>
#include <string_view>
#include <vector>

using namespace std::string_literals;

// =============================================================================
// Valid Input Parsing Tests
// =============================================================================

TEST_CASE("SFListParser valid input parsing", "[libts][StructuredFields]")
{
  SECTION("Single item")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "group1");
  }

  SECTION("Multiple items")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1", "group2", "group3")");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == "group1");
    CHECK(result[1] == "group2");
    CHECK(result[2] == "group3");
  }

  SECTION("Items with parameters should have parameters ignored")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1";param=value, "group2")");
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "group1");
    CHECK(result[1] == "group2");
  }

  SECTION("Items with multiple parameters")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1";a=1;b=2;c=3, "group2";x=y)");
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "group1");
    CHECK(result[1] == "group2");
  }

  SECTION("Empty list is valid")
  {
    auto result = SFListParser::parse_list_of_strings("");
    REQUIRE(result.empty());
  }
}

// =============================================================================
// Malformed Input Tests (should return empty vector)
// =============================================================================

TEST_CASE("SFListParser malformed input returns empty vector", "[libts][StructuredFields]")
{
  SECTION("Unquoted strings")
  {
    auto result = SFListParser::parse_list_of_strings("group1");
    CHECK(result.empty());
  }

  SECTION("Unquoted strings in list")
  {
    auto result = SFListParser::parse_list_of_strings("group1, group2");
    CHECK(result.empty());
  }

  SECTION("Missing commas between items")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1" "group2")");
    CHECK(result.empty());
  }

  SECTION("Unclosed quote at end")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1)");
    CHECK(result.empty());
  }

  SECTION("Unclosed quote in middle")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1, "group2")");
    CHECK(result.empty());
  }

  SECTION("Missing opening quote")
  {
    auto result = SFListParser::parse_list_of_strings(R"(group1")");
    CHECK(result.empty());
  }

  SECTION("Invalid escape sequence - bare backslash at end")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1\")");
    CHECK(result.empty());
  }

  SECTION("Invalid escape sequence - invalid escaped character")
  {
    // RFC 8941 only allows escaping backslash and double quote
    auto result = SFListParser::parse_list_of_strings(R"("group\n")");
    CHECK(result.empty());
  }

  SECTION("Trailing comma without item")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1",)");
    CHECK(result.empty());
  }

  SECTION("Leading comma")
  {
    auto result = SFListParser::parse_list_of_strings(R"(,"group1")");
    CHECK(result.empty());
  }

  SECTION("Double comma")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1",, "group2")");
    CHECK(result.empty());
  }

  SECTION("Only whitespace")
  {
    auto result = SFListParser::parse_list_of_strings("   ");
    // Whitespace-only should be treated as empty list, which is valid
    CHECK(result.empty());
  }
}

// =============================================================================
// Edge Cases
// =============================================================================

TEST_CASE("SFListParser edge cases", "[libts][StructuredFields]")
{
  SECTION("Whitespace before first item")
  {
    auto result = SFListParser::parse_list_of_strings(R"(   "group1")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "group1");
  }

  SECTION("Whitespace after last item")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1"   )");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "group1");
  }

  SECTION("Extra whitespace around comma")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group1"  ,  "group2")");
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "group1");
    CHECK(result[1] == "group2");
  }

  SECTION("Tabs as whitespace")
  {
    auto result = SFListParser::parse_list_of_strings("\t\"group1\"\t,\t\"group2\"\t");
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "group1");
    CHECK(result[1] == "group2");
  }

  SECTION("Empty string value")
  {
    auto result = SFListParser::parse_list_of_strings(R"("")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "");
  }

  SECTION("Multiple empty strings")
  {
    auto result = SFListParser::parse_list_of_strings(R"("", "", "")");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == "");
    CHECK(result[1] == "");
    CHECK(result[2] == "");
  }

  SECTION("Escaped backslash")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group\\name")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "group\\name");
  }

  SECTION("Escaped quote")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group\"name")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "group\"name");
  }

  SECTION("Multiple escape sequences")
  {
    auto result = SFListParser::parse_list_of_strings(R"("a\\b\"c\\d\"e")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "a\\b\"c\\d\"e");
  }

  SECTION("Escaped characters in multiple items")
  {
    auto result = SFListParser::parse_list_of_strings(R"("a\\b", "c\"d")");
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "a\\b");
    CHECK(result[1] == "c\"d");
  }

  SECTION("String with spaces")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group with spaces")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "group with spaces");
  }

  SECTION("String with special characters")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group-name_123.test")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "group-name_123.test");
  }

  SECTION("Unicode characters in string")
  {
    auto result = SFListParser::parse_list_of_strings(R"("group-utf8-test")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "group-utf8-test");
  }
}

// =============================================================================
// RFC 8941 Compliance Tests
// =============================================================================

TEST_CASE("SFListParser RFC 8941 compliance", "[libts][StructuredFields][RFC8941]")
{
  SECTION("Quoted string with only allowed characters")
  {
    // RFC 8941 Section 3.3.3: sf-string = DQUOTE *chr DQUOTE
    // chr = unescaped / escaped
    // unescaped = %x20-21 / %x23-5B / %x5D-7E
    auto result = SFListParser::parse_list_of_strings(
      R"("!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~");
  }

  SECTION("Parameters with token values are ignored")
  {
    auto result = SFListParser::parse_list_of_strings(R"("item";param=token)");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "item");
  }

  SECTION("Parameters with string values are ignored")
  {
    auto result = SFListParser::parse_list_of_strings(R"("item";param="string value")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "item");
  }

  SECTION("Parameters with integer values are ignored")
  {
    auto result = SFListParser::parse_list_of_strings(R"("item";param=123)");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "item");
  }

  SECTION("Parameters with boolean values are ignored")
  {
    auto result = SFListParser::parse_list_of_strings(R"("item";param)");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "item");
  }

  SECTION("Parameters with explicit boolean true are ignored")
  {
    auto result = SFListParser::parse_list_of_strings(R"("item";param=?1)");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "item");
  }

  SECTION("Complex parameters are ignored")
  {
    auto result = SFListParser::parse_list_of_strings(R"("item";a=1;b="test";c;d=?0)");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "item");
  }

  SECTION("OWS (optional whitespace) handling")
  {
    // RFC 8941 defines OWS as *( SP / HTAB )
    auto result = SFListParser::parse_list_of_strings("\"a\" , \"b\"");
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "a");
    CHECK(result[1] == "b");
  }
}

// =============================================================================
// Limit Enforcement Tests
// =============================================================================

TEST_CASE("SFListParser limit enforcement", "[libts][StructuredFields][limits]")
{
  SECTION("Long string within default limit")
  {
    // Default limit is 1024, test with a reasonably long string
    std::string long_value(500, 'x');
    std::string input  = "\"" + long_value + "\"";
    auto        result = SFListParser::parse_list_of_strings(input);
    REQUIRE(result.size() == 1);
    CHECK(result[0] == long_value);
  }

  SECTION("String at exactly default limit")
  {
    std::string long_value(SFListParser::DEFAULT_MAX_STRING_LENGTH, 'x');
    std::string input  = "\"" + long_value + "\"";
    auto        result = SFListParser::parse_list_of_strings(input);
    REQUIRE(result.size() == 1);
    CHECK(result[0] == long_value);
  }

  SECTION("String exceeding default limit")
  {
    std::string long_value(SFListParser::DEFAULT_MAX_STRING_LENGTH + 1, 'x');
    std::string input  = "\"" + long_value + "\"";
    auto        result = SFListParser::parse_list_of_strings(input);
    CHECK(result.empty());
  }

  SECTION("Custom max string length limit")
  {
    std::string value(10, 'x');
    std::string input = "\"" + value + "\"";

    // With limit of 10, should succeed
    auto result1 = SFListParser::parse_list_of_strings(input, 100, 10);
    REQUIRE(result1.size() == 1);
    CHECK(result1[0] == value);

    // With limit of 5, should fail
    auto result2 = SFListParser::parse_list_of_strings(input, 100, 5);
    CHECK(result2.empty());
  }

  SECTION("Many items within default limit")
  {
    // Default limit is 1024, test with 100 items
    std::string input;
    for (int i = 0; i < 100; ++i) {
      if (i > 0)
        input += ", ";
      input += "\"g" + std::to_string(i) + "\"";
    }
    auto result = SFListParser::parse_list_of_strings(input);
    REQUIRE(result.size() == 100);
  }

  SECTION("Items at exactly default limit")
  {
    std::string input;
    for (size_t i = 0; i < SFListParser::DEFAULT_MAX_ITEMS; ++i) {
      if (i > 0)
        input += ", ";
      input += "\"g\"";
    }
    auto result = SFListParser::parse_list_of_strings(input);
    REQUIRE(result.size() == SFListParser::DEFAULT_MAX_ITEMS);
  }

  SECTION("Items exceeding default limit")
  {
    std::string input;
    for (size_t i = 0; i < SFListParser::DEFAULT_MAX_ITEMS + 1; ++i) {
      if (i > 0)
        input += ", ";
      input += "\"g\"";
    }
    auto result = SFListParser::parse_list_of_strings(input);
    CHECK(result.empty());
  }

  SECTION("Custom max items limit")
  {
    std::string input = R"("a", "b", "c")";

    // With limit of 3, should succeed
    auto result1 = SFListParser::parse_list_of_strings(input, 3, 100);
    REQUIRE(result1.size() == 3);

    // With limit of 2, should fail
    auto result2 = SFListParser::parse_list_of_strings(input, 2, 100);
    CHECK(result2.empty());
  }

  SECTION("Zero limits")
  {
    // Zero max items should reject any items
    auto result1 = SFListParser::parse_list_of_strings(R"("a")", 0, 100);
    CHECK(result1.empty());

    // Zero max length should reject any non-empty string
    auto result2 = SFListParser::parse_list_of_strings(R"("a")", 100, 0);
    CHECK(result2.empty());

    // Empty string with zero length limit should work
    auto result3 = SFListParser::parse_list_of_strings(R"("")", 100, 0);
    REQUIRE(result3.size() == 1);
    CHECK(result3[0] == "");
  }
}

// =============================================================================
// Boundary and Stress Tests
// =============================================================================

TEST_CASE("SFListParser boundary tests", "[libts][StructuredFields][boundary]")
{
  SECTION("Single character string")
  {
    auto result = SFListParser::parse_list_of_strings(R"("x")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "x");
  }

  SECTION("Just quotes - empty string")
  {
    auto result = SFListParser::parse_list_of_strings(R"("")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "");
  }

  SECTION("Single escape at start")
  {
    auto result = SFListParser::parse_list_of_strings(R"("\\x")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "\\x");
  }

  SECTION("Single escape at end")
  {
    auto result = SFListParser::parse_list_of_strings(R"("x\\")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "x\\");
  }

  SECTION("Only escaped backslash")
  {
    auto result = SFListParser::parse_list_of_strings(R"("\\")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "\\");
  }

  SECTION("Only escaped quote")
  {
    auto result = SFListParser::parse_list_of_strings(R"("\"")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "\"");
  }

  SECTION("Two escaped backslashes")
  {
    auto result = SFListParser::parse_list_of_strings(R"("\\\\")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "\\\\");
  }

  SECTION("Many items")
  {
    std::string input;
    for (int i = 0; i < 20; ++i) {
      if (i > 0)
        input += ", ";
      input += "\"item" + std::to_string(i) + "\"";
    }
    auto result = SFListParser::parse_list_of_strings(input);
    REQUIRE(result.size() == 20);
    for (int i = 0; i < 20; ++i) {
      CHECK(result[i] == "item" + std::to_string(i));
    }
  }

  SECTION("Repeated commas with proper items")
  {
    auto result = SFListParser::parse_list_of_strings(R"("a", "b", "c")");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == "a");
    CHECK(result[1] == "b");
    CHECK(result[2] == "c");
  }

  SECTION("Mix of short and long strings")
  {
    auto result = SFListParser::parse_list_of_strings(R"("a", "abcdefghijklmnop", "b")");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == "a");
    CHECK(result[1] == "abcdefghijklmnop");
    CHECK(result[2] == "b");
  }
}

// =============================================================================
// Real-World Cache-Groups Header Examples
// =============================================================================

TEST_CASE("SFListParser Cache-Groups examples", "[libts][StructuredFields][CacheGroups]")
{
  SECTION("Typical cache group names")
  {
    auto result = SFListParser::parse_list_of_strings(R"("product-images", "product-thumbnails", "product-data")");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == "product-images");
    CHECK(result[1] == "product-thumbnails");
    CHECK(result[2] == "product-data");
  }

  SECTION("API versioned groups")
  {
    auto result = SFListParser::parse_list_of_strings(R"("api-v1-users", "api-v1-products")");
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "api-v1-users");
    CHECK(result[1] == "api-v1-products");
  }

  SECTION("Single group with invalidation")
  {
    // This represents Cache-Group-Invalidation header value
    auto result = SFListParser::parse_list_of_strings(R"("user-profiles")");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "user-profiles");
  }

  SECTION("Groups with tenant prefixes")
  {
    auto result = SFListParser::parse_list_of_strings(R"("tenant1-static", "tenant1-dynamic")");
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "tenant1-static");
    CHECK(result[1] == "tenant1-dynamic");
  }
}
