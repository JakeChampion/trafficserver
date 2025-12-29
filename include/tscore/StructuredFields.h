/** @file

  RFC 8941 Structured Fields parser for Cache-Groups header support.

  This implements a minimal subset of RFC 8941 Structured Fields parsing,
  specifically for parsing a list of strings as required by the Cache Groups
  specification.

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

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstddef>

/**
 * @brief RFC 8941 Structured Fields parser for list of strings.
 *
 * This class provides parsing capabilities for RFC 8941 Structured Field Values,
 * specifically for the List type containing String members as used by the
 * Cache-Groups header.
 *
 * The parser handles:
 * - Quoted strings with escape sequences (\\ and \")
 * - Optional parameters on list members (which are ignored)
 * - Optional whitespace (OWS) around list items
 *
 * Per RFC 8941, malformed input results in an empty vector being returned.
 *
 * Example input: "group1", "group2", "group3"
 */
class SFListParser
{
public:
  /**
   * @brief Default maximum number of items in a list.
   *
   * Per RFC 8941 Section 4.2, implementations should limit the number of
   * items in a list to protect against resource exhaustion attacks.
   */
  static constexpr size_t DEFAULT_MAX_ITEMS = 1024;

  /**
   * @brief Default maximum length of a string value.
   *
   * Per RFC 8941 Section 4.2, implementations should limit the length of
   * strings to protect against resource exhaustion attacks.
   */
  static constexpr size_t DEFAULT_MAX_STRING_LENGTH = 1024;

  /**
   * @brief Parse a structured field list of strings.
   *
   * Parses input according to RFC 8941 as a List containing String members.
   * Parameters on list members are parsed and ignored.
   *
   * @param input The input string to parse.
   * @param max_items Maximum number of items allowed (default: 1024).
   * @param max_string_length Maximum length of each string (default: 1024).
   * @return A vector of parsed strings, or an empty vector if parsing fails.
   */
  static std::vector<std::string> parse_list_of_strings(std::string_view input, size_t max_items = DEFAULT_MAX_ITEMS,
                                                        size_t max_string_length = DEFAULT_MAX_STRING_LENGTH);

private:
  /**
   * @brief Internal parser state.
   */
  struct ParseState {
    std::string_view input;
    size_t           pos{0};
    size_t           max_items;
    size_t           max_string_length;

    explicit ParseState(std::string_view in, size_t max_i, size_t max_s) : input(in), max_items(max_i), max_string_length(max_s) {}

    bool
    at_end() const
    {
      return pos >= input.size();
    }

    char
    peek() const
    {
      return at_end() ? '\0' : input[pos];
    }

    char
    consume()
    {
      return at_end() ? '\0' : input[pos++];
    }

    void
    skip_ows()
    {
      while (!at_end() && (input[pos] == ' ' || input[pos] == '\t')) {
        ++pos;
      }
    }

    void
    skip_sp()
    {
      while (!at_end() && input[pos] == ' ') {
        ++pos;
      }
    }
  };

  // Parsing helper methods
  static bool           parse_list(ParseState &state, std::vector<std::string> &result);
  static bool           parse_list_member(ParseState &state, std::vector<std::string> &result);
  static bool           parse_item(ParseState &state, std::string &value);
  static bool           parse_bare_item(ParseState &state, std::string &value);
  static bool           parse_string(ParseState &state, std::string &value);
  static bool           parse_parameters(ParseState &state);
  static bool           parse_parameter(ParseState &state);
  static bool           parse_key(ParseState &state);
  static bool           skip_bare_item(ParseState &state);
  static constexpr bool is_lcalpha(char c);
  static constexpr bool is_tchar(char c);
};
