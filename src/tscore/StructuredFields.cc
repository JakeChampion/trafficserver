/** @file

  RFC 8941 Structured Fields parser implementation.

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
#include "tsutil/DbgCtl.h"

namespace
{
DbgCtl dbg_ctl_cache_groups{"cache_groups"};
} // namespace

std::vector<std::string>
SFListParser::parse_list_of_strings(std::string_view input, size_t max_items, size_t max_string_length)
{
  std::vector<std::string> result;
  ParseState               state(input, max_items, max_string_length);

  // Skip leading OWS (optional whitespace: SP / HTAB)
  state.skip_ows();

  if (state.at_end()) {
    // Empty input is valid - returns empty list
    Dbg(dbg_ctl_cache_groups, "parse_list_of_strings: empty input, returning empty list");
    return result;
  }

  if (!parse_list(state, result)) {
    Dbg(dbg_ctl_cache_groups, "parse_list_of_strings: parse failed at position %zu", state.pos);
    return {};
  }

  // Skip trailing OWS
  state.skip_ows();

  // Per RFC 8941, there should be no remaining input after parsing
  if (!state.at_end()) {
    Dbg(dbg_ctl_cache_groups, "parse_list_of_strings: unexpected trailing content at position %zu", state.pos);
    return {};
  }

  Dbg(dbg_ctl_cache_groups, "parse_list_of_strings: successfully parsed %zu items", result.size());
  return result;
}

bool
SFListParser::parse_list(ParseState &state, std::vector<std::string> &result)
{
  // RFC 8941 Section 4.2.1: Parsing a List
  // list = list-member *( OWS "," OWS list-member )

  // Check limit before parsing first item
  if (state.max_items == 0) {
    Dbg(dbg_ctl_cache_groups, "parse_list: max_items is 0, rejecting list");
    return false;
  }

  if (!parse_list_member(state, result)) {
    return false;
  }

  while (!state.at_end()) {
    // Check for limit before parsing next item
    if (result.size() >= state.max_items) {
      Dbg(dbg_ctl_cache_groups, "parse_list: exceeded max_items limit of %zu", state.max_items);
      return false;
    }

    state.skip_ows();

    if (state.at_end() || state.peek() != ',') {
      break;
    }

    // Consume the comma
    state.consume();

    state.skip_ows();

    if (!parse_list_member(state, result)) {
      return false;
    }
  }

  return true;
}

bool
SFListParser::parse_list_member(ParseState &state, std::vector<std::string> &result)
{
  // RFC 8941 Section 4.2.1.1: Parsing a List Member
  // list-member = sf-item / inner-list
  //
  // For our use case (Cache-Groups), we only need to handle sf-item,
  // specifically strings. Inner lists are not expected.

  std::string value;
  if (!parse_item(state, value)) {
    return false;
  }

  result.push_back(std::move(value));
  return true;
}

bool
SFListParser::parse_item(ParseState &state, std::string &value)
{
  // RFC 8941 Section 4.2.3: Parsing an Item
  // sf-item = bare-item parameters

  if (!parse_bare_item(state, value)) {
    return false;
  }

  // Parse and ignore parameters
  if (!parse_parameters(state)) {
    return false;
  }

  return true;
}

bool
SFListParser::parse_bare_item(ParseState &state, std::string &value)
{
  // RFC 8941 Section 4.2.3.1: Parsing a Bare Item
  // bare-item = sf-integer / sf-decimal / sf-string / sf-token / sf-binary / sf-boolean
  //
  // For Cache-Groups, we only expect strings (quoted).

  if (state.at_end()) {
    return false;
  }

  char c = state.peek();
  if (c == '"') {
    return parse_string(state, value);
  }

  // For our use case, we only support strings
  Dbg(dbg_ctl_cache_groups, "parse_bare_item: expected string (quoted), got '%c'", c);
  return false;
}

bool
SFListParser::parse_string(ParseState &state, std::string &value)
{
  // RFC 8941 Section 4.2.5: Parsing a String
  // sf-string = DQUOTE *chr DQUOTE
  // chr       = unescaped / escaped
  // unescaped = %x20-21 / %x23-5B / %x5D-7E
  // escaped   = "\" ( DQUOTE / "\" )

  if (state.at_end() || state.peek() != '"') {
    return false;
  }

  // Consume opening quote
  state.consume();

  value.clear();

  while (!state.at_end()) {
    char c = state.consume();

    if (c == '"') {
      // End of string
      if (value.size() > state.max_string_length) {
        Dbg(dbg_ctl_cache_groups, "parse_string: string length %zu exceeds max of %zu", value.size(), state.max_string_length);
        return false;
      }
      return true;
    }

    if (c == '\\') {
      // Escape sequence
      if (state.at_end()) {
        Dbg(dbg_ctl_cache_groups, "parse_string: incomplete escape sequence at end of input");
        return false;
      }
      char escaped = state.consume();
      if (escaped != '"' && escaped != '\\') {
        Dbg(dbg_ctl_cache_groups, "parse_string: invalid escape sequence \\%c", escaped);
        return false;
      }
      value += escaped;
    } else if (c >= 0x20 && c <= 0x7E && c != '"' && c != '\\') {
      // Valid unescaped character (printable ASCII except quote and backslash)
      value += c;
    } else {
      // Invalid character in string
      Dbg(dbg_ctl_cache_groups, "parse_string: invalid character 0x%02x in string", static_cast<unsigned char>(c));
      return false;
    }

    // Check length limit during parsing to fail early on very long strings
    if (value.size() > state.max_string_length) {
      Dbg(dbg_ctl_cache_groups, "parse_string: string length exceeds max of %zu", state.max_string_length);
      return false;
    }
  }

  // Reached end without closing quote
  Dbg(dbg_ctl_cache_groups, "parse_string: unterminated string");
  return false;
}

bool
SFListParser::parse_parameters(ParseState &state)
{
  // RFC 8941 Section 4.2.3.2: Parsing Parameters
  // parameters = *( ";" *SP parameter )

  while (!state.at_end() && state.peek() == ';') {
    // Consume semicolon
    state.consume();

    // Skip SP (not OWS - only space allowed before parameter)
    state.skip_sp();

    if (!parse_parameter(state)) {
      return false;
    }
  }

  return true;
}

bool
SFListParser::parse_parameter(ParseState &state)
{
  // RFC 8941 Section 4.2.3.2: parameter = param-key [ "=" param-value ]
  // param-key   = key
  // param-value = bare-item

  if (!parse_key(state)) {
    return false;
  }

  if (!state.at_end() && state.peek() == '=') {
    // Consume equals sign
    state.consume();

    // Skip the bare-item value (we ignore parameter values)
    if (!skip_bare_item(state)) {
      return false;
    }
  }
  // If no '=', the parameter value defaults to Boolean true (which we ignore)

  return true;
}

bool
SFListParser::parse_key(ParseState &state)
{
  // RFC 8941 Section 4.2.3.3: Parsing a Key
  // key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
  // lcalpha = %x61-7A ; a-z

  if (state.at_end()) {
    return false;
  }

  char c = state.peek();
  if (!is_lcalpha(c) && c != '*') {
    return false;
  }

  // Consume first character
  state.consume();

  // Consume remaining key characters
  while (!state.at_end()) {
    c = state.peek();
    if (is_lcalpha(c) || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '*') {
      state.consume();
    } else {
      break;
    }
  }

  return true;
}

bool
SFListParser::skip_bare_item(ParseState &state)
{
  // RFC 8941 Section 4.2.3.1: Parsing a Bare Item
  // We skip over the item value without storing it.

  if (state.at_end()) {
    return false;
  }

  char c = state.peek();

  if (c == '"') {
    // String - skip over it
    state.consume(); // opening quote
    while (!state.at_end()) {
      char sc = state.consume();
      if (sc == '"') {
        return true;
      }
      if (sc == '\\') {
        if (state.at_end()) {
          return false;
        }
        char escaped = state.consume();
        if (escaped != '"' && escaped != '\\') {
          return false;
        }
      } else if (sc < 0x20 || sc > 0x7E) {
        return false;
      }
    }
    return false; // unterminated string
  }

  if (c == ':') {
    // Binary - skip over it
    state.consume(); // opening colon
    while (!state.at_end()) {
      char bc = state.peek();
      if (bc == ':') {
        state.consume();
        return true;
      }
      // Base64 alphabet: A-Z, a-z, 0-9, +, /, =
      if ((bc >= 'A' && bc <= 'Z') || (bc >= 'a' && bc <= 'z') || (bc >= '0' && bc <= '9') || bc == '+' || bc == '/' || bc == '=') {
        state.consume();
      } else {
        return false;
      }
    }
    return false; // unterminated binary
  }

  if (c == '?') {
    // Boolean: ?0 or ?1
    state.consume();
    if (!state.at_end()) {
      char bc = state.peek();
      if (bc == '0' || bc == '1') {
        state.consume();
        return true;
      }
    }
    return false;
  }

  if (c == '-' || (c >= '0' && c <= '9')) {
    // Integer or Decimal
    if (c == '-') {
      state.consume();
      if (state.at_end()) {
        return false;
      }
    }
    // Consume digits
    bool has_dot = false;
    while (!state.at_end()) {
      char nc = state.peek();
      if (nc >= '0' && nc <= '9') {
        state.consume();
      } else if (nc == '.' && !has_dot) {
        has_dot = true;
        state.consume();
      } else {
        break;
      }
    }
    return true;
  }

  if (is_tchar(c) || c == '*') {
    // Token
    while (!state.at_end()) {
      char tc = state.peek();
      if (is_tchar(tc) || tc == ':' || tc == '/') {
        state.consume();
      } else {
        break;
      }
    }
    return true;
  }

  return false;
}

constexpr bool
SFListParser::is_lcalpha(char c)
{
  return c >= 'a' && c <= 'z';
}

constexpr bool
SFListParser::is_tchar(char c)
{
  // RFC 7230 tchar: token characters
  // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
  //         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
  if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
    return true;
  }
  switch (c) {
  case '!':
  case '#':
  case '$':
  case '%':
  case '&':
  case '\'':
  case '*':
  case '+':
  case '-':
  case '.':
  case '^':
  case '_':
  case '`':
  case '|':
  case '~':
    return true;
  default:
    return false;
  }
}
