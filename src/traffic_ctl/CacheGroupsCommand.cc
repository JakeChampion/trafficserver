/** @file

  Cache Groups CLI commands for traffic_ctl.

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

#include "CacheGroupsCommand.h"
#include "jsonrpc/CtrlRPCRequests.h"
#include "jsonrpc/ctrl_yaml_codecs.h"

CacheGroupsCommand::CacheGroupsCommand(ts::Arguments *args) : CtrlCommand(args)
{
  BasePrinter::Options printOpts{parse_print_opts(args)};

  if (get_parsed_arguments()->get(LIST_STR)) {
    _printer      = std::make_unique<CacheGroupsListPrinter>(printOpts);
    _invoked_func = [&]() { groups_list(); };
  } else if (get_parsed_arguments()->get(SHOW_STR)) {
    _printer      = std::make_unique<CacheGroupsShowPrinter>(printOpts);
    _invoked_func = [&]() { groups_show(); };
  } else if (get_parsed_arguments()->get(INVALIDATE_STR)) {
    _printer      = std::make_unique<CacheGroupsInvalidatePrinter>(printOpts);
    _invoked_func = [&]() { groups_invalidate(); };
  } else if (get_parsed_arguments()->get(STATS_STR)) {
    _printer      = std::make_unique<CacheGroupsStatsPrinter>(printOpts);
    _invoked_func = [&]() { groups_stats(); };
  }
}

void
CacheGroupsCommand::groups_list()
{
  CacheGroupsListRequest::Params params;
  if (auto origin = get_parsed_arguments()->get(ORIGIN_STR); origin) {
    params.origin = origin.value();
  }

  CacheGroupsListRequest       request{params};
  shared::rpc::JSONRPCResponse response = invoke_rpc(request);
  _printer->write_output(response);
}

void
CacheGroupsCommand::groups_show()
{
  auto const &data = get_parsed_arguments()->get(SHOW_STR);

  CacheGroupsShowRequest::Params params;
  params.group_name = data.value();

  if (auto origin = get_parsed_arguments()->get(ORIGIN_STR); origin) {
    params.origin = origin.value();
  }

  CacheGroupsShowRequest       request{params};
  shared::rpc::JSONRPCResponse response = invoke_rpc(request);
  _printer->write_output(response);
}

void
CacheGroupsCommand::groups_invalidate()
{
  auto const &data = get_parsed_arguments()->get(INVALIDATE_STR);

  CacheGroupsInvalidateRequest::Params params;
  params.group_name = data.value();

  if (auto origin = get_parsed_arguments()->get(ORIGIN_STR); origin) {
    params.origin = origin.value();
  }

  CacheGroupsInvalidateRequest request{params};
  shared::rpc::JSONRPCResponse response = invoke_rpc(request);
  _printer->write_output(response);
}

void
CacheGroupsCommand::groups_stats()
{
  CacheGroupsStatsRequest      request;
  shared::rpc::JSONRPCResponse response = invoke_rpc(request);
  _printer->write_output(response);
}
