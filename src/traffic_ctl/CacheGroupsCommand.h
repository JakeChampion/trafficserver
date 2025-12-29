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

#pragma once

#include "CtrlCommands.h"

// Forward declarations for printers
class CacheGroupsListPrinter;
class CacheGroupsShowPrinter;
class CacheGroupsInvalidatePrinter;
class CacheGroupsStatsPrinter;

/// @brief Cache Groups command implementation for traffic_ctl cache groups subcommands.
class CacheGroupsCommand : public CtrlCommand
{
public:
  CacheGroupsCommand(ts::Arguments *args);

private:
  static inline const std::string LIST_STR{"list"};
  static inline const std::string SHOW_STR{"show"};
  static inline const std::string INVALIDATE_STR{"invalidate"};
  static inline const std::string STATS_STR{"stats"};
  static inline const std::string ORIGIN_STR{"origin"};

  void groups_list();
  void groups_show();
  void groups_invalidate();
  void groups_stats();
};
