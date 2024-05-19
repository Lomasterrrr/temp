/*
 *          NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef NESCALOG_HEADER
#define NESCALOG_HEADER

#include <iostream>
#include <cstdarg>
#include <fstream>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <regex>
#include <sstream>
#include <cstdarg>
#include <chrono>
#include <stdio.h>
#include <vector>

#include "../ncsock/include/types.h"
#include "../ncsock/include/utils.h"
#include "nescadata.h"
#include "nescaengine.h"
#include "nescaopts.h"

#define checkroot() (geteuid() == 0)
#define enclose(str) ("'" + str + "'")

extern const char *nescalogpath;

void nescalog(const char *p, const char *fmt, ...);
void nescahdrlog(const std::string &dst, const std::string &dns, double rtt);
void nescacontentlog(const std::string & title, const std::string &content);
void nescaerrlog(const std::string &err);
void nescarunlog(const std::string &version);
void nescaendlog(ssize_t success);
void nescausage(char **argv);
void nescapktlog(const u8 *pkt, u32 len, NESCAOPTS *no);

std::string portblock(NESCATARGET *t, NESCAOPTS *no);
std::string passblock(std::vector<std::string> login, std::vector<std::string> pass);
std::string identblock(NESCATARGET *t, NESCAOPTS *no);
std::string join(const std::vector<std::string> &vec, const std::string &del);

#endif
