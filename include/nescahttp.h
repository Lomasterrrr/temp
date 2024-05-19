/*
 *          NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 *
*/

#ifndef NESCAHTTP_HEADER
#define NESCAHTTP_HEADER

#include "../include/nescadata.h"
#include "../ncsock/include/socket.h"
#include "../ncsock/include/ftp.h"
#include "../ncsock/include/http.h"
#include "nescaopts.h"

#define HTTP_BUFLEN 65535

void prepare_redirect(const char* redirect, char* reshost, char* respath, ssize_t buflen);
void send_http(struct http_request *r, NESCATARGET *t, const std::string& ip,
	       const u16 dstport, const long long timeoutns, long long replytimeoutns, NESCAOPTS *no);

#endif

