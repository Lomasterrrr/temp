/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef SMTP_H
#define SMTP_H

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "../ncsock-config.h"
#include "sys/types.h"
#include "sys/nethdrs.h"

/* SMTP Response codes */
#define SMTP_REPLY_READY           220
#define SMTP_REPLY_COMPLETED       250
#define SMTP_REPLY_STARTTLS        220
#define SMTP_REPLY_AUTH_REQUIRED   334
#define SMTP_REPLY_AUTH_SUCCESS    235
#define SMTP_REPLY_AUTH_FAILED     535
#define SMTP_REPLY_MAIL_OKAY       250
#define SMTP_REPLY_RCPT_OKAY       250
#define SMTP_REPLY_DATA_OKAY       354
#define SMTP_REPLY_QUIT_OKAY       221
#define SMTP_REPLY_SERVER_ERROR    421
#define SMTP_REPLY_COMMAND_ERROR   500
#define SMTP_REPLY_AUTH_DISABLE    503
#define SMTP_REPLY_PARAM_ERROR     501
#define SMTP_REPLY_AUTH_ERROR      535
#define SMTP_REPLY_TRANSACTION_FAILED 554

__BEGIN_DECLS

void smtp_qprc_version(const char* dst, u16 dstport, long long timeoutns,
    u8* verbuf, size_t buflen);

__END_DECLS

#endif
