/*
 * ______  ___            ______
 * ___   |/  /_____ _________  /_
 * __  /|_/ /_  __ `/  ___/_  __ \
 * _  /  / / / /_/ // /__ _  / / /
 * /_/  /_/  \__,_/ \___/ /_/ /_/
 * ________
 * ___  __ \_____ ___________
 * __  /_/ /  __ `/  ___/  _ \
 * _  _, _// /_/ // /__ /  __/
 * /_/ |_| \__,_/ \___/ \___/
 *
 * Mach Race OS X Local Privilege Escalation Exploit
 *
 * Created by reverser on 27/04/15.
 * Copyright (c) fG!, 2015, 2016. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * logging.h
 *
 */

#ifndef server_logging_h
#define server_logging_h

#include <stdio.h>

#define ERROR_MSG(fmt, ...) fprintf(stderr, "[ERROR] " fmt " \n", ## __VA_ARGS__)
#define OUTPUT_MSG(fmt, ...) fprintf(stdout, fmt " \n", ## __VA_ARGS__)
#if DEBUG == 0
#   define DEBUG_MSG(fmt, ...) do {} while (0)
#else
#   define DEBUG_MSG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ## __VA_ARGS__)
#endif

#endif
