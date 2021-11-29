/**
 * This file is part of Darling.
 *
 * Copyright (C) 2021 Darling developers
 *
 * Darling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Darling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Darling.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ODD_LOG_H_
#define _ODD_LOG_H_

#include <os/log.h>

os_log_t general_get_log(void);
os_log_t membership_get_log(void);

#define general_log(format, ...)       //os_log_with_type(general_get_log(), OS_LOG_TYPE_DEFAULT, format, ##__VA_ARGS__)
#define general_log_info(format, ...)  //os_log_with_type(general_get_log(),    OS_LOG_TYPE_INFO, format, ##__VA_ARGS__)
#define general_log_debug(format, ...) //os_log_with_type(general_get_log(),   OS_LOG_TYPE_DEBUG, format, ##__VA_ARGS__)
#define general_log_error(format, ...) //os_log_with_type(general_get_log(),   OS_LOG_TYPE_ERROR, format, ##__VA_ARGS__)
#define general_log_fault(format, ...) //os_log_with_type(general_get_log(),   OS_LOG_TYPE_FAULT, format, ##__VA_ARGS__)

#define membership_log(format, ...)       //os_log_with_type(membership_get_log(), OS_LOG_TYPE_DEFAULT, format, ##__VA_ARGS__)
#define membership_log_info(format, ...)  //os_log_with_type(membership_get_log(),    OS_LOG_TYPE_INFO, format, ##__VA_ARGS__)
#define membership_log_debug(format, ...) //os_log_with_type(membership_get_log(),   OS_LOG_TYPE_DEBUG, format, ##__VA_ARGS__)
#define membership_log_error(format, ...) //os_log_with_type(membership_get_log(),   OS_LOG_TYPE_ERROR, format, ##__VA_ARGS__)
#define membership_log_fault(format, ...) //os_log_with_type(membership_get_log(),   OS_LOG_TYPE_FAULT, format, ##__VA_ARGS__)

#endif // _ODD_LOG_H_
