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

#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <opendirectory/odipc.h>
#include <errno.h>
#include <membership.h>
#include <membershipPriv.h>
#include <pwd.h>

#include "log.h"

#define GET_LOG(_name) os_log_t _name ## _get_log(void) { \
		static dispatch_once_t once_token; \
		static os_log_t log = NULL; \
		dispatch_once(&once_token, ^{ \
			log = os_log_create("com.apple.opendirectoryd", #_name); \
			if (!log) { \
				abort(); \
			} \
		}); \
		return log; \
	};

GET_LOG(general);
GET_LOG(membership);

// ODD = *O*pen*D*irectory*D*

#define ODD_PRIVATE_RPC_SERVICE_NAME "com.apple.private.opendirectoryd.rpc"
#define ODD_LIBINFO_LEGACY_SERVICE_NAME "com.apple.system.DirectoryService.libinfo_v1"
#define ODD_MEMBERSHIP_LEGACY_SERVICE_NAME "com.apple.system.DirectoryService.membership_v1"
#define ODD_API_SERVICE_NAME "com.apple.system.opendirectoryd.api"
#define ODD_LIBINFO_SERVICE_NAME "com.apple.system.opendirectoryd.libinfo"
#define ODD_MEMBERSHIP_SERVICE_NAME "com.apple.system.opendirectoryd.membership"

#define ODD_MEMBERSHIP_CURRENT_RPC_VERSION 2

static dispatch_queue_t membership_service_queue = NULL;
static xpc_connection_t membership_service_listener = NULL;

static void membership_reply_with_error(xpc_object_t incoming_message, int error) {
	xpc_object_t reply = xpc_dictionary_create_reply(incoming_message);
	xpc_dictionary_set_int64(reply, OD_RPC_ERROR, error);
	xpc_connection_send_message(xpc_dictionary_get_remote_connection(incoming_message), reply);
	xpc_release(reply);
};

// copied in from libinfo
static const uuid_t _user_compat_prefix = {0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00};
static const uuid_t _group_compat_prefix = {0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00};
#define COMPAT_PREFIX_LEN	(sizeof(uuid_t) - sizeof(id_t))

static void build_uuid(const uuid_t source, id_t id, uuid_t dest) {
	// adapted from libinfo
	uuid_copy(dest, _user_compat_prefix);
	*((id_t *) &dest[COMPAT_PREFIX_LEN]) = htonl(id);
};

static void rpc_mbr_identifier_translate(xpc_object_t message) {
	int target_type = xpc_dictionary_get_int64(message, "requesting");
	int id_type = xpc_dictionary_get_int64(message, "type");
	size_t identifier_size = 0;
	const void* identifier = xpc_dictionary_get_data(message, "identifier", &identifier_size);


	if (id_type == ID_TYPE_USERNAME && target_type == ID_TYPE_UUID) {
		char tmp_string[256];
		strncpy(tmp_string, identifier, (identifier_size < sizeof(tmp_string)) ? identifier_size : sizeof(tmp_string));
		tmp_string[(identifier_size < sizeof(tmp_string)) ? identifier_size : sizeof(tmp_string) - 1] = '\0';
		struct passwd* pw = getpwnam(tmp_string);

		FILE* logfile = fopen("/tmp/odd.log", "a");
		fprintf(logfile, "name = %s; pw = %p; id length = %zu; id = %*s", tmp_string, pw, identifier_size, (int)identifier_size, (const char*)identifier);
		fclose(logfile);

		if (!pw) {
			membership_reply_with_error(message, EINVAL);
			return;
		}

		uuid_t tmp_uuid;

		build_uuid(_user_compat_prefix, pw->pw_uid, tmp_uuid);

		xpc_object_t reply = xpc_dictionary_create_reply(message);

		xpc_dictionary_set_data(reply, "identifier", tmp_uuid, sizeof(tmp_uuid));
		xpc_dictionary_set_int64(reply, "rectype", MBR_REC_TYPE_USER);

		xpc_dictionary_set_int64(reply, OD_RPC_ERROR, 0);
		xpc_connection_send_message(xpc_dictionary_get_remote_connection(message), reply);
		xpc_release(reply);
	} else {
		membership_reply_with_error(message, ENOSYS);
	}
};

static void rpc_mbr_check_service_membership(xpc_object_t message) {
	int user_id_type = xpc_dictionary_get_int64(message, "user_idtype");
	size_t user_id_size = 0;
	const uint8_t* user_id = xpc_dictionary_get_data(message, "user_id", &user_id_size);
	const char* service = xpc_dictionary_get_string(message, "service");

	if (user_id_type != ID_TYPE_UUID || user_id_size != sizeof(uuid_t)) {
		membership_reply_with_error(message, EINVAL);
		return;
	}

	xpc_object_t reply = xpc_dictionary_create_reply(message);

	// Darling doesn't really need permissions checking since everything happens within a container anyways, so just report that the user is allowed by the service.
	xpc_dictionary_set_bool(reply, "ismember", true);

	xpc_dictionary_set_int64(reply, OD_RPC_ERROR, 0);
	xpc_connection_send_message(xpc_dictionary_get_remote_connection(message), reply);
	xpc_release(reply);
};

static void rpc_mbr_set_identifier_ttl(xpc_object_t message) {
	int id_type = xpc_dictionary_get_int64(message, "type");
	size_t id_size = 0;
	const void* id = xpc_dictionary_get_data(message, "identifier", &id_size);
	unsigned int ttl_seconds = xpc_dictionary_get_int64(message, "ttl");

	// just ignore this and return success

	xpc_object_t reply = xpc_dictionary_create_reply(message);
	xpc_dictionary_set_int64(reply, OD_RPC_ERROR, 0);
	xpc_connection_send_message(xpc_dictionary_get_remote_connection(message), reply);
	xpc_release(reply);
};

static void rpc_mbr_check_membership(xpc_object_t message) {
	int user_id_type = xpc_dictionary_get_int64(message, "user_idtype");
	int group_id_type = xpc_dictionary_get_int64(message, "group_idtype");
	size_t user_id_size = 0;
	const void* user_id = xpc_dictionary_get_data(message, "user_id", &user_id_size);
	size_t group_id_size = 0;
	const void* group_id = xpc_dictionary_get_data(message, "group_id", &group_id_size);
	bool refresh = xpc_dictionary_get_bool(message, "refresh");

	xpc_object_t reply = xpc_dictionary_create_reply(message);

	// TODO: actually implement this
	//
	// While Darling doesn't need permissions checking, it may be useful to correctly determine whether a user is part of a given group.
	xpc_dictionary_set_bool(reply, "ismember", true);

	xpc_dictionary_set_int64(reply, OD_RPC_ERROR, 0);
	xpc_connection_send_message(xpc_dictionary_get_remote_connection(message), reply);
	xpc_release(reply);
};

static void rpc_mbr_cache_flush(xpc_object_t message) {
	// just ignore this and return success

	xpc_object_t reply = xpc_dictionary_create_reply(message);
	xpc_dictionary_set_int64(reply, OD_RPC_ERROR, 0);
	xpc_connection_send_message(xpc_dictionary_get_remote_connection(message), reply);
	xpc_release(reply);
};

static void handle_new_membership_connection(xpc_connection_t connection) {
	xpc_connection_set_event_handler(connection, ^(xpc_object_t object) {
		xpc_type_t type = xpc_get_type(object);

		if (type == XPC_TYPE_DICTIONARY) {
			membership_log_debug("membership connection received dictionary: %@", object);

			int rpc_version = xpc_dictionary_get_int64(object, OD_RPC_VERSION);

			if (rpc_version != ODD_MEMBERSHIP_CURRENT_RPC_VERSION) {
				membership_log_error("invalid RPC version %d in message: %@", rpc_version, object);
				membership_reply_with_error(object, EINVAL);
				return;
			}

			const char* rpc_name = xpc_dictionary_get_string(object, OD_RPC_NAME);

			if (!rpc_name) {
				membership_log_error("no RPC procedure name in message: %@", object);
				membership_reply_with_error(object, EINVAL);
			}

			membership_log_debug("RPC procedure call message: %@", object);

			if (strcmp(rpc_name, "mbr_identifier_translate") == 0) {
				rpc_mbr_identifier_translate(object);
			} else if (strcmp(rpc_name, "mbr_check_service_membership") == 0) {
				rpc_mbr_check_service_membership(object);
			} else if (strcmp(rpc_name, "mbr_set_identifier_ttl") == 0) {
				rpc_mbr_set_identifier_ttl(object);
			} else if (strcmp(rpc_name, "mbr_check_membership") == 0) {
				rpc_mbr_check_membership(object);
			} else if (strcmp(rpc_name, "mbr_cache_flush") == 0) {
				rpc_mbr_cache_flush(object);
			} else {
				membership_log_error("invalid RPC procedure name \"%s\" in message: %@", rpc_name, object);
				membership_reply_with_error(object, EINVAL);
			}
		} else if (type == XPC_TYPE_ERROR) {
			if (object == XPC_ERROR_CONNECTION_INVALID) {
				membership_log_debug("membership connection invalidated");
			} else {
				membership_log_error("membership connection received XPC error: %@", object);
			}
		} else {
			membership_log_error("unknown XPC object received in service listener: %@", object);
		}
	});
	xpc_connection_resume(connection);
};

int main(int argc, char** argv) {
	membership_service_queue = dispatch_queue_create(ODD_MEMBERSHIP_SERVICE_NAME, DISPATCH_QUEUE_CONCURRENT);
	if (!membership_service_queue) {
		abort();
	}

	membership_service_listener = xpc_connection_create_mach_service(ODD_MEMBERSHIP_SERVICE_NAME, membership_service_queue, XPC_CONNECTION_MACH_SERVICE_LISTENER);
	if (!membership_service_listener) {
		abort();
	}

	xpc_connection_set_event_handler(membership_service_listener, ^(xpc_object_t object) {
		xpc_type_t type = xpc_get_type(object);

		if (type == XPC_TYPE_CONNECTION) {
			handle_new_membership_connection(object);
		} else if (type == XPC_TYPE_ERROR) {
			general_log_error("service listener received XPC error: %@", object);
		} else {
			general_log_error("unknown XPC object received in service listener: %@", object);
		}
	});

	xpc_connection_resume(membership_service_listener);

	dispatch_main();
	return 0;
};
