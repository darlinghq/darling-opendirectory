project(memberd)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
)

add_compile_options(
	-includestdio.h
	-includeobjc/objc.h
)

add_darling_executable(memberd
	HashTable.c
	Listener.c
	main.c
	MembershipResolver.c
	UDaemonHelpers.c
	UserGroup.c
	#USimpleLog.c
	${CMAKE_CURRENT_BINARY_DIR}/memberdServer.c
	${CMAKE_CURRENT_BINARY_DIR}/memberdUser.c
)
target_link_libraries(memberd DirectoryService)

mig(memberd.defs)

install(TARGETS memberd DESTINATION libexec/darling/usr/sbin)
install(FILES memberd.plist DESTINATION libexec/darling/System/Library/LaunchDaemons)
install(FILES mbr_check_membership.3  mbr_gid_to_uuid.3  mbr_sid_to_uuid.3
	mbr_uid_to_uuid.3  mbr_uuid_to_id.3
	mbr_uuid_to_sid.3 DESTINATION libexec/darling/usr/share/man/man3)
install(FILES memberd.8 DESTINATION libexec/darling/usr/share/man/man8)
