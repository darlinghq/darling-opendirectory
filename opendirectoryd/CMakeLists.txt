project(OpenDirectory-opendirectoryd)

include_directories(
	include/
)

add_darling_executable(opendirectoryd
	src/main.c
)

install(TARGETS opendirectoryd DESTINATION libexec/darling/usr/libexec)
install(FILES com.apple.opendirectoryd.plist DESTINATION libexec/darling/System/Library/LaunchDaemons)
