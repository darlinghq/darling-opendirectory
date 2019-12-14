project(OpenDirectoryCore)

set(DYLIB_COMPAT_VERSION "1.0.0")
set(DYLIB_CURRENT_VERSION "1.0.0")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_framework(CFOpenDirectory
    FAT
    CURRENT_VERSION
    VERSION "A"
    PARENT "OpenDirectory"
    SOURCES
        CFODContext.c
        CFODNode.c
        CFODQuery.c
        CFODRecord.c
        CFODSession.c
        CFODTrigger.c
        constants.c
        errors.c
        extauth.c
        format.c
        odxpc.c
        rb.c
        transaction.c
    DEPENDENCIES
        system
        CoreFoundation
        opendirectory_internal
        SystemConfiguration
)
