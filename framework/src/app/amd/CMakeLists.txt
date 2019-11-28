CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)

PROJECT(amd C)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

# Compiler flags
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc)
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wl,-zdefs" )
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fpic")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Werror")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")
SET(CMAKE_SKIP_BUILD_RPATH true)
# Linker flags
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

#################################################################
# Build AMD                                                     #
#################################################################
SET(AMD "amd")
AUX_SOURCE_DIRECTORY(src/amd AMD_SRCS)

INCLUDE(FindPkgConfig)

FOREACH(flag ${AMD_PKGS_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

ADD_EXECUTABLE(${AMD} ${AMD_SRCS})
SET_TARGET_PROPERTIES(${AMD} PROPERTIES COMPILE_FLAGS "${EXTRA_CFLAGS} -fPIE")
TARGET_LINK_LIBRARIES(${AMD} ${AMD_PKGS_LDFLAGS} "-pie -ldl -Wl,-z,relro")
INSTALL(TARGETS ${AMD} DESTINATION bin)

#################################################################
# Build AMD Library                                             #
#################################################################
SET(LIB_AMD "libamd")
AUX_SOURCE_DIRECTORY(src/lib LIB_AMD_SRCS)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc)
SET(HEADERS_LIB_AMD
	amd.h
	amd_api_noti.h
	amd_api_wayland.h
	amd_api_app_status.h
	amd_api_appinfo.h
	amd_api_launch_context.h
	amd_api_app_com.h
	amd_api_request.h
	amd_api_cynara.h
	amd_api_launch.h
	amd_api_launchpad.h
	amd_api_login_monitor.h
	amd_api_suspend.h
	amd_api_signal.h
	amd_api_inotify.h
	amd_api_util.h
	amd_api_socket.h
	amd_api_config.h
	amd_api_proc.h
	amd_api_app_property.h
	)

INCLUDE(FindPkgConfig)

SET(LIB_AMD_PKG_CHECK_MODULES
	dlog
	aul
	glib-2.0
	gio-2.0
	vconf
	pkgmgr-info
	pkgmgr
	bundle
	libsystemd
	cert-svc-vcore
	libtzplatform-config
	ttrace
	app2sd
	capi-system-info
	iniparser
	uuid
	)

PKG_CHECK_MODULES(LIB_AMD_PKGS REQUIRED ${LIB_AMD_PKG_CHECK_MODULES})

FOREACH(flag ${LIB_AMD_PKGS_CFLAGS})
	SET(EXTRA_CFLAGS_LIB_AMD "${EXTRA_CFLAGS_LIB_AMD} ${flag}")
ENDFOREACH(flag)

ADD_LIBRARY(${LIB_AMD} SHARED ${LIB_AMD_SRCS})
SET_TARGET_PROPERTIES(${LIB_AMD} PROPERTIES COMPILE_FLAGS "${EXTRA_CFLAGS_LIB_AMD}")
SET_TARGET_PROPERTIES(${LIB_AMD} PROPERTIES SOVERSION ${MAJORVER})
SET_TARGET_PROPERTIES(${LIB_AMD} PROPERTIES VERSION ${FULLVER})
SET_TARGET_PROPERTIES(${LIB_AMD} PROPERTIES OUTPUT_NAME amd)
TARGET_LINK_LIBRARIES(${LIB_AMD} ${LIB_AMD_PKGS_LDFLAGS})

CONFIGURE_FILE(${LIB_AMD}.pc.in ${AMD}.pc @ONLY)

INSTALL(TARGETS ${LIB_AMD} DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${AMD}.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
FOREACH(hfile ${HEADERS_LIB_AMD})
	INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/inc/${hfile} DESTINATION include/amd)
ENDFOREACH(hfile)

ADD_CUSTOM_TARGET(${LIB_AMD}.so ALL
	COMMAND ${CMAKE_COMMAND} -E create_symlink ${LIB_INSTALL_DIR}/${LIB_AMD}.so.${MAJORVER} ${LIB_AMD}.so)
ADD_DEPENDENCIES(${LIB_AMD}.so ${LIB_AMD})
INSTALL(FILES ${LIB_AMD}.so DESTINATION ${AMD_MODULES_DIR})

ADD_SUBDIRECTORY(modules)
