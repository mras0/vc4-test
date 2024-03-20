cmake_minimum_required(VERSION 3.14)
project(vc4-test C)

find_program(VC4_GCC vc4-elf-gcc)
if (NOT VC4_GCC)
    message(FATAL_ERROR "vc4-elf-gcc not found")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall -Wextra -Wno-pointer-sign")

set(VC4_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/vc4-code.c
	)

add_custom_command(
    OUTPUT code.elf
	COMMAND ${VC4_GCC} -std=gnu11 -Wall -Wextra -falign-functions=4 -O3 -Wl,-q -Wl,-N -ffreestanding -nostdlib -nostartfiles -o code.elf ${VC4_SOURCES}
	DEPENDS ${VC4_SOURCES}
    )
add_custom_target(code_elf DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/code.elf)

if (${CMAKE_SYSTEM_NAME} STREQUAL "AmigaOS")
	message(STATUS "Amiga!")
	set(PLATFORM_FILES platform/amiga/vc4.c)
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "armv7l")
	message(STATUS "Assuming rasperrypi")
	set(PLATFORM_FILES platform/rpi/mailbox.c platform/rpi/vc4.c)
else()
	message(WARNING "Unknown platform")
	set(PLATFORM_FILES platform/dummy/vc4.c)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(vc4-test main.c ${PLATFORM_FILES})
add_dependencies(vc4-test code_elf)
