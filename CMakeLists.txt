cmake_minimum_required(VERSION 2.8.9)
project(ircd)

# IncludeOS install location
if (NOT DEFINED ENV{INCLUDEOS_PREFIX})
  set(ENV{INCLUDEOS_PREFIX} /usr/local)
endif()

# Human-readable name of your service
set(SERVICE_NAME "Botan TLS test")

# Name of your service binary
set(BINARY       "botan_tls")

# Maximum memory can be hard-coded into the binary
set(MAX_MEM 100)


# Source files to be linked with OS library parts to form bootable image
set(SOURCES
    service.cpp
  )

# To add your own include paths:
set(LOCAL_INCLUDES 
    "include"
    "$ENV{INCLUDEOS_PREFIX}/includeos/include/botan-2"
    )

# DRIVERS / PLUGINS:
set(DRIVERS
  virtionet
  #vmxnet3
  silent_start
  #heap_debugging
  )

set(LIBRARIES
    "$ENV{INCLUDEOS_PREFIX}/includeos/lib/libbotan-2.a"
    "../../LiveUpdate/build/libliveupdate.a"
    )

# include service build script
include($ENV{INCLUDEOS_PREFIX}/includeos/service.cmake)
