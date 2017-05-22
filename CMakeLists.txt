cmake_minimum_required(VERSION 2.8.9)
# IncludeOS install location
if (NOT DEFINED ENV{INCLUDEOS_PREFIX})
  set(ENV{INCLUDEOS_PREFIX} /usr/local)
endif()
include($ENV{INCLUDEOS_PREFIX}/includeos/pre.service.cmake)
project(service)

# Human-readable name of your service
set(SERVICE_NAME "Botan TLS test")

# Name of your service binary
set(BINARY       "botan_tls")

# Source files to be linked with OS library parts to form bootable image
set(SOURCES
    service.cpp
  )

# To add your own include paths:
set(LOCAL_INCLUDES
    "include"
  )

# DRIVERS / PLUGINS:
set(DRIVERS
  virtionet
  #vmxnet3
  silent_start
  #heap_debugging
  )

set(LIBRARIES
    "libbotan-2.a"
    )

# include service build script
include($ENV{INCLUDEOS_PREFIX}/includeos/post.service.cmake)

diskbuilder(drive)
