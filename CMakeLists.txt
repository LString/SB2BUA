# CMakeList.txt: sb2bua 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

project ("sb2bua")

set(SURFFIX "")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if (WIN32)
  include_directories(
    "F:/wg/voip/pjproject-2.15.1/pjsip/include"
    "F:/wg/voip/pjproject-2.15.1/pjlib/include"
    "F:/wg/voip/pjproject-2.15.1/pjlib-util/include"
    "F:/wg/voip/pjproject-2.15.1/pjmedia/include"
    "F:/wg/voip/openssl-openssl-3.6.0/include"
    "F:/wg/voip/pjproject-2.15.1/pjnath/include"
  )

  link_directories(
    "f:/wg/voip/pjproject-2.15.1/lib"
    "f:/wg/voip/pjproject-2.15.1/pjsip/lib"
    "f:/wg/voip/pjproject-2.15.1/pjlib/lib"
    "f:/wg/voip/pjproject-2.15.1/pjmedia/lib"
    "f:/wg/voip/pjproject-2.15.1/pjlib-util/lib"
    "f:/wg/voip/pjproject-2.15.1/pjnath/lib"
    "f:/wg/voip/pjproject-2.15.1/third_party/lib"
    "f:/wg/voip/openssl-openssl-3.6.0/"
  )

  #set(SURFFIX "-x86_64-x64-vc14-Debug-Static")
  set(SURFFIX "-x86_64-x64-vc14-Debug")

  set(PJPROJECT_LIBS
    libpjproject${SURFFIX}
    pjlib-util${SURFFIX}
    pjlib${SURFFIX}
    pjmedia${SURFFIX}
    #opus${SURFFIX}
    pjmedia-codec${SURFFIX}
    pjmedia-audiodev${SURFFIX}
    pjnath${SURFFIX}
    pjsip-core${SURFFIX}
    pjsip-simple${SURFFIX}
  )
  set(PLATFORM_EXTRA_LIBS Crypt32 ws2_32 Threads::Threads)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(PJ REQUIRED libpjproject QUIET)
  if (NOT PJ_FOUND)
    pkg_check_modules(PJ REQUIRED pjproject)
  endif()

  include_directories(${PJ_INCLUDE_DIRS})
  link_directories(${PJ_LIBRARY_DIRS})
  add_definitions(${PJ_CFLAGS_OTHER})

  set(PJPROJECT_LIBS ${PJ_LIBRARIES})
  set(PLATFORM_EXTRA_LIBS Threads::Threads)
endif()

# 将源代码添加到此项目的可执行文件。
add_executable (sb2bua "sb2bua.h"
"sb2bua.cpp"
"uasess.h"
"uasess.cpp"
"ciphers.h"
"ciphers.cpp"
"commons.h"
"mediaplayer.h"
"mediaplayer.cpp" "config.h" "config.cpp")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET sb2bua PROPERTY CXX_STANDARD 20)
endif()

target_link_libraries(sb2bua
  ${PJPROJECT_LIBS}
  OpenSSL::Crypto
  ${PLATFORM_EXTRA_LIBS}
)

##################################
##      测试工程
##################################
add_definitions(-D_UNIT_TEST_)
add_executable (unit_test "test.cpp"
"ciphers.h"
"ciphers.cpp"
"config.cpp"
)

target_link_libraries(unit_test
  ${PJPROJECT_LIBS}
  OpenSSL::Crypto
  ${PLATFORM_EXTRA_LIBS}
)


# TODO: 如有需要，请添加测试并安装目标。
