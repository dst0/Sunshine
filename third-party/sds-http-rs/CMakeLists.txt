cmake_minimum_required(VERSION 3.20)
project(sds-http-rs LANGUAGES C CXX)

find_program(
  SDS_HTTP_RS_CARGO_EXECUTABLE
  NAMES cargo
  PATHS ENV CARGO_HOME "/cargo/bin" "$ENV{HOME}/.cargo/bin"
  PATH_SUFFIXES bin
  REQUIRED
)

set(_sds_cargo_cmd "${SDS_HTTP_RS_CARGO_EXECUTABLE}" build --locked)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(_sds_cargo_profile_dir "debug")
else()
  list(APPEND _sds_cargo_cmd "--release")
  set(_sds_cargo_profile_dir "release")
endif()

set(_sds_cargo_target_dir "${CMAKE_CURRENT_BINARY_DIR}/cargo-target")
set(_sds_cargo_env
  "CARGO_TARGET_DIR=${_sds_cargo_target_dir}"
)
set(_sds_cargo_unset "")
set(_sds_rust_target_subdir "")

if(WIN32 AND MINGW)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
    set(_sds_rust_target "aarch64-pc-windows-gnu")
    set(_sds_rust_env_prefix "AARCH64_PC_WINDOWS_GNU")
  else()
    set(_sds_rust_target "x86_64-pc-windows-gnu")
    set(_sds_rust_env_prefix "X86_64_PC_WINDOWS_GNU")
  endif()
  list(APPEND _sds_cargo_cmd "--target" "${_sds_rust_target}")
  set(_sds_rust_target_subdir "${_sds_rust_target}/")
  string(TOLOWER "${_sds_rust_env_prefix}" _sds_cc_env_suffix)

  # Host build scripts / proc-macros must compile with the Linux host C toolchain,
  # never inheriting Windows case-alias C_INCLUDE_PATH / CPLUS_INCLUDE_PATH headers.
  if(CMAKE_CROSSCOMPILING AND CMAKE_HOST_UNIX)
    list(APPEND _sds_cargo_unset
      "--unset=C_INCLUDE_PATH"
      "--unset=CPLUS_INCLUDE_PATH"
    )
    find_program(_sds_host_cc NAMES cc gcc PATHS /usr/bin /bin NO_CMAKE_FIND_ROOT_PATH)
    find_program(_sds_host_cxx NAMES c++ g++ PATHS /usr/bin /bin NO_CMAKE_FIND_ROOT_PATH)
    if(NOT _sds_host_cc)
      set(_sds_host_cc "/usr/bin/cc")
    endif()
    if(NOT _sds_host_cxx)
      set(_sds_host_cxx "/usr/bin/c++")
    endif()
    if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
      set(_sds_host_rust_suffix "aarch64_unknown_linux_gnu")
    else()
      set(_sds_host_rust_suffix "x86_64_unknown_linux_gnu")
    endif()
    string(TOUPPER "${_sds_host_rust_suffix}" _sds_host_rust_upper)
    list(APPEND _sds_cargo_env
      "HOST_CC=${_sds_host_cc}"
      "HOST_CXX=${_sds_host_cxx}"
      "CC_${_sds_host_rust_suffix}=${_sds_host_cc}"
      "CXX_${_sds_host_rust_suffix}=${_sds_host_cxx}"
      "CARGO_TARGET_${_sds_host_rust_upper}_LINKER=${_sds_host_cc}"
    )
  endif()

  if(CMAKE_C_COMPILER)
    list(APPEND _sds_cargo_env
      "CC_${_sds_cc_env_suffix}=${CMAKE_C_COMPILER}"
      "CARGO_TARGET_${_sds_rust_env_prefix}_LINKER=${CMAKE_C_COMPILER}"
    )
  endif()
  if(CMAKE_CXX_COMPILER)
    list(APPEND _sds_cargo_env
      "CXX_${_sds_cc_env_suffix}=${CMAKE_CXX_COMPILER}"
    )
  endif()
  if(CMAKE_AR)
    list(APPEND _sds_cargo_env "AR_${_sds_cc_env_suffix}=${CMAKE_AR}")
  endif()
  if(CMAKE_RANLIB)
    list(APPEND _sds_cargo_env "RANLIB_${_sds_cc_env_suffix}=${CMAKE_RANLIB}")
  endif()
endif()

set(_sds_lib_name "${CMAKE_STATIC_LIBRARY_PREFIX}sds_http_rs${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(_sds_lib_path "${_sds_cargo_target_dir}/${_sds_rust_target_subdir}${_sds_cargo_profile_dir}/${_sds_lib_name}")

file(GLOB_RECURSE _sds_http_rs_sources CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.rs"
  "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
  "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.lock"
)

add_custom_command(
  OUTPUT "${_sds_lib_path}"
  COMMAND ${CMAKE_COMMAND} -E env ${_sds_cargo_unset} ${_sds_cargo_env} ${_sds_cargo_cmd}
  DEPENDS ${_sds_http_rs_sources}
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  COMMENT "Building sds-http-rs Rust HTTP/PQ-TLS static library"
  VERBATIM
)

add_custom_target(sds_http_rs_cargo DEPENDS "${_sds_lib_path}")

add_library(sds_http_rs_static STATIC IMPORTED GLOBAL)
set_target_properties(sds_http_rs_static PROPERTIES
  IMPORTED_LOCATION "${_sds_lib_path}"
)
add_dependencies(sds_http_rs_static sds_http_rs_cargo)

add_library(simple-web-server INTERFACE)
add_dependencies(simple-web-server sds_http_rs_cargo)
target_include_directories(simple-web-server INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

if(WIN32)
  target_link_libraries(simple-web-server INTERFACE
    sds_http_rs_static
    ws2_32
    bcrypt
    userenv
    ntdll
    crypt32
    advapi32
    iphlpapi
  )
elseif(APPLE)
  target_link_libraries(simple-web-server INTERFACE
    sds_http_rs_static
    iconv
    pthread
    dl
    m
  )
else()
  target_link_libraries(simple-web-server INTERFACE
    sds_http_rs_static
    ${CMAKE_DL_LIBS}
    pthread
    m
  )
endif()
