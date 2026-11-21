/**
 * @file src/sds/clipboard_backend_none.cpp
 * @brief Fallback clipboard backend factory for builds without a platform backend.
 *
 * CMake adds this file only when no `src/platform/<os>/clipboard*.cpp` source is part of the
 * build. On ELF targets the definition is additionally weak, so a platform factory that is linked
 * in under an unexpected file name still wins instead of causing a duplicate symbol.
 */
// local includes
#include "clipboard_backend.h"

namespace sds::clipboard {
#if defined(__GNUC__) && !defined(_WIN32) && !defined(__APPLE__)
  __attribute__((weak))
#endif
  std::unique_ptr<backend_t>
    make_backend() {
    return nullptr;
  }
}  // namespace sds::clipboard
