/**
 * @file tests/unit/sds/sds_test_utils.h
 * @brief Shared helpers for secure-desktop-stream tests.
 */
#pragma once

// standard includes
#include <array>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>

// lib includes
#include <openssl/evp.h>

namespace test_utils::sds {
  /**
   * @brief Lowercase hex SHA-256 of a byte string.
   *
   * @param data Bytes.
   * @return 64 hex digits.
   */
  inline std::string sha256_hex(const std::string &data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int length = 0;
    EVP_Digest(data.data(), data.size(), digest.data(), &length, EVP_sha256(), nullptr);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < length; ++i) {
      out.push_back(hex[digest[i] >> 4]);
      out.push_back(hex[digest[i] & 0x0F]);
    }
    return out;
  }

  /**
   * @brief Deterministic pseudo-random bytes.
   *
   * @param size Byte count.
   * @param seed Seed.
   * @return Bytes.
   */
  inline std::string random_bytes(std::size_t size, unsigned seed = 1) {
    std::mt19937 engine {seed};
    std::string out(size, '\0');
    for (auto &c : out) {
      c = static_cast<char>(engine() & 0xFF);
    }
    return out;
  }

  /**
   * @brief Read a whole file.
   *
   * @param path File.
   * @return Contents.
   */
  inline std::string read_file(const std::filesystem::path &path) {
    std::ifstream in {path, std::ios::binary};
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
  }

  /**
   * @brief Write a whole file.
   *
   * @param path File.
   * @param data Contents.
   */
  inline void write_file(const std::filesystem::path &path, const std::string &data) {
    std::ofstream out {path, std::ios::binary | std::ios::trunc};
    out << data;
  }

  /**
   * @brief Fresh, empty scratch directory under the system temp directory.
   *
   * @param prefix Name prefix.
   * @return Absolute path.
   */
  inline std::filesystem::path scratch_dir(const std::string &prefix) {
    std::random_device device;
    const auto path = std::filesystem::temp_directory_path() / (prefix + "_" + std::to_string(device()) + std::to_string(device()));  // NOSONAR(cpp:S5443): test scratch space
    std::filesystem::remove_all(path);
    std::filesystem::create_directories(path);
    std::filesystem::permissions(path, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
    return path;
  }
}  // namespace test_utils::sds
