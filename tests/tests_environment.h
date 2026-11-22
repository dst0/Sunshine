/**
 * @file tests/tests_environment.h
 * @brief Declarations for SunshineEnvironment.
 */
#pragma once

// test includes
#include "tests_common.h"

struct SunshineEnvironment: testing::Environment {
  void SetUp() override {
    mail::man = std::make_shared<safe::mail_raw_t>();
#if GTEST_HAS_DEATH_TEST
    // The re-executed death-test child shares the parent's working directory.
    // Initializing its file sink would rotate the log while the parent still writes to it.
    if (!GTEST_FLAG_GET(internal_run_death_test).empty()) {
      return;
    }
#endif
    deinit_log = logging::init(0, "test_sunshine.log");
  }

  void TearDown() override {
    deinit_log = {};
    mail::man = {};
  }

  std::unique_ptr<logging::deinit_t> deinit_log;
};
