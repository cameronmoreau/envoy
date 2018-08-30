#include <stdexcept>
#include "extensions/filters/http/common/session_manager.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace {
  static const std::string goodKey = "pkb8+yUNwrVoYGaAwU9p/h6Mz0ryYwKoG1Irma6q8UY=";
  static const std::string badKey = "invalid";

  class SessionManagerTest : public ::testing::Test {};

  TEST_F(SessionManagerTest, TestConstructorWithConfig) {
    EXPECT_NO_THROW(SessionManager::Create(goodKey));
    EXPECT_THROW(SessionManager::Create(badKey), std::runtime_error);
  }

TEST_F(SessionManagerTest, TestTokens) {
  auto manager = SessionManager::Create(goodKey);
  auto token1 = manager->CreateToken("something");
  EXPECT_EQ(44, token1.size()); // base64 encoded 32-byte digest
  EXPECT_TRUE(manager->VerifyToken("something", token1));
  EXPECT_FALSE(manager->VerifyToken("somethingelse", token1));
}
} // namespace
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy