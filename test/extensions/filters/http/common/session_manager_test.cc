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
static const std::string invalidEncodedToken = "invalid+token/encoding";
static const std::string invalidLengthToken = "AAAAAAAA";

class SessionManagerTest : public ::testing::Test {};

TEST_F(SessionManagerTest, TestConstructor) {
  EXPECT_NO_THROW(SessionManager::Create(goodKey));
  EXPECT_THROW(SessionManager::Create(badKey), std::runtime_error);
}

TEST_F(SessionManagerTest, TestTokens) {
  auto manager = SessionManager::Create(goodKey);
  auto token1 = manager->CreateToken("something");
  auto token2 = manager->CreateToken("somethingelse");
  // base64url encoded 32-byte digest, 43 characters not including null terminator.
  EXPECT_EQ(43, token1.size());
  EXPECT_EQ(43, token2.size());
  EXPECT_FALSE(manager->VerifyToken("something", invalidEncodedToken));
  EXPECT_FALSE(manager->VerifyToken("something", invalidLengthToken));
  EXPECT_TRUE(manager->VerifyToken("something", token1));
  EXPECT_TRUE(manager->VerifyToken("somethingelse", token2));
  EXPECT_FALSE(manager->VerifyToken("something", token2));
  EXPECT_FALSE(manager->VerifyToken("somethingelse", token1));
}
} // namespace
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy