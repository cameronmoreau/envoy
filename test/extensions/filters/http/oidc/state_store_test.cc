#include "extensions/filters/http/oidc/state_store.h"
#include "common/common/assert.h"

#include "gtest/gtest.h"
#include "openssl/rand.h"

#include <thread>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {

class StateStoreTest : public ::testing::Test {
 public:
  void SetUp() override {
    store_ = StateStore::create();
  }
  StateStorePtr store_;
};

TEST_F(StateStoreTest, create) {
  StateStore::StateContext ctx;
  auto expiry = std::chrono::seconds(10);
  auto handle1 = store_->create(ctx, expiry);
  auto handle2 = store_->create(ctx, expiry);
  EXPECT_NE(handle1, handle2);
};

TEST_F(StateStoreTest, get) {
  // Case 1) get state that exists
  StateStore::StateContext put("idp", "hostname");
  auto handle = store_->create(put, std::chrono::seconds(10));
  auto expected = store_->get(handle);
  EXPECT_FALSE(expected == store_->end());
  EXPECT_TRUE(put == expected);

  // Case 2) get state that does not exists
  auto missing = store_->get(handle);
  ASSERT_TRUE(missing == store_->end());

  // Case 3) state has expired
  handle = store_->create(put, std::chrono::seconds(1));
  /* Allow state to expire. */
  std::this_thread::__sleep_for(std::chrono::seconds(2), std::chrono::nanoseconds(2));
  auto expired = store_->get(handle);
  ASSERT_TRUE(expired == store_->end());
};

} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
