#include <thread>

#include "common/common/assert.h"

#include "extensions/filters/http/oidc/state_store.h"

#include "test/test_common/simulated_time_system.h"

#include "gtest/gtest.h"
#include "openssl/rand.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {

class StateStoreTest : public ::testing::Test {
public:
  void SetUp() override { store_ = StateStore::create(); }
  StateStorePtr store_;
  Event::SimulatedTimeSystem time_system_;
};

TEST_F(StateStoreTest, create) {
  StateStore::StateContext ctx;
  auto expiry = std::chrono::seconds(10);
  auto handle1 = store_->create(ctx, expiry, time_system_);
  auto handle2 = store_->create(ctx, expiry, time_system_);
  EXPECT_NE(handle1, handle2);
};

TEST_F(StateStoreTest, get) {
  // Case 1) get state that exists
  StateStore::StateContext put("idp", "hostname");
  auto handle = store_->create(put, std::chrono::seconds(10), time_system_);
  auto expected = store_->get(handle, time_system_);
  EXPECT_FALSE(expected == store_->end());
  EXPECT_TRUE(put == expected);

  // Case 2) get state that does not exists
  auto missing = store_->get(handle, time_system_);
  ASSERT_TRUE(missing == store_->end());

  // Case 3) state has expired
  handle = store_->create(put, std::chrono::seconds(1), time_system_);
  /* Allow state to expire. */
  time_system_.sleep(std::chrono::seconds(2));
  auto expired = store_->get(handle, time_system_);
  ASSERT_TRUE(expired == store_->end());
};

} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
