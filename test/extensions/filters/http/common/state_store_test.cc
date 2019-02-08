#include <thread>

#include "common/common/assert.h"

#include "extensions/filters/http/common/state_store.h"

#include "test/test_common/simulated_time_system.h"

#include "gtest/gtest.h"
#include "openssl/rand.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class StateCreationLambdaReceiver : public StateStore::StateCreationReceiver {
public:
  StateCreationLambdaReceiver(
      std::function<void(StateStore::state_handle_t, StateStore::StateContext ctx)> onSuccess,
      std::function<void(StateStore::Failure)> onFailure)
      : onSuccess_(onSuccess), onFailure_(onFailure) {}
  virtual ~StateCreationLambdaReceiver() = default;

  virtual void onCreationSuccess(StateStore::state_handle_t handle,
                                 StateStore::StateContext ctx) override {
    onSuccess_(handle, ctx);
  }

  virtual void onCreationFailure(StateStore::Failure failure) override { onFailure_(failure); }

private:
  std::function<void(StateStore::state_handle_t, StateStore::StateContext ctx)> onSuccess_;
  std::function<void(StateStore::Failure)> onFailure_;
};

class StateGetLambdaReceiver : public StateStore::StateGetReceiver {
public:
  StateGetLambdaReceiver(std::function<void(StateStore::StateContext ctx)> onSuccess,
                         std::function<void(StateStore::Failure)> onFailure)
      : onSuccess_(onSuccess), onFailure_(onFailure) {}
  virtual ~StateGetLambdaReceiver() = default;

  virtual void onGetSuccess(StateStore::StateContext ctx) override { onSuccess_(ctx); }

  virtual void onGetFailure(StateStore::Failure failure) override { onFailure_(failure); }

private:
  std::function<void(StateStore::StateContext ctx)> onSuccess_;
  std::function<void(StateStore::Failure)> onFailure_;
};

class StateStoreTest : public ::testing::Test {
public:
  void SetUp() override { store_ = StateStore::create(); }
  StateStorePtr store_;
  Event::SimulatedTimeSystem time_system_;
};

TEST_F(StateStoreTest, create) {
  StateStore::StateContext ctx;
  auto expiry = std::chrono::seconds(10);

  bool failed = false;
  StateStore::state_handle_t handle1 = "";
  StateCreationLambdaReceiver receiver1(
      [&handle1](StateStore::state_handle_t handle, const StateStore::StateContext&) {
        handle1 = handle;
      },
      [&failed](StateStore::Failure) { failed = true; });

  store_->create(ctx, expiry, time_system_, receiver1);
  ASSERT_FALSE(failed);
  ASSERT_NE(handle1, "");

  StateStore::state_handle_t handle2 = "";
  StateCreationLambdaReceiver receiver2(
      [&handle2](StateStore::state_handle_t handle, const StateStore::StateContext&) {
        handle2 = handle;
      },
      [&failed](StateStore::Failure) { failed = true; });

  store_->create(ctx, expiry, time_system_, receiver2);
  ASSERT_FALSE(failed);
  ASSERT_NE(handle2, "");

  EXPECT_NE(handle1, handle2);
};

TEST_F(StateStoreTest, get) {
  // Case 1) get state that exists
  StateStore::StateContext put("idp", "hostname");

  bool failed = false;
  StateStore::state_handle_t handle = "";
  StateCreationLambdaReceiver create_receiver(
      [&handle](StateStore::state_handle_t new_handle, const StateStore::StateContext&) {
        handle = new_handle;
      },
      [&failed](StateStore::Failure) { failed = true; });

  store_->create(put, std::chrono::seconds(10), time_system_, create_receiver);
  ASSERT_FALSE(failed);
  ASSERT_NE(handle, "");

  StateStore::StateContext context;
  StateGetLambdaReceiver get_receiver([&context](StateStore::StateContext ctx) { context = ctx; },
                                      [&failed](StateStore::Failure) { failed = true; });

  store_->get(handle, time_system_, get_receiver);
  ASSERT_FALSE(failed);
  EXPECT_TRUE(put == context);

  // Case 2) get state that does not exist
  store_->get(handle, time_system_, get_receiver);
  ASSERT_TRUE(failed);
  failed = false;

  // Case 3) state has expired
  store_->create(put, std::chrono::seconds(1), time_system_, create_receiver);
  ASSERT_FALSE(failed);

  /* Allow state to expire. */
  time_system_.sleep(std::chrono::seconds(2));
  store_->get(handle, time_system_, get_receiver);
  ASSERT_TRUE(failed);
};

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
