#include "extensions/filters/http/common/state_store.h"

#include <map>

#include "envoy/common/time.h"

#include "common/common/lock_guard.h"
#include "common/common/thread.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace {
StateStore::StateContext unknown_context;
}

/**
 * LocalStateStoreImpl implements the StateStore interface.
 */
class LocalStateStoreImpl : public StateStore {
public:
  LocalStateStoreImpl() {}

  /**
   * Create a new state context.
   * @param ctx The context to store.
   * @param expiry The expiration time.
   * @return A handle to the stored state.
   */
  StateStore::state_handle_t create(const StateContext& ctx, const std::chrono::seconds& expiry,
                                    TimeSource& time_source) override {
    Thread::LockGuard lock(storeMutex_);
    state_handle_t handle;
    do {
      handle = randomHandle();
    } while (store_.find(handle) != store_.end());
    auto calculated_expiry = time_source.monotonicTime() + expiry;
    ContextWrapper wrapper{ctx, calculated_expiry};
    store_[handle] = wrapper;
    return handle;
  }

  const StateContext& end() const override { return unknown_context; }

  /**
   * Given a handle, return the stored state or the zero entry if the given
   * handle does not exist.
   * @param handle The handle to the state being stored.
   * @return The found state when the given handle is found else the zero state.
   */
  StateContext get(const StateStore::state_handle_t& handle, TimeSource& time_source) override {
    ContextWrapper ctx;
    if (!get_internal(handle, ctx)) {
      return end();
    }
    auto diff =
        std::chrono::duration_cast<std::chrono::seconds>(ctx.expiry_ - time_source.monotonicTime());
    if (diff <= std::chrono::seconds(0)) {
      return end();
    }
    return ctx.ctx_;
  }

private:
  struct ContextWrapper {
    StateContext ctx_;
    std::chrono::steady_clock::time_point expiry_;
  };
  typedef std::map<StateStore::state_handle_t, ContextWrapper> Store;
  Store store_;
  Thread::MutexBasicLockable storeMutex_;

  /**
   * Given a handle, return the stored state or the zero entry if the given
   * handle does not exist.
   * @param handle The handle to the state being stored.
   * @param result The container to store the return state.
   * @return True when state is found else false.
   */
  bool get_internal(const StateStore::state_handle_t& handle, ContextWrapper& result) {
    Thread::LockGuard lock(storeMutex_);
    const auto& it = store_.find(handle);
    if (it == store_.end()) {
      return false;
    }
    result = it->second;
    store_.erase(it);
    return true;
  }

  /**
   * Generate a random context handle.
   */
  StateStore::state_handle_t randomHandle() const {
    unsigned char random_data[16];
    int rc = RAND_bytes(random_data, sizeof(random_data));
    ASSERT(rc == 1);
    return Base64Url::encode(reinterpret_cast<char*>(random_data), sizeof(random_data));
  }

  /**
   * Remove any expired state entries.
   */
  void clean(TimeSource& time_source) {
    // TODO (nickrmc83): We need to periodically call this method.
    auto now = time_source.monotonicTime();
    Thread::LockGuard lock(storeMutex_);
    for (auto iter = store_.begin(); iter != store_.end();) {
      if (iter->second.expiry_ > now) {
        iter = store_.erase(iter);
      } else {
        ++iter;
      }
    }
  }
};

/**
 * Create an instance of LocalStateStoreImpl
 * @param time_source the source of required time values.
 * @return The instance.
 */
StateStorePtr StateStore::create() { return std::make_shared<LocalStateStoreImpl>(); }

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy