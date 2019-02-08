#include "extensions/filters/http/common/state_store.h"

#include <map>

#include "envoy/common/time.h"
#include "envoy/config/filter/http/oidc/v1alpha/config.pb.h"

#include "common/common/base64.h"
#include "common/common/lock_guard.h"
#include "common/common/thread.h"

#include "extensions/filters/http/common/redis_conn.h"

#include "cpp_redis/core/reply.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class BaseStore : public StateStore {
protected:
  /**
   * Generate a random context handle.
   */
  StateStore::state_handle_t randomHandle() const {
    unsigned char random_data[16];
    int rc = RAND_bytes(random_data, sizeof(random_data));
    ASSERT(rc == 1);
    return Base64Url::encode(reinterpret_cast<char*>(random_data), sizeof(random_data));
  }
};

/**
 * LocalStateStoreImpl implements the StateStore interface.
 */
class LocalStateStoreImpl : public BaseStore {
public:
  /**
   * Create a new state context.
   * @param ctx The context to store.
   * @param expiry The expiration time.
   * @return A handle to the stored state.
   */
  void create(const StateContext& ctx, const std::chrono::seconds& expiry, TimeSource& time_source,
              StateCreationReceiver& receiver) override {
    state_handle_t handle;
    {
      Thread::LockGuard lock(storeMutex_);
      do {
        handle = randomHandle();
      } while (store_.find(handle) != store_.end());
      auto calculated_expiry = time_source.monotonicTime() + expiry;
      ContextWrapper wrapper{ctx, calculated_expiry};
      store_[handle] = wrapper;
    }

    receiver.onCreationSuccess(handle, ctx);
  }

  /**
   * Given a handle, return the stored state or the zero entry if the given
   * handle does not exist.
   * @param handle The handle to the state being stored.
   * @return The found state when the given handle is found else the zero state.
   */
  void get(const StateStore::state_handle_t& handle, TimeSource& time_source,
           StateGetReceiver& receiver) override {
    ContextWrapper ctx;
    if (!get_internal(handle, ctx)) {
      receiver.onGetFailure("Handle not found");
    }
    auto diff =
        std::chrono::duration_cast<std::chrono::seconds>(ctx.expiry_ - time_source.monotonicTime());
    if (diff <= std::chrono::seconds(0)) {
      receiver.onGetFailure("Handle expired");
    }

    receiver.onGetSuccess(ctx.ctx_);
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
 * RedisStateStoreImpl implements the StateStore interface and stores the data in a Redis store.
 */
class RedisStateStoreImpl : public BaseStore {
public:
  RedisStateStoreImpl(
      const ::envoy::config::filter::http::oidc::v1alpha::StateStore::RedisConnection& config,
      Upstream::ClusterManager& cluster_manager)
      : connection_(RedisConnection::create(config, cluster_manager)) {
    connection_->connect();
  }

  ~RedisStateStoreImpl() {}

  void create(const StateContext& ctx, const std::chrono::seconds& expiry, TimeSource&,
              StateCreationReceiver& receiver) override {
    auto handle = randomHandle();
    auto key = std::string("state-context-") + handle;
    auto nonce_b64 =
        Base64::encode(reinterpret_cast<const char*>(ctx.nonce_.Value), sizeof(ctx.nonce_.Value));

    RedisConnectionPtr connection(connection_);

    // First create a hashset to store the data
    connection_->hmset(key, {{"idp", ctx.idp_}, {"hostname", ctx.hostname_}, {"nonce", nonce_b64}},
                       [connection, &receiver, key, expiry, ctx](cpp_redis::reply& reply) {
                         if (!reply.ok()) {
                           receiver.onCreationFailure(reply.error());
                           return;
                         }
                         // Set the expiry on the hashset
                         connection->expire(key, expiry.count(),
                                            [&receiver, key, ctx](cpp_redis::reply& reply) {
                                              if (!reply.ok()) {
                                                receiver.onCreationFailure(reply.error());
                                                return;
                                              }

                                              receiver.onCreationSuccess(key, ctx);
                                            });
                         connection->commit();
                       });
    connection_->commit();
  }

  void get(const StateStore::state_handle_t& handle, TimeSource&,
           StateGetReceiver& receiver) override {
    auto key = std::string("state-context-") + handle;

    RedisConnectionPtr connection(connection_);

    // Get the hashset
    connection->hgetall(key, [connection, key, &receiver](cpp_redis::reply& reply) {
      if (!reply.ok()) {
        receiver.onGetFailure(reply.error());
        return;
      }

      if (!reply.is_array()) {
        receiver.onGetFailure("Unexpected reply type");
        return;
      }

      auto array = reply.as_array();
      if (array.size() % 2 != 0) {
        receiver.onGetFailure("Unexpected element count in reply");
        return;
      }

      // The results are the hashset contents represented as an array of values alternating between
      // keys and values
      StateContext ctx{};
      for (size_t i = 0; i + 1 < array.size(); i += 2) {
        if (!array[i].is_string() || !array[i + 1].is_string()) {
          receiver.onGetFailure("Unexpected element type");
          return;
        }

        auto str = array[i].as_string();
        if (str == "idp") {
          ctx.idp_ = array[i + 1].as_string();
        } else if (str == "hostname") {
          ctx.hostname_ = array[i + 1].as_string();
        } else if (str == "nonce") {
          auto nonce_b64 = array[i + 1].as_string();
          auto nonce = Base64::decode(nonce_b64);

          if (nonce.size() != sizeof(ctx.nonce_.Value)) {
            receiver.onGetFailure("Unexpected nonce size");
            return;
          }

          std::memcpy(ctx.nonce_.Value, nonce.data(), nonce.size());
        } else {
          receiver.onGetFailure("Unexpected hash key in reply");
          return;
        }
      }

      connection->del({key}, [](cpp_redis::reply&) {
        // Ignore deletion failure, as long as we successfully retrieved the value we can continue,
        // and the entry will eventually expire anyway
      });

      receiver.onGetSuccess(ctx);
    });

    connection_->commit();
  }

private:
  RedisConnectionPtr connection_;
};

StateStorePtr
StateStore::create(const ::envoy::config::filter::http::oidc::v1alpha::StateStore& config,
                   Upstream::ClusterManager& cluster_manager) {
  if (config.store_type() == ::envoy::config::filter::http::oidc::v1alpha::StateStore::REDIS) {
    return std::make_shared<RedisStateStoreImpl>(config.redis(), cluster_manager);
  }

  return std::make_shared<LocalStateStoreImpl>();
}

StateStorePtr
StateStore::create(const ::envoy::config::filter::http::oidc::v1alpha::StateStore& config) {
  if (config.store_type() == ::envoy::config::filter::http::oidc::v1alpha::StateStore::REDIS) {
    throw EnvoyException("Redis state store requires cluster manager");
  }

  return std::make_shared<LocalStateStoreImpl>();
}

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy