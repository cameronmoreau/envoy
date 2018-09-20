#pragma once

#include <chrono>
#include <cstring>
#include <memory>
#include <string>

#include "envoy/common/pure.h"

#include "openssl/crypto.h"

// TODO: We need to clear up expired states asynchronously somewhere.
namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {
class StateStore;
typedef std::shared_ptr<StateStore> StateStorePtr;

class StateStore {
public:
  typedef std::string state_handle_t;
  struct StateContext {
    typedef uint8_t Nonce[32];
    std::string idp_;
    std::string hostname_;
    Nonce nonce_{};

    StateContext() {}
    StateContext(const std::string& idp, const std::string& hostname,
                 const StateContext::Nonce& nonce)
        : idp_(idp), hostname_(hostname) {
      std::memcpy(nonce_, nonce, sizeof(nonce_));
    }

    bool operator==(const StateContext& rhs) const {
      return CRYPTO_memcmp(nonce_, rhs.nonce_, sizeof(StateContext::Nonce)) == 0;
    }
  };
  /**
   * unknown state identifier.
   * @return the identity of the unknown state.
   */
  virtual const StateContext& end() const PURE;

  virtual ~StateStore(){};
  /**
   * create stores the given ctx parameter returning a handle that can be used to retrieve it later.
   * @param ctx the state to store.
   * @param expiry the expiration of the state.
   * @return a handle to the state stored.
   */
  virtual state_handle_t create(const StateContext& ctx, const std::chrono::seconds& expiry) PURE;
  /**
   * get returns the state for the given handle and removing it from the state store.
   * If no state is associated with the given handle, the returned value will be equal to the result
   * of end().
   * @param handle the handle to the stored state.
   * @return the state context associated with the handle.
   */
  virtual StateContext get(const state_handle_t& handle) PURE;

  /**
   * Create an instance of a StateStore.
   * @return An instance of a StateStore.
   */
  static StateStorePtr create();
};
} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
