#pragma once

#include <chrono>
#include <cstring>
#include <memory>
#include <string>

#include "common/common/assert.h"
#include "common/common/base64.h"
#include "envoy/common/pure.h"

#include "openssl/crypto.h"
#include "openssl/rand.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {
class StateStore;
typedef std::shared_ptr<StateStore> StateStorePtr;

class StateStore {
public:
  typedef std::string state_handle_t;
  struct Nonce {
    typedef uint8_t NonceValue[32];
    NonceValue Value {0};
    Nonce() {
      static const NonceValue zero = {0};
      do {
        int rc = RAND_bytes(Value, sizeof(NonceValue));
        ASSERT(rc == 1);
      } while(memcpy(Value, zero, sizeof(NonceValue)) == 0);
    }

    explicit Nonce(const std::string& str) {
      std::string tmp = Base64Url::decode(str);
      if (tmp.length() == sizeof(NonceValue)) {
        memcpy(Value, tmp.c_str(), sizeof(NonceValue));
      }
    }

    Nonce& operator=(const Nonce& rhs) {
      memcpy(Value, rhs.Value, sizeof(NonceValue));
      return *this;
    }

    bool operator ==(const Nonce& rhs) const {
      return CRYPTO_memcmp(Value, rhs.Value, sizeof(NonceValue)) == 0;
    }

    bool operator !=(const Nonce& rhs) const {
      return !(*this == rhs);
    }

    std::string ToString() const {
      return Base64Url::encode(reinterpret_cast<const char*>(Value), sizeof(NonceValue));
    }
  };

  struct StateContext {
    std::string idp_;
    std::string hostname_;
    Nonce nonce_;

    StateContext() {}
    StateContext(const std::string& idp, const std::string& hostname)
        : idp_(idp), hostname_(hostname) {

    }

    bool operator!=(const StateContext& rhs) const {
      return !(*this == rhs);
    }

    bool operator ==(const StateContext& rhs) const {
      return (idp_ == rhs.idp_ && hostname_ == rhs.hostname_ && nonce_ == rhs.nonce_);
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
