#pragma once
#include <memory>
#include <string>

#include "envoy/common/pure.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class SessionManager;
typedef std::shared_ptr<const SessionManager> SessionManagerPtr;

/**
 * SessionManager is a class that can be used to generate and validate cryptographic
 * session tokens that can be used to protect again XSRF, person-in-the-middle and
 * person-in-the-browser attacks.
 */
class SessionManager {
public:
  /**
   * A SessionToken is a type that cryptographically binds a SessionManager::Context
   * to the current session. SessionTokens can be used for Cross-Site Request Forgery
   * protection (XSRF), person-in-the-middle (PiTM/MiTM) and person-in-the-browser
   * (PiTB/MiTB) attacks. SessionTokens can be inserted into cookies or HTTP headers.
   */
  typedef std::string SessionToken;
  /**
   * A Context is some value that a SessionManager::SessionToken is cryptographically
   * bound to. An example might be an HTTP value.
   */
  typedef std::string Context;

  virtual ~SessionManager(){};
  /* CreateToken creates a cryptographically protected token bound to the given context.
   * This function is thread-safe.
   * @param ctx_ the value to be bound.
   * @return the binding token.
   */
  virtual SessionToken CreateToken(const Context& ctx) const PURE;
  /* VerifyToken verify that the given token is bound to the given context
   * This function is thread-safe.
   * @param ctx_ the value that should be bound.
   * @param token the bindind token.
   * @return true or false.
   */
  virtual bool VerifyToken(const Context& ctx, const SessionToken& token) const PURE;

  /**
   * Create create an instance of a SessionManager.
   * @param key the key used to protect session tokens base64 encoded.
   * @return an instance of a SessionManager.
   */
  static SessionManagerPtr Create(const std::string& key);
};
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
