#pragma once

#include <memory>
#include <string>

#include "envoy/config/filter/http/session_manager/v1alpha/config.pb.h"

#include "common/common/logger.h"

#include "extensions/filters/http/common/state_store.h"

#include "absl/types/optional.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class TokenEncryptor;
typedef std::shared_ptr<TokenEncryptor> TokenEncryptorPtr;

class TokenEncryptor : public Logger::Loggable<Logger::Id::filter> {
public:
  using Config = ::envoy::config::filter::http::session_manager::v1alpha::TokenBinding;
  virtual ~TokenEncryptor(){};

  /**
   * Encrypt the given token.
   * @param token the token to encrypt and authenticate.
   * @return base64 string representing the encrypted/authenticated data
   */
  virtual std::string encrypt(const std::string& token, const StateStore::Nonce& nonce) = 0;

  /**
   * Decrypt the given token.
   * @param ciphertext the data (nonce || ciphertext || tag) to be decrypted.
   * @param aad        additional authenticated data.
   * @return plaintext string, or absl::nullopt if verification failed.
   */
  virtual absl::optional<std::string> decrypt(const std::string& ciphertext) = 0;

  /**
   * Create an instance of a TokenEncryptor.
   * @param secret       base64 encoded data of the secret used to derive the encryption key.
   * @param enc_alg      encryption algorithm to be used for encryption/decryption.
   * @param hash_alg     hash algorithm to be used for key derivation.
   * @return an instance of a TokenEncryptor.
   */
  static TokenEncryptorPtr create(const std::string& secret,
                                  const Config::EncryptionAlg& enc_alg = Config::AES256GCM,
                                  const Config::HkdfHash& hash_alg = Config::SHA256);

  /**
   * Create an instance of a TokenEncryptor.
   * @param config       token binding configuration.
   * @return an instance of a TokenEncryptor.
   */
  static TokenEncryptorPtr create(const Config& config);
};

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy