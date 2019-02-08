#pragma once

#include <vector>

#include "common/common/logger.h"

#include "absl/types/optional.h"
#include "openssl/aead.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class GcmEncryptor;
typedef std::shared_ptr<GcmEncryptor> GcmEncryptorPtr;

class GcmEncryptor : public Logger::Loggable<Logger::Id::filter> {
public:
  virtual ~GcmEncryptor(){};

  /**
   * GCM encrypt and authenticate some data.
   * @param plaintext the data to encrypt and authenticate.
   * @param nonce     nonce to be used. If none supplied, one will be randomly generated.
   * @param aad       additional authenticated data.
   * @return bytes representing the encrypted/authenticated data (nonce || ciphertext || tag).
   */
  virtual std::vector<unsigned char>
  seal(const std::vector<unsigned char>& plaintext,
       absl::optional<std::vector<unsigned char>> nonce = absl::nullopt,
       const std::vector<unsigned char>& aad = {}) PURE;

  /**
   * GCM decrypt and verify some data.
   * @param ciphertext the data (nonce || ciphertext || tag) to be decrypted.
   * @param aad        additional authenticated data.
   * @return bytes representing the decrypted plaintext, or absl::nullopt if verification failed.
   */
  virtual absl::optional<std::vector<unsigned char>>
  open(const std::vector<unsigned char>& ciphertext,
       const std::vector<unsigned char>& aad = {}) PURE;

  /**
   * Create an instance of a GcmEncryptor.
   * @param key       data of the key used to encrypt/decrypt.
   * @param tag_len   GCM tag length.
   * @return an instance of a GcmEncryptor.
   */
  static GcmEncryptorPtr create(const std::vector<unsigned char>& key,
                                size_t tag_len = EVP_AEAD_DEFAULT_TAG_LENGTH);
};

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy