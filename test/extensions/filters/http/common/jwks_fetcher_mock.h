#pragma once

#include "extensions/filters/http/common/jwks_fetcher.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class MockJwksFetcher : public JwksFetcher {
public:
  MOCK_METHOD0(cancel, void());
  MOCK_CONST_METHOD1(validContentType, bool(const std::string& content));
  MOCK_METHOD2(fetch, void(const ::envoy::api::v2::core::HttpUri& uri,
                           JwksFetcher::JwksReceiver& receiver));
};

class MockJwksReceiver : public JwksFetcher::JwksReceiver {
public:
  /* GoogleMock does handle r-value references hence the below construction.
   * Expectations and assertions should be made on onJwksSuccessImpl in place
   * of onJwksSuccess.
   */
  void onJwksSuccess(google::jwt_verify::JwksPtr&& jwks) {
    ASSERT(jwks);
    onJwksSuccessImpl(*jwks.get());
  }
  MOCK_METHOD1(onJwksSuccessImpl, void(const google::jwt_verify::Jwks& jwks));
  MOCK_METHOD1(onJwksFailure, void(Failure reason));
};

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy