#pragma once

#include "extensions/filters/http/oidc/jwt_fetcher.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {

class MockJwtFetcher : public JwtFetcher {
public:
  MOCK_METHOD0(cancel, void());
  MOCK_METHOD6(fetch, void(const ::envoy::api::v2::core::HttpUri& uri, const std::string& client_id,
                           const std::string& client_secret, const std::string& code,
                           const std::string& redirect_uri, JwtReceiver& receiver));
};

class MockJwtReceiver : public JwtFetcher::JwtReceiver {
public:
  /* GoogleMock does handle r-value references hence the below construction.
   * Expectations and assertions should be made on onJwtSuccessImpl in place
   * of onJwtSuccess.
   */
  void onJwtSuccess(JwtPtr&& jwt) {
    ASSERT(jwt);
    onJwtSuccessImpl(*jwt.get());
  }
  MOCK_METHOD1(onJwtSuccessImpl, void(const google::jwt_verify::Jwt& jwt));
  MOCK_METHOD1(onJwtFailure, void(Common::Failure reason));
};

} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy