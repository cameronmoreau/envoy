#include "common/common/enum_to_int.h"
#include "common/http/headers.h"
#include "common/http/utility.h"

#include "extensions/filters/http/oidc/jwt_fetcher.h"

#include "jwt_verify_lib/status.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {
namespace {
const std::string content_type_form("application/x-www-form-urlencoded");

class JwtFetcherImpl : public JwtFetcher,
 public Common::Fetcher::Receiver,
                        public Logger::Loggable<Logger::Id::filter> {
 private:
  JwtFetcher::JwtReceiver* receiver_ = nullptr;
  Common::FetcherPtr fetcher_;

 public:
  JwtFetcherImpl(Upstream::ClusterManager& cm) {
    ENVOY_LOG(trace, "{}", __func__);
    fetcher_ = Common::Fetcher::create(cm);
  }

  void cancel() {
    ENVOY_LOG(trace, "{}", __func__);
    fetcher_->cancel();
  }

  void fetch(const ::envoy::api::v2::core::HttpUri& uri,
                     const std::string& client_id,
                     const std::string& client_secret,
                     const std::string& code,
                     const std::string& redirect_uri,
                     JwtReceiver& receiver) override {
    ENVOY_LOG(trace, "{}", __func__);
    receiver_ = &receiver;
    auto body = fmt::format("code={}&client_id={}&client_secret={}&redirect_uri={}&grant_type=authorization_code",
                            code,
                            client_id,
                            client_secret,
                            Http::Utility::urlSafeEncode(redirect_uri));
    fetcher_->fetch(uri, Http::Headers::get().MethodValues.Post, "", content_type_form, body, *this);
  }

  // HTTP async receive methods
  void onFetchSuccess(const std::string&, Buffer::InstancePtr&& response) override {
    // TODO (nickrmc83): verify content-type
    ENVOY_LOG(trace, "{}", __func__);
    const auto len = response->length();
    const auto body = std::string(static_cast<char *>(response->linearize(len)), len);
    auto jwt = std::make_unique<google::jwt_verify::Jwt>();
    if (jwt->parseFromString(body) == google::jwt_verify::Status::Ok) {
      ENVOY_LOG(debug, "{}: fetch Jwt: succeeded", __func__);
      receiver_->onJwtSuccess(std::move(jwt));
    } else {
      ENVOY_LOG(debug, "{}: fetch jwt: invalid jwt", __func__);
      receiver_->onJwtFailure(Common::Failure::InvalidData);
    }
  }

  void onFetchFailure(Common::Failure reason) override {
    ENVOY_LOG(debug, "{}: fetch jwt: error {}", __func__,
              enumToInt(reason));
    receiver_->onJwtFailure(reason);
  }
};
} // namespace

JwtFetcherPtr JwtFetcher::create(Upstream::ClusterManager& cm) {
  return std::make_unique<JwtFetcherImpl>(cm);
}
} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
