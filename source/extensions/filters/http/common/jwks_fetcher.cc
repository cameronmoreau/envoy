#include "common/common/enum_to_int.h"
#include "common/http/headers.h"
#include "common/http/utility.h"

#include "extensions/filters/http/common/jwks_fetcher.h"

#include "jwt_verify_lib/status.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace {
class JwksFetcherImpl : public JwksFetcher,
                        public Fetcher::Receiver,
                        public Logger::Loggable<Logger::Id::filter> {
private:
  JwksFetcher::JwksReceiver* receiver_ = nullptr;
  FetcherPtr fetcher_;

public:
  JwksFetcherImpl(Upstream::ClusterManager& cm) {
    ENVOY_LOG(trace, "{}", __func__);
    fetcher_ = Fetcher::create(cm);
  }

  void cancel() {
    ENVOY_LOG(trace, "{}", __func__);
    fetcher_->cancel();
  }

  void fetch(const ::envoy::api::v2::core::HttpUri& uri, JwksFetcher::JwksReceiver& receiver) override {
    ENVOY_LOG(trace, "{}", __func__);
    receiver_ = &receiver;
    fetcher_->fetch(uri,
                    Http::Headers::get().MethodValues.Get,
                    Http::Headers::get().ContentTypeValues.Json,
                    "",
                    *this);
  }

  // HTTP async receive methods
  void onFetchSuccess(Buffer::InstancePtr&& response) override {
    ENVOY_LOG(trace, "{}", __func__);
    const auto len = response->length();
    const auto body = std::string(static_cast<char *>(response->linearize(len)), len);
    auto jwks =
        google::jwt_verify::Jwks::createFrom(body, google::jwt_verify::Jwks::Type::JWKS);
    if (jwks->getStatus() == google::jwt_verify::Status::Ok) {
      ENVOY_LOG(debug, "{}: fetch pubkey: succeeded", __func__);
      receiver_->onJwksSuccess(std::move(jwks));
    } else {
      ENVOY_LOG(debug, "{}: fetch pubkey: invalid jwks", __func__);
      std::cerr << "jwks 1" << std::endl;
      receiver_->onJwksFailure(Failure::InvalidData);
    }
  }

  void onFetchFailure(Failure reason) override {
    ENVOY_LOG(debug, "{}: fetch pubkey: error {}", __func__,
              enumToInt(reason));
    receiver_->onJwksFailure(Failure::Network);
  }
};
} // namespace

JwksFetcherPtr JwksFetcher::create(Upstream::ClusterManager& cm) {
  return std::make_unique<JwksFetcherImpl>(cm);
}
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
