#include "extensions/filters/http/common/fetcher.h"

#include <iosfwd>

#include "common/buffer/buffer_impl.h"
#include "common/common/enum_to_int.h"
#include "common/http/headers.h"
#include "common/http/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace {

class FetcherImpl : public Fetcher,
                    public Logger::Loggable<Logger::Id::filter>,
                    public Http::AsyncClient::Callbacks {
private:
  Upstream::ClusterManager& cm_;
  const ::envoy::api::v2::core::HttpUri* uri_ = nullptr;
  std::string method_;
  std::string accept_;
  std::string content_type_;
  Fetcher::Receiver* receiver_;
  Http::AsyncClient::Request* request_ = nullptr;

public:
  FetcherImpl(Upstream::ClusterManager& cm) : cm_(cm) { ENVOY_LOG(trace, "{}", __func__); }

  void cancel() override {
    if (request_) {
      request_->cancel();
      request_ = nullptr;
      ENVOY_LOG(debug, "fetch [uri = {}]: canceled", uri_->uri());
    }
  }

  void fetch(const ::envoy::api::v2::core::HttpUri& uri, const std::string& method,
             const std::string& accept, const std::string& content_type, const std::string& body,
             Fetcher::Receiver& receiver) override {
    ENVOY_LOG(trace, "{} {} {}", __func__, uri.uri(), content_type);
    // Only GET and POST methods should be used.
    ASSERT(method == Http::Headers::get().MethodValues.Get ||
           method == Http::Headers::get().MethodValues.Post);
    // Never issue a GET request with a body.
    ASSERT(!(method == Http::Headers::get().MethodValues.Get && body.length() > 0));
    receiver_ = &receiver;
    uri_ = &uri;
    method_ = method;
    accept_ = accept;
    content_type_ = content_type;
    Http::MessagePtr message = Http::Utility::prepareHeaders(uri);
    message->headers().insertMethod().value().setReference(method_);
    if (accept_.length() > 0) {
      message->headers().insertAccept().value().setReference(accept_);
    }
    if (content_type_.length() > 0) {
      message->headers().insertContentType().value().setReference(content_type_);
    }
    if (body.length() > 0) {
      message->body().reset(new Buffer::OwnedImpl(body));
    }
    ENVOY_LOG(debug, "fetch from [uri = {}]: start", uri_->uri());
    request_ =
        cm_.httpAsyncClientForCluster(uri.cluster())
            .send(std::move(message), *this,
                  std::chrono::milliseconds(DurationUtil::durationToMilliseconds(uri.timeout())));
  }

  // HTTP async receive methods
  void onSuccess(Http::MessagePtr&& response) override {
    ENVOY_LOG(trace, "{}", __func__);
    request_ = nullptr;
    // Did the call succeed?
    const uint64_t status_code = Http::Utility::getResponseStatus(response->headers());
    if (status_code != enumToInt(Http::Code::OK)) {
      ENVOY_LOG(debug, "{}: fetch [uri = {}]: response status code {}", __func__, uri_->uri(),
                status_code);
      receiver_->onFetchFailure(Failure::Network);
      return;
    }
    // Does the request contain a body?
    if (!response->body()) {
      ENVOY_LOG(debug, "{}: fetch [uri = {}]: body is empty", __func__, uri_->uri());
      receiver_->onFetchFailure(Failure::InvalidData);
      return;
    }

    auto content_type_header = response->headers().ContentType();
    if (content_type_header) {
      receiver_->onFetchSuccess(content_type_header->value().c_str(), std::move(response->body()));
    } else {
      receiver_->onFetchSuccess("", std::move(response->body()));
    }
  }

  void onFailure(Http::AsyncClient::FailureReason reason) override {
    ENVOY_LOG(debug, "{}: fetch [uri = {}]: network error {}", __func__, uri_->uri(),
              enumToInt(reason));
    request_ = nullptr;
    receiver_->onFetchFailure(Failure::Network);
  }
};
} // namespace

FetcherPtr Fetcher::create(Upstream::ClusterManager& cm) {
  return std::make_unique<FetcherImpl>(cm);
}
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
