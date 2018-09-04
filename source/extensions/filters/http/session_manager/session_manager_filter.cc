#include "extensions/filters/http/session_manager/session_manager_filter.h"

#include <string>
#include <vector>

//#include "common/common/enum_to_int.h"
//#include "common/common/hex.h"
//#include "common/http/codes.h"
//#include "common/http/message_impl.h"
#include "common/http/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SessionManager {
namespace {
const std::vector<std::string> httpSafeMethods = {
    "GET", "HEAD", "OPTIONS",
};
}

SessionManagerFilter::SessionManagerFilter(Upstream::ClusterManager &cluster_manager,
                                           const ::envoy::config::filter::http::session_manager::v1alpha::SessionManager &config,
                                           Common::SessionManagerPtr session_manager)
    : cluster_manager_(cluster_manager), session_manager_(session_manager), config_(config) {
  ENVOY_LOG(trace, "{}", __func__);
}

SessionManagerFilter::~SessionManagerFilter() { ENVOY_LOG(trace, "{}", __func__); }

void SessionManagerFilter::onDestroy() { ENVOY_LOG(trace, "{}", __func__); }

void SessionManagerFilter::encodeToken(Http::HeaderMap &headers, const std::string &token) {
  auto encodedHeaderValue = config_.forward_header().preamble().empty() ?
                            token :
                            config_.forward_header().preamble() + " " + token;
  headers.addCopy(Http::LowerCaseString(config_.forward_header().name()), encodedHeaderValue);
}

Http::FilterHeadersStatus SessionManagerFilter::decodeHeaders(Http::HeaderMap &headers, bool) {
  ENVOY_LOG(trace, "{}", __func__);
  auto token = Http::Utility::parseCookieValue(headers, config_.token());
  if (!token.empty()) {
    // If the http method is a safe method (it is non-mutating) forgo binding validation.
    auto verb = std::string(headers.Method()->value().c_str());
    auto isSafe = std::find(httpSafeMethods.begin(), httpSafeMethods.end(), verb) != httpSafeMethods.end();
    if (isSafe) {
      ENVOY_LOG(trace, "{} Request is non-mutating/safe. Passing token through.", __func__);
      encodeToken(headers, token);
      return Http::FilterHeadersStatus::Continue;
    }
    // Any mutating or potentially mutating command requires binding validation.
    auto binding = headers.get(Http::LowerCaseString(config_.binding()));
    if (binding) {
      auto bindingValue = std::string(binding->value().c_str());
      // Remove quotes
      auto bindingValueStripped = bindingValue.substr(1, bindingValue.length() - 2);
      auto verified = session_manager_->VerifyToken(token, bindingValueStripped);
      if (verified) {
        encodeToken(headers, token);
        return Http::FilterHeadersStatus::Continue;
      } else {
        // The option here is to return 403 Forbidden or simply to not copy the token into the expected
        // header. We've chosen the latter but the former might be more secure.
        ENVOY_LOG(debug, "{} token and binding do not match.", __func__);
        return Http::FilterHeadersStatus::Continue;
      }
    } else {
      // The option here is to return 403 Forbidden or simply to not copy the token into the expected
      // header. We've chosen the latter but the former might be more secure.
      ENVOY_LOG(debug, "{} Mutating request contains token cookie but no binding header",
                __func__);
      return Http::FilterHeadersStatus::Continue;
    }
  }
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus SessionManagerFilter::decodeData(Buffer::Instance &, bool) {
  ENVOY_LOG(trace, "{}", __func__);
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus SessionManagerFilter::decodeTrailers(Http::HeaderMap &) {
  ENVOY_LOG(trace, "{}", __func__);
  return Http::FilterTrailersStatus::Continue;
}

void SessionManagerFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks &callbacks) {
  ENVOY_LOG(trace, "{}", __func__);
  decoder_callbacks_ = &callbacks;
}
} // namespace SessionManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
