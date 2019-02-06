#include "extensions/filters/http/session_manager/session_manager_filter.h"

#include <string>
#include <vector>

#include "common/common/base64.h"
#include "common/http/utility.h"

#include "extensions/filters/http/common/state_store.h"
#include "extensions/filters/http/common/token_encryptor.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SessionManager {
namespace {

const std::vector<std::string> httpSafeMethods = {
    "GET",
    "HEAD",
    "OPTIONS",
};
} // namespace

SessionManagerFilter::SessionManagerFilter(
    std::shared_ptr<::envoy::config::filter::http::session_manager::v1alpha::SessionManager> config,
    Common::SessionManagerPtr session_manager)
    : session_manager_(session_manager), config_(config) {
  ENVOY_LOG(trace, "{}", __func__);
}

SessionManagerFilter::~SessionManagerFilter() { ENVOY_LOG(trace, "{}", __func__); }

void SessionManagerFilter::onDestroy() { ENVOY_LOG(trace, "{}", __func__); }

void SessionManagerFilter::encodeToken(Http::HeaderMap& headers, const std::string& token) const {
  auto encodedHeaderValue = config_->forward_rule().preamble().empty()
                                ? token
                                : config_->forward_rule().preamble() + " " + token;
  headers.addCopy(Http::LowerCaseString(config_->forward_rule().name()), encodedHeaderValue);
}

absl::optional<std::string> SessionManagerFilter::decryptToken(const std::string& token) const {
  // Use the configured secret to decrypt the token
  auto token_encryptor = Common::TokenEncryptor::create(config_->token_binding());
  return token_encryptor->decrypt(token);
}

Http::FilterHeadersStatus SessionManagerFilter::decodeHeaders(Http::HeaderMap& headers, bool) {
  ENVOY_LOG(trace, "{} {}", __func__, config_->token_binding().token());
  auto token = Http::Utility::parseCookieValue(headers, config_->token_binding().token());
  ENVOY_LOG(trace, "{} {}", __func__, token);
  if (!token.empty()) {
    // Decrypted the token
    auto tokenValue = decryptToken(token);
    if (!tokenValue) {
      ENVOY_LOG(debug, "{} token decryption failed.", __func__);
      return Http::FilterHeadersStatus::Continue;
    }

    // If the http method is a safe method (that it is non-mutating) forgo binding validation.
    auto verb = std::string(headers.Method()->value().c_str());
    auto isSafe =
        std::find(httpSafeMethods.begin(), httpSafeMethods.end(), verb) != httpSafeMethods.end();
    if (isSafe) {
      ENVOY_LOG(trace, "{} Request is non-mutating/safe. Passing token through.", __func__);
      encodeToken(headers, *tokenValue);
      return Http::FilterHeadersStatus::Continue;
    }
    // Any mutating or potentially mutating command requires binding validation.
    auto binding = headers.get(Http::LowerCaseString(config_->token_binding().binding()));
    if (binding) {
      auto bindingValue = std::string(binding->value().c_str());
      auto verified = session_manager_->VerifyToken(*tokenValue, bindingValue);
      if (verified) {
        encodeToken(headers, *tokenValue);
        return Http::FilterHeadersStatus::Continue;
      } else {
        // The option here is to return 403 Forbidden or simply to not copy the token into the
        // expected header. We've chosen the latter but the former might be more secure.
        ENVOY_LOG(debug, "{} token and binding do not match.", __func__);
        return Http::FilterHeadersStatus::Continue;
      }
    } else {
      // The option here is to return 403 Forbidden or simply to not copy the token into the
      // expected header. We've chosen the latter but the former might be more secure.
      ENVOY_LOG(debug, "{} Mutating request contains token cookie but no binding header", __func__);
      return Http::FilterHeadersStatus::Continue;
    }
  }
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus SessionManagerFilter::decodeData(Buffer::Instance&, bool) {
  ENVOY_LOG(trace, "{}", __func__);
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus SessionManagerFilter::decodeTrailers(Http::HeaderMap&) {
  ENVOY_LOG(trace, "{}", __func__);
  return Http::FilterTrailersStatus::Continue;
}

void SessionManagerFilter::setDecoderFilterCallbacks(
    Http::StreamDecoderFilterCallbacks& callbacks) {
  ENVOY_LOG(trace, "{}", __func__);
  decoder_callbacks_ = &callbacks;
}
} // namespace SessionManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
