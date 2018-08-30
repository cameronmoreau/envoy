#include "session_manager_filter.h"

#include <string>

#include "common/common/enum_to_int.h"
#include "common/common/hex.h"
#include "common/http/codes.h"
#include "common/http/message_impl.h"
#include "common/http/utility.h"

namespace Envoy {
namespace Http {
namespace {
const std::string tokenCookieName = "istio_session";
const LowerCaseString xsrfHeaderName{"x-xsrf-token"};
const std::vector<std::string> httpSafeMethods{"GET", "HEAD", "OPTIONS"};
} // namespace
XsrfFilter::XsrfFilter(Upstream::ClusterManager& cluster_manager,
                       Utils::SessionManager::SessionManagerPtr session_manager)
    : cluster_manager_(cluster_manager), session_manager_(session_manager),
      decoder_callbacks_(nullptr) {
  ENVOY_LOG(trace, "{}", __func__);
}

XsrfFilter::~XsrfFilter() { ENVOY_LOG(trace, "{}", __func__); }

void XsrfFilter::onDestroy() { ENVOY_LOG(trace, "{}", __func__); }

FilterHeadersStatus XsrfFilter::decodeHeaders(HeaderMap& headers, bool) {
  ENVOY_LOG(trace, "{}", __func__);
  auto authz = headers.get(Headers::get().Authorization);
  if (authz) {
    // We have an authorization header so we let processing continue.
    ENVOY_LOG(trace, "{} Request contains authorization header. Continue processing.", __func__);
    return FilterHeadersStatus::Continue;
  }
  if (headers.Method() == nullptr) {
    ENVOY_LOG(debug, "{} Request does not contain an HTTP method", __func__);
    Utility::sendLocalReply(*decoder_callbacks_, false, Code::BadRequest,
                            CodeUtility::toString(Code::BadRequest));
    return FilterHeadersStatus::StopIteration;
  }
  auto verb = std::string(headers.Method()->value().c_str());
  auto token = Utility::parseCookieValue(headers, tokenCookieName);
  if (token != "") {
    auto isSafe = std::find(httpSafeMethods.begin(), httpSafeMethods.end(), verb);
    if (isSafe != httpSafeMethods.end()) {
      // Non-mutating request. Extract token from cookie and pass it through.
      ENVOY_LOG(trace, "{} Request is non-mutating/safe. Passing token through. {}", __func__,
                token);
      headers.addCopy(Headers::get().Authorization, "Bearer " + token);
      return FilterHeadersStatus::Continue;
    }
    auto xsrf = headers.get(xsrfHeaderName);
    if (xsrf) {
      ENVOY_LOG(trace, "{} Request contains JWT and xsrf tokens", __func__);
      auto xsrfValue = std::string(xsrf->value().c_str());
      // Remove quotes
      auto xsrfValueStripped = xsrfValue.substr(1, xsrfValue.length() - 2);
      auto verified = session_manager_->verifyToken(token, xsrfValueStripped);
      if (verified) {
        headers.addCopy(Headers::get().Authorization, "Bearer " + token);
        ENVOY_LOG(trace, "{} Adding jwt token as authorization header...", __func__);
        return FilterHeadersStatus::Continue;
      } else {
        ENVOY_LOG(debug, "{} XSRF and Authorization tokens do not match. {} {}", __func__,
                  xsrfValueStripped, token);
        return FilterHeadersStatus::Continue;
      }
    } else {
      ENVOY_LOG(debug, "{} Mutating request contains JWT cookie but no X-XSRF-TOKEN header",
                __func__);
      return FilterHeadersStatus::Continue;
    }
  }
  ENVOY_LOG(trace, "XsrfFilter {} Request is does not contain XSRF tokens or cookies", __func__);
  return FilterHeadersStatus::Continue;
}

FilterDataStatus XsrfFilter::decodeData(Buffer::Instance&, bool) {
  ENVOY_LOG(trace, "{}", __func__);
  return FilterDataStatus::Continue;
}

FilterTrailersStatus XsrfFilter::decodeTrailers(HeaderMap&) {
  ENVOY_LOG(trace, "{}", __func__);
  return FilterTrailersStatus::Continue;
}

void XsrfFilter::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
  ENVOY_LOG(trace, "{}", __func__);
  decoder_callbacks_ = &callbacks;
}
} // namespace Http
} // namespace Envoy
