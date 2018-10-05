#include <chrono>
#include <ctime>
#include <string>


#include "extensions/filters/http/oidc/oidc_filter.h"

#include "common/common/enum_to_int.h"
#include "common/http/codes.h"
#include "common/http/utility.h"
#include "common/http/message_impl.h"
#include "external/envoy_api/envoy/config/filter/http/oidc/v1alpha/config.pb.h"

#include "openssl/crypto.h"

using Envoy::Http::LowerCaseString;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {
namespace {
  const char* nonceClaim = "nonce";
  const char hexTable[16] = {
    '0', '1', '2', '3',
    '4', '5', '6', '7',
    '8', '9', 'A', 'B',
    'C', 'D', 'E', 'F'
  };
  const std::vector<LowerCaseString> validTokenResponseContentTypes = {
      LowerCaseString{"application/json"},
      LowerCaseString{"application/json;charset=utf-8"},
      LowerCaseString{"application/json; charset=utf-8"},
  };
  const std::chrono::milliseconds tokenRedemptionTimeout(120 * 1000); // 120 seconds
  // TODO: Define the below cookie and token name constants in a shared header for use
  // in the xsrf_filter and here.
  const std::string tokenCookieName = "istio_session";
  const std::string xsrfCookieName = "XSRF-TOKEN";
  const LowerCaseString xsrfHeaderName{"x-xsrf-token"};
  const std::chrono::seconds authentictionResponseTimeout(5*60); // 5 minutes
  const std::string tokenResponseSchema(
      R"EOF(
      {
        "$schema": "http://json-schema.org/schema#",
        "type" : "object",
        "properties" : {
          "access_token": {"type": "string"},
          "id_token": {"type": "string"},
          "token_type": {"type": "string", "enum": ["Bearer"]},
          "expires_in": {"type": "integer"}
        },
        "required" : ["id_token"],
        "additionalProperties" : true
      }
    )EOF"
      );

  typedef std::vector<std::pair<const LowerCaseString&, std::string>> AdditionalHeaders_t;

  // TODO (nickrmc83)
  /* Give an expiration point in seconds from the unix epoch, calculate how many seconds are left. */
  /* Warning: This will not work on a non-Unix machine. */
  int64_t expiry(int64_t timestamp) {
    std::chrono::seconds now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());
    std::chrono::seconds expiration = std::chrono::seconds(timestamp) - now;
    return expiration.count();
  }
  void sendResponse(Http::StreamDecoderFilterCallbacks& callbacks,
                    Http::Code response_code,
                    const AdditionalHeaders_t &additionalHeaders) {
    Http::HeaderMapPtr response_headers{
      new Http::HeaderMapImpl{
        {Http::Headers::get().Status, std::to_string(enumToInt(response_code))},
      }
    };
    for(auto iter = additionalHeaders.begin(); iter != additionalHeaders.end(); ++iter) {
      response_headers->addCopy(iter->first, iter->second);
    }
    callbacks.encodeHeaders(std::move(response_headers), true);
  }

  void sendRedirect(Http::StreamDecoderFilterCallbacks& callbacks,
                    const std::string& new_path,
                    Http::Code response_code,
                    const AdditionalHeaders_t &additionalHeaders) {
    AdditionalHeaders_t allHeaders = additionalHeaders;
    allHeaders.push_back(std::pair<const LowerCaseString&, std::string>(Http::Headers::get().Location, new_path));
    sendResponse(callbacks, response_code, allHeaders);
  }

  void sendRedirect(Http::StreamDecoderFilterCallbacks& callbacks,
                    const std::string& new_path,
                    Http::Code response_code) {
    AdditionalHeaders_t additionalHeaders;
    sendRedirect(callbacks, new_path, response_code, additionalHeaders);
  }
} // unnamed namespace

std::string OidcFilter::urlSafeEncode(const std::string &param) {
  std::ostringstream result;
  for(auto character = param.begin(); character != param.end(); character++) {
    if(*character ==  ' ') {
      result << "%20";
    } else if((*character >= 'A' && *character <= 'Z') ||
        (*character >= 'a' && *character <= 'z') ||
        (*character >= '0' && *character <= '9') ||
        (*character == '*') ||
        (*character == '-') ||
        (*character == '_') ||
        (*character == '~')) {
      result << *character;
    } else {
      result << '%' << hexTable[((*character & 0xF0) >> 4)] << hexTable[(*character & 0x0F)];
    }
  }
  return result.str();
}

bool OidcFilter::isSupportedContentType(const LowerCaseString &got) {
  return std::find(validTokenResponseContentTypes.begin(), validTokenResponseContentTypes.end(), got) != validTokenResponseContentTypes.end();
}

std::string OidcFilter::makeSetCookieValueHttpOnly(const std::string &name, const std::string &value, int64_t max_age) {
  // We use the following cookie attributes for the following reasons:
  // - Max-Age: provides a limited session time frame.
  // - Secure: instruct the user-agent (browser) to only send this cookie over a secure link.
  // - HttpOnly: instruct the user-agent (browser) to disallow access to this cookie from Javascript.
  // - SameSite=strict: instruct the user-agent (browser) to prevent 3rd-party site requests using this cookie.`
  return fmt::format("{}=\"{}\"; Max-Age={}; Secure; HttpOnly; SameSite=strict", name, value, max_age);
}

std::string OidcFilter::makeSetCookieValue(const std::string &name, const std::string &value, int64_t max_age) {
  // We use the following cookie attributes for the following reasons:
  // - Max-Age: provides a limited session time frame.
  // - Secure: instruct the user-agent (browser) to only send this cookie over a secure link.
  // - SameSite=strict: instruct the user-agent (browser) to prevent 3rd-party site requests using this cookie.`
  return fmt::format("{}=\"{}\"; Max-Age={}; Secure; SameSite=strict", name, value, max_age);
}

OidcFilter::OidcFilter(
    Upstream::ClusterManager &cluster_manager,
    Common::SessionManagerPtr session_manager,
    StateStorePtr state_store,
    const ::envoy::config::filter::http::oidc::v1alpha::OidcConfig& config,
    CreateJwksFetcherCb fetcherCb):
  cluster_manager_(cluster_manager),
  session_manager_(session_manager),
  state_store_(state_store),
  config_(config),
  fetcherCb_(fetcherCb)
{
  ENVOY_LOG(trace, "{}", __func__);
}

OidcFilter::~OidcFilter() {
  ENVOY_LOG(trace, "{}", __func__);
}

void OidcFilter::onDestroy() {
  ENVOY_LOG(trace, "{}", __func__);
  if (auth_request_.request) {
    auth_request_.request->cancel();
    auth_request_.request = nullptr;
  }
}

void OidcFilter::redeemCode(const StateStore::StateContext& ctx, const std::string& code) {
  ENVOY_LOG(trace, "{}", __func__);
  ENVOY_LOG(trace, "Attempting to redeem code {}, for idp {}", code, ctx.idp_);
  const auto &matches = config_.matches();
  auto iter = matches.find(ctx.idp_);
  if(iter == matches.end()) {
    // Not an IdP we know about. This could happen due to eventual consistency when multiple envoy instances are
    // deployed.
    ENVOY_LOG(warn, "Received authentication response with unknown IdP: {}. ", ctx.idp_);
    Http::Utility::sendLocalReply(false, *decoder_callbacks_, false, Http::Code::BadRequest, Http::CodeUtility::toString(Http::Code::BadRequest), false);
    state_machine_ = state::replied;
    return;
  }
  auto idpRef = iter->second.idp();
  Http::MessagePtr request = Http::Utility::prepareHeaders(idpRef.token_endpoint());
  request->headers().insertMethod().value(Http::Headers::get().MethodValues.Post);
  request->headers().insertContentType().value(std::string("application/x-www-form-urlencoded"));
  auto endpoint = fmt::format("https://{}{}", ctx.hostname_, config_.authentication_callback());
  auto body = fmt::format("code={}&client_id={}&client_secret={}&redirect_uri={}&grant_type=authorization_code",
      code, idpRef.client_id(), idpRef.client_secret(), urlSafeEncode(endpoint));
  request->body().reset(new Buffer::OwnedImpl(body));
  ENVOY_LOG(trace, "Sending async code redemption message ...");
  auth_request_.nonce = ctx.nonce_;
  auth_request_.idp = &idpRef;
  auth_request_.request = cluster_manager_.httpAsyncClientForCluster(idpRef.token_endpoint().cluster())
    .send(std::move(request), *this, std::chrono::milliseconds(tokenRedemptionTimeout));
}

void OidcFilter::handleAuthenticationResponse(const std::string &method, const std::string &url) {
  // Verify the authentication callback by:
  // - extract and check the state is valid (this is an expected request.
  // - extract the authorization code and redeem  at the authorization token endpoint.
  if(Http::Headers::get().MethodValues.Get != method) {
    ENVOY_LOG(warn, "Received authentication response with incorrect method. Wanted: Get, received: {}", method);
    Http::Utility::sendLocalReply(false, *decoder_callbacks_, false, Http::Code::BadRequest, Http::CodeUtility::toString(Http::Code::BadRequest), false);
    state_machine_ = state::replied;
  } else {
    auto parameters = Http::Utility::parseQueryString(url);
    auto state = parameters.find("state");
    auto code = parameters.find("code");
    if(state == parameters.end() || code == parameters.end()) {
      // This is a badly formed command.
      ENVOY_LOG(info, "Missing state or code parameter in handleAuthenticationResponse");
      Http::Utility::sendLocalReply(false,
                              *decoder_callbacks_,
                              false,
                              Http::Code::BadRequest,
                              Http::CodeUtility::toString(Http::Code::BadRequest),
                              false);
      state_machine_ = state::replied;
    } else {
      StateStore::StateContext ctx = state_store_->get(state->second);
      if (ctx != state_store_->end()) {
        // State has been found. Redeem JWT using the authorization code.
        ENVOY_LOG(trace, "Valid state in handleAuthenticationResponse. Redeeming token...");
        redeemCode(ctx, code->second);
      } else {
        // Unknown/unexpected state
        ENVOY_LOG(info, "Invalid state in handleAuthenticationResponse");
        Http::Utility::sendLocalReply(false, *decoder_callbacks_, false, Http::Code::BadRequest, Http::CodeUtility::toString(Http::Code::BadRequest), false);
        state_machine_ = state::replied;
      }
    }
  }
}

void OidcFilter::redirectToAuthenticationServer(const std::string &idp_name, const ::envoy::config::filter::http::oidc::v1alpha::OidcClient& idp, const std::string &host) {
  StateStore::StateContext ctx(idp_name, host);
  auto state = state_store_->create(ctx, authentictionResponseTimeout);
  // We need to construct our local authentication callback endpoint.
  std::ostringstream endpoint_stream;
  endpoint_stream << "https://" << host << config_.authentication_callback();
  auto location = fmt::format("{}?response_type=code&scope=openid%20email&client_id={}&state={}&nonce={}&redirect_uri={}",
      idp.authorization_endpoint().uri(), idp.client_id(), state, ctx.nonce_.ToString(), urlSafeEncode(endpoint_stream.str()));
  sendRedirect(*decoder_callbacks_, location, Http::Code::Found);
}

void OidcFilter::verifyIdToken(const std::string &token) {
  ENVOY_LOG(trace, "{}", __func__);
  // Validate the token is well formed
  auto status = jwt_.parseFromString(token);
  if (status != ::google::jwt_verify::Status::Ok) {
    // TODO (nickrmc): remove all the duplicate fail code.
    auth_request_.request = nullptr;
    ENVOY_LOG(warn, "Failed to retrieve JWKS.");
    Http::Utility::sendLocalReply(false,
                                  *decoder_callbacks_,
                                  false,
                                  Http::Code::InternalServerError,
                                  Http::CodeUtility::toString(Http::Code::InternalServerError),
                                  false);
    state_machine_ = state::replied;
    return;
  }
  fetcher_ = fetcherCb_(cluster_manager_);
  fetcher_->fetch(auth_request_.idp->jwks_uri(), *this);
}

Http::FilterHeadersStatus OidcFilter::decodeHeaders(Http::HeaderMap& headers, bool) {
  ENVOY_LOG(trace, "{}", __func__);
  headers_ = &headers;
  auto authz = headers.get(Http::Headers::get().Authorization);
  if(authz) {
    // We have an authorization header so we let processing continue.
    ENVOY_LOG(trace, "Request contains authorization header. Passing through as is.");
    state_machine_ = state::forwarding;
    return Http::FilterHeadersStatus::Continue;
  }
  // Check if the request is directed at our local authentication callback endpoint.
  auto host = headers.get(Http::Headers::get().Host);
  auto destination = headers.get(Http::Headers::get().Path);
  auto method = headers.get(Http::Headers::get().Method);

  if(host && destination && method) {
    ENVOY_LOG(trace, "{} decoder headers with host: {}, dest: {}, method: {}", __func__, host->value().c_str(), destination->value().c_str(), method->value().c_str());
    auto destination_str = std::string(destination->value().c_str());
    // Is this for our authentication callback?
    auto position = destination_str.find(config_.authentication_callback()); // TODO: There must be a better way to match urls?
    if(position == 0) {
      handleAuthenticationResponse(method->value().c_str(), destination_str);
      ENVOY_LOG(trace, "{} decoder headers completed with outstanding token redemption", __func__);
      if (state_machine_ == state::replied) {
        return Http::FilterHeadersStatus::StopIteration;
      } else {
        state_machine_ = state::stopped;
        return Http::FilterHeadersStatus::StopIteration;
      }
    } else {
      // Find a Match for the request
      for(const auto &match : config_.matches()) {
        const auto& criteriaRef = match.second.criteria();
        auto header = headers.get(Http::LowerCaseString(criteriaRef.header()));
        if(header && std::string(header->value().c_str()) == criteriaRef.value()) {
          ENVOY_LOG(trace, "{} request matches criteria {}:{}", __func__, criteriaRef.header(), criteriaRef.value());
          redirectToAuthenticationServer(match.first, match.second.idp(), host->value().c_str());
          if (state_machine_ == state::replied) {
            return Http::FilterHeadersStatus::StopIteration;
          } else {
            state_machine_ = state::stopped;
            return Http::FilterHeadersStatus::StopIteration;
          }
        }
      }
      ENVOY_LOG(trace, "{} decoder headers unauthenticated request.", __func__);
      state_machine_ = state::forwarding;
      return Http::FilterHeadersStatus::Continue;
    }
  } else {
    ENVOY_LOG(warn, "Received request without host, path and/or method.");
    Http::Utility::sendLocalReply(false, *decoder_callbacks_, false, Http::Code::BadRequest, Http::CodeUtility::toString(Http::Code::BadRequest), false);
    state_machine_ = state::replied;
    return Http::FilterHeadersStatus::StopIteration;
  }
}

Http::FilterDataStatus OidcFilter::decodeData(Buffer::Instance&, bool) {
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus OidcFilter::decodeTrailers(Http::HeaderMap&) {
  return Http::FilterTrailersStatus::Continue;
}

Http::FilterHeadersStatus OidcFilter::encodeHeaders(Http::HeaderMap& headers, bool) {
  ENVOY_LOG(trace, "OidcFilter {}", __func__);
  if (state_machine_ == state::setCookie) {
    ENVOY_LOG(trace, "OidcFilter {} setting cookies in reply", __func__);
    int64_t seconds_until_expiration = expiry(expiry_);
    // Expire cookie 30 seconds before the jwt.
    int64_t cookieLifetime = std::max(seconds_until_expiration - 30, int64_t(0));
    auto xsrfToken = session_manager_->CreateToken(jwt_.jwt_);
    auto xsrf = makeSetCookieValue(xsrfCookieName, xsrfToken, cookieLifetime);
    auto cookie = makeSetCookieValueHttpOnly(tokenCookieName, jwt_.jwt_, cookieLifetime);
    headers.addCopy(Http::Headers::get().SetCookie, xsrf);
    headers.addCopy(Http::Headers::get().SetCookie, cookie);
  }
  return Http::FilterHeadersStatus::Continue;
}

void OidcFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  ENVOY_LOG(trace, "OidcFilter {}", __func__);
  decoder_callbacks_ = &callbacks;
}

void OidcFilter::onJwksSuccess(google::jwt_verify::JwksPtr&& jwks) {
  ENVOY_LOG(trace, "OidcFilter {}", __func__);
  // Verify the tokens signature.
  ::google::jwt_verify::Status status = ::google::jwt_verify::verifyJwt(jwt_, *jwks);
  if (status != ::google::jwt_verify::Status::Ok) {
    // TODO (nickrmc): remove all the duplicate fail code.
    auth_request_.request = nullptr;
    ENVOY_LOG(warn, "Failed to retrieve JWKS.");
    Http::Utility::sendLocalReply(false, *decoder_callbacks_, false, Http::Code::InternalServerError, Http::CodeUtility::toString(Http::Code::InternalServerError), false);
    state_machine_ = state::replied;
    return;
  }
  // Verify our expected nonce is present as a claim in the JWT
  auto claim = jwt_.payload_json_.FindMember(nonceClaim);
  if(claim ==  jwt_.payload_json_.MemberEnd() ||
      auth_request_.nonce != StateStore::Nonce(claim->value.GetString())) {
    ENVOY_LOG(debug,
              "{} Authentication failed as the expected nonce claim is missing or incorrect.");
    Http::Utility::sendLocalReply(false, *decoder_callbacks_, false, Http::Code::Unauthorized, Http::CodeUtility::toString(Http::Code::Unauthorized), false);
    state_machine_ = state::replied;
  } else {
    expiry_ = jwt_.exp_;
    ENVOY_LOG(debug, "{} Authentication complete, redirecting to landing page.", __func__);
    // Rewrite request and forward to landing page including JWT.
    std::string bearerTokenValue = "Bearer " +  jwt_.jwt_;
    headers_->addCopy(Http::Headers::get().Authorization, bearerTokenValue);
    headers_->remove(Http::Headers::get().Path);
    headers_->addCopy(Http::Headers::get().Path, config_.landing_page());
    if (state_machine_ == state::stopped) {
      decoder_callbacks_->continueDecoding();
    }
    state_machine_ = state::setCookie;
  }
}

void OidcFilter::onJwksError(Common::JwksFetcher::JwksReceiver::Failure reason) {
  ENVOY_LOG(trace, "OidcFilter {}", __func__);
  auth_request_.request = nullptr;
  ENVOY_LOG(warn, "Failed to retrieve JWKS because {}.", static_cast<int>(reason));
  Http::Utility::sendLocalReply(false, *decoder_callbacks_, false, Http::Code::InternalServerError, Http::CodeUtility::toString(Http::Code::InternalServerError), false);
  state_machine_ = state::replied;
}

void OidcFilter::onSuccess(Http::MessagePtr&& response) {
  auth_request_.request = nullptr;
  uint64_t response_code = Http::Utility::getResponseStatus(response->headers());
  std::string response_body(response->bodyAsString());
  ENVOY_LOG(debug, "Received response from token endpoint: {}", response_code);
  if (response_code != enumToInt(Http::Code::OK)) {
    Http::Utility::sendLocalReply(false, *decoder_callbacks_, false, Http::Code::Unauthorized, Http::CodeUtility::toString(Http::Code::Unauthorized), false);
    state_machine_ = state::replied;
  } else {
    // Verify content-type of response is application/json
    auto content_type = response->headers().get(Http::Headers::get().ContentType);
    if(!content_type || !isSupportedContentType(LowerCaseString(content_type->value().c_str()))) {
      ENVOY_LOG(info, "Unexpected or missing Content-type in token response.");
      if(content_type) {
        ENVOY_LOG(info, "Got Content-type {}", content_type->value().c_str());
      }
      Http::Utility::sendLocalReply(false, *decoder_callbacks_, false, Http::Code::BadGateway, Http::CodeUtility::toString(Http::Code::BadGateway), false);
      state_machine_ = state::replied;
    } else {
      Json::ObjectSharedPtr token_response = Json::Factory::loadFromString(response->bodyAsString());
      // Verify response body conforms to that defined in http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
      token_response->validateSchema(tokenResponseSchema);
      // Extract identity token.
      auto id_token = token_response->getString("id_token");
      // asynchronous verification of token
      verifyIdToken(id_token);
    }
  }
}

void OidcFilter::onFailure(Http::AsyncClient::FailureReason) {
  auth_request_.request = nullptr;
  ENVOY_LOG(warn, "Token endpoint request reset.");
  Http::Utility::sendLocalReply(false, *decoder_callbacks_, false, Http::Code::InternalServerError, Http::CodeUtility::toString(Http::Code::InternalServerError), false);
  state_machine_ = state::replied;
}
} // namespace Oidc
} // namespace HttpFilter
} // namespace Extensions
} // Envoy
