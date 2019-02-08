#pragma once

#include <string>

#include "envoy/config/filter/http/oidc/v1alpha/config.pb.h"
#include "envoy/http/filter.h"
#include "envoy/upstream/cluster_manager.h"

#include "common/common/logger.h"

#include "extensions/filters/http/common/jwks_fetcher.h"
#include "extensions/filters/http/common/session_manager.h"
#include "extensions/filters/http/common/state_store.h"

#include "jwt_verify_lib/jwt.h"
#include "jwt_verify_lib/verify.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {
/**
 *  CreateJwksFetcherCb is a callback interface for creating a JwksFetcher instance.
 */
typedef std::function<Common::JwksFetcherPtr(Upstream::ClusterManager&)> CreateJwksFetcherCb;

class OidcFilter : public Http::StreamFilter, // TODO: This is just a decoder stream filter
                   public Common::JwksFetcher::JwksReceiver,
                   public Http::AsyncClient::Callbacks,
                   public Common::StateStore::StateCreationReceiver,
                   public Common::StateStore::StateGetReceiver,
                   public Logger::Loggable<Logger::Id::filter> {
public:
  /* OidcFilter constructor.
   * Will initialise a new state store based on the configuration given.
   * @param manager the cluster manager to address the configured OIDC provider.
   * @param the name of the configured OIDC provider.
   */
  OidcFilter(Upstream::ClusterManager& cluster_manager, Common::SessionManagerPtr session_manager,
             std::shared_ptr<const ::envoy::config::filter::http::oidc::v1alpha::OidcConfig> config,
             CreateJwksFetcherCb fetcherCb, TimeSource& time_source);

  /* OidcFilter constructor.
   * Allows injection of an existing state store.
   * @param manager the cluster manager to address the configured OIDC provider.
   * @param the name of the configured OIDC provider.
   * @param state_store existing state store to be used.
   */
  OidcFilter(Upstream::ClusterManager& cluster_manager, Common::SessionManagerPtr session_manager,
             std::shared_ptr<const ::envoy::config::filter::http::oidc::v1alpha::OidcConfig> config,
             CreateJwksFetcherCb fetcherCb, TimeSource& time_source,
             Common::StateStorePtr state_store);
  ~OidcFilter();

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  /* Entry point for decoding request headers. */
  Http::FilterHeadersStatus decodeHeaders(Http::HeaderMap& headers, bool) override;
  /* Entry point for decoding request data. */
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  /* Entry point for decoding request headers. */
  Http::FilterTrailersStatus decodeTrailers(Http::HeaderMap&) override;
  /* Decoder configuration. */
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;
  // Http::StreamEncoderFilter
  Http::FilterHeadersStatus encode100ContinueHeaders(Http::HeaderMap&) override {
    return Http::FilterHeadersStatus::Continue;
  };
  Http::FilterHeadersStatus encodeHeaders(Http::HeaderMap& headers, bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::Continue;
  }
  Http::FilterTrailersStatus encodeTrailers(Http::HeaderMap&) override {
    return Http::FilterTrailersStatus::Continue;
  };
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) override {
    encoder_callbacks_ = &callbacks;
  }

  // JwksFetcher::JwksReceiver interface methods
  void onJwksSuccess(google::jwt_verify::JwksPtr&& jwks) override;
  void onJwksFailure(Common::Failure reason) override;

  // Http::AsyncClient::Callbacks
  /* onSuccess is used to handle oidc token responses verifying the success of a request
   * as well as token validity.
   * @param response the response to be verified.*/
  void onSuccess(Http::MessagePtr&& response) override;
  /* onFailure is used to handle oidc token request failures.
   * @param reason the reason an http request failed*/
  void onFailure(Http::AsyncClient::FailureReason reason) override;

  /* urlSafeEncode encodes the given parameter so that it can included as a query string in a url.
   * Ideally this function should be moved into utilities.h or replaced completely.
   * @param param the parameter to encode.
   */
  static std::string urlSafeEncode(const std::string& param);

  /* isSupportedContentType verifies whether the given media-type is a supported in a token
   * redemption response.
   * @param got the received media-type.
   * @return true if the media-type is supported.
   */
  static bool isSupportedContentType(const Http::LowerCaseString& got);

  /* makeSetCookieValueHttpOnly encodes the given cookie including the name, value, max-age as well
   * as including the HttpOnly, Secure and Strict tags.
   * @param name the name of the cookie.
   * @param value the value of the cookie.
   * @param max_age the expiry of the cookie.
   * @return the encoded cookie.
   */
  static std::string makeSetCookieValueHttpOnly(const std::string& name, const std::string& value,
                                                int64_t max_age);
  /* makeSetCookieValueHttpOnly encodes the given cookie including the name, value, max-age as well
   * as including the Strict and Secure tags.
   * @param name the name of the cookie.
   * @param value the value of the cookie.
   * @param max_age the expiry of the cookie.
   * @return the encoded cookie.
   */
  static std::string makeSetCookieValue(const std::string& name, const std::string& value,
                                        int64_t max_age);

private:
  struct RequestContext {
    Http::AsyncClient::Request* request;
    ::envoy::api::v2::core::HttpUri jwks_uri;
    ::envoy::api::v2::core::DataSource local_jwks;
    Common::StateStore::Nonce nonce;
  };

  enum state {
    init,
    stopped,
    replied,
    forwarding,
    setCookie,
  };

  Http::HeaderMap* headers_ = nullptr;
  state state_machine_ = state::init;
  Upstream::ClusterManager& cluster_manager_;
  std::string cluster_;
  Common::SessionManagerPtr session_manager_;
  Common::StateStorePtr state_store_;
  std::shared_ptr<const ::envoy::config::filter::http::oidc::v1alpha::OidcConfig> config_;
  CreateJwksFetcherCb fetcherCb_;
  Common::JwksFetcherPtr fetcher_ = {};
  RequestContext auth_request_ = {};
  ::google::jwt_verify::Jwt jwt_;
  int64_t expiry_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_ = {};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_ = {};
  TimeSource& time_source_;

  /* redeemCode redeems the given code for authorization and ID tokens at the token endpoint/
   * @param ctx the state context.
   * @param code the one-time code to redeem.
   */
  void redeemCode(const Common::StateStore::StateContext& ctx, const std::string& code);
  /* handleAuthenticationResponse handles a redirection from an OIDC provider after a user has
   * authenitcated.
   * @param method the HTTP verb the request was made with.
   * @param url the url including query parameters addressed.
   */
  void handleAuthenticationResponse(const std::string& method, const std::string& url);
  /* redirectToAuthenticationServer redirects a user agent to an OIDC provider for authentication.
   * @param idp_name the idp identifier.
   * @param idp the idp to redirect to.
   * @param host the host being addressed that'll be used to forward a token redemption code.
   */
  void redirectToAuthenticationServer(const std::string& idp_name, const std::string& host);
  /* verifyToken verifies a JWT token is authentic.
   * @param token the token to verify.
   */
  void verifyIdToken(const std::string& token);

  /* AESGCM encrypt the JWT using a key derived from the binding secret and the claim nonce
   * @return the encrypted JWT
   */
  std::string encryptJwt() const;

  std::string state_;
  std::string code_;

  // StateStore::StateCreationReceiver callbacks
  /* onCreationSuccess is used to handle the successful creation of a state context
   * @param handle  the handle that has been generated for the new context.
   * @param ctx     the state context data.
   */
  void onCreationSuccess(Common::StateStore::state_handle_t handle,
                         Common::StateStore::StateContext ctx);
  /* onCreationSuccess is used to handle failure in the creation of a state context.
   * @param failure   the reason for failure.
   */
  void onCreationFailure(Common::StateStore::Failure failure);

  // StateStore::StateGetReceiver callbacks
  /* onGetSuccess is used to handle the successful retrieval of a state context.
   * @param context   the state context data.
   */
  void onGetSuccess(Common::StateStore::StateContext context);
  /* onGetFailure is used to handle failure in the retrieval of a state context.
   * @param failure   the reason for failure.
   */
  void onGetFailure(Common::StateStore::Failure failure);
};
} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
