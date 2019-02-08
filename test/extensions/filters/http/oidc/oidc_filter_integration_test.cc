#include <regex>

#include "common/common/base64.h"
#include "common/http/utility.h"

#include "test/common/upstream/utility.h"
#include "test/extensions/filters/http/jwt_authn/test_common.h"
#include "test/integration/http_integration.h"

#include "gtest/gtest.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {

const std::string CONFIG = R"EOF(
admin:
  access_log_path: /tmp/envoy_admin_access.log
  address:
    socket_address: { address: 127.0.0.1, port_value: 9901 }
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address: { address: 127.0.0.1, port_value: 8443 }
    filter_chains:
      filters:
      - name: envoy.http_connection_manager
        config:
          stat_prefix: config_test
          codec_type: AUTO
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: "*"
              routes:
              - match: { prefix: "/" }
                route: { cluster: "internal-cluster" }
          http_filters:
          - name: envoy.filters.http.session_manager
            config:
              token_binding:
                secret: Mb07unY1jd4h2s5wUSO9KJzhqjVTazXMWCp4OAiiGko=
                token: __Secure-acme-session-cookie
                binding: x-xsrf-token
              forward_rule:
                name: Authorization
                preamble: Bearer
          - name: envoy.filters.http.oidc
            config:
              matches:
                tenant1.acme.com:
                  idp:
                    authorization_endpoint:
                      uri: https://accounts.google.com/o/oauth2/v2/auth
                      cluster: idp-accounts-cluster
                    token_endpoint:
                      uri: https://www.googleapis.com/oauth2/v4/token
                      cluster: idp-api-cluster
                    jwks_uri:
                      uri: https://www.googleapis.com/oauth2/v3/certs
                      cluster: idp-api-cluster
                    client_id: 1234abcd
                    client_secret: abcd1234
                  criteria:
                    header: :authority
                    value: tenant.cluster.com:8443
              authentication_callback: "/oidc/authenticate"
              landing_page: "https://tenant.cluster.com:8443/home"
              binding:
                secret: Mb07unY1jd4h2s5wUSO9KJzhqjVTazXMWCp4OAiiGko=
                token: __Secure-acme-session-cookie
                binding: x-xsrf-token
                hkdf_hash: SHA256
                encryption_alg: AES256GCM
          - name: envoy.router
  clusters:
  - name: internal-cluster
    hosts:
      socket_address:
        address: 127.0.0.1
        port_value: 0
  - name: idp-accounts-cluster
    hosts:
      socket_address:
        address: 127.0.0.1
        port_value: 0
  - name: idp-oauth2-cluster
    hosts:
      socket_address:
        address: 127.0.0.1
        port_value: 0
  - name: idp-api-cluster
    hosts:
      socket_address:
        address: 127.0.0.1
        port_value: 0
)EOF";

const std::string JWT_HEADER =
    R"EOF(
{
  "alg": "RS256",
  "typ": "JWT"
}
)EOF";

const std::string JWT_PAYLOAD =
    R"EOF(
{{
  "iss": "https://example.com",
  "sub": "test@example.com",
  "exp": 2001001001,
  "aud": "example_service",
  "nonce": "{}"
}}
)EOF";

using ::testing::ContainsRegex;
using ::testing::HasSubstr;
using ::testing::MatchesRegex;

class OidcFilterIntegrationTest : public HttpIntegrationTest, public ::testing::Test {
public:
  OidcFilterIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, Network::Address::IpVersion::v4,
                            simTime(), CONFIG){};

  /**
   * Initializer for an individual integration test.
   */
  void initialize() override {
    setUpstreamCount(4);

    HttpIntegrationTest::initialize();
    codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  }

  std::string signJwt(absl::string_view data) {
    auto bio =
        bssl::UniquePtr<BIO>(BIO_new_mem_buf(JwtAuthn::PrivateKey, sizeof(JwtAuthn::PrivateKey)));
    RELEASE_ASSERT(bio, "");

    auto pkey =
        bssl::UniquePtr<EVP_PKEY>(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    RELEASE_ASSERT(pkey, "");

    auto ctx = bssl::UniquePtr<EVP_MD_CTX>(EVP_MD_CTX_create());
    RELEASE_ASSERT(ctx, "");

    auto rc = EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get());
    RELEASE_ASSERT(rc == 1, "");

    size_t sigLen;
    rc = EVP_DigestSign(ctx.get(), nullptr, &sigLen,
                        reinterpret_cast<const unsigned char*>(data.data()), data.size());
    RELEASE_ASSERT(rc == 1, "");

    std::vector<unsigned char> signature(sigLen);
    rc = EVP_DigestSign(ctx.get(), signature.data(), &sigLen,
                        reinterpret_cast<const unsigned char*>(data.data()), data.size());
    RELEASE_ASSERT(rc == 1, "");

    return std::string(signature.begin(), signature.end());
  }

  std::string generateJwt(absl::string_view nonce) {
    auto headerB64 = Base64Url::encode(JWT_HEADER.data(), JWT_HEADER.size());

    auto payload = fmt::format(JWT_PAYLOAD, nonce);
    auto payloadB64 = Base64Url::encode(payload.data(), payload.size());

    auto signature = signJwt(fmt::format("{}.{}", headerB64, payloadB64));
    auto signatureB64 = Base64Url::encode(signature.data(), signature.size());

    auto jwt = fmt::format("{}.{}.{}", headerB64, payloadB64, signatureB64);
    return jwt;
  }

  /**
   * Initialize before every test.
   */
  void SetUp() override { initialize(); }
};

TEST_F(OidcFilterIntegrationTest, TestRedirectToIdp) {
  // Send request with no authentication headers
  auto response = codec_client_->makeHeaderOnlyRequest(Http::TestHeaderMapImpl{
      {":method", "GET"},
      {":path", "/"},
      {":scheme", "http"},
      {":authority", "tenant.cluster.com:8443"},
  });

  response->waitForEndStream();
  ASSERT_TRUE(response->complete());

  // Test that we have been redirected to the OAuth authorisation endpoint
  EXPECT_STREQ("303", response->headers().Status()->value().c_str());
  std::string location(response->headers().get(Http::Headers::get().Location)->value().c_str());
  EXPECT_THAT(location, ContainsRegex("^https://accounts\\.google\\.com/o/oauth2/v2/auth"));
  EXPECT_THAT(location, HasSubstr("client_id=1234abcd"));
  EXPECT_THAT(location, ContainsRegex("state=(.+)"));
  EXPECT_THAT(location, ContainsRegex("nonce=(.+)"));
  EXPECT_THAT(
      location,
      HasSubstr("redirect_uri=https%3A%2F%2Ftenant.cluster.com%3A8443%2Foidc%2Fauthenticate"));
}

TEST_F(OidcFilterIntegrationTest, TestAuthCallback) {
  // Send request with no authentication headers
  auto response = codec_client_->makeHeaderOnlyRequest(Http::TestHeaderMapImpl{
      {":method", "GET"},
      {":path", "/"},
      {":scheme", "http"},
      {":authority", "tenant.cluster.com:8443"},
  });

  response->waitForEndStream();
  ASSERT_TRUE(response->complete());

  // Get our state token from the redirect URL
  std::string location(response->headers().get(Http::Headers::get().Location)->value().c_str());
  std::regex state_regex("state=([^&]+)");
  std::smatch state_match;
  ASSERT_TRUE(std::regex_search(location, state_match, state_regex));
  ASSERT_EQ(2, state_match.size());
  auto state = state_match[1].str();

  // Get the nonce from the URL
  std::regex nonce_regex("nonce=([^&]+)");
  std::smatch nonce_match;
  ASSERT_TRUE(std::regex_search(location, nonce_match, nonce_regex));
  ASSERT_EQ(2, nonce_match.size());
  auto nonce = nonce_match[1].str();

  // Send request to mimic the IDP redirect after successful authentication
  response = codec_client_->makeHeaderOnlyRequest(Http::TestHeaderMapImpl{
      {":method", "GET"},
      {":path", "/oidc/authenticate?state=" + state + "&code=testcode123"},
      {":scheme", "http"},
      {":authority", "tenant.cluster.com:8443"},
  });

  // Await the request to the token endpoint
  waitForNextUpstreamRequest(3, std::chrono::milliseconds(500));
  fake_upstreams_[3]->set_allow_unexpected_disconnects(true);

  // Make sure the token redeem request is correct
  auto redeemBody = upstream_request_->body().toString();
  EXPECT_STREQ("/oauth2/v4/token",
               upstream_request_->headers().get(Http::Headers::get().Path)->value().c_str());
  EXPECT_THAT(redeemBody, HasSubstr("code=testcode123"));
  EXPECT_THAT(redeemBody, HasSubstr("client_id=1234abcd"));
  EXPECT_THAT(redeemBody, HasSubstr("client_secret=abcd1234"));
  EXPECT_THAT(
      redeemBody,
      HasSubstr("redirect_uri=https%3A%2F%2Ftenant.cluster.com%3A8443%2Foidc%2Fauthenticate"));

  // Generate a JWT
  auto jwt = generateJwt(nonce);

  // Mimic response containing the token
  upstream_request_->encodeHeaders(
      Http::TestHeaderMapImpl{{":status", "200"}, {"content-type", "application/json"}}, false);
  Buffer::OwnedImpl token_data(fmt::format("{{\"id_token\":\"{}\"}}", jwt));
  upstream_request_->encodeData(token_data, true);

  // Await the request to the jwks endpoint, and respond with the public key/s to verify the JWT
  waitForNextUpstreamRequest(3, std::chrono::milliseconds(500));
  fake_upstreams_[3]->set_allow_unexpected_disconnects(true);
  upstream_request_->encodeHeaders(
      Http::TestHeaderMapImpl{{":status", "200"}, {"content-type", "application/json"}}, false);
  Buffer::OwnedImpl jwks_data(JwtAuthn::PublicKey);
  upstream_request_->encodeData(jwks_data, true);

  // Test that we have been redirected to the landing page
  response->waitForEndStream();
  ASSERT_TRUE(response->complete());
  EXPECT_STREQ("303", response->headers().Status()->value().c_str());
  location = std::string(response->headers().get(Http::Headers::get().Location)->value().c_str());
  EXPECT_EQ(location, "https://tenant.cluster.com:8443/home");

  // Test that the session cookie is being set, and store it to use later
  EXPECT_TRUE(Http::Utility::hasSetCookie(response->headers(), "__Secure-acme-session-cookie"));
  auto cookie =
      Http::Utility::parseSetCookieValue(response->headers(), "__Secure-acme-session-cookie");

  // Send a new request, including our session cookie
  response = codec_client_->makeHeaderOnlyRequest(Http::TestHeaderMapImpl{
      {":method", "GET"},
      {":path", "/home"},
      {":scheme", "http"},
      {":authority", "tenant.cluster.com:8443"},
      {Http::Headers::get().Cookie.get(), fmt::format("__Secure-acme-session-cookie={}", cookie)}});

  fake_upstream_connection_ = nullptr;
  waitForNextUpstreamRequest(0, std::chrono::milliseconds(500));
  fake_upstreams_[0]->set_allow_unexpected_disconnects(true);

  // Test that our upstream received the decrypted JWT in the authorisation header
  EXPECT_STREQ(upstream_request_->headers().Path()->value().c_str(), "/home");
  EXPECT_STREQ(upstream_request_->headers().Authorization()->value().c_str(),
               fmt::format("Bearer {}", jwt).c_str());

  // Send a test response
  upstream_request_->encodeHeaders(
      Http::TestHeaderMapImpl{{":status", "200"}, {"content-type", "test/plain"}}, false);
  Buffer::OwnedImpl response_data("Test response body");
  upstream_request_->encodeData(response_data, true);

  response->waitForEndStream();
  ASSERT_TRUE(response->complete());

  // Test that we no longer get redirected
  EXPECT_STREQ("200", response->headers().Status()->value().c_str());

  // Test that we received the response from the upstream service
  EXPECT_EQ("Test response body", response->body());
}

} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
