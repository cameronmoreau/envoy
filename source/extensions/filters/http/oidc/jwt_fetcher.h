#pragma once

#include "envoy/api/v2/core/http_uri.pb.h"
#include "envoy/common/pure.h"
#include "envoy/upstream/cluster_manager.h"

#include "extensions/filters/http/common/fetcher.h"

#include "jwt_verify_lib/jwt.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {

class JwtFetcher;
typedef std::unique_ptr<JwtFetcher> JwtFetcherPtr;
/**
 * JwtFetcher interface can be used to retrieve remote Jwt
 * (https://tools.ietf.org/html/rfc7519) data structures returning a concrete,
 * type-safe representation. An instance of this interface is designed to
 * retrieve a single Jwt and should not be re-used to fetch further instances.
 */

typedef std::unique_ptr<google::jwt_verify::Jwt> JwtPtr;
class JwtFetcher {
public:
  class JwtReceiver {
  public:
    virtual ~JwtReceiver(){};
    /*
     * Successful retrieval callback.
     * of the returned Jwt object.
     * @param Jwt the Jwt object retrieved.
     */
    virtual void onJwtSuccess(JwtPtr&& jwt) PURE;
    /*
     * Retrieval error callback.
     * * @param reason the failure reason.
     */
    virtual void onJwtFailure(Common::Failure reason) PURE;
  };

  virtual ~JwtFetcher(){};

  /*
   * Cancel any inflight requests.
   */
  virtual void cancel() PURE;

  /*
   * Retrieve a Jwt resource from a remote HTTP host.
   * @param uri the uri to retrieve the Jwt from.
   * @param client_id the client identifier used to authenticate the requester.
   * @param client_secret the client secret used to authenticate the requester.
   * @param code one-time passcode for redeeming the requested JWT.
   * @param redirect_uri the uri to redirect response to.
   * @param receiver the receiver of the fetched Jwt or error.
   */
  virtual void fetch(const ::envoy::api::v2::core::HttpUri& uri, const std::string& client_id,
                     const std::string& client_secret, const std::string& code,
                     const std::string& redirect_uri, JwtReceiver& receiver) PURE;

  /*
   * Factory method for creating a jwt_fetcher.
   * @param cm the cluster manager to use during Jwt retrieval
   * @return a jwt_fetcher instance
   */
  static JwtFetcherPtr create(Upstream::ClusterManager& cm);
};
} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
