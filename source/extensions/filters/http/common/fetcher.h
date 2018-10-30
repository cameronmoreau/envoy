#pragma once

#include "envoy/api/v2/core/http_uri.pb.h"
#include "envoy/common/pure.h"
#include "envoy/buffer/buffer.h"
#include "envoy/upstream/cluster_manager.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class Fetcher;
typedef std::unique_ptr<Fetcher> FetcherPtr;
/**
 * Failure reasons when fetching a remote resource.
 */
enum class Failure {
  Unknown,
  Network,
  InvalidData,
};


/**
 * Fetcher interface can be used to retrieve remote Http resources.
 * An instance of this interface is designed to retrieve a single resource
 * and should not be re-used to fetch further resources.
 */
class Fetcher {
 public:
  class Receiver {
   public:
    virtual ~Receiver(){};
    /*
     * Successful retrieval callback.
     * @param body the body of the HTTP response.
     */
    virtual void onFetchSuccess(Buffer::InstancePtr&& body) PURE;
    /*
     * Retrieval error callback.
     * @param err the reason for failure.
     */
    virtual void onFetchFailure(Failure err) PURE;
  };
  virtual ~Fetcher(){};

  /*
   * Cancel any inflight request.
   */
  virtual void cancel() PURE;
  /*
   * Retrieve a resource from a remote HTTP host.
   * @param uri the uri to retrieve the jwks from.
   * @param method the HTTP method to use. Typically GET or POST. This reference must live longer than the request.
   * @param content_type the Accept header value to send. This reference must live longer than the request.
   * @param body the body of the request. GET requests must pass an empty string.
   * @param receiver the receiver of the fetched resource or error.
   */
  virtual void fetch(const ::envoy::api::v2::core::HttpUri& uri,
                     const std::string& method,
                     const std::string& content_type,
                     const std::string& body,
                     Receiver& receiver) PURE;
  /*
   * Factory method for creating a Fetcher.
   * @param cm the cluster manager to use during resource retrieval
   * @return a Fetcher instance
   */
  static FetcherPtr create(Upstream::ClusterManager& cm);
};

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy