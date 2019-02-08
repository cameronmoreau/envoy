#pragma once

#include <memory>

#include "envoy/config/filter/http/oidc/v1alpha/config.pb.h"
#include "envoy/upstream/cluster_manager.h"

#include "cpp_redis/core/client.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class RedisConnection;
typedef std::shared_ptr<RedisConnection> RedisConnectionPtr;

class RedisConnection : public cpp_redis::client {
public:
  using cpp_redis::client::client;

  /**
   * Create an instance of a RedisConnection.
   * @param config            the connection configuration.
   * @param cluster_manager   a cluster manager
   * @return An instance of a RedisConnection.
   */
  static RedisConnectionPtr
  create(const ::envoy::config::filter::http::oidc::v1alpha::StateStore::RedisConnection& config,
         Upstream::ClusterManager& cluster_manager);
};

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
