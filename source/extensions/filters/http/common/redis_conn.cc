#include "extensions/filters/http/common/redis_conn.h"

#include <memory>
#include <queue>

#include "envoy/upstream/cluster_manager.h"

#include "common/buffer/buffer_impl.h"
#include "common/network/filter_impl.h"

#include "cpp_redis/core/client.hpp"
#include "cpp_redis/network/tcp_client_iface.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

namespace {

/* Implementation of cpp_redis::network::tcp_client_iface used by cpp_redis for network
 * communication. Uses a Network::ClientConnection so the Redis server can itself be an upstream
 * cluster.
 */
class EnvoyClusterTcpClient : public cpp_redis::network::tcp_client_iface,
                              public Network::ConnectionCallbacks,
                              public Network::ReadFilterBaseImpl,
                              public std::enable_shared_from_this<Network::ReadFilter> {
public:
  EnvoyClusterTcpClient(Network::ClientConnectionPtr connection)
      : connection_(std::move(connection)), disconnection_handler_(nullptr) {
    connection_->addConnectionCallbacks(*this);
  }

  virtual void connect(const std::string&, std::uint32_t, std::uint32_t) override {
    if (!filter_added_) {
      // We cannot call this in the constructor, because shared_from_this cannot be used from the
      // constructor
      connection_->addReadFilter(shared_from_this());
      filter_added_ = true;
    }

    connection_->connect();
  }

  virtual void disconnect(bool) override {
    connection_->close(Network::ConnectionCloseType::FlushWrite);
  }

  virtual bool is_connected() const override {
    return connection_->state() == Network::Connection::State::Open;
  }

  virtual void async_read(cpp_redis::network::tcp_client_iface::read_request& request) override {
    requests_.push(request);
    processBuffer();
  }

  virtual void async_write(cpp_redis::network::tcp_client_iface::write_request& request) override {
    std::shared_ptr<Buffer::Instance> buffer(
        new Buffer::OwnedImpl(request.buffer.data(), request.buffer.size()));
    connection_->write(*buffer, false);

    if (request.async_write_callback) {
      write_result result{true, request.buffer.size()};
      request.async_write_callback(result);
    }
  }

  virtual void set_on_disconnection_handler(
      const cpp_redis::network::tcp_client_iface::disconnection_handler_t& handler) override {
    disconnection_handler_ = handler;
  }

  virtual void onEvent(Network::ConnectionEvent event) override {
    switch (event) {
    case Network::ConnectionEvent::LocalClose:
    case Network::ConnectionEvent::RemoteClose:
      disconnected();
      break;
    case Network::ConnectionEvent::Connected:
      break;
    }
  }

  virtual void onAboveWriteBufferHighWatermark() override {}

  virtual void onBelowWriteBufferLowWatermark() override {}

  virtual Network::FilterStatus onData(Buffer::Instance& buffer, bool end_stream) override {
    addToBuffer(buffer);
    processBuffer();

    if (end_stream) {
      if (disconnection_handler_) {
        disconnection_handler_();
      }
    }

    return Network::FilterStatus::Continue;
  }

private:
  bool filter_added_ = false;

  Network::ClientConnectionPtr connection_;
  disconnection_handler_t disconnection_handler_;

  std::queue<cpp_redis::network::tcp_client_iface::read_request> requests_;

  Buffer::OwnedImpl buffer_;

  void disconnected() {
    // Process any data we we have received
    processBuffer();

    // Fail any requests still outstanding
    while (!requests_.empty()) {
      auto request = requests_.front();
      requests_.pop();

      read_result result{false, {}};
      request.async_read_callback(result);
    }

    // Trigger cpp_rest disconnection handler
    if (disconnection_handler_) {
      disconnection_handler_();
    }
  }

  void addToBuffer(Buffer::Instance& buffer) { buffer_.move(buffer); }

  void processBuffer() {
    if (!requests_.empty()) {
      if (buffer_.length() > 0) {
        auto request = requests_.front();
        requests_.pop();

        // The request size is the maximum amount to read, so we'll read in up to that amount, but
        // no more than we have in the buffer
        auto amount_to_drain = std::min(buffer_.length(), request.size);

        // Drain the requested amount of data from the buffer
        std::vector<char> data(amount_to_drain);
        buffer_.copyOut(0, amount_to_drain, data.data());
        buffer_.drain(amount_to_drain);

        // Send the data to the callback
        if (request.async_read_callback) {
          read_result result{true, std::move(data)};
          request.async_read_callback(result);
        }
      }
    }
  }
};

} // namespace

typedef std::shared_ptr<cpp_redis::network::tcp_client_iface> TcpClient;

class RedisConnectionImpl : public RedisConnection {
public:
  RedisConnectionImpl(const std::string& cluster, Upstream::ClusterManager& cluster_manager)
      : RedisConnection(TcpClient(std::make_shared<EnvoyClusterTcpClient>(
            cluster_manager.tcpConnForCluster(cluster, nullptr).connection_))) {}
};

RedisConnectionPtr RedisConnection::create(
    const ::envoy::config::filter::http::oidc::v1alpha::StateStore::RedisConnection& config,
    Upstream::ClusterManager& cluster_manager) {
  return std::make_shared<RedisConnectionImpl>(config.cluster(), cluster_manager);
}

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
