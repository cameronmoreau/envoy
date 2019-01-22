#pragma once

#include "extensions/filters/http/common/session_manager.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
class MockSessionManager : public SessionManager {
public:
  MOCK_CONST_METHOD1(CreateToken, SessionToken(const Context&));
  MOCK_CONST_METHOD2(VerifyToken, bool(const Context&, const SessionToken&));
};
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy