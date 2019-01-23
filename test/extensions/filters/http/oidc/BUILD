licenses(["notice"])  # Apache 2

load("//bazel:envoy_build_system.bzl", "envoy_package")
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_cc_test_library",
    "envoy_extension_cc_test",
)

envoy_cc_test_library(
    name = "mock_lib",
    hdrs = [
        "jwt_fetcher_mock.h",
    ],
    deps = [
        "//source/extensions/filters/http/common:jwks_fetcher_lib",
        "//test/mocks/server:server_mocks",
    ],
)

envoy_extension_cc_test(
    name = "state_store_test",
    srcs = [
        "state_store_test.cc",
    ],
    extension_name = "envoy.filters.http.oidc",
    deps = [
        "//source/extensions/filters/http/oidc:state_store_lib",
        "//test/test_common:simulated_time_system_lib",
        "//test/test_common:utility_lib",
    ],
)

envoy_extension_cc_test(
    name = "jwt_fetcher_test",
    srcs = [
        "jwt_fetcher_test.cc",
    ],
    extension_name = "envoy.filters.http.oidc",
    deps = [
        "//source/extensions/filters/http/oidc:jwt_fetcher_lib",
        "//test/extensions/filters/http/common:mock_lib",
        "//test/extensions/filters/http/oidc:mock_lib",
        "//test/mocks/http:http_mocks",
        "//test/test_common:utility_lib",
    ],
)
