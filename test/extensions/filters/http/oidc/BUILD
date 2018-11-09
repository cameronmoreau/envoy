licenses(["notice"])  # Apache 2

load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

envoy_extension_cc_test(
    name = "state_store_test",
    srcs = [
        "state_store_test.cc",
    ],
    extension_name = "envoy.filters.http.oidc",
    deps = [
        "//source/extensions/filters/http/oidc:state_store_lib",
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
        "//test/mocks/http:http_mocks",
        "//test/mocks/server:server_mocks",
        "//test/test_common:utility_lib",
    ],
)
