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
