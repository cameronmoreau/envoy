licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_cc_test_library",
    "envoy_extension_cc_test",
)

envoy_package()

envoy_cc_test_library(
    name = "mock_lib",
    srcs = [
        "mock.cc",
    ],
    hdrs = [
        "jwks_fetcher_mock.h",
        "mock.h",
    ],
    deps = [
        "//source/extensions/filters/http/common:jwks_fetcher_lib",
        "//test/mocks/server:server_mocks",
    ],
)

envoy_cc_test_library(
    name = "session_manager_mock_lib",
    hdrs = [
        "session_manager_mock.h",
    ],
    deps = [
    ],
)

envoy_extension_cc_test(
    name = "jwks_fetcher_test",
    srcs = [
        "jwks_fetcher_test.cc",
    ],
    extension_name = "envoy.filters.http.jwt_authn",
    deps = [
        "//source/extensions/filters/http/common:jwks_fetcher_lib",
        "//test/extensions/filters/http/common:mock_lib",
        "//test/mocks/http:http_mocks",
        "//test/test_common:utility_lib",
    ],
)

envoy_extension_cc_test(
    name = "fetcher_test",
    srcs = [
        "fetcher_test.cc",
    ],
    extension_name = "envoy.filters.http.jwt_authn",
    deps = [
        "//source/common/buffer:buffer_lib",
        "//source/extensions/filters/http/common:fetcher_lib",
        "//test/mocks/http:http_mocks",
        "//test/mocks/server:server_mocks",
        "//test/test_common:utility_lib",
    ],
)

envoy_extension_cc_test(
    name = "session_manager_test",
    srcs = [
        "session_manager_test.cc",
    ],
    extension_name = "envoy.filters.http.jwt_authn",
    deps = [
        "//source/extensions/filters/http/common:session_manager_lib",
    ],
)

envoy_extension_cc_test(
    name = "state_store_test",
    srcs = [
        "state_store_test.cc",
    ],
    extension_name = "envoy.filters.http.oidc",
    deps = [
        "//source/extensions/filters/http/common:state_store_lib",
        "//test/test_common:simulated_time_system_lib",
        "//test/test_common:utility_lib",
    ],
)

envoy_extension_cc_test(
    name = "gcm_encryptor_test",
    srcs = [
        "gcm_encryptor_test.cc",
    ],
    extension_name = "envoy.filters.http.oidc",
    deps = [
        "//source/extensions/filters/http/common:token_encryptor_lib",
    ],
)

envoy_extension_cc_test(
    name = "hkdf_deriver_test",
    srcs = [
        "hkdf_deriver_test.cc",
    ],
    extension_name = "envoy.filters.http.oidc",
    deps = [
        "//source/extensions/filters/http/common:token_encryptor_lib",
    ],
)
