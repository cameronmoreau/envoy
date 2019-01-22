licenses(["notice"])  # Apache 2

load("//bazel:envoy_build_system.bzl", "envoy_package")
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

envoy_package()

envoy_extension_cc_test(
    name = "session_manager_filter_test",
    srcs = [
        "session_manager_filter_test.cc",
    ],
    extension_name = "envoy.filters.http.session_manager",
    deps = [
        "//source/extensions/filters/http/session_manager:session_manager_filter_lib",
        "//test/extensions/filters/http/common:session_manager_mock_lib",
        "//test/mocks/server:server_mocks",
        "//test/test_common:utility_lib",
    ],
)

envoy_extension_cc_test(
    name = "session_manager_factory_test",
    srcs = [
        "session_manager_factory_test.cc",
    ],
    extension_name = "envoy.filters.http.session_manager",
    deps = [
        "//source/extensions/filters/http/session_manager:config",
        "//test/mocks/server:server_mocks",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/config/filter/http/session_manager/v1alpha:session_manager_cc",
    ],
)
