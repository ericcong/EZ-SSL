java_test(
    name = "SSLSocketTest",
    srcs = ["SSLSocketTest.java"],
    resources = [
        "//src/test/resources:alpha_keystore",
        "//src/test/resources:beta_keystore",
        "//src/test/resources:trusted_keystore",
    ],
    deps = [
        "//src/main/java/io/cong/chen/ezssl:ssl_server_socket_builder",
        "//src/main/java/io/cong/chen/ezssl:ssl_socket_builder",
        "@junit//jar",
    ],
)
