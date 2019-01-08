# Preface

To run the below examples on a local development machine you must first create a private key and certificate
used during TLS negotiation. All examples are configured to expect the key and certificate to be found under
`/tmp`. To create a self-signed certificate using OpenSSL run the following command from your terminal:

```bash
openssl req -outform PEM -out /tmp/key.crt -new -keyout /tmp/key.pem -newkey rsa:2048 -batch -nodes -x509 -subj "/CN=tenant.cluster.com" -days 365
```

Configuration items that appear in angled brackets - <> - must be replaced.


## Example Google OIDC config

```yaml
admin:
  access_log_path: /tmp/envoy_admin_access.log
  address:
    socket_address: { address: 127.0.0.1, port_value: 9901 }
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address: { address: 127.0.0.1, port_value: 8443 }
    filter_chains:
    - tls_context:
        common_tls_context:
          tls_certificates:
            - certificate_chain:
                filename: "/tmp/key.crt"
              private_key:
                filename: "/tmp/key.pem"
      filters:
      - name: envoy.http_connection_manager
        config:
          stat_prefix: ingress_http
          codec_type: AUTO
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: internal-cluster }
          http_filters:
          - name: envoy.filters.http.oidc
            config:
              matches:
                tenant1.acme.com:
                  idp:
                    authorization_endpoint:
                      uri: https://accounts.google.com/o/oauth2/v2/auth
                      cluster: idp-accounts-cluster
                    token_endpoint:
                      uri: https://www.googleapis.com/oauth2/v4/token
                      cluster: idp-api-cluster
                    jwks_uri:
                      uri: https://www.googleapis.com/oauth2/v3/certs
                      cluster: idp-api-cluster
                    client_id: <client-id>
                    client_secret: <client-secret>
                  criteria:
                    header: :authority
                    value: tenant.cluster.com:8443
              authentication_callback: "/oidc/authenticate"
              landing_page: "https://tenant.cluster.com:8443/home"
              binding:
                secret: Mb07unY1jd4h2s5wUSO9KJzhqjVTazXMWCp4OAiiGko=
                token: __Secure-acme-session-cookie
                binding: x-xsrf-token
  clusters:
  - name: internal-cluster
    connect_timeout: 1.0s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: internal-cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 8080
  - name: idp-accounts-cluster
    connect_timeout: 1.0s
    type: LOGICAL_DNS
    lb_policy: ROUND_ROBIN
    dns_lookup_family: V4_ONLY
    tls_context:
      sni: accounts.google.com
    load_assignment:
      cluster_name: idp-accounts-cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                protocol: TCP
                address: accounts.google.com
                port_value: 443
  - name: idp-oauth2-cluster
    connect_timeout: 1.0s
    type: LOGICAL_DNS
    lb_policy: ROUND_ROBIN
    dns_lookup_family: V4_ONLY
    tls_context:
      sni: oauth2.googleapis.com
    load_assignment:
      cluster_name: idp-oauth2-cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                protocol: TCP
                address: oauth2.googleapis.com
                port_value: 443
  - name: idp-api-cluster
    connect_timeout: 1.0s
    type: LOGICAL_DNS
    lb_policy: ROUND_ROBIN
    dns_lookup_family: V4_ONLY
    tls_context:
      sni: www.googleapis.com
    load_assignment:
      cluster_name: idp-api-cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                protocol: TCP
                address: www.googleapis.com
                port_value: 443
```