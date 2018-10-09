The below example configuration defines an OpenID Connect filter that
intercepts requests to the host (authority) `tenant1.acme.com` forcing an
OpenID Connect authentication session when the `__Secure-acme-session-cookie`
cookie is missing.

```yaml
matches:
  tenant1.acme.com:
    idp:
      authorization_endpoint:
        uri: https://acme-idp.com/authorization
        cluster: tenant1-cluster
      token_endpoint:
        uri: https://acme-idp.com/token
        cluster: tenant1-cluster
      jwks_uri:
        uri: https://acme-idp.com/.well-known/jwks
        cluster: tenant1-cluster
      client_id: client-10
      client_secret: ABCDEF0123456789
    criteria:
      header: :authority
      value: tenant1.acme.com
authentication_callback: "/oidc/authenticate"
landing_page: "/home"
binding:
  secret: Mb07unY1jd4h2s5wUSO9KJzhqjVTazXMWCp4OAiiGko=
  token: __Secure-acme-session-cookie
  binding: x-xsrf-token
```