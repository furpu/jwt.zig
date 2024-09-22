# jwt.zig

Zig implementation of JSON Web Tokens ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)).

## Claims

Claim verification is not implemented yet.

Future work includes adding features to verify `aud`, `exp`, `iat` and `nbf` claims as described in [Section 4](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1) of the RFC.

## Algorithms

| Supported | alg Parameter | Description |
|:---------:|---------------|-------------|
| ✅        | HS256         | HMAC using SHA-256 hash algorithm |
| ❌        | HS384         | HMAC using SHA-384 hash algorithm |
| ❌        | HS512         | HMAC using SHA-512 hash algorithm |
| ❌        | RS256         | RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm |
| ❌        | RS384         | RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm |
| ❌        | RS512         | RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm |
| ❌        | PS256         | RSASSA-PSS using SHA-256 hash algorithm |
| ❌        | PS384         | RSASSA-PSS using SHA-384 hash algorithm |
| ❌        | PS512         | RSASSA-PSS using SHA-512 hash algorithm |
| ✅        | ES256         | ECDSA using P-256 curve and SHA-256 hash algorithm |
| ❌        | ES384         | ECDSA using P-384 curve and SHA-384 hash algorithm |
| ❌        | ES512         | ECDSA using P-521 curve and SHA-512 hash algorithm |
| ✅        | none          | No digital signature or MAC value included |
