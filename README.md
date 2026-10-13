# php-jwt-auth

Dependency-free **JWT (RFC 7519)** encode/decode for PHP. No firebase/php-jwt, no composer — one file you can drop into any project.

## Features

- **HS256 / HS384 / HS512** (HMAC) and **RS256 / RS384 / RS512** (RSA via OpenSSL)
- `exp` / `nbf` / `iat` validation with configurable **leeway** for clock skew
- **`kid` key registry** — rotate keys without breaking live tokens: `['v1' => $old, 'v2' => $new]`
- **Alg-confusion guard** — decode only accepts algorithms from your allow-list, so an RS256 token can never be passed off as HS256
- Constant-time signature comparison (`hash_equals`)

## Quick start

```php
require 'src/Jwt.php';

// Issue
$token = Jwt::encode(['sub' => 42, 'role' => 'admin'], $secret, 'HS256', 3600, ['kid' => 'v1']);

// Verify
$claims = Jwt::decode($token, ['v1' => $secret], ['HS256'], ['leeway' => 30]);
// $claims['sub'] === 42
```

Anything wrong (bad signature, expired, wrong alg, unknown kid) throws `InvalidTokenException` — catch it and return 401.

Run the demo: `php examples/jwt-example.php` (also exercises the tamper, expiry and alg-confusion cases).

## Security notes

- Use a secret ≥ 32 random bytes for HMAC (`random_bytes(32)`).
- Keep the allow-list tight: pass only the algorithms you actually issue.
- Short TTLs + refresh tokens beat long-lived access tokens.

Requires PHP 7.4+ (OpenSSL extension for RS*). MIT licensed.
