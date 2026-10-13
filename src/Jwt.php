<?php
/**
 * Jwt — dependency-free JSON Web Token (RFC 7519) for PHP 7.4+.
 *
 * Supported algorithms: HS256, HS384, HS512 (HMAC) and
 * RS256, RS384, RS512 (RSA via OpenSSL).
 *
 * Features:
 *  - exp / nbf / iat claim validation with configurable leeway (clock skew)
 *  - `kid` key registry for rotation: ['key-id' => 'secret-or-pem']
 *  - Algorithm allow-list enforced on decode (no alg-confusion: an "HS256"
 *    token can never be verified with an RSA key and vice versa)
 *  - Constant-time signature comparison (hash_equals)
 *
 * Usage:
 *   $jwt = Jwt::encode(['sub' => 42, 'role' => 'admin'], 'your-256-bit-secret',
 *                      'HS256', 3600, ['kid' => 'v1']);
 *   $claims = Jwt::decode($jwt, ['v1' => 'your-256-bit-secret'], ['HS256'],
 *                          ['leeway' => 30]);
 *
 * @author Azan Umer <https://github.com/Azanumer>
 * @license MIT
 */

class InvalidTokenException extends RuntimeException {}

final class Jwt
{
    private const HMAC_ALGS = ['HS256' => 'sha256', 'HS384' => 'sha384', 'HS512' => 'sha512'];
    private const RSA_ALGS  = ['RS256' => OPENSSL_ALGO_SHA256,
                              'RS384' => OPENSSL_ALGO_SHA384,
                              'RS512' => OPENSSL_ALGO_SHA512];

    /**
     * Create a signed JWT.
     *
     * @param array  $claims  Custom claims (sub, role, ...).
     * @param string $key     HMAC secret, or PEM private key for RS*.
     * @param string $alg     One of HS256/HS384/HS512/RS256/RS384/RS512.
     * @param int    $ttl     Seconds until expiry (exp = now + ttl). 0 = no exp.
     * @param array  $headers Extra JOSE header fields (e.g. ['kid' => 'v1']).
     */
    public static function encode(array $claims, string $key, string $alg = 'HS256',
                                  int $ttl = 3600, array $headers = []): string
    {
        if (!self::isSupported($alg)) {
            throw new InvalidArgumentException("Unsupported algorithm: {$alg}");
        }
        $now = time();
        $payload = array_merge($claims, ['iat' => $now]);
        if ($ttl > 0) {
            $payload['exp'] = $now + $ttl;
        }

        $headerB64  = self::b64url(json_encode(['typ' => 'JWT', 'alg' => $alg] + $headers));
        $payloadB64 = self::b64url(json_encode($payload));
        $signing    = $headerB64 . '.' . $payloadB64;

        return $signing . '.' . self::b64url(self::sign($signing, $key, $alg));
    }

    /**
     * Verify and decode a JWT. Returns the claims array.
     *
     * @param string $token        The compact JWT string.
     * @param array  $keys         Key registry: ['kid' => 'secret-or-pem'].
     *                             A single key may be passed as ['default' => $key].
     * @param array  $allowedAlgs  Algorithms you accept (default: all HMAC ones).
     * @param array  $options      ['leeway' => seconds of clock skew, default 0,
     *                             'now' => override current time (tests)]
     *
     * @throws InvalidTokenException on any failure (bad format, bad signature,
     *         wrong/forbidden alg, expired, used-before-nbf, unknown kid).
     */
    public static function decode(string $token, array $keys,
                                  array $allowedAlgs = ['HS256', 'HS384', 'HS512'],
                                  array $options = []): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidTokenException('Malformed token: expected 3 segments');
        }
        [$headerB64, $payloadB64, $sigB64] = $parts;

        $header = json_decode(self::b64urlDecode($headerB64), true);
        $claims = json_decode(self::b64urlDecode($payloadB64), true);
        if (!is_array($header) || !is_array($claims)) {
            throw new InvalidTokenException('Malformed token: bad JSON');
        }

        $alg = $header['alg'] ?? null;
        if (!is_string($alg) || !self::isSupported($alg)) {
            throw new InvalidTokenException('Unsupported or missing alg');
        }
        if (!in_array($alg, $allowedAlgs, true)) {
            throw new InvalidTokenException("Algorithm not allowed: {$alg}");
        }

        // Resolve the key via kid (or the single 'default' key).
        $kid = $header['kid'] ?? 'default';
        if (!array_key_exists($kid, $keys)) {
            throw new InvalidTokenException("Unknown key id: {$kid}");
        }
        $key = $keys[$kid];

        if (!self::verify($headerB64 . '.' . $payloadB64, self::b64urlDecode($sigB64), $key, $alg)) {
            throw new InvalidTokenException('Signature verification failed');
        }

        $now    = (int) ($options['now'] ?? time());
        $leeway = max(0, (int) ($options['leeway'] ?? 0));

        if (isset($claims['exp']) && $now > (int) $claims['exp'] + $leeway) {
            throw new InvalidTokenException('Token expired');
        }
        if (isset($claims['nbf']) && $now + $leeway < (int) $claims['nbf']) {
            throw new InvalidTokenException('Token not yet valid (nbf)');
        }
        if (isset($claims['iat']) && (int) $claims['iat'] > $now + $leeway) {
            throw new InvalidTokenException('Token issued in the future (iat)');
        }

        return $claims;
    }

    // ------------------------------------------------------------------ internals

    private static function isSupported(string $alg): bool
    {
        return isset(self::HMAC_ALGS[$alg]) || isset(self::RSA_ALGS[$alg]);
    }

    private static function sign(string $data, string $key, string $alg): string
    {
        if (isset(self::HMAC_ALGS[$alg])) {
            return hash_hmac(self::HMAC_ALGS[$alg], $data, $key, true);
        }
        $priv = openssl_pkey_get_private($key);
        if ($priv === false) {
            throw new InvalidArgumentException('Invalid RSA private key');
        }
        if (!openssl_sign($data, $sig, $priv, self::RSA_ALGS[$alg])) {
            throw new RuntimeException('RSA signing failed');
        }
        return $sig;
    }

    private static function verify(string $data, string $signature, string $key, string $alg): bool
    {
        if (isset(self::HMAC_ALGS[$alg])) {
            $expected = hash_hmac(self::HMAC_ALGS[$alg], $data, $key, true);
            return hash_equals($expected, $signature); // constant-time
        }
        $pub = openssl_pkey_get_public($key);
        if ($pub === false) {
            throw new InvalidArgumentException('Invalid RSA public key');
        }
        return openssl_verify($data, $signature, $pub, self::RSA_ALGS[$alg]) === 1;
    }

    private static function b64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function b64urlDecode(string $data): string
    {
        $padded = strtr($data, '-_', '+/');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);
        $decoded = base64_decode($padded, true);
        if ($decoded === false) {
            throw new InvalidTokenException('Malformed token: bad base64url');
        }
        return $decoded;
    }
}
