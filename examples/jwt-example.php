<?php
/**
 * jwt-example.php — quick demo of the Jwt class.
 * Run: php examples/jwt-example.php
 */

require __DIR__ . '/../src/Jwt.php';

// ---------------------------------------------------------------- HMAC demo
$keys = ['v1' => 'a-very-long-random-secret-at-least-32-bytes'];

$token = Jwt::encode(['sub' => 42, 'role' => 'admin'], $keys['v1'], 'HS256', 3600, ['kid' => 'v1']);
echo "Token:\n{$token}\n\n";

$claims = Jwt::decode($token, $keys, ['HS256'], ['leeway' => 30]);
echo "Decoded claims:\n";
print_r($claims);

// ---------------------------------------------------------------- failure demo
try {
    Jwt::decode($token, ['v1' => 'wrong-secret'], ['HS256']);
    echo "ERROR: tampered/wrong key accepted!\n";
} catch (InvalidTokenException $e) {
    echo "Wrong key correctly rejected: {$e->getMessage()}\n";
}

// ------------------------------------------------------------- expiry demo
$expired = Jwt::encode(['sub' => 1], $keys['v1'], 'HS256', 1);
sleep(2);
try {
    Jwt::decode($expired, $keys, ['HS256']);
    echo "ERROR: expired token accepted!\n";
} catch (InvalidTokenException $e) {
    echo "Expired token correctly rejected: {$e->getMessage()}\n";
}

// ----------------------------------------------------------------- RSA demo
if (function_exists('openssl_pkey_new')) {
    $res  = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($res, $privPem);
    $pubPem = openssl_pkey_get_details($res)['key'];

    $rsaToken = Jwt::encode(['sub' => 7], $privPem, 'RS256', 600, ['kid' => 'rsa1']);
    $rsaClaims = Jwt::decode($rsaToken, ['rsa1' => $pubPem], ['RS256']);
    echo "RSA round-trip OK, sub={$rsaClaims['sub']}\n";

    // alg-confusion guard: same token must NOT verify as HS256 with the public key.
    try {
        Jwt::decode($rsaToken, ['rsa1' => $pubPem], ['HS256']);
        echo "ERROR: alg confusion possible!\n";
    } catch (InvalidTokenException $e) {
        echo "Alg confusion correctly blocked: {$e->getMessage()}\n";
    }
} else {
    echo "OpenSSL unavailable — skipping RSA demo.\n";
}
