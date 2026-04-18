--TEST--
Signature deterministic keypair (keypairDerand)
--SKIPIF--
<?php if (!extension_loaded('oqs')) die('skip oqs not loaded'); ?>
--FILE--
<?php
$alg = 'ML-DSA-65';
$seed = str_repeat("\x42", 32); // fixed seed for determinism

// keypairDerand must be deterministic: same seed → same keys
$kp1 = OQS\Signature::keypairDerand($alg, $seed);
$kp2 = OQS\Signature::keypairDerand($alg, $seed);

var_dump(hash_equals($kp1['publicKey'], $kp2['publicKey']));
var_dump(hash_equals($kp1['secretKey'], $kp2['secretKey']));
var_dump(strlen($kp1['publicKey']) === 1952);
var_dump(strlen($kp1['secretKey']) === 4032);

// Different seed → different keys
$kp3 = OQS\Signature::keypairDerand($alg, str_repeat("\xAA", 32));
var_dump(!hash_equals($kp1['publicKey'], $kp3['publicKey']));

// Keypair usable for sign/verify
$sig = OQS\Signature::sign($alg, 'hello', $kp1['secretKey']);
var_dump(OQS\Signature::verify($alg, 'hello', $sig, $kp1['publicKey']));

// A subsequent OQS\Signature::keypair() call must use real entropy again
// (the derand helper restores the system RNG). Two back-to-back calls must
// produce different output.
$rand1 = OQS\Signature::keypair($alg);
$rand2 = OQS\Signature::keypair($alg);
var_dump(!hash_equals($rand1['publicKey'], $rand2['publicKey']));

// Seed too short → throws
try {
    OQS\Signature::keypairDerand($alg, 'short');
    echo "expected throw\n";
} catch (OQS\Exception $e) {
    echo "caught short seed: ok\n";
}

// Unsupported algorithm → throws
try {
    OQS\Signature::keypairDerand('NOT-AN-ALG', $seed);
    echo "expected throw\n";
} catch (OQS\Exception $e) {
    echo "caught unsupported alg: ok\n";
}
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
caught short seed: ok
caught unsupported alg: ok
