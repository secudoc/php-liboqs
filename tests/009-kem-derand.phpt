--TEST--
KEM deterministic keypair and encapsulation
--SKIPIF--
<?php if (!extension_loaded('oqs')) die('skip oqs not loaded'); ?>
--FILE--
<?php
$alg = 'ML-KEM-768';
$seed = random_bytes(64);

// keypairDerand must be deterministic
$kp1 = OQS\KEM::keypairDerand($alg, $seed);
$kp2 = OQS\KEM::keypairDerand($alg, $seed);

var_dump(hash_equals($kp1['publicKey'], $kp2['publicKey']));
var_dump(hash_equals($kp1['secretKey'], $kp2['secretKey']));
var_dump(strlen($kp1['publicKey']) === 1184);
var_dump(strlen($kp1['secretKey']) === 2400);

// encapsulateDerand must be deterministic
$encSeed = random_bytes(64);
$enc1 = OQS\KEM::encapsulateDerand($alg, $kp1['publicKey'], $encSeed);
$enc2 = OQS\KEM::encapsulateDerand($alg, $kp1['publicKey'], $encSeed);

var_dump(hash_equals($enc1['ciphertext'], $enc2['ciphertext']));
var_dump(hash_equals($enc1['sharedSecret'], $enc2['sharedSecret']));

// decapsulate must recover the same shared secret
$ss = OQS\KEM::decapsulate($alg, $enc1['ciphertext'], $kp1['secretKey']);
var_dump(hash_equals($ss, $enc1['sharedSecret']));
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
