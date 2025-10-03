--TEST--
KEM roundtrip: keypair -> encapsulate -> decapsulate
--SKIPIF--
<?php
if (!extension_loaded('oqs')) die("skip ext not loaded");
if (!class_exists('OQS\\KEM')) die("skip class missing");
$alg = getenv('KEM_ALG') ?: 'Kyber768';
try {
    [$pk, $sk] = OQS\KEM::keypair($alg);
} catch (Throwable $e) {
    die("skip $alg not available: " . $e->getMessage());
}
?>
--FILE--
<?php
$alg = getenv('KEM_ALG') ?: 'Kyber768';
[$pk, $sk] = OQS\KEM::keypair($alg);
[$ct, $ss1] = OQS\KEM::encapsulate($alg, $pk);
$ss2 = OQS\KEM::decapsulate($alg, $ct, $sk);
echo (hash_equals($ss1, $ss2) ? "OK\n" : "FAIL\n");
?>
--EXPECT--
OK
