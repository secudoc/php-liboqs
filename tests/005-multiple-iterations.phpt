--TEST--
Multiple iterations are independent and consistent
--SKIPIF--
<?php
if (!extension_loaded('oqs')) die("skip ext not loaded");
if (!class_exists('OQS\\KEM')) die("skip class missing");
$alg = getenv('KEM_ALG') ?: 'Kyber768';
try { OQS\KEM::keypair($alg); } catch (Throwable $e) { die("skip $alg not available"); }
?>
--FILE--
<?php
$alg = getenv('KEM_ALG') ?: 'Kyber768';
for ($i = 0; $i < 5; $i++) {
    [$pk, $sk] = OQS\KEM::keypair($alg);
    [$ct, $ss1] = OQS\KEM::encapsulate($alg, $pk);
    $ss2 = OQS\KEM::decapsulate($alg, $ct, $sk);
    if (!hash_equals($ss1, $ss2)) { echo "FAIL\n"; exit; }
}
echo "OK\n";
?>
--EXPECT--
OK
