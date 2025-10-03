--TEST--
Error on wrong key/ciphertext lengths
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
[$pk, $sk] = OQS\KEM::keypair($alg);

// Truncate to force a length error
$badPk = substr($pk, 0, max(0, strlen($pk)-5));
$badCt = substr(OQS\KEM::encapsulate($alg, $pk)[0], 0, 5);
$failed = 0;

try {
    OQS\KEM::encapsulate($alg, $badPk);
} catch (Throwable $e) { echo "encaps:ERROR\n"; $failed++; }

try {
    OQS\KEM::decapsulate($alg, $badCt, $sk);
} catch (Throwable $e) { echo "decaps:ERROR\n"; $failed++; }

echo ($failed === 2 ? "OK\n" : "FAIL\n");
?>
--EXPECT--
encaps:ERROR
decaps:ERROR
OK
