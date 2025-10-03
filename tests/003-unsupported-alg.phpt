--TEST--
Exception on unsupported algorithm name
--SKIPIF--
<?php
if (!extension_loaded('oqs')) die("skip ext not loaded");
if (!class_exists('OQS\\KEM')) die("skip class missing");
?>
--FILE--
<?php
$alg = "Kyber9999";
$ok = 0;
try {
    OQS\KEM::keypair($alg);
} catch (Throwable $e) {
    echo "OK\n";
    $ok = 1;
}
if (!$ok) echo "FAIL\n";
?>
--EXPECT--
OK
