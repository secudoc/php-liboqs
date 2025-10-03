--TEST--
Signature roundtrip: keypair -> sign -> verify
--SKIPIF--
<?php
if (!extension_loaded('oqs')) die("skip ext not loaded");
if (!class_exists('OQS\\Signature')) die("skip class missing");
$alg = getenv('SIG_ALG');
if ($alg === false || $alg === '') {
    $algs = OQS\Signature::algorithms();
    if (empty($algs)) {
        die("skip no signature algorithms available");
    }
    $alg = $algs[0];
}
try { OQS\Signature::keypair($alg); } catch (Throwable $e) { die("skip $alg not available"); }
?>
--FILE--
<?php
$alg = getenv('SIG_ALG');
if ($alg === false || $alg === '') {
    $algs = OQS\Signature::algorithms();
    if (empty($algs)) {
        throw new RuntimeException('No signature algorithms available');
    }
    $alg = $algs[0];
}
[$pk, $sk] = OQS\Signature::keypair($alg);
$message = random_bytes(32);
$sig = OQS\Signature::sign($alg, $message, $sk);
var_export(OQS\Signature::verify($alg, $message, $sig, $pk));
?>
--EXPECT--
true
