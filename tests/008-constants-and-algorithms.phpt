--TEST--
Algorithms and constants are exposed
--SKIPIF--
<?php
if (!extension_loaded('oqs')) die("skip ext not loaded");
if (!class_exists('OQS\\KEM')) die("skip class missing");
?>
--FILE--
<?php
$algs = OQS\KEM::algorithms();
if ($algs) {
    $first = $algs[0];
    $const = 'OQS\\KEM::ALG_' . strtoupper(preg_replace('/[^A-Za-z0-9]/', '_', $first));
    if (!defined($const) || constant($const) !== $first) {
        echo "FAIL\n";
        return;
    }
}

echo (defined('OQS\\EXTENSION_VERSION') ? "OK\n" : "FAIL\n");
?>
--EXPECT--
OK
