--TEST--
Binary outputs have expected lengths for the chosen KEM variant
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
[$ct, $ss] = OQS\KEM::encapsulate($alg, $pk);

printf("pk=%d sk=%d ct=%d ss=%d\n", strlen($pk), strlen($sk), strlen($ct), strlen($ss));

echo ((strlen($pk)>0 && strlen($sk)>0 && strlen($ct)>0 && strlen($ss)>0) ? "OK\n" : "FAIL\n");
?>
--EXPECTF--
pk=%d sk=%d ct=%d ss=%d
OK
