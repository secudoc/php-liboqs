--TEST--
Signature with context binding
--SKIPIF--
<?php if (!extension_loaded('oqs')) die('skip oqs not loaded'); ?>
--FILE--
<?php
$alg = 'ML-DSA-65';
$kp = OQS\Signature::keypair($alg);
$msg = 'Test message for context signing';
$ctx = 'secudoc-test-context';

// Sign with context
$sig = OQS\Signature::signWithContext($alg, $msg, $ctx, $kp['secretKey']);
var_dump(strlen($sig) > 0);

// Verify with correct context
var_dump(OQS\Signature::verifyWithContext($alg, $msg, $sig, $ctx, $kp['publicKey']));

// Verify with wrong context must fail
var_dump(OQS\Signature::verifyWithContext($alg, $msg, $sig, 'wrong-context', $kp['publicKey']));

// Verify without context must fail
var_dump(OQS\Signature::verify($alg, $msg, $sig, $kp['publicKey']));

// Sign without context, verify with context must fail
$sigNoCtx = OQS\Signature::sign($alg, $msg, $kp['secretKey']);
var_dump(OQS\Signature::verifyWithContext($alg, $msg, $sigNoCtx, $ctx, $kp['publicKey']));
?>
--EXPECT--
bool(true)
bool(true)
bool(false)
bool(false)
bool(false)
