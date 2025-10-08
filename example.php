<?php

require_once 'vendor/autoload.php';

use App\Services\MoneroService;

// Example usage
$monero = new MoneroService();

// Validate an address
$address = '4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRJ5BNjPiQCm5oC9t3ScZ6XwxmcfMwjvDjgBLnWBBVH';
$isValid = $monero->isValidAddress($address);
echo "Address valid: " . ($isValid ? 'Yes' : 'No') . "\n";

// Generate integrated address
$paymentId = '1234567890abcdef';
$integratedAddress = $monero->generateIntegratedAddress($paymentId);
echo "Integrated address: " . $integratedAddress . "\n";

// Get balance (requires configured wallet)
// $balance = $monero->getBalance();
// echo "Balance: " . $balance . "\n";