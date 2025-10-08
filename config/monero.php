<?php

return [
    'scheme' => env('MONERO_SCHEME', 'http'),
    'host' => env('MONERO_HOST', 'localhost'),
    'port' => env('MONERO_PORT', '18082'),
    'auth' => [
        env('MONERO_USERNAME', 'username'),
        env('MONERO_PASSWORD', 'password')
    ],
    'wallet-address' => env('MONERO_WALLET_ADDRESS', 'your-wallet-address'), // needs to be the current wallet open in RPC
];