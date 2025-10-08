# Laravel Monero Integration

## Installation

Copy files to your Laravel project:

- `src/Services/` → `app/Services/`
- `src/Cryptography/` → `app/Utilities/Cryptography/`
- `config/monero.php` → Laravel config directory

Install PHP dependencies:

```bash
composer require guzzlehttp/guzzle
```

Set environment variables in `.env`:

```env
MONERO_SCHEME=http
MONERO_HOST=localhost
MONERO_PORT=18082
MONERO_USERNAME=your_username
MONERO_PASSWORD=your_password
MONERO_WALLET_ADDRESS=your_wallet_address
```

## Usage

```php
use App\Services\MoneroService;

$monero = new MoneroService();

// Validate Monero address
$address = '4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRJ5BNjPiQCm5oC9t3ScZ6XwxmcfMwjvDjgBLnWBBVH';
$isValid = $monero->isValidAddress($address);

// Generate integrated address with payment ID
$paymentId = '1234567890abcdef';
$integratedAddress = $monero->generateIntegratedAddress($paymentId);

// Get wallet balance (requires configured RPC wallet)
$balance = $monero->getBalance();

// Get payments by payment ID
$payments = $monero->getPayments($paymentId);
```

## Credits

Monero & Cryptography utilities are a modified version of [monerophp](https://github.com/monero-integrations/monerophp).