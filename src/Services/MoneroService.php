<?php

namespace App\Services;

use Exception;
use App\Models\User;
use App\Cryptography\Cryptonote;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class MoneroService
{
    protected string $rpcUrl;
    protected GuzzleClient $client;
    protected array $auth;
    protected Cryptonote $cryptonote;

    public function __construct()
    {
        $this->rpcUrl = config('monero.scheme') . '://' . config('monero.host') . ':' . config('monero.port');
        $this->auth = config('monero.auth');
        $this->client = new GuzzleClient([
            'base_uri' => $this->rpcUrl,
            'timeout' => 10.0,
        ]);

        if (config('app.debug')) {
            // Stagenet
            $this->cryptonote = new Cryptonote([
                'address'    => '18', // 24 (0x18)
                'integrated' => '19', // 25 (0x19)
                'subaddress' => '24', // 36 (0x24)
            ]);
        } else {
            // Mainnet
            $this->cryptonote = new Cryptonote([
                'address'    => '12', // 18 (0x12)
                'integrated' => '13', // 19 (0x13)
                'subaddress' => '2a', // 42 (0x2a)
            ]);
        }
    }

    /**
     * Make a POST request to the Monero RPC.
     */
    private function makeRpcRequest(string $method, array $params = null): array
    {
        try {
            $response = $this->client->post('/json_rpc', [
                'auth' => [
                    $this->auth[0], // username
                    $this->auth[1], // password
                    'digest',
                ],
                'json' => [
                    'jsonrpc' => '2.0',
                    'id' => 0,
                    'method' => $method,
                    'params' => $params,
                ],
            ]);
            return $this->handleResponse($response);
        } catch (RequestException $e) {
            Log::error("MoneroRPC request error: " . $e->getMessage());
            return ['error' => $e->getMessage()];
        }
    }

    /**
     * Handle and decode Guzzle response.
     */
    private function handleResponse($response): array
    {
        $body = (string) $response->getBody();
        $decoded = json_decode($body, true);
        
        if (!is_array($decoded)) {
            return ['error' => 'Invalid JSON response'];
        }
        
        if (isset($decoded['error'])) {
            throw new Exception('Monero Json RPC returned an error (' . $decoded['error']['code'] . '). ' . $decoded['error']['message']);
        }
        
        return $decoded['result'] ?? $decoded;
    }

    /**
     * Validate Monero address.
     */
    public function isValidAddress(string $address): bool
    {
        try {
            $this->cryptonote->decode_address($address);
            return true;
        } catch (Exception) {
            return false;
        }
    }

    /**
     * Generate an integrated address from public view and spend key.
     */
    public function generateIntegratedAddress($paymentId)
    {
        $publicKeys = $this->cryptonote->decode_address(config('monero.wallet-address'));
        $integratedAddress = $this->cryptonote->integrated_addr_from_keys($publicKeys['spendKey'], $publicKeys['viewKey'], $paymentId);

        return $integratedAddress;
    }

    /**
     * Get wallet balance.
     */
    public function getBalance()
    {
        $response = $this->makeRpcRequest('get_balance');
        $walletAddress = config('monero.wallet-address');
        
        foreach ($response['per_subaddress'] as $subaddress) {
            if ($subaddress['address'] === $walletAddress) {
                return $subaddress['balance'];
            }
        }
        
        return 0;
    }

    /**
     * Get payments by payment ID.
     */
    public function getPayments(string $paymentId): array
    {
        return $this->makeRpcRequest('get_payments', ['payment_id' => $paymentId]);
    }
}