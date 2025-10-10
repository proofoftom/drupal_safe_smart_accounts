<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\RequestException;

/**
 * Service for interacting with Safe API services.
 *
 * This service provides an abstraction layer for Safe API operations.
 * In Phase 1 (MVP), it uses mock implementations.
 * In Phase 2, it will integrate with actual Safe API services.
 */
class SafeApiService {

  // Safe contract addresses used on Hardhat (mainnet addresses since Hardhat forks mainnet)
  public const HARDHAT_SAFE_SINGLETON = '0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552';
  public const HARDHAT_SAFE_PROXY_FACTORY = '0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2';
  public const HARDHAT_COMPATIBILITY_FALLBACK_HANDLER = '0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4';

  /**
   * The HTTP client.
   *
   * @var \GuzzleHttp\ClientInterface
   */
  protected ClientInterface $httpClient;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelInterface
   */
  protected LoggerChannelInterface $logger;

  /**
   * Constructs a SafeApiService object.
   *
   * @param \GuzzleHttp\ClientInterface $http_client
   *   The HTTP client.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   */
  public function __construct(
    ClientInterface $http_client,
    ConfigFactoryInterface $config_factory,
    LoggerChannelFactoryInterface $logger_factory,
  ) {
    $this->httpClient = $http_client;
    $this->configFactory = $config_factory;
    $this->logger = $logger_factory->get('safe_smart_accounts');
  }

  /**
   * Gets Safe account information from Safe API.
   *
   * @param string $safe_address
   *   The Safe Smart Account address.
   * @param string $network
   *   The network identifier.
   *
   * @return array|null
   *   Safe account data or NULL on failure.
   */
  public function getSafeInfo(string $safe_address, string $network = 'sepolia'): ?array {
    // Phase 1: Mock implementation.
    if ($this->isMockMode()) {
      return $this->getMockSafeInfo($safe_address, $network);
    }

    // Phase 2: Real API implementation.
    try {
      $config = $this->configFactory->get('safe_smart_accounts.settings');
      $api_url = $config->get("network.{$network}.safe_service_url");

      if (!$api_url) {
        $this->logger->error('No Safe service URL configured for network: @network', [
          '@network' => $network,
        ]);
        return NULL;
      }

      $response = $this->httpClient->request('GET', "{$api_url}/api/v1/safes/{$safe_address}/", [
        'timeout' => $config->get('api.timeout') ?? 30,
        'headers' => [
          'Accept' => 'application/json',
        ],
      ]);

      if ($response->getStatusCode() === 200) {
        return json_decode($response->getBody()->getContents(), TRUE);
      }

    }
    catch (RequestException $e) {
      $this->logger->error('Failed to get Safe info from API: @message', [
        '@message' => $e->getMessage(),
      ]);
    }

    return NULL;
  }

  /**
   * Gets transaction history for a Safe.
   *
   * @param string $safe_address
   *   The Safe Smart Account address.
   * @param string $network
   *   The network identifier.
   * @param int $limit
   *   Maximum number of transactions to return.
   * @param int $offset
   *   Number of transactions to skip.
   *
   * @return array|null
   *   Transaction history data or NULL on failure.
   */
  public function getTransactionHistory(string $safe_address, string $network = 'sepolia', int $limit = 20, int $offset = 0): ?array {
    // Phase 1: Mock implementation.
    if ($this->isMockMode()) {
      return $this->getMockTransactionHistory($safe_address, $network, $limit, $offset);
    }

    // Phase 2: Real API implementation.
    try {
      $config = $this->configFactory->get('safe_smart_accounts.settings');
      $api_url = $config->get("network.{$network}.safe_service_url");

      if (!$api_url) {
        return NULL;
      }

      $query = http_build_query([
        'limit' => $limit,
        'offset' => $offset,
        'ordering' => '-execution_date',
      ]);

      $response = $this->httpClient->request('GET', "{$api_url}/api/v1/safes/{$safe_address}/multisig-transactions/?{$query}", [
        'timeout' => $config->get('api.timeout') ?? 30,
      ]);

      if ($response->getStatusCode() === 200) {
        return json_decode($response->getBody()->getContents(), TRUE);
      }

    }
    catch (RequestException $e) {
      $this->logger->error('Failed to get transaction history from API: @message', [
        '@message' => $e->getMessage(),
      ]);
    }

    return NULL;
  }

  /**
   * Gets pending transactions for a Safe.
   *
   * @param string $safe_address
   *   The Safe Smart Account address.
   * @param string $network
   *   The network identifier.
   *
   * @return array|null
   *   Pending transactions data or NULL on failure.
   */
  public function getPendingTransactions(string $safe_address, string $network = 'sepolia'): ?array {
    // Phase 1: Mock implementation.
    if ($this->isMockMode()) {
      return $this->getMockPendingTransactions($safe_address, $network);
    }

    // Phase 2: Real API implementation.
    try {
      $config = $this->configFactory->get('safe_smart_accounts.settings');
      $api_url = $config->get("network.{$network}.safe_service_url");

      if (!$api_url) {
        return NULL;
      }

      $response = $this->httpClient->request('GET', "{$api_url}/api/v1/safes/{$safe_address}/multisig-transactions/", [
        'query' => ['executed' => 'false'],
        'timeout' => $config->get('api.timeout') ?? 30,
      ]);

      if ($response->getStatusCode() === 200) {
        return json_decode($response->getBody()->getContents(), TRUE);
      }

    }
    catch (RequestException $e) {
      $this->logger->error('Failed to get pending transactions from API: @message', [
        '@message' => $e->getMessage(),
      ]);
    }

    return NULL;
  }

  /**
   * Proposes a new transaction to the Safe API.
   *
   * @param string $safe_address
   *   The Safe Smart Account address.
   * @param array $transaction_data
   *   The transaction data.
   * @param string $network
   *   The network identifier.
   *
   * @return array|null
   *   Transaction proposal response or NULL on failure.
   */
  public function proposeTransaction(string $safe_address, array $transaction_data, string $network = 'sepolia'): ?array {
    // Phase 1: Mock implementation.
    if ($this->isMockMode()) {
      return $this->getMockTransactionProposal($safe_address, $transaction_data, $network);
    }

    // Phase 2: Real API implementation.
    try {
      $config = $this->configFactory->get('safe_smart_accounts.settings');
      $api_url = $config->get("network.{$network}.safe_service_url");

      if (!$api_url) {
        return NULL;
      }

      $response = $this->httpClient->request('POST', "{$api_url}/api/v1/safes/{$safe_address}/multisig-transactions/", [
        'json' => $transaction_data,
        'timeout' => $config->get('api.timeout') ?? 30,
        'headers' => [
          'Content-Type' => 'application/json',
        ],
      ]);

      if ($response->getStatusCode() === 201) {
        return json_decode($response->getBody()->getContents(), TRUE);
      }

    }
    catch (RequestException $e) {
      $this->logger->error('Failed to propose transaction to API: @message', [
        '@message' => $e->getMessage(),
      ]);
    }

    return NULL;
  }

  /**
   * Gets gas estimation for a transaction.
   *
   * @param string $safe_address
   *   The Safe Smart Account address.
   * @param array $transaction_data
   *   The transaction data.
   * @param string $network
   *   The network identifier.
   *
   * @return array|null
   *   Gas estimation data or NULL on failure.
   */
  public function estimateGas(string $safe_address, array $transaction_data, string $network = 'sepolia'): ?array {
    // Phase 1: Mock implementation.
    if ($this->isMockMode()) {
      return [
        'safeTxGas' => 21000,
        'baseGas' => 60000,
        'dataGas' => 1000,
        'operationalGas' => 10000,
      // 20 gwei
        'gasPrice' => 20000000000,
        'lastUsedNonce' => 0,
        'gasToken' => '0x0000000000000000000000000000000000000000',
        'refundReceiver' => '0x0000000000000000000000000000000000000000',
      ];
    }

    // Phase 2: Real API implementation would go here.
    return NULL;
  }

  /**
   * Checks if the service is in mock mode.
   *
   * @return bool
   *   TRUE if in mock mode, FALSE otherwise.
   */
  protected function isMockMode(): bool {
    $config = $this->configFactory->get('safe_smart_accounts.settings');
    // Default to mock mode in MVP.
    return $config->get('api.mock_mode') ?? TRUE;
  }

  /**
   * Provides mock Safe info data.
   *
   * @param string $safe_address
   *   The Safe address.
   * @param string $network
   *   The network identifier.
   *
   * @return array
   *   Mock Safe info data.
   */
  protected function getMockSafeInfo(string $safe_address, string $network): array {
    return [
      'address' => $safe_address,
      'nonce' => 0,
      'threshold' => 1,
      'owners' => [
        '0x1234567890123456789012345678901234567890',
      ],
      'masterCopy' => '0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552',
      'modules' => [],
      'fallbackHandler' => '0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4',
      'guard' => '0x0000000000000000000000000000000000000000',
      'version' => '1.4.1',
      'network' => $network,
    ];
  }

  /**
   * Provides mock transaction history data.
   *
   * @param string $safe_address
   *   The Safe address.
   * @param string $network
   *   The network identifier.
   * @param int $limit
   *   The limit.
   * @param int $offset
   *   The offset.
   *
   * @return array
   *   Mock transaction history data.
   */
  protected function getMockTransactionHistory(string $safe_address, string $network, int $limit, int $offset): array {
    return [
      'count' => 2,
      'next' => NULL,
      'previous' => NULL,
      'results' => [
        [
          'safe' => $safe_address,
          'to' => '0x742d35Cc6634C0532925a3b8D8938d9e1Aac5C63',
          'value' => '1000000000000000000',
          'data' => '0x',
          'operation' => 0,
          'gasToken' => '0x0000000000000000000000000000000000000000',
          'safeTxGas' => 21000,
          'baseGas' => 60000,
          'gasPrice' => 20000000000,
          'refundReceiver' => '0x0000000000000000000000000000000000000000',
          'nonce' => 1,
          'executionDate' => '2025-01-06T12:00:00Z',
          'submissionDate' => '2025-01-06T11:55:00Z',
          'modified' => '2025-01-06T12:00:00Z',
          'blockNumber' => 5000000,
          'transactionHash' => '0x9876543210987654321098765432109876543210987654321098765432109876',
          'safeTxHash' => '0x1234567890123456789012345678901234567890123456789012345678901234',
          'signatures' => '0xabcdef...',
          'isExecuted' => TRUE,
          'isSuccessful' => TRUE,
        ],
      ],
    ];
  }

  /**
   * Provides mock pending transactions data.
   *
   * @param string $safe_address
   *   The Safe address.
   * @param string $network
   *   The network identifier.
   *
   * @return array
   *   Mock pending transactions data.
   */
  protected function getMockPendingTransactions(string $safe_address, string $network): array {
    return [
      'count' => 1,
      'results' => [
        [
          'safe' => $safe_address,
          'to' => '0x742d35Cc6634C0532925a3b8D8938d9e1Aac5C63',
          'value' => '500000000000000000',
          'data' => '0x',
          'operation' => 0,
          'nonce' => 2,
          'safeTxHash' => '0x5678901234567890123456789012345678901234567890123456789012345678',
          'signatures' => '0x',
          'isExecuted' => FALSE,
          'isSuccessful' => NULL,
          'confirmations' => [],
          'confirmationsRequired' => 1,
        ],
      ],
    ];
  }

  /**
   * Provides mock transaction proposal data.
   *
   * @param string $safe_address
   *   The Safe address.
   * @param array $transaction_data
   *   The transaction data.
   * @param string $network
   *   The network identifier.
   *
   * @return array
   *   Mock transaction proposal response.
   */
  protected function getMockTransactionProposal(string $safe_address, array $transaction_data, string $network): array {
    return [
      'safe' => $safe_address,
      'to' => $transaction_data['to'] ?? '0x0000000000000000000000000000000000000000',
      'value' => $transaction_data['value'] ?? '0',
      'data' => $transaction_data['data'] ?? '0x',
      'operation' => $transaction_data['operation'] ?? 0,
      'nonce' => 3,
      'safeTxHash' => '0x' . bin2hex(random_bytes(32)),
      'signatures' => '0x',
      'isExecuted' => FALSE,
      'isSuccessful' => NULL,
      'created' => date('c'),
    ];
  }

}
