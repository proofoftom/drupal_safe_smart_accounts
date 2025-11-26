<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Service;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\safe_smart_accounts\Entity\SafeAccount;
use Drupal\safe_smart_accounts\Entity\SafeTransaction;
use Drupal\safe_smart_accounts\Entity\SafeConfiguration;

/**
 * Service for managing Safe transaction workflows.
 *
 * This service orchestrates Safe transaction operations including creation,
 * signature collection, and execution. It coordinates between API and
 * blockchain services to provide a complete transaction management workflow.
 */
class SafeTransactionService {

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * The Safe API service.
   *
   * @var \Drupal\safe_smart_accounts\Service\SafeApiService
   */
  protected SafeApiService $safeApiService;

  /**
   * The Safe blockchain service.
   *
   * @var \Drupal\safe_smart_accounts\Service\SafeBlockchainService
   */
  protected SafeBlockchainService $safeBlockchainService;

  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelInterface
   */
  protected LoggerChannelInterface $logger;

  /**
   * Constructs a SafeTransactionService object.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\safe_smart_accounts\Service\SafeApiService $safe_api_service
   *   The Safe API service.
   * @param \Drupal\safe_smart_accounts\Service\SafeBlockchainService $safe_blockchain_service
   *   The Safe blockchain service.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   */
  public function __construct(
    EntityTypeManagerInterface $entity_type_manager,
    SafeApiService $safe_api_service,
    SafeBlockchainService $safe_blockchain_service,
    LoggerChannelFactoryInterface $logger_factory,
  ) {
    $this->entityTypeManager = $entity_type_manager;
    $this->safeApiService = $safe_api_service;
    $this->safeBlockchainService = $safe_blockchain_service;
    $this->logger = $logger_factory->get('safe_smart_accounts');
  }

  /**
   * Creates a new Safe transaction proposal.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   * @param array $transaction_data
   *   Transaction data (to, value, data, operation).
   * @param int $created_by_uid
   *   User ID of the transaction creator.
   *
   * @return \Drupal\safe_smart_accounts\Entity\SafeTransaction|null
   *   The created transaction entity or NULL on failure.
   */
  public function createTransaction(SafeAccount $safe_account, array $transaction_data, int $created_by_uid): ?SafeTransaction {
    try {
      // Validate transaction data.
      if (!$this->validateTransactionData($transaction_data)) {
        $this->logger->error('Invalid transaction data provided');
        return NULL;
      }

      // Get next nonce for the Safe.
      $nonce = $this->getNextNonce($safe_account);

      // Create SafeTransaction entity.
      $transaction_storage = $this->entityTypeManager->getStorage('safe_transaction');
      $transaction = $transaction_storage->create([
        'safe_account' => $safe_account->id(),
        'to_address' => $transaction_data['to'],
        'value' => (string) $transaction_data['value'],
        'data' => $transaction_data['data'] ?? '0x',
        'operation' => $transaction_data['operation'] ?? 0,
        'gas_estimate' => $transaction_data['gas_limit'] ?? NULL,
        'nonce' => $nonce,
        'status' => 'draft',
        'created_by' => $created_by_uid,
        'signatures' => json_encode([]),
      ]);

      $transaction->save();

      $this->logger->info('Created Safe transaction @id for Safe @safe', [
        '@id' => $transaction->id(),
        '@safe' => $safe_account->id(),
      ]);

      /** @var \Drupal\safe_smart_accounts\Entity\SafeTransaction $transaction */
      return $transaction;

    }
    catch (\Exception $e) {
      $this->logger->error('Failed to create Safe transaction: @message', [
        '@message' => $e->getMessage(),
      ]);
    }

    return NULL;
  }

  /**
   * Adds a signature to a transaction.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeTransaction $transaction
   *   The transaction entity.
   * @param string $signature
   *   The signature to add.
   * @param string $signer_address
   *   The address of the signer.
   *
   * @return bool
   *   TRUE if signature was added successfully, FALSE otherwise.
   */
  public function addSignature(SafeTransaction $transaction, string $signature, string $signer_address): bool {
    try {
      // Validate signer is authorized.
      if (!$this->isValidSigner($transaction->getSafeAccount(), $signer_address)) {
        $this->logger->warning('Unauthorized signer attempted to sign transaction @id', [
          '@id' => $transaction->id(),
        ]);
        return FALSE;
      }

      // Get existing signatures.
      $signatures = $transaction->getSignatures();

      // Check if this signer already signed.
      foreach ($signatures as $existing_signature) {
        if ($existing_signature['signer'] === $signer_address) {
          $this->logger->info('Signer @signer already signed transaction @id', [
            '@signer' => $signer_address,
            '@id' => $transaction->id(),
          ]);
          // Already signed.
          return TRUE;
        }
      }

      // Add new signature.
      $signatures[] = [
        'signer' => $signer_address,
        'signature' => $signature,
        'signed_at' => time(),
      ];

      $transaction->setSignatures($signatures);

      // Update status if we have enough signatures.
      if ($transaction->canExecute()) {
        $transaction->setStatus('pending');
      }

      $transaction->save();

      $this->logger->info('Added signature from @signer to transaction @id', [
        '@signer' => $signer_address,
        '@id' => $transaction->id(),
      ]);

      return TRUE;

    }
    catch (\Exception $e) {
      $this->logger->error('Failed to add signature to transaction: @message', [
        '@message' => $e->getMessage(),
      ]);
    }

    return FALSE;
  }

  /**
   * Executes a Safe transaction.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeTransaction $transaction
   *   The transaction to execute.
   *
   * @return bool
   *   TRUE if execution was initiated successfully, FALSE otherwise.
   */
  public function executeTransaction(SafeTransaction $transaction): bool {
    try {
      // Check if transaction can be executed.
      if (!$transaction->canExecute()) {
        $this->logger->warning('Transaction @id cannot be executed - insufficient signatures', [
          '@id' => $transaction->id(),
        ]);
        return FALSE;
      }

      $safe_account = $transaction->getSafeAccount();
      if (!$safe_account) {
        $this->logger->error('No Safe account found for transaction @id', [
          '@id' => $transaction->id(),
        ]);
        return FALSE;
      }

      // Prepare transaction data for blockchain submission.
      $blockchain_data = [
        'to' => $transaction->getToAddress(),
        'value' => $transaction->getValue(),
        'data' => $transaction->getData(),
        'operation' => $transaction->getOperation(),
        'nonce' => $transaction->get('nonce')->value,
        'signatures' => $transaction->getSignatures(),
      ];

      // Submit to blockchain.
      $result = $this->safeBlockchainService->submitTransaction(
        $safe_account->getSafeAddress(),
        $blockchain_data,
        $safe_account->getNetwork()
      );

      if ($result && isset($result['transaction_hash'])) {
        $transaction->set('blockchain_tx_hash', $result['transaction_hash']);
        $transaction->setStatus('pending');
        $transaction->save();

        $this->logger->info('Submitted transaction @id to blockchain with hash @hash', [
          '@id' => $transaction->id(),
          '@hash' => $result['transaction_hash'],
        ]);

        return TRUE;
      }

    }
    catch (\Exception $e) {
      $this->logger->error('Failed to execute Safe transaction: @message', [
        '@message' => $e->getMessage(),
      ]);
    }

    return FALSE;
  }

  /**
   * Updates transaction statuses by checking blockchain.
   *
   * @param string $network
   *   The network to check (optional).
   *
   * @return int
   *   Number of transactions updated.
   */
  public function updateTransactionStatuses(?string $network = NULL): int {
    $updated_count = 0;

    try {
      // Get pending transactions.
      $transaction_storage = $this->entityTypeManager->getStorage('safe_transaction');
      $query = $transaction_storage->getQuery()
        ->accessCheck(FALSE)
        ->condition('status', ['pending'], 'IN')
        ->condition('blockchain_tx_hash', '', '<>');

      if ($network) {
        // Filter by network through Safe account relationship.
        $safe_account_storage = $this->entityTypeManager->getStorage('safe_account');
        $safe_query = $safe_account_storage->getQuery()
          ->accessCheck(FALSE)
          ->condition('network', $network);
        $safe_ids = $safe_query->execute();

        if (!empty($safe_ids)) {
          $query->condition('safe_account', $safe_ids, 'IN');
        }
      }

      $transaction_ids = $query->execute();

      if (empty($transaction_ids)) {
        return 0;
      }

      $transactions = $transaction_storage->loadMultiple($transaction_ids);

      /** @var \Drupal\safe_smart_accounts\Entity\SafeTransaction $transaction */
      foreach ($transactions as $transaction) {
        if ($this->updateTransactionStatus($transaction)) {
          $updated_count++;
        }
      }

      $this->logger->info('Updated @count transaction statuses', [
        '@count' => $updated_count,
      ]);

    }
    catch (\Exception $e) {
      $this->logger->error('Failed to update transaction statuses: @message', [
        '@message' => $e->getMessage(),
      ]);
    }

    return $updated_count;
  }

  /**
   * Updates a single transaction's status.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeTransaction $transaction
   *   The transaction to update.
   *
   * @return bool
   *   TRUE if status was updated, FALSE otherwise.
   */
  protected function updateTransactionStatus(SafeTransaction $transaction): bool {
    $blockchain_tx_hash = $transaction->get('blockchain_tx_hash')->value;
    if (empty($blockchain_tx_hash)) {
      return FALSE;
    }

    $safe_account = $transaction->getSafeAccount();
    if (!$safe_account) {
      return FALSE;
    }

    try {
      $status_data = $this->safeBlockchainService->getTransactionStatus(
        $blockchain_tx_hash,
        $safe_account->getNetwork()
      );

      if (!$status_data) {
        return FALSE;
      }

      $current_status = $transaction->getStatus();
      $new_status = $this->mapBlockchainStatus($status_data['status']);

      if ($current_status !== $new_status) {
        $transaction->setStatus($new_status);

        if ($new_status === 'executed') {
          $transaction->set('executed_at', time());
        }

        $transaction->save();

        $this->logger->info('Updated transaction @id status from @old to @new', [
          '@id' => $transaction->id(),
          '@old' => $current_status,
          '@new' => $new_status,
        ]);

        return TRUE;
      }

    }
    catch (\Exception $e) {
      $this->logger->error('Failed to update transaction @id status: @message', [
        '@id' => $transaction->id(),
        '@message' => $e->getMessage(),
      ]);
    }

    return FALSE;
  }

  /**
   * Gets the next nonce for a Safe account.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   *
   * @return int
   *   The next nonce.
   */
  protected function getNextNonce(SafeAccount $safe_account): int {
    // Get the highest nonce from existing transactions.
    // NOTE: We must check for IS NOT NULL instead of not-equal-to-empty-string
    // because nonce can be 0, and we need to include that in our search.
    $transaction_storage = $this->entityTypeManager->getStorage('safe_transaction');
    $query = $transaction_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('safe_account', $safe_account->id())
      ->condition('nonce', NULL, 'IS NOT NULL')
      ->sort('nonce', 'DESC')
      ->range(0, 1);

    $result = $query->execute();

    if (!empty($result)) {
      /** @var \Drupal\safe_smart_accounts\Entity\SafeTransaction $transaction */
      $transaction = $transaction_storage->load(reset($result));
      return (int) $transaction->get('nonce')->value + 1;
    }

    // If no transactions exist, start from 0.
    return 0;
  }

  /**
   * Validates transaction data.
   *
   * @param array $transaction_data
   *   The transaction data to validate.
   *
   * @return bool
   *   TRUE if valid, FALSE otherwise.
   */
  protected function validateTransactionData(array $transaction_data): bool {
    // Check required fields.
    if (empty($transaction_data['to'])) {
      return FALSE;
    }

    // Validate Ethereum address format.
    if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $transaction_data['to'])) {
      return FALSE;
    }

    // Validate value is non-negative.
    if (isset($transaction_data['value']) && $transaction_data['value'] < 0) {
      return FALSE;
    }

    // Validate operation type.
    if (isset($transaction_data['operation']) && !in_array($transaction_data['operation'], [0, 1], TRUE)) {
      return FALSE;
    }

    return TRUE;
  }

  /**
   * Checks if an address is a valid signer for the Safe.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   * @param string $signer_address
   *   The signer address to validate.
   *
   * @return bool
   *   TRUE if valid signer, FALSE otherwise.
   */
  protected function isValidSigner(SafeAccount $safe_account, string $signer_address): bool {
    // Get Safe configuration.
    $config_storage = $this->entityTypeManager->getStorage('safe_configuration');
    $query = $config_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('safe_account_id', $safe_account->id())
      ->range(0, 1);

    $result = $query->execute();
    if (empty($result)) {
      return FALSE;
    }

    $config = $config_storage->load(reset($result));
    if (!$config instanceof SafeConfiguration) {
      return FALSE;
    }

    return $config->isSigner($signer_address);
  }

  /**
   * Maps blockchain status to Safe transaction status.
   *
   * @param string $blockchain_status
   *   The blockchain status.
   *
   * @return string
   *   The mapped Safe transaction status.
   */
  protected function mapBlockchainStatus(string $blockchain_status): string {
    switch ($blockchain_status) {
      case 'confirmed':
        return 'executed';

      case 'failed':
        return 'failed';

      case 'pending':
      default:
        return 'pending';
    }
  }

}
