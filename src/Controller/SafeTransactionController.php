<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Controller;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\safe_smart_accounts\Entity\SafeAccount;
use Drupal\safe_smart_accounts\Entity\SafeTransaction;
use Drupal\safe_smart_accounts\Service\SafeTransactionService;
use Drupal\safe_smart_accounts\Service\SafeConfigurationService;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * Controller for Safe transaction API endpoints.
 */
class SafeTransactionController extends ControllerBase {

  /**
   * The Safe transaction service.
   *
   * @var \Drupal\safe_smart_accounts\Service\SafeTransactionService
   */
  protected SafeTransactionService $transactionService;

  /**
   * The Safe configuration service.
   *
   * @var \Drupal\safe_smart_accounts\Service\SafeConfigurationService
   */
  protected SafeConfigurationService $configurationService;

  /**
   * The logger service.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected LoggerInterface $logger;

  /**
   * Constructs a SafeTransactionController object.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\safe_smart_accounts\Service\SafeTransactionService $transaction_service
   *   The Safe transaction service.
   * @param \Drupal\safe_smart_accounts\Service\SafeConfigurationService $configuration_service
   *   The Safe configuration service.
   * @param \Psr\Log\LoggerInterface $logger
   *   The logger service.
   */
  public function __construct(
    EntityTypeManagerInterface $entity_type_manager,
    SafeTransactionService $transaction_service,
    SafeConfigurationService $configuration_service,
    LoggerInterface $logger,
  ) {
    $this->entityTypeManager = $entity_type_manager;
    $this->transactionService = $transaction_service;
    $this->configurationService = $configuration_service;
    $this->logger = $logger;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity_type.manager'),
      $container->get('safe_smart_accounts.transaction_service'),
      $container->get('safe_smart_accounts.configuration_service'),
      $container->get('logger.factory')->get('safe_smart_accounts')
    );
  }

  /**
   * Gets transaction data for signing.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param \Drupal\safe_smart_accounts\Entity\SafeTransaction $safe_transaction
   *   The Safe transaction entity.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with transaction data for signing.
   */
  public function getTransactionData(SafeAccount $safe_account, SafeTransaction $safe_transaction, Request $request): JsonResponse {
    // Verify transaction belongs to this Safe.
    if ($safe_transaction->getSafeAccount()?->id() !== $safe_account->id()) {
      return new JsonResponse(['error' => 'Transaction does not belong to this Safe account'], 400);
    }

    // Get Safe configuration for signers list.
    $safe_config_storage = $this->entityTypeManager()->getStorage('safe_configuration');
    $configurations = $safe_config_storage->loadByProperties(['safe_account_id' => $safe_account->id()]);
    $safe_configuration = !empty($configurations) ? reset($configurations) : NULL;

    $signers = $safe_configuration ? $safe_configuration->getSigners() : [];

    // Get nonce value, ensuring it's an integer.
    $nonce = $safe_transaction->get('nonce')->value;
    if ($nonce === NULL || $nonce === '') {
      $nonce = 0;
    }

    // Get value as string to avoid scientific notation.
    $value = $safe_transaction->getValue();
    // Ensure value is a string representation without scientific notation.
    // If it's already a valid numeric string without 'E', use it as-is.
    // Otherwise, convert through bcmath to handle large numbers safely.
    if (stripos($value, 'e') !== FALSE) {
      // Scientific notation detected, convert using sprintf with proper formatting.
      $value = sprintf('%.0f', (float) $value);
    }

    return new JsonResponse([
      'transaction_id' => $safe_transaction->id(),
      'safe_address' => $safe_account->getSafeAddress(),
      'safe_account_id' => $safe_account->id(),
      'network' => $safe_account->getNetwork(),
      'to' => $safe_transaction->getToAddress(),
      'value' => $value,
      'data' => $safe_transaction->getData(),
      'operation' => (int) $safe_transaction->getOperation(),
      'nonce' => (int) $nonce,
      'threshold' => $safe_account->getThreshold(),
      'signers' => $signers,
      'signatures' => $safe_transaction->getSignatures(),
      'status' => $safe_transaction->getStatus(),
      'can_execute' => $safe_transaction->canExecute(),
    ]);
  }

  /**
   * Signs a Safe transaction.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param \Drupal\safe_smart_accounts\Entity\SafeTransaction $safe_transaction
   *   The Safe transaction entity.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with signature status.
   */
  public function signTransaction(SafeAccount $safe_account, SafeTransaction $safe_transaction, Request $request): JsonResponse {
    // Verify transaction belongs to this Safe.
    if ($safe_transaction->getSafeAccount()?->id() !== $safe_account->id()) {
      return new JsonResponse(['error' => 'Transaction does not belong to this Safe account'], 400);
    }

    // Check if transaction can be signed.
    if ($safe_transaction->isExecuted()) {
      return new JsonResponse(['error' => 'Transaction is already executed'], 400);
    }

    if ($safe_transaction->getStatus() === 'cancelled') {
      return new JsonResponse(['error' => 'Transaction is cancelled'], 400);
    }

    // Get request data.
    $content = $request->getContent();
    if (empty($content)) {
      throw new BadRequestHttpException('Request body is empty');
    }

    $data = json_decode($content, TRUE);
    if (json_last_error() !== JSON_ERROR_NONE) {
      throw new BadRequestHttpException('Invalid JSON in request body');
    }

    // Validate required fields.
    if (!isset($data['signature']) || !isset($data['signer'])) {
      return new JsonResponse(['error' => 'Missing required fields: signature and signer'], 400);
    }

    $signature = $data['signature'];
    $signer_address = strtolower($data['signer']);

    // Validate Ethereum address format.
    if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $signer_address)) {
      return new JsonResponse(['error' => 'Invalid signer address format'], 400);
    }

    // Validate signature format (r, s, v format: 65 bytes = 132 hex chars + 0x).
    if (!preg_match('/^0x[a-fA-F0-9]{130}$/', $signature)) {
      return new JsonResponse(['error' => 'Invalid signature format'], 400);
    }

    try {
      // Add signature using transaction service.
      $result = $this->transactionService->addSignature($safe_transaction, $signature, $signer_address);

      if (!$result) {
        return new JsonResponse(['error' => 'Failed to add signature'], 500);
      }

      // Reload transaction to get updated signatures.
      $safe_transaction = $this->entityTypeManager()->getStorage('safe_transaction')->load($safe_transaction->id());

      return new JsonResponse([
        'success' => TRUE,
        'message' => 'Signature added successfully',
        'transaction_id' => $safe_transaction->id(),
        'signatures' => $safe_transaction->getSignatures(),
        'signature_count' => count($safe_transaction->getSignatures()),
        'threshold' => $safe_account->getThreshold(),
        'can_execute' => $safe_transaction->canExecute(),
        'status' => $safe_transaction->getStatus(),
      ]);

    }
    catch (\Exception $e) {
      $this->logger->error('Failed to sign transaction: @message', [
        '@message' => $e->getMessage(),
      ]);

      return new JsonResponse(['error' => 'Failed to sign transaction: ' . $e->getMessage()], 500);
    }
  }

  /**
   * Executes a Safe transaction.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param \Drupal\safe_smart_accounts\Entity\SafeTransaction $safe_transaction
   *   The Safe transaction entity.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with execution status.
   */
  public function executeTransaction(SafeAccount $safe_account, SafeTransaction $safe_transaction, Request $request): JsonResponse {
    // Verify transaction belongs to this Safe.
    if ($safe_transaction->getSafeAccount()?->id() !== $safe_account->id()) {
      return new JsonResponse(['error' => 'Transaction does not belong to this Safe account'], 400);
    }

    // Check if transaction can be executed.
    if ($safe_transaction->isExecuted()) {
      return new JsonResponse(['error' => 'Transaction is already executed'], 400);
    }

    if ($safe_transaction->getStatus() === 'cancelled') {
      return new JsonResponse(['error' => 'Transaction is cancelled'], 400);
    }

    if (!$safe_transaction->canExecute()) {
      $threshold = $safe_account->getThreshold();
      $signature_count = count($safe_transaction->getSignatures());
      return new JsonResponse([
        'error' => "Transaction does not have enough signatures ({$signature_count} of {$threshold})",
      ], 400);
    }

    // Get request data (blockchain tx hash after execution).
    $content = $request->getContent();
    if (empty($content)) {
      throw new BadRequestHttpException('Request body is empty');
    }

    $data = json_decode($content, TRUE);
    if (json_last_error() !== JSON_ERROR_NONE) {
      throw new BadRequestHttpException('Invalid JSON in request body');
    }

    // Validate blockchain transaction hash.
    if (!isset($data['blockchain_tx_hash'])) {
      return new JsonResponse(['error' => 'Missing required field: blockchain_tx_hash'], 400);
    }

    $blockchain_tx_hash = $data['blockchain_tx_hash'];

    // Validate transaction hash format.
    if (!preg_match('/^0x[a-fA-F0-9]{64}$/', $blockchain_tx_hash)) {
      return new JsonResponse(['error' => 'Invalid blockchain transaction hash format'], 400);
    }

    try {
      // Mark transaction as executed.
      $safe_transaction->markExecuted($blockchain_tx_hash);
      $safe_transaction->save();

      $this->logger->info('Safe transaction @id executed with blockchain tx @tx', [
        '@id' => $safe_transaction->id(),
        '@tx' => $blockchain_tx_hash,
      ]);

      // Check if this is a configuration change transaction and apply it.
      $tx_data = $safe_transaction->getData();
      if (!empty($tx_data) && $tx_data !== '0x') {
        $config_change = $this->configurationService->detectConfigurationChange($tx_data);

        if ($config_change) {
          $this->logger->info('Detected configuration change transaction: @type', [
            '@type' => $config_change['type'],
          ]);

          $applied = $this->configurationService->applyConfigurationChange($safe_account, $config_change);

          if ($applied) {
            $this->logger->info('Successfully applied configuration change to Safe @id', [
              '@id' => $safe_account->id(),
            ]);
          }
          else {
            $this->logger->warning('Failed to apply configuration change to Safe @id', [
              '@id' => $safe_account->id(),
            ]);
          }
        }
      }

      return new JsonResponse([
        'success' => TRUE,
        'message' => 'Transaction executed successfully',
        'transaction_id' => $safe_transaction->id(),
        'blockchain_tx_hash' => $blockchain_tx_hash,
        'status' => $safe_transaction->getStatus(),
      ]);

    }
    catch (\Exception $e) {
      $this->logger->error('Failed to execute transaction: @message', [
        '@message' => $e->getMessage(),
      ]);

      return new JsonResponse(['error' => 'Failed to execute transaction: ' . $e->getMessage()], 500);
    }
  }

  /**
   * Gets transaction status.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param \Drupal\safe_smart_accounts\Entity\SafeTransaction $safe_transaction
   *   The Safe transaction entity.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with transaction status.
   */
  public function getTransactionStatus(SafeAccount $safe_account, SafeTransaction $safe_transaction, Request $request): JsonResponse {
    // Verify transaction belongs to this Safe.
    if ($safe_transaction->getSafeAccount()?->id() !== $safe_account->id()) {
      return new JsonResponse(['error' => 'Transaction does not belong to this Safe account'], 400);
    }

    return new JsonResponse([
      'transaction_id' => $safe_transaction->id(),
      'status' => $safe_transaction->getStatus(),
      'signatures' => $safe_transaction->getSignatures(),
      'signature_count' => count($safe_transaction->getSignatures()),
      'threshold' => $safe_account->getThreshold(),
      'can_execute' => $safe_transaction->canExecute(),
      'blockchain_tx_hash' => $safe_transaction->get('blockchain_tx_hash')->value,
      'executed_at' => $safe_transaction->get('executed_at')->value,
      'created' => $safe_transaction->get('created')->value,
    ]);
  }

  /**
   * Access callback for transaction API endpoints.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param \Drupal\safe_smart_accounts\Entity\SafeTransaction $safe_transaction
   *   The Safe transaction entity.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The user account to check access for.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function transactionApiAccess(SafeAccount $safe_account, SafeTransaction $safe_transaction, AccountInterface $account): AccessResultInterface {
    // Check if transaction belongs to this Safe.
    if ($safe_transaction->getSafeAccount()?->id() !== $safe_account->id()) {
      return AccessResult::forbidden('Transaction does not belong to this Safe account');
    }

    // Check if user owns the Safe account.
    if ($safe_account->getUser()?->id() == $account->id()) {
      if ($account->hasPermission('manage own safe smart accounts')) {
        return AccessResult::allowed()->addCacheableDependency($safe_account)->addCacheableDependency($safe_transaction);
      }
    }

    // Check if user is a signer on the Safe.
    // Load Safe configuration to check signers.
    $safe_config_storage = $this->entityTypeManager()->getStorage('safe_configuration');
    $configurations = $safe_config_storage->loadByProperties(['safe_account_id' => $safe_account->id()]);
    $safe_configuration = !empty($configurations) ? reset($configurations) : NULL;

    if ($safe_configuration) {
      // Get user's Ethereum address.
      $user_storage = $this->entityTypeManager()->getStorage('user');
      $user = $user_storage->load($account->id());

      if ($user && $user->hasField('field_ethereum_address')) {
        $user_eth_address = strtolower($user->get('field_ethereum_address')->value ?? '');
        $signers = array_map('strtolower', $safe_configuration->getSigners());

        if (in_array($user_eth_address, $signers, TRUE)) {
          return AccessResult::allowed()->addCacheableDependency($safe_account)->addCacheableDependency($safe_transaction);
        }
      }
    }

    // Check if user is an admin.
    if ($account->hasPermission('administer safe smart accounts')) {
      return AccessResult::allowed()->addCacheableDependency($safe_account)->addCacheableDependency($safe_transaction);
    }

    return AccessResult::forbidden()->addCacheableDependency($safe_account)->addCacheableDependency($safe_transaction);
  }

}