<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Service;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\safe_smart_accounts\Entity\SafeAccount;
use Drupal\safe_smart_accounts\Entity\SafeConfiguration;

/**
 * Service for encoding Safe configuration change transaction data.
 *
 * This service generates transaction data for Safe owner management operations:
 * - addOwnerWithThreshold: Add a new signer and update threshold
 * - removeOwner: Remove a signer and update threshold
 * - swapOwner: Replace one signer with another
 * - changeThreshold: Update the signature threshold
 *
 * Safe uses a linked list structure for owners, requiring prevOwner references.
 */
class SafeConfigurationService {

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelInterface
   */
  protected LoggerChannelInterface $logger;

  /**
   * Safe OwnerManager contract address (same as Safe singleton).
   *
   * Owner management functions are part of the Safe contract itself.
   *
   * @var string
   */
  protected const SENTINEL_OWNER = '0x0000000000000000000000000000000000000001';

  /**
   * Constructs a SafeConfigurationService object.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   */
  public function __construct(
    EntityTypeManagerInterface $entity_type_manager,
    LoggerChannelFactoryInterface $logger_factory,
  ) {
    $this->entityTypeManager = $entity_type_manager;
    $this->logger = $logger_factory->get('safe_smart_accounts');
  }

  /**
   * Generates transaction data for adding an owner with threshold.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   * @param string $new_owner
   *   Address of the new owner to add.
   * @param int $new_threshold
   *   New signature threshold.
   *
   * @return array
   *   Transaction data array with 'to', 'value', 'data', 'operation'.
   */
  public function encodeAddOwnerWithThreshold(SafeAccount $safe_account, string $new_owner, int $new_threshold): array {
    $safe_address = $safe_account->getSafeAddress();

    // Validate inputs.
    if (!$this->isValidAddress($new_owner)) {
      throw new \InvalidArgumentException('Invalid owner address: ' . $new_owner);
    }

    if ($new_threshold < 1) {
      throw new \InvalidArgumentException('Threshold must be at least 1');
    }

    // Function signature: addOwnerWithThreshold(address owner, uint256 _threshold)
    $function_selector = '0x0d582f13';

    // Encode parameters: address (32 bytes) + uint256 (32 bytes)
    $encoded_params = $this->encodeAddress($new_owner) . $this->encodeUint256($new_threshold);

    return [
      'to' => $safe_address,
      'value' => '0',
      'data' => $function_selector . $encoded_params,
      'operation' => 0,
    ];
  }

  /**
   * Generates transaction data for removing an owner.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   * @param string $owner_to_remove
   *   Address of the owner to remove.
   * @param int $new_threshold
   *   New signature threshold.
   *
   * @return array
   *   Transaction data array with 'to', 'value', 'data', 'operation'.
   */
  public function encodeRemoveOwner(SafeAccount $safe_account, string $owner_to_remove, int $new_threshold): array {
    $safe_address = $safe_account->getSafeAddress();
    $safe_config = $this->getSafeConfiguration($safe_account);

    if (!$safe_config) {
      throw new \RuntimeException('Safe configuration not found');
    }

    // Validate inputs.
    if (!$this->isValidAddress($owner_to_remove)) {
      throw new \InvalidArgumentException('Invalid owner address: ' . $owner_to_remove);
    }

    if ($new_threshold < 1) {
      throw new \InvalidArgumentException('Threshold must be at least 1');
    }

    // Get the previous owner in the linked list.
    $prev_owner = $this->getPreviousOwner($safe_config, $owner_to_remove);

    if (!$prev_owner) {
      throw new \RuntimeException('Could not determine previous owner for removal');
    }

    // Function signature: removeOwner(address prevOwner, address owner, uint256 _threshold)
    $function_selector = '0xf8dc5dd9';

    // Encode parameters: address + address + uint256
    $encoded_params = $this->encodeAddress($prev_owner)
      . $this->encodeAddress($owner_to_remove)
      . $this->encodeUint256($new_threshold);

    return [
      'to' => $safe_address,
      'value' => '0',
      'data' => $function_selector . $encoded_params,
      'operation' => 0,
    ];
  }

  /**
   * Generates transaction data for swapping an owner.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   * @param string $old_owner
   *   Address of the owner to replace.
   * @param string $new_owner
   *   Address of the new owner.
   *
   * @return array
   *   Transaction data array with 'to', 'value', 'data', 'operation'.
   */
  public function encodeSwapOwner(SafeAccount $safe_account, string $old_owner, string $new_owner): array {
    $safe_address = $safe_account->getSafeAddress();
    $safe_config = $this->getSafeConfiguration($safe_account);

    if (!$safe_config) {
      throw new \RuntimeException('Safe configuration not found');
    }

    // Validate inputs.
    if (!$this->isValidAddress($old_owner)) {
      throw new \InvalidArgumentException('Invalid old owner address: ' . $old_owner);
    }

    if (!$this->isValidAddress($new_owner)) {
      throw new \InvalidArgumentException('Invalid new owner address: ' . $new_owner);
    }

    // Get the previous owner in the linked list.
    $prev_owner = $this->getPreviousOwner($safe_config, $old_owner);

    if (!$prev_owner) {
      throw new \RuntimeException('Could not determine previous owner for swap');
    }

    // Function signature: swapOwner(address prevOwner, address oldOwner, address newOwner)
    $function_selector = '0xe318b52b';

    // Encode parameters: address + address + address
    $encoded_params = $this->encodeAddress($prev_owner)
      . $this->encodeAddress($old_owner)
      . $this->encodeAddress($new_owner);

    return [
      'to' => $safe_address,
      'value' => '0',
      'data' => $function_selector . $encoded_params,
      'operation' => 0,
    ];
  }

  /**
   * Generates transaction data for changing the threshold.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   * @param int $new_threshold
   *   New signature threshold.
   *
   * @return array
   *   Transaction data array with 'to', 'value', 'data', 'operation'.
   */
  public function encodeChangeThreshold(SafeAccount $safe_account, int $new_threshold): array {
    $safe_address = $safe_account->getSafeAddress();

    // Validate threshold.
    if ($new_threshold < 1) {
      throw new \InvalidArgumentException('Threshold must be at least 1');
    }

    $safe_config = $this->getSafeConfiguration($safe_account);
    if ($safe_config) {
      $owner_count = count($safe_config->getSigners());
      if ($new_threshold > $owner_count) {
        throw new \InvalidArgumentException("Threshold ({$new_threshold}) cannot exceed number of owners ({$owner_count})");
      }
    }

    // Function signature: changeThreshold(uint256 _threshold)
    $function_selector = '0x694e80c3';

    // Encode parameter: uint256
    $encoded_params = $this->encodeUint256($new_threshold);

    return [
      'to' => $safe_address,
      'value' => '0',
      'data' => $function_selector . $encoded_params,
      'operation' => 0,
    ];
  }

  /**
   * Calculates the difference between current and new signer lists.
   *
   * @param array $current_signers
   *   Current signer addresses.
   * @param array $new_signers
   *   New signer addresses.
   *
   * @return array
   *   Array with 'additions' and 'removals' keys.
   */
  public function calculateSignerChanges(array $current_signers, array $new_signers): array {
    // Normalize addresses to lowercase for comparison.
    $current = array_map('strtolower', $current_signers);
    $new = array_map('strtolower', $new_signers);

    return [
      'additions' => array_values(array_diff($new, $current)),
      'removals' => array_values(array_diff($current, $new)),
    ];
  }

  /**
   * Gets the previous owner in the linked list for a given owner.
   *
   * Safe uses a linked list where each owner points to the next.
   * SENTINEL_OWNER (0x1) is the first element, pointing to the first real owner.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeConfiguration $safe_config
   *   The Safe configuration.
   * @param string $owner
   *   The owner address to find the previous owner for.
   *
   * @return string|null
   *   The previous owner address, or NULL if not found.
   */
  protected function getPreviousOwner(SafeConfiguration $safe_config, string $owner): ?string {
    $signers = $safe_config->getSigners();

    // Normalize to lowercase for comparison.
    $owner = strtolower($owner);
    $signers = array_map('strtolower', $signers);

    // Find the position of the owner.
    $position = array_search($owner, $signers, TRUE);

    if ($position === FALSE) {
      $this->logger->error('Owner not found in signers list: @owner', ['@owner' => $owner]);
      return NULL;
    }

    // If it's the first owner, the previous is SENTINEL_OWNER.
    if ($position === 0) {
      return self::SENTINEL_OWNER;
    }

    // Otherwise, return the previous signer.
    return $signers[$position - 1];
  }

  /**
   * Validates an Ethereum address format.
   *
   * @param string $address
   *   The address to validate.
   *
   * @return bool
   *   TRUE if valid, FALSE otherwise.
   */
  protected function isValidAddress(string $address): bool {
    return preg_match('/^0x[a-fA-F0-9]{40}$/', $address) === 1;
  }

  /**
   * Encodes an Ethereum address to 32-byte hex string.
   *
   * @param string $address
   *   The address (20 bytes with 0x prefix).
   *
   * @return string
   *   32-byte hex string (no 0x prefix).
   */
  protected function encodeAddress(string $address): string {
    // Remove 0x prefix and pad to 32 bytes (64 hex chars).
    return str_pad(substr($address, 2), 64, '0', STR_PAD_LEFT);
  }

  /**
   * Encodes a uint256 value to 32-byte hex string.
   *
   * @param int $value
   *   The uint256 value.
   *
   * @return string
   *   32-byte hex string (no 0x prefix).
   */
  protected function encodeUint256(int $value): string {
    return str_pad(dechex($value), 64, '0', STR_PAD_LEFT);
  }

  /**
   * Gets the SafeConfiguration for a Safe account.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   *
   * @return \Drupal\safe_smart_accounts\Entity\SafeConfiguration|null
   *   The configuration or NULL if not found.
   */
  protected function getSafeConfiguration(SafeAccount $safe_account): ?SafeConfiguration {
    $config_storage = $this->entityTypeManager->getStorage('safe_configuration');
    $query = $config_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('safe_account_id', $safe_account->id())
      ->range(0, 1);

    $result = $query->execute();
    if (!empty($result)) {
      return $config_storage->load(reset($result));
    }

    return NULL;
  }

  /**
   * Detects if transaction data is a configuration change operation.
   *
   * Checks the function selector (first 4 bytes of data) to identify
   * Safe owner management functions.
   *
   * @param string $data
   *   The transaction data (0x-prefixed hex).
   *
   * @return array|null
   *   Array with 'type' and 'params' if it's a config change, NULL otherwise.
   */
  public function detectConfigurationChange(string $data): ?array {
    if (empty($data) || $data === '0x' || strlen($data) < 10) {
      return NULL;
    }

    // Extract function selector (first 4 bytes = 8 hex chars after 0x).
    $selector = substr($data, 0, 10);

    // Map of function selectors to their types.
    $config_functions = [
      '0x0d582f13' => 'addOwnerWithThreshold',
      '0xf8dc5dd9' => 'removeOwner',
      '0xe318b52b' => 'swapOwner',
      '0x694e80c3' => 'changeThreshold',
    ];

    if (!isset($config_functions[$selector])) {
      return NULL;
    }

    $type = $config_functions[$selector];

    // Parse parameters based on function type.
    $params = $this->parseConfigurationChangeParams($type, $data);

    return [
      'type' => $type,
      'params' => $params,
    ];
  }

  /**
   * Parses configuration change parameters from transaction data.
   *
   * @param string $type
   *   The configuration change type.
   * @param string $data
   *   The transaction data.
   *
   * @return array
   *   Parsed parameters.
   */
  protected function parseConfigurationChangeParams(string $type, string $data): array {
    // Remove 0x prefix and function selector (8 hex chars).
    $params_hex = substr($data, 10);

    switch ($type) {
      case 'addOwnerWithThreshold':
        // addOwnerWithThreshold(address owner, uint256 _threshold)
        // 32 bytes owner + 32 bytes threshold.
        return [
          'owner' => '0x' . substr($params_hex, 24, 40),
          'threshold' => hexdec(substr($params_hex, 64, 64)),
        ];

      case 'removeOwner':
        // removeOwner(address prevOwner, address owner, uint256 _threshold)
        // 32 bytes prevOwner + 32 bytes owner + 32 bytes threshold.
        return [
          'prevOwner' => '0x' . substr($params_hex, 24, 40),
          'owner' => '0x' . substr($params_hex, 88, 40),
          'threshold' => hexdec(substr($params_hex, 128, 64)),
        ];

      case 'swapOwner':
        // swapOwner(address prevOwner, address oldOwner, address newOwner)
        // 32 bytes prevOwner + 32 bytes oldOwner + 32 bytes newOwner.
        return [
          'prevOwner' => '0x' . substr($params_hex, 24, 40),
          'oldOwner' => '0x' . substr($params_hex, 88, 40),
          'newOwner' => '0x' . substr($params_hex, 152, 40),
        ];

      case 'changeThreshold':
        // changeThreshold(uint256 _threshold)
        // 32 bytes threshold.
        return [
          'threshold' => hexdec(substr($params_hex, 0, 64)),
        ];

      default:
        return [];
    }
  }

  /**
   * Gets all SafeAccount IDs where a given address is a signer.
   *
   * @param string $address
   *   The Ethereum address to search for (case-insensitive).
   *
   * @return array
   *   Array of SafeAccount IDs where the address is a signer.
   */
  public function getSafesForSigner(string $address): array {
    $safe_ids = [];
    $address = strtolower($address);

    // Query all SafeConfiguration entities.
    $config_storage = $this->entityTypeManager->getStorage('safe_configuration');
    $configs = $config_storage->loadMultiple();

    foreach ($configs as $config) {
      if ($config->isSigner($address)) {
        $safe_account_id = $config->getSafeAccountId();
        if ($safe_account_id) {
          $safe_ids[] = $safe_account_id;
        }
      }
    }

    return $safe_ids;
  }

  /**
   * Applies a configuration change to the SafeConfiguration entity.
   *
   * This should be called after a configuration transaction is executed on-chain.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   * @param array $change
   *   Configuration change data from detectConfigurationChange().
   *
   * @return bool
   *   TRUE if the configuration was updated, FALSE otherwise.
   */
  public function applyConfigurationChange(SafeAccount $safe_account, array $change): bool {
    $safe_config = $this->getSafeConfiguration($safe_account);

    if (!$safe_config) {
      $this->logger->error('Cannot apply configuration change: SafeConfiguration not found for Safe @id', [
        '@id' => $safe_account->id(),
      ]);
      return FALSE;
    }

    $type = $change['type'];
    $params = $change['params'];

    try {
      switch ($type) {
        case 'addOwnerWithThreshold':
          $safe_config->addSigner($params['owner']);
          $safe_config->setThreshold($params['threshold']);
          $safe_account->setThreshold($params['threshold']);
          $this->logger->info('Added signer @owner to Safe @id, threshold set to @threshold', [
            '@owner' => $params['owner'],
            '@id' => $safe_account->id(),
            '@threshold' => $params['threshold'],
          ]);
          break;

        case 'removeOwner':
          $safe_config->removeSigner($params['owner']);
          $safe_config->setThreshold($params['threshold']);
          $safe_account->setThreshold($params['threshold']);
          $this->logger->info('Removed signer @owner from Safe @id, threshold set to @threshold', [
            '@owner' => $params['owner'],
            '@id' => $safe_account->id(),
            '@threshold' => $params['threshold'],
          ]);
          break;

        case 'swapOwner':
          $safe_config->removeSigner($params['oldOwner']);
          $safe_config->addSigner($params['newOwner']);
          $this->logger->info('Swapped signer @old with @new on Safe @id', [
            '@old' => $params['oldOwner'],
            '@new' => $params['newOwner'],
            '@id' => $safe_account->id(),
          ]);
          break;

        case 'changeThreshold':
          $safe_config->setThreshold($params['threshold']);
          $safe_account->setThreshold($params['threshold']);
          $this->logger->info('Changed threshold to @threshold on Safe @id', [
            '@threshold' => $params['threshold'],
            '@id' => $safe_account->id(),
          ]);
          break;

        default:
          $this->logger->warning('Unknown configuration change type: @type', ['@type' => $type]);
          return FALSE;
      }

      // Save both entities.
      $safe_config->save();
      $safe_account->save();

      return TRUE;
    }
    catch (\Exception $e) {
      $this->logger->error('Failed to apply configuration change: @message', [
        '@message' => $e->getMessage(),
      ]);
      return FALSE;
    }
  }

}
