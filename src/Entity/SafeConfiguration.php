<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Entity;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\user\UserInterface;

/**
 * Defines the Safe Configuration entity.
 *
 * @ConfigEntityType(
 *   id = "safe_configuration",
 *   label = @Translation("Safe Configuration"),
 *   label_collection = @Translation("Safe Configurations"),
 *   handlers = {
 *     "view_builder" = "Drupal\Core\Entity\EntityViewBuilder",
 *     "list_builder" = "Drupal\safe_smart_accounts\SafeConfigurationListBuilder",
 *     "access" = "Drupal\safe_smart_accounts\SafeConfigurationAccessControlHandler",
 *     "form" = {
 *       "add" = "Drupal\safe_smart_accounts\Form\SafeConfigurationForm",
 *       "edit" = "Drupal\safe_smart_accounts\Form\SafeConfigurationForm",
 *       "delete" = "Drupal\Core\Entity\EntityDeleteForm",
 *     },
 *   },
 *   config_prefix = "safe_configuration",
 *   admin_permission = "administer safe smart accounts",
 *   entity_keys = {
 *     "id" = "id",
 *     "label" = "label",
 *     "uuid" = "uuid"
 *   },
 *   links = {
 *     "canonical" = "/admin/config/safe-accounts/configuration/{safe_configuration}",
 *     "add-form" = "/admin/config/safe-accounts/configuration/add",
 *     "edit-form" = "/admin/config/safe-accounts/configuration/{safe_configuration}/edit",
 *     "delete-form" = "/admin/config/safe-accounts/configuration/{safe_configuration}/delete",
 *     "collection" = "/admin/config/safe-accounts/configuration",
 *   },
 *   config_export = {
 *     "id",
 *     "label",
 *     "uuid",
 *     "safe_account_id",
 *     "signers",
 *     "threshold",
 *     "modules",
 *     "fallback_handler",
 *     "version",
 *     "salt_nonce",
 *     "updated",
 *     "updated_by",
 *     "auto_adjust_threshold",
 *   }
 * )
 */
class SafeConfiguration extends ConfigEntityBase implements SafeConfigurationInterface {

  /**
   * The Safe configuration ID.
   *
   * @var string
   */
  protected $id;

  /**
   * The Safe configuration label.
   *
   * @var string
   */
  protected $label;

  /**
   * The associated Safe account ID.
   *
   * @var int
   */
  protected $safe_account_id;

  /**
   * Array of signer addresses.
   *
   * @var array
   */
  protected $signers = [];

  /**
   * Required signature threshold.
   *
   * @var int
   */
  protected $threshold = 1;

  /**
   * Array of enabled module addresses.
   *
   * @var array
   */
  protected $modules = [];

  /**
   * Fallback handler address.
   *
   * @var string
   */
  protected $fallback_handler = '';

  /**
   * Safe contract version.
   *
   * @var string
   */
  protected $version = '1.4.1';

  /**
   * Salt nonce for deterministic Safe address generation.
   *
   * @var int
   */
  protected $salt_nonce = 0;

  /**
   * Last updated timestamp.
   *
   * @var int
   */
  protected $updated;

  /**
   * User who last updated the configuration.
   *
   * @var int
   */
  protected $updated_by;

  /**
   * Whether to auto-adjust threshold when adding/removing signers.
   *
   * @var bool
   */
  protected $auto_adjust_threshold = FALSE;

  /**
   * {@inheritdoc}
   */
  public function preSave($storage): void {
    parent::preSave($storage);

    // Update timestamp and user.
    $this->updated = \Drupal::time()->getRequestTime();
    $current_user = \Drupal::currentUser();
    if ($current_user->isAuthenticated()) {
      $this->updated_by = $current_user->id();
    }
  }

  /**
   * {@inheritdoc}
   */
  public function postSave($storage, $update = TRUE): void {
    parent::postSave($storage, $update);

    // Invalidate cache for all users who are signers on this Safe.
    // This ensures their Safe account list updates when signers change.
    $cache_tags = [];

    // Get all signers and invalidate their safe_account_list cache.
    foreach ($this->getSigners() as $signer_address) {
      // Find user with this Ethereum address.
      $user_storage = \Drupal::entityTypeManager()->getStorage('user');
      $users = $user_storage->loadByProperties([
        'field_ethereum_address' => strtolower($signer_address),
      ]);

      foreach ($users as $user) {
        $cache_tags[] = 'safe_account_list:' . $user->id();
      }
    }

    // Also invalidate for the Safe account owner.
    if ($this->safe_account_id) {
      $safe_account = $this->getSafeAccount();
      if ($safe_account && $safe_account->getUser()) {
        $cache_tags[] = 'safe_account_list:' . $safe_account->getUser()->id();
      }
    }

    if (!empty($cache_tags)) {
      \Drupal::service('cache_tags.invalidator')->invalidateTags($cache_tags);
    }
  }

  /**
   * Gets the associated Safe account ID.
   *
   * @return int|null
   *   The Safe account ID.
   */
  public function getSafeAccountId(): ?int {
    return $this->safe_account_id !== NULL ? (int) $this->safe_account_id : NULL;
  }

  /**
   * Sets the associated Safe account ID.
   *
   * @param int $safe_account_id
   *   The Safe account ID.
   *
   * @return $this
   */
  public function setSafeAccountId(int $safe_account_id): static {
    $this->safe_account_id = $safe_account_id;
    return $this;
  }

  /**
   * Gets the associated Safe account.
   *
   * @return \Drupal\safe_smart_accounts\Entity\SafeAccount|null
   *   The Safe account entity or null if not found.
   */
  public function getSafeAccount(): ?SafeAccount {
    if (!$this->safe_account_id) {
      return NULL;
    }

    $storage = \Drupal::entityTypeManager()->getStorage('safe_account');
    return $storage->load($this->safe_account_id);
  }

  /**
   * Gets the signers.
   *
   * @return array
   *   Array of signer addresses.
   */
  public function getSigners(): array {
    return $this->signers ?? [];
  }

  /**
   * Sets the signers.
   *
   * @param array $signers
   *   Array of signer addresses.
   *
   * @return $this
   */
  public function setSigners(array $signers): static {
    $this->signers = array_values(array_unique($signers));
    return $this;
  }

  /**
   * Adds a signer.
   *
   * @param string $signer
   *   The signer address to add.
   *
   * @return $this
   */
  public function addSigner(string $signer): static {
    $signers = $this->getSigners();
    if (!in_array($signer, $signers, TRUE)) {
      // Add at the beginning to match Safe's linked list order.
      // Safe's addOwnerWithThreshold adds new owners after SENTINEL.
      array_unshift($signers, $signer);
      $this->setSigners($signers);
    }
    return $this;
  }

  /**
   * Removes a signer.
   *
   * @param string $signer
   *   The signer address to remove.
   *
   * @return $this
   */
  public function removeSigner(string $signer): static {
    $signers = $this->getSigners();
    $key = array_search($signer, $signers, TRUE);
    if ($key !== FALSE) {
      unset($signers[$key]);
      $this->setSigners($signers);
    }
    return $this;
  }

  /**
   * Checks if an address is a signer.
   *
   * @param string $address
   *   The address to check.
   *
   * @return bool
   *   TRUE if the address is a signer.
   */
  public function isSigner(string $address): bool {
    return in_array(strtolower($address), array_map('strtolower', $this->getSigners()), TRUE);
  }

  /**
   * Gets the threshold.
   *
   * @return int
   *   The signature threshold.
   */
  public function getThreshold(): int {
    return $this->threshold ?? 1;
  }

  /**
   * Sets the threshold.
   *
   * @param int $threshold
   *   The signature threshold.
   *
   * @return $this
   */
  public function setThreshold(int $threshold): static {
    $this->threshold = max(1, min($threshold, count($this->getSigners())));
    return $this;
  }

  /**
   * Gets whether to auto-adjust threshold.
   *
   * @return bool
   *   TRUE if threshold should auto-adjust, FALSE otherwise.
   */
  public function getAutoAdjustThreshold(): bool {
    return $this->auto_adjust_threshold ?? FALSE;
  }

  /**
   * Sets whether to auto-adjust threshold.
   *
   * @param bool $auto_adjust
   *   Whether to auto-adjust threshold when adding/removing signers.
   *
   * @return $this
   */
  public function setAutoAdjustThreshold(bool $auto_adjust): static {
    $this->auto_adjust_threshold = $auto_adjust;
    return $this;
  }

  /**
   * Gets the modules.
   *
   * @return array
   *   Array of module addresses.
   */
  public function getModules(): array {
    return $this->modules ?? [];
  }

  /**
   * Sets the modules.
   *
   * @param array $modules
   *   Array of module addresses.
   *
   * @return $this
   */
  public function setModules(array $modules): static {
    $this->modules = array_values(array_unique($modules));
    return $this;
  }

  /**
   * Adds a module.
   *
   * @param string $module
   *   The module address to add.
   *
   * @return $this
   */
  public function addModule(string $module): static {
    $modules = $this->getModules();
    if (!in_array($module, $modules, TRUE)) {
      $modules[] = $module;
      $this->setModules($modules);
    }
    return $this;
  }

  /**
   * Removes a module.
   *
   * @param string $module
   *   The module address to remove.
   *
   * @return $this
   */
  public function removeModule(string $module): static {
    $modules = $this->getModules();
    $key = array_search($module, $modules, TRUE);
    if ($key !== FALSE) {
      unset($modules[$key]);
      $this->setModules($modules);
    }
    return $this;
  }

  /**
   * Gets the fallback handler.
   *
   * @return string
   *   The fallback handler address.
   */
  public function getFallbackHandler(): string {
    return $this->fallback_handler ?? '';
  }

  /**
   * Sets the fallback handler.
   *
   * @param string $fallback_handler
   *   The fallback handler address.
   *
   * @return $this
   */
  public function setFallbackHandler(string $fallback_handler): static {
    $this->fallback_handler = $fallback_handler;
    return $this;
  }

  /**
   * Gets the Safe version.
   *
   * @return string
   *   The Safe contract version.
   */
  public function getVersion(): string {
    return $this->version ?? '1.4.1';
  }

  /**
   * Sets the Safe version.
   *
   * @param string $version
   *   The Safe contract version.
   *
   * @return $this
   */
  public function setVersion(string $version): static {
    $this->version = $version;
    return $this;
  }

  /**
   * Gets the salt nonce.
   *
   * @return int
   *   The salt nonce for deterministic address generation.
   */
  public function getSaltNonce(): int {
    return $this->salt_nonce ?? 0;
  }

  /**
   * Sets the salt nonce.
   *
   * @param int $salt_nonce
   *   The salt nonce.
   *
   * @return $this
   */
  public function setSaltNonce(int $salt_nonce): static {
    $this->salt_nonce = max(0, $salt_nonce);
    return $this;
  }

  /**
   * Gets the last updated timestamp.
   *
   * @return int
   *   The timestamp.
   */
  public function getUpdated(): int {
    return $this->updated ?? 0;
  }

  /**
   * Gets the user who last updated the configuration.
   *
   * @return \Drupal\user\UserInterface|null
   *   The user entity or null if not set.
   */
  public function getUpdatedBy(): ?UserInterface {
    if (!$this->updated_by) {
      return NULL;
    }

    $storage = \Drupal::entityTypeManager()->getStorage('user');
    return $storage->load($this->updated_by);
  }

  /**
   * Validates the configuration.
   *
   * @return array
   *   Array of validation errors.
   */
  public function validate(): array {
    $errors = [];

    $signers = $this->getSigners();
    $threshold = $this->getThreshold();

    // Check minimum signers.
    if (empty($signers)) {
      $errors[] = 'At least one signer is required.';
    }

    // Check threshold.
    if ($threshold < 1) {
      $errors[] = 'Threshold must be at least 1.';
    }

    if ($threshold > count($signers)) {
      $errors[] = 'Threshold cannot exceed number of signers.';
    }

    // Validate signer addresses.
    foreach ($signers as $signer) {
      if (!$this->isValidEthereumAddress($signer)) {
        $errors[] = sprintf('Invalid signer address: %s', $signer);
      }
    }

    // Validate module addresses.
    foreach ($this->getModules() as $module) {
      if (!$this->isValidEthereumAddress($module)) {
        $errors[] = sprintf('Invalid module address: %s', $module);
      }
    }

    // Validate fallback handler.
    $fallback_handler = $this->getFallbackHandler();
    if (!empty($fallback_handler) && !$this->isValidEthereumAddress($fallback_handler)) {
      $errors[] = sprintf('Invalid fallback handler address: %s', $fallback_handler);
    }

    return $errors;
  }

  /**
   * Validates an Ethereum address format.
   *
   * @param string $address
   *   The address to validate.
   *
   * @return bool
   *   TRUE if the address is valid.
   */
  protected function isValidEthereumAddress(string $address): bool {
    return preg_match('/^0x[a-fA-F0-9]{40}$/', $address) === 1;
  }

}
