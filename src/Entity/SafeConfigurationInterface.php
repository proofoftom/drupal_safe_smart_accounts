<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Entity;

use Drupal\Core\Config\Entity\ConfigEntityInterface;
use Drupal\user\UserInterface;

/**
 * Provides an interface for Safe Configuration entities.
 */
interface SafeConfigurationInterface extends ConfigEntityInterface {

  /**
   * Gets the associated Safe account ID.
   *
   * @return int|null
   *   The Safe account ID.
   */
  public function getSafeAccountId(): ?int;

  /**
   * Sets the associated Safe account ID.
   *
   * @param int $safe_account_id
   *   The Safe account ID.
   *
   * @return $this
   */
  public function setSafeAccountId(int $safe_account_id): static;

  /**
   * Gets the associated Safe account.
   *
   * @return \Drupal\safe_smart_accounts\Entity\SafeAccount|null
   *   The Safe account entity or null if not found.
   */
  public function getSafeAccount(): ?SafeAccount;

  /**
   * Gets the signers.
   *
   * @return array
   *   Array of signer addresses.
   */
  public function getSigners(): array;

  /**
   * Sets the signers.
   *
   * @param array $signers
   *   Array of signer addresses.
   *
   * @return $this
   */
  public function setSigners(array $signers): static;

  /**
   * Adds a signer.
   *
   * @param string $signer
   *   The signer address to add.
   *
   * @return $this
   */
  public function addSigner(string $signer): static;

  /**
   * Removes a signer.
   *
   * @param string $signer
   *   The signer address to remove.
   *
   * @return $this
   */
  public function removeSigner(string $signer): static;

  /**
   * Checks if an address is a signer.
   *
   * @param string $address
   *   The address to check.
   *
   * @return bool
   *   TRUE if the address is a signer.
   */
  public function isSigner(string $address): bool;

  /**
   * Gets the threshold.
   *
   * @return int
   *   The signature threshold.
   */
  public function getThreshold(): int;

  /**
   * Sets the threshold.
   *
   * @param int $threshold
   *   The signature threshold.
   *
   * @return $this
   */
  public function setThreshold(int $threshold): static;

  /**
   * Gets whether to auto-adjust threshold.
   *
   * @return bool
   *   TRUE if threshold should auto-adjust, FALSE otherwise.
   */
  public function getAutoAdjustThreshold(): bool;

  /**
   * Sets whether to auto-adjust threshold.
   *
   * @param bool $auto_adjust
   *   Whether to auto-adjust threshold when adding/removing signers.
   *
   * @return $this
   */
  public function setAutoAdjustThreshold(bool $auto_adjust): static;

  /**
   * Gets the modules.
   *
   * @return array
   *   Array of module addresses.
   */
  public function getModules(): array;

  /**
   * Sets the modules.
   *
   * @param array $modules
   *   Array of module addresses.
   *
   * @return $this
   */
  public function setModules(array $modules): static;

  /**
   * Adds a module.
   *
   * @param string $module
   *   The module address to add.
   *
   * @return $this
   */
  public function addModule(string $module): static;

  /**
   * Removes a module.
   *
   * @param string $module
   *   The module address to remove.
   *
   * @return $this
   */
  public function removeModule(string $module): static;

  /**
   * Gets the fallback handler.
   *
   * @return string
   *   The fallback handler address.
   */
  public function getFallbackHandler(): string;

  /**
   * Sets the fallback handler.
   *
   * @param string $fallback_handler
   *   The fallback handler address.
   *
   * @return $this
   */
  public function setFallbackHandler(string $fallback_handler): static;

  /**
   * Gets the Safe version.
   *
   * @return string
   *   The Safe contract version.
   */
  public function getVersion(): string;

  /**
   * Sets the Safe version.
   *
   * @param string $version
   *   The Safe contract version.
   *
   * @return $this
   */
  public function setVersion(string $version): static;

  /**
   * Gets the salt nonce.
   *
   * @return int
   *   The salt nonce for deterministic address generation.
   */
  public function getSaltNonce(): int;

  /**
   * Sets the salt nonce.
   *
   * @param int $salt_nonce
   *   The salt nonce.
   *
   * @return $this
   */
  public function setSaltNonce(int $salt_nonce): static;

  /**
   * Gets the last updated timestamp.
   *
   * @return int
   *   The timestamp.
   */
  public function getUpdated(): int;

  /**
   * Gets the user who last updated the configuration.
   *
   * @return \Drupal\user\UserInterface|null
   *   The user entity or null if not set.
   */
  public function getUpdatedBy(): ?UserInterface;

  /**
   * Validates the configuration.
   *
   * @return array
   *   Array of validation errors.
   */
  public function validate(): array;

}
