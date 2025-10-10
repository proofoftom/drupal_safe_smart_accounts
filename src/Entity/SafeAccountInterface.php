<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Entity;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\user\UserInterface;

/**
 * Provides an interface for Safe Smart Account entities.
 */
interface SafeAccountInterface extends ContentEntityInterface {

  /**
   * Gets the associated user.
   *
   * @return \Drupal\user\UserInterface|null
   *   The user entity or null if not set.
   */
  public function getUser(): ?UserInterface;

  /**
   * Sets the associated user.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   *
   * @return $this
   */
  public function setUser(UserInterface $user): static;

  /**
   * Gets the Safe address.
   *
   * @return string
   *   The Safe Smart Account address.
   */
  public function getSafeAddress(): string;

  /**
   * Sets the Safe address.
   *
   * @param string $address
   *   The Safe Smart Account address.
   *
   * @return $this
   */
  public function setSafeAddress(string $address): static;

  /**
   * Gets the network.
   *
   * @return string
   *   The network identifier.
   */
  public function getNetwork(): string;

  /**
   * Gets the signature threshold.
   *
   * @return int
   *   The signature threshold.
   */
  public function getThreshold(): int;

  /**
   * Sets the signature threshold.
   *
   * @param int $threshold
   *   The signature threshold.
   *
   * @return $this
   */
  public function setThreshold(int $threshold): static;

  /**
   * Gets the current status.
   *
   * @return string
   *   The status.
   */
  public function getStatus(): string;

  /**
   * Sets the status.
   *
   * @param string $status
   *   The status.
   *
   * @return $this
   */
  public function setStatus(string $status): static;

  /**
   * Checks if the Safe is active.
   *
   * @return bool
   *   TRUE if the Safe is active.
   */
  public function isActive(): bool;

  /**
   * Marks the Safe as deployed.
   *
   * @param string $tx_hash
   *   The deployment transaction hash.
   * @param string $safe_address
   *   The deployed Safe address.
   *
   * @return $this
   */
  public function markDeployed(string $tx_hash, string $safe_address): static;

}
