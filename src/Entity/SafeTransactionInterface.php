<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Entity;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\user\UserInterface;

/**
 * Provides an interface for Safe Transaction entities.
 */
interface SafeTransactionInterface extends ContentEntityInterface {

  /**
   * Gets the associated Safe account.
   *
   * @return \Drupal\safe_smart_accounts\Entity\SafeAccount|null
   *   The Safe account entity or null if not set.
   */
  public function getSafeAccount(): ?SafeAccount;

  /**
   * Sets the associated Safe account.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   *
   * @return $this
   */
  public function setSafeAccount(SafeAccount $safe_account): static;

  /**
   * Gets the transaction creator.
   *
   * @return \Drupal\user\UserInterface|null
   *   The user entity or null if not set.
   */
  public function getCreatedBy(): ?UserInterface;

  /**
   * Sets the transaction creator.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   *
   * @return $this
   */
  public function setCreatedBy(UserInterface $user): static;

  /**
   * Gets the to address.
   *
   * @return string
   *   The recipient address.
   */
  public function getToAddress(): string;

  /**
   * Gets the transaction value in wei.
   *
   * @return string
   *   The value in wei.
   */
  public function getValue(): string;

  /**
   * Gets the transaction data.
   *
   * @return string
   *   The transaction data.
   */
  public function getData(): string;

  /**
   * Gets the operation type.
   *
   * @return int
   *   The operation type (0 for Call, 1 for DelegateCall).
   */
  public function getOperation(): int;

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
   * Gets the signatures.
   *
   * @return array
   *   Array of signatures.
   */
  public function getSignatures(): array;

  /**
   * Sets the signatures.
   *
   * @param array $signatures
   *   Array of signatures.
   *
   * @return $this
   */
  public function setSignatures(array $signatures): static;

  /**
   * Adds a signature.
   *
   * @param string $signature
   *   The signature to add.
   *
   * @return $this
   */
  public function addSignature(string $signature): static;

  /**
   * Checks if the transaction can be executed.
   *
   * @return bool
   *   TRUE if the transaction can be executed.
   */
  public function canExecute(): bool;

  /**
   * Checks if this transaction is the next one that can be executed.
   *
   * @return bool
   *   TRUE if this transaction's nonce is next in the execution order.
   */
  public function isNextExecutable(): bool;

  /**
   * Checks if the transaction is in draft state.
   *
   * @return bool
   *   TRUE if the transaction is in draft state.
   */
  public function isDraft(): bool;

  /**
   * Checks if the transaction is executed.
   *
   * @return bool
   *   TRUE if the transaction is executed.
   */
  public function isExecuted(): bool;

  /**
   * Marks the transaction as executed.
   *
   * @param string $blockchain_tx_hash
   *   The blockchain transaction hash.
   *
   * @return $this
   */
  public function markExecuted(string $blockchain_tx_hash): static;

}
