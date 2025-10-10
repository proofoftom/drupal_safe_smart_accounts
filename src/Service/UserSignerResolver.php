<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Service;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\user\UserInterface;

/**
 * Service for resolving between Drupal usernames and Ethereum addresses.
 */
class UserSignerResolver {

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * Constructs a UserSignerResolver object.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   */
  public function __construct(EntityTypeManagerInterface $entity_type_manager) {
    $this->entityTypeManager = $entity_type_manager;
  }

  /**
   * Gets a username for an Ethereum address.
   *
   * @param string $address
   *   The Ethereum address.
   *
   * @return string|null
   *   The username or NULL if no user found.
   */
  public function getUsernameByAddress(string $address): ?string {
    $user = $this->getUserByAddress($address);
    return $user ? $user->getAccountName() : NULL;
  }

  /**
   * Gets an Ethereum address for a username.
   *
   * @param string $username
   *   The Drupal username.
   *
   * @return string|null
   *   The Ethereum address or NULL if not found.
   */
  public function getAddressByUsername(string $username): ?string {
    $user_storage = $this->entityTypeManager->getStorage('user');
    $query = $user_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('name', $username)
      ->range(0, 1);

    $result = $query->execute();
    if (empty($result)) {
      return NULL;
    }

    /** @var \Drupal\user\UserInterface $user */
    $user = $user_storage->load(reset($result));
    if (!$user || !$user->hasField('field_ethereum_address')) {
      return NULL;
    }

    return $user->get('field_ethereum_address')->value;
  }

  /**
   * Gets a user entity by Ethereum address.
   *
   * @param string $address
   *   The Ethereum address.
   *
   * @return \Drupal\user\UserInterface|null
   *   The user entity or NULL if not found.
   */
  public function getUserByAddress(string $address): ?UserInterface {
    // Normalize address to lowercase for comparison.
    $normalized_address = strtolower($address);

    $user_storage = $this->entityTypeManager->getStorage('user');
    $query = $user_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('field_ethereum_address', $normalized_address)
      ->range(0, 1);

    $result = $query->execute();
    if (empty($result)) {
      return NULL;
    }

    $user = $user_storage->load(reset($result));
    return $user instanceof UserInterface ? $user : NULL;
  }

  /**
   * Formats a signer display label with username if available.
   *
   * @param string $address
   *   The Ethereum address.
   *
   * @return string
   *   Formatted label: "username (0x123...)" or just "0x123..." if no user.
   */
  public function formatSignerLabel(string $address): string {
    $username = $this->getUsernameByAddress($address);
    if ($username) {
      return sprintf('%s (%s)', $username, $this->truncateAddress($address));
    }
    return $address;
  }

  /**
   * Searches for users by username with Ethereum addresses.
   *
   * @param string $search
   *   The search string.
   * @param int $limit
   *   Maximum number of results.
   *
   * @return array
   *   Array of matches with 'value' (address) and 'label' (username + address).
   */
  public function searchUsers(string $search, int $limit = 10): array {
    $user_storage = $this->entityTypeManager->getStorage('user');
    $query = $user_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('name', $search, 'CONTAINS')
      ->condition('status', 1)
      ->exists('field_ethereum_address')
      ->sort('name', 'ASC')
      ->range(0, $limit);

    $result = $query->execute();
    if (empty($result)) {
      return [];
    }

    $users = $user_storage->loadMultiple($result);
    $matches = [];

    /** @var \Drupal\user\UserInterface $user */
    foreach ($users as $user) {
      if (!$user->hasField('field_ethereum_address')) {
        continue;
      }

      $address = $user->get('field_ethereum_address')->value;
      if (empty($address)) {
        continue;
      }

      $matches[] = [
        'value' => $address,
        'label' => sprintf('%s (%s)', $user->getAccountName(), $this->truncateAddress($address)),
      ];
    }

    return $matches;
  }

  /**
   * Converts a mixed input (username or address) to an address.
   *
   * @param string $input
   *   The input string (username or address).
   *
   * @return string|null
   *   The Ethereum address or NULL if invalid.
   */
  public function resolveToAddress(string $input): ?string {
    $input = trim($input);

    // Check if it's already an Ethereum address.
    if (preg_match('/^0x[a-fA-F0-9]{40}$/', $input)) {
      return $input;
    }

    // Try to resolve as username.
    return $this->getAddressByUsername($input);
  }

  /**
   * Truncates an Ethereum address for display.
   *
   * @param string $address
   *   The full address.
   *
   * @return string
   *   Truncated address like "0x1234...5678".
   */
  protected function truncateAddress(string $address): string {
    if (strlen($address) <= 10) {
      return $address;
    }
    return substr($address, 0, 6) . '...' . substr($address, -4);
  }

}
