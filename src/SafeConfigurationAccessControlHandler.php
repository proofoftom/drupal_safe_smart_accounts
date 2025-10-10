<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Entity\EntityAccessControlHandler;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Session\AccountInterface;

/**
 * Access controller for the Safe Configuration entity.
 */
class SafeConfigurationAccessControlHandler extends EntityAccessControlHandler {

  /**
   * {@inheritdoc}
   */
  protected function checkAccess(EntityInterface $entity, $operation, AccountInterface $account) {
    /** @var \Drupal\safe_smart_accounts\Entity\SafeConfigurationInterface $entity */

    // Admin permission grants all access.
    if ($account->hasPermission('administer safe smart accounts')) {
      return AccessResult::allowed()->cachePerPermissions();
    }

    // Load the associated Safe account.
    $safe_account = $entity->getSafeAccount();
    if (!$safe_account) {
      return AccessResult::forbidden('No associated Safe account found.')
        ->cachePerPermissions()
        ->addCacheableDependency($entity);
    }

    switch ($operation) {
      case 'view':
        // Users can view configuration for their own Safe accounts.
        if ($safe_account->getUser() && $safe_account->getUser()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }

        // Signers can view the configuration.
        if ($this->isUserSigner($entity, $account)) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }

        return AccessResult::forbidden('You do not have permission to view this Safe configuration.')
          ->cachePerPermissions()
          ->cachePerUser()
          ->addCacheableDependency($entity)
          ->addCacheableDependency($safe_account);

      case 'update':
        // Only the Safe account owner can update configuration.
        if ($safe_account->getUser() && $safe_account->getUser()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }
        return AccessResult::forbidden('Only the Safe account owner can update its configuration.')
          ->cachePerPermissions()
          ->cachePerUser()
          ->addCacheableDependency($entity)
          ->addCacheableDependency($safe_account);

      case 'delete':
        // Only the Safe account owner can delete configuration.
        if ($safe_account->getUser() && $safe_account->getUser()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }
        return AccessResult::forbidden('Only the Safe account owner can delete its configuration.')
          ->cachePerPermissions()
          ->cachePerUser()
          ->addCacheableDependency($entity)
          ->addCacheableDependency($safe_account);
    }

    return AccessResult::neutral()
      ->cachePerPermissions();
  }

  /**
   * {@inheritdoc}
   */
  protected function checkCreateAccess(AccountInterface $account, array $context, $entity_bundle = NULL) {
    // Admin permission allows creation.
    if ($account->hasPermission('administer safe smart accounts')) {
      return AccessResult::allowed()->cachePerPermissions();
    }

    // Anyone who can create Safe accounts can create configurations.
    return AccessResult::allowedIfHasPermission($account, 'create safe smart accounts')
      ->cachePerPermissions();
  }

  /**
   * Checks if a user is a signer on the Safe.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The Safe configuration entity.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The user account to check.
   *
   * @return bool
   *   TRUE if the user is a signer, FALSE otherwise.
   */
  protected function isUserSigner(EntityInterface $entity, AccountInterface $account): bool {
    // Load user to get Ethereum address.
    $user = \Drupal::entityTypeManager()->getStorage('user')->load($account->id());
    if (!$user || !$user->hasField('field_ethereum_address')) {
      return FALSE;
    }

    $ethereum_address = $user->get('field_ethereum_address')->value;
    if (empty($ethereum_address)) {
      return FALSE;
    }

    return $entity->isSigner($ethereum_address);
  }

}
