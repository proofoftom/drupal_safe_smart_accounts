<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Entity\EntityAccessControlHandler;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Session\AccountInterface;

/**
 * Access controller for the Safe Account entity.
 */
class SafeAccountAccessControlHandler extends EntityAccessControlHandler {

  /**
   * {@inheritdoc}
   */
  protected function checkAccess(EntityInterface $entity, $operation, AccountInterface $account) {
    /** @var \Drupal\safe_smart_accounts\Entity\SafeAccountInterface $entity */

    // Admin permission grants all access.
    if ($account->hasPermission('administer safe smart accounts')) {
      return AccessResult::allowed()->cachePerPermissions();
    }

    switch ($operation) {
      case 'view':
        // Users can view their own Safe accounts.
        if ($entity->getUser() && $entity->getUser()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity);
        }

        // Check if user is a signer on this Safe.
        if ($this->isUserSigner($entity, $account)) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity);
        }

        // Otherwise, check permission.
        return AccessResult::allowedIfHasPermission($account, 'view safe smart accounts')
          ->cachePerPermissions()
          ->addCacheableDependency($entity);

      case 'update':
        // Only owner can update.
        if ($entity->getUser() && $entity->getUser()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity);
        }
        return AccessResult::forbidden('Only the Safe account owner can update it.')
          ->cachePerPermissions()
          ->cachePerUser()
          ->addCacheableDependency($entity);

      case 'delete':
        // Only owner can delete.
        if ($entity->getUser() && $entity->getUser()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity);
        }
        return AccessResult::forbidden('Only the Safe account owner can delete it.')
          ->cachePerPermissions()
          ->cachePerUser()
          ->addCacheableDependency($entity);
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

    // Check for create permission.
    return AccessResult::allowedIfHasPermission($account, 'create safe smart accounts')
      ->cachePerPermissions();
  }

  /**
   * Checks if a user is a signer on a Safe account.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The Safe account entity.
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

    // Load Safe configuration to check signers.
    $config_storage = \Drupal::entityTypeManager()->getStorage('safe_configuration');
    $configs = $config_storage->loadByProperties(['safe_account_id' => $entity->id()]);

    foreach ($configs as $config) {
      if ($config->isSigner($ethereum_address)) {
        return TRUE;
      }
    }

    return FALSE;
  }

}
