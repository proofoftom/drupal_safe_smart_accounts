<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Entity\EntityAccessControlHandler;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Session\AccountInterface;

/**
 * Access controller for the Safe Transaction entity.
 */
class SafeTransactionAccessControlHandler extends EntityAccessControlHandler {

  /**
   * {@inheritdoc}
   */
  protected function checkAccess(EntityInterface $entity, $operation, AccountInterface $account) {
    /** @var \Drupal\safe_smart_accounts\Entity\SafeTransactionInterface $entity */

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
        // Owner can view all transactions.
        if ($safe_account->getUser() && $safe_account->getUser()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }

        // Signers can view transactions.
        if ($this->isUserSigner($safe_account, $account)) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }

        // Transaction creator can view their own transaction.
        if ($entity->getCreatedBy() && $entity->getCreatedBy()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }

        return AccessResult::forbidden('You do not have permission to view this transaction.')
          ->cachePerPermissions()
          ->cachePerUser()
          ->addCacheableDependency($entity)
          ->addCacheableDependency($safe_account);

      case 'update':
        // Only signers can update (sign) transactions.
        if ($this->isUserSigner($safe_account, $account)) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }

        // Owner can update.
        if ($safe_account->getUser() && $safe_account->getUser()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }

        return AccessResult::forbidden('Only signers can update transactions.')
          ->cachePerPermissions()
          ->cachePerUser()
          ->addCacheableDependency($entity)
          ->addCacheableDependency($safe_account);

      case 'delete':
        // Transaction creator can delete their own draft transactions.
        if ($entity->isDraft() && $entity->getCreatedBy() && $entity->getCreatedBy()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }

        // Safe account owner can delete transactions.
        if ($safe_account->getUser() && $safe_account->getUser()->id() == $account->id()) {
          return AccessResult::allowed()
            ->cachePerPermissions()
            ->cachePerUser()
            ->addCacheableDependency($entity)
            ->addCacheableDependency($safe_account);
        }

        return AccessResult::forbidden('Only the transaction creator (for drafts) or Safe owner can delete transactions.')
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

    // Check if user has permission to create transactions.
    // Note: Additional checks for Safe account ownership/signer status
    // should be done in the form/controller before reaching this point.
    return AccessResult::allowedIfHasPermission($account, 'create safe transactions')
      ->cachePerPermissions();
  }

  /**
   * Checks if a user is a signer on a Safe account.
   *
   * @param \Drupal\Core\Entity\EntityInterface $safe_account
   *   The Safe account entity.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The user account to check.
   *
   * @return bool
   *   TRUE if the user is a signer, FALSE otherwise.
   */
  protected function isUserSigner(EntityInterface $safe_account, AccountInterface $account): bool {
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
    $configs = $config_storage->loadByProperties(['safe_account_id' => $safe_account->id()]);

    foreach ($configs as $config) {
      if ($config->isSigner($ethereum_address)) {
        return TRUE;
      }
    }

    return FALSE;
  }

}
