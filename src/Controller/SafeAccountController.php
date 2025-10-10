<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Url;
use Drupal\user\UserInterface;
use Drupal\safe_smart_accounts\Entity\SafeAccount;

/**
 * Controller for Safe Smart Account operations.
 */
class SafeAccountController extends ControllerBase {

  /**
   * Lists Safe accounts for a user.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   *
   * @return array
   *   A render array.
   */
  public function userAccountList(UserInterface $user): array {
    $build = [];

    $build['#title'] = $this->t('Safe Smart Accounts for @user', ['@user' => $user->getDisplayName()]);

    // Add cache tags for all Safe entities to ensure page updates when entities change
    $build['#cache']['tags'] = ['safe_account_list:' . $user->id()];

    // Load Safe accounts for this user
    $safe_storage = $this->entityTypeManager()->getStorage('safe_account');

    // Get Safes where user is the owner
    $owned_safes = $safe_storage->loadByProperties(['user_id' => $user->id()]);

    // Get user's Ethereum address
    $ethereum_address = $user->get('field_ethereum_address')->value;
    $safe_accounts_with_roles = [];

    // Mark owned Safes
    foreach ($owned_safes as $safe_id => $safe_account) {
      $safe_accounts_with_roles[$safe_id] = [
        'safe' => $safe_account,
        'role' => 'owner',
      ];
    }

    // If user has an Ethereum address, find Safes where they are a signer
    if (!empty($ethereum_address)) {
      $config_service = \Drupal::service('safe_smart_accounts.configuration_service');
      $signer_safe_ids = $config_service->getSafesForSigner($ethereum_address);

      foreach ($signer_safe_ids as $safe_id) {
        // Skip if already marked as owner
        if (isset($safe_accounts_with_roles[$safe_id])) {
          continue;
        }

        $safe_account = $safe_storage->load($safe_id);
        if ($safe_account) {
          $safe_accounts_with_roles[$safe_id] = [
            'safe' => $safe_account,
            'role' => 'signer',
          ];
        }
      }
    }

    // Ensure we're not using cached entities - reload from database
    $safe_ids = array_keys($safe_accounts_with_roles);
    if (!empty($safe_ids)) {
      $safe_storage->resetCache($safe_ids);
      foreach ($safe_accounts_with_roles as $safe_id => $data) {
        $safe_accounts_with_roles[$safe_id]['safe'] = $safe_storage->load($safe_id);
      }
    }

    // Add cache tags for each Safe account
    foreach ($safe_accounts_with_roles as $safe_id => $data) {
      $build['#cache']['tags'][] = 'safe_account:' . $safe_id;
    }

    if (!empty($safe_accounts_with_roles)) {
      $build['accounts'] = [
        '#type' => 'table',
        '#header' => [
          $this->t('Network'),
          $this->t('Safe Address'),
          $this->t('Status'),
          $this->t('Threshold'),
          $this->t('Role'),
          $this->t('Created'),
          $this->t('Actions'),
        ],
        '#rows' => $this->buildSafeAccountRows($safe_accounts_with_roles, $user),
        '#empty' => $this->t('No Safe Smart Accounts found.'),
        '#attached' => [
          'library' => ['safe_smart_accounts/safe_accounts'],
        ],
      ];
    }
    else {
      $build['empty'] = [
        '#markup' => '<p>' . $this->t('You do not have any Safe Smart Accounts yet.') . '</p>',
      ];
    }
    
    // Add "Create New Safe Account" button
    $build['create_new'] = [
      '#type' => 'link',
      '#title' => $this->t('Create New Safe Account'),
      '#url' => Url::fromRoute('safe_smart_accounts.user_account_create', ['user' => $user->id()]),
      '#attributes' => [
        'class' => ['button', 'button--primary'],
      ],
    ];
    
    // Add help text
    $build['help'] = [
      '#markup' => '<div class="description">' . 
        $this->t('Safe Smart Accounts provide enhanced security through multi-signature functionality. You can create multiple Safe accounts on different networks.') . 
        '</div>',
      '#weight' => 10,
    ];

    return $build;
  }

  /**
   * Builds table rows for Safe accounts.
   *
   * @param array $safe_accounts_with_roles
   *   Array of SafeAccount data with role information.
   *   Each element has 'safe' (SafeAccount entity) and 'role' (string).
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   *
   * @return array
   *   Array of table rows.
   */
  protected function buildSafeAccountRows(array $safe_accounts_with_roles, UserInterface $user): array {
    $rows = [];

    foreach ($safe_accounts_with_roles as $data) {
      $safe_account = $data['safe'];
      $role = $data['role'];
      $status = $safe_account->getStatus();
      $safe_address = $safe_account->getSafeAddress();
      
      // Format the Safe address
      $address_display = $safe_address ? 
        substr($safe_address, 0, 10) . '...' . substr($safe_address, -8) : 
        $this->t('Pending');
      
      // Create status indicator with appropriate styling
      $status_class = match($status) {
        'active' => 'status-active',
        'pending' => 'status-pending', 
        'deploying' => 'status-deploying',
        'error' => 'status-error',
        default => 'status-unknown',
      };
      
      $status_display = [
        '#markup' => '<span class="' . $status_class . '">' . ucfirst($status) . '</span>',
      ];
      
      // Create action links
      $actions = [];
      
      // Manage link - always available
      $actions['manage'] = [
        '#type' => 'link',
        '#title' => $this->t('Manage'),
        '#url' => Url::fromRoute('safe_smart_accounts.user_account_manage', [
          'user' => $user->id(),
          'safe_account' => $safe_account->id(),
        ]),
        '#attributes' => ['class' => ['button', 'button--small']],
      ];
      
      // Create transaction link - only for active Safes
      if ($status === 'active') {
        $actions['create_tx'] = [
          '#type' => 'link',
          '#title' => $this->t('New Transaction'),
          '#url' => Url::fromRoute('safe_smart_accounts.transaction_create', [
            'safe_account' => $safe_account->id(),
          ]),
          '#attributes' => ['class' => ['button', 'button--small', 'button--secondary']],
        ];
      }
      
      $actions_cell = [
        '#theme' => 'item_list',
        '#items' => $actions,
        '#attributes' => ['class' => ['inline-actions']],
      ];

      // Format role display
      $role_display = [
        '#markup' => '<span class="role-' . $role . '">' . ucfirst($role) . '</span>',
      ];

      $rows[] = [
        ucfirst($safe_account->getNetwork()),
        $address_display,
        ['data' => $status_display],
        $safe_account->getThreshold(),
        ['data' => $role_display],
        \Drupal::service('date.formatter')->format($safe_account->get('created')->value, 'short'),
        ['data' => $actions_cell],
      ];
    }
    
    return $rows;
  }

  /**
   * Access callback for creating Safe accounts.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function createAccess(UserInterface $user): AccessResultInterface {
    $current_user = $this->currentUser();
    
    // Users can create Safe accounts for themselves if they have permission
    // and are authenticated via SIWE.
    if ($current_user->id() == $user->id() && $current_user->hasPermission('create safe smart accounts')) {
      return AccessResult::allowed();
    }
    
    // Admins can create Safe accounts for any user.
    if ($current_user->hasPermission('administer safe smart accounts')) {
      return AccessResult::allowed();
    }

    return AccessResult::forbidden();
  }

  /**
   * Access callback for managing Safe accounts.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function manageAccess(UserInterface $user, SafeAccount $safe_account): AccessResultInterface {
    $current_user = $this->currentUser();

    // Users can manage their own Safe accounts.
    if ($current_user->id() == $user->id() && $safe_account->getUser()?->id() == $user->id()) {
      if ($current_user->hasPermission('manage own safe smart accounts')) {
        return AccessResult::allowed();
      }
    }

    // Check if user is a signer on this Safe account.
    if ($current_user->id() == $user->id()) {
      $user_obj = \Drupal::entityTypeManager()->getStorage('user')->load($current_user->id());
      $ethereum_address = $user_obj->get('field_ethereum_address')->value;

      if (!empty($ethereum_address)) {
        $config_service = \Drupal::service('safe_smart_accounts.configuration_service');
        $signer_safe_ids = $config_service->getSafesForSigner($ethereum_address);

        if (in_array($safe_account->id(), $signer_safe_ids)) {
          if ($current_user->hasPermission('manage own safe smart accounts')) {
            return AccessResult::allowed();
          }
        }
      }
    }

    // Admins can manage any Safe account.
    if ($current_user->hasPermission('administer safe smart accounts')) {
      return AccessResult::allowed();
    }

    return AccessResult::forbidden();
  }

  /**
   * Access callback for listing Safe accounts.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function listAccess(UserInterface $user): AccessResultInterface {
    $current_user = $this->currentUser();
    
    // Users can view their own Safe accounts.
    if ($current_user->id() == $user->id() && $current_user->hasPermission('view own safe smart accounts')) {
      return AccessResult::allowed();
    }
    
    // Admins can view any user's Safe accounts.
    if ($current_user->hasPermission('administer safe smart accounts')) {
      return AccessResult::allowed();
    }

    return AccessResult::forbidden();
  }

  /**
   * Access callback for Safe transaction operations.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function transactionAccess(SafeAccount $safe_account): AccessResultInterface {
    $current_user = $this->currentUser();

    // First check if Safe account is active
    if ($safe_account->getStatus() !== 'active') {
      return AccessResult::forbidden('Safe account must be active to create transactions.')
        ->addCacheableDependency($safe_account);
    }

    // Users can create transactions for their Safe accounts.
    if ($safe_account->getUser()?->id() == $current_user->id()) {
      if ($current_user->hasPermission('create safe transactions')) {
        return AccessResult::allowed()->addCacheableDependency($safe_account);
      }
    }

    // Check if user is a signer on this Safe account.
    $user_obj = \Drupal::entityTypeManager()->getStorage('user')->load($current_user->id());
    $ethereum_address = $user_obj->get('field_ethereum_address')->value;

    if (!empty($ethereum_address)) {
      $config_service = \Drupal::service('safe_smart_accounts.configuration_service');
      $signer_safe_ids = $config_service->getSafesForSigner($ethereum_address);

      if (in_array($safe_account->id(), $signer_safe_ids)) {
        if ($current_user->hasPermission('create safe transactions')) {
          return AccessResult::allowed()->addCacheableDependency($safe_account);
        }
      }
    }

    return AccessResult::forbidden();
  }

  /**
   * View a specific Safe transaction.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param \Drupal\safe_smart_accounts\Entity\SafeTransaction $safe_transaction
   *   The Safe transaction entity.
   *
   * @return array
   *   A render array for the transaction view.
   */
  public function viewTransaction(SafeAccount $safe_account, $safe_transaction): array {
    // Load the transaction entity if it's just an ID
    if (!is_object($safe_transaction)) {
      $transaction_storage = $this->entityTypeManager()->getStorage('safe_transaction');
      $safe_transaction = $transaction_storage->load($safe_transaction);
    }

    if (!$safe_transaction) {
      throw new \Symfony\Component\HttpKernel\Exception\NotFoundHttpException();
    }

    $build = [];

    // Attach transaction manager library for sign/execute functionality.
    $build['#attached']['library'][] = 'safe_smart_accounts/transaction_manager';

    // Transaction details table.
    $build['transaction'] = [
      '#type' => 'table',
      '#header' => [$this->t('Property'), $this->t('Value')],
      '#rows' => [
        [$this->t('Transaction ID'), $safe_transaction->id()],
        [$this->t('To Address'), $safe_transaction->getToAddress()],
        [$this->t('Value (ETH)'), number_format((float) $safe_transaction->getValue() / 1e18, 4)],
        [$this->t('Status'), ucfirst($safe_transaction->getStatus())],
        [$this->t('Operation'), $safe_transaction->getOperation() == 0 ? $this->t('Call') : $this->t('Delegate Call')],
        [$this->t('Data'), $safe_transaction->getData() ?: '0x'],
        [$this->t('Nonce'), $safe_transaction->get('nonce')->value ?? $this->t('Not set')],
        [$this->t('Gas Estimate'), $safe_transaction->get('gas_estimate')->value ?? $this->t('Not estimated')],
        [$this->t('Created'), \Drupal::service('date.formatter')->format($safe_transaction->get('created')->value, 'medium')],
        [$this->t('Safe TX Hash'), $safe_transaction->get('safe_tx_hash')->value ?: $this->t('Not generated')],
        [$this->t('Blockchain TX Hash'), $safe_transaction->get('blockchain_tx_hash')->value ?: $this->t('Not executed')],
      ],
    ];

    // Signatures section.
    $signatures = $safe_transaction->getSignatures();
    $threshold = $safe_account->getThreshold();
    $signature_count = count($signatures);

    $build['signatures'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Signatures (@count of @threshold)', [
        '@count' => $signature_count,
        '@threshold' => $threshold,
      ]),
      '#weight' => 10,
    ];

    if (!empty($signatures)) {
      $signature_rows = [];
      foreach ($signatures as $index => $sig) {
        $signer_address = $sig['signer'] ?? '';
        $signed_at = isset($sig['signed_at']) ? \Drupal::service('date.formatter')->format($sig['signed_at'], 'medium') : '';

        // Try to get username for the signer.
        $signer_resolver = \Drupal::service('safe_smart_accounts.user_signer_resolver');
        $signer_label = $signer_resolver->formatSignerLabel($signer_address);

        $signature_rows[] = [
          ($index + 1),
          $signer_label,
          $signed_at,
          substr($sig['signature'], 0, 20) . '...',
        ];
      }

      $build['signatures']['table'] = [
        '#type' => 'table',
        '#header' => [
          $this->t('#'),
          $this->t('Signer'),
          $this->t('Signed At'),
          $this->t('Signature'),
        ],
        '#rows' => $signature_rows,
      ];
    }
    else {
      $build['signatures']['empty'] = [
        '#markup' => $this->t('No signatures collected yet.'),
      ];
    }

    // Action buttons.
    $build['actions'] = [
      '#type' => 'actions',
      '#weight' => 20,
    ];

    // Add sign button if transaction is not executed and not cancelled.
    if (!in_array($safe_transaction->getStatus(), ['executed', 'cancelled'], TRUE)) {
      $build['actions']['sign'] = [
        '#type' => 'button',
        '#value' => $this->t('Sign Transaction'),
        '#attributes' => [
          'class' => ['button', 'button--primary', 'safe-transaction-sign'],
          'data-safe-account-id' => $safe_account->id(),
          'data-transaction-id' => $safe_transaction->id(),
        ],
      ];
    }

    // Add execute button if transaction can be executed.
    if ($safe_transaction->canExecute() && !$safe_transaction->isExecuted()) {
      $build['actions']['execute'] = [
        '#type' => 'button',
        '#value' => $this->t('Execute Transaction'),
        '#attributes' => [
          'class' => ['button', 'button--action', 'safe-transaction-execute'],
          'data-safe-account-id' => $safe_account->id(),
          'data-transaction-id' => $safe_transaction->id(),
        ],
      ];
    }
    elseif (!$safe_transaction->isExecuted() && !in_array($safe_transaction->getStatus(), ['cancelled'], TRUE)) {
      // Show explanation if transaction cannot be executed.
      if (!$safe_transaction->isNextExecutable()) {
        $build['actions']['blocked_message'] = [
          '#markup' => '<div class="messages messages--warning">' .
            $this->t('This transaction cannot be executed yet. Transactions must be executed in sequential nonce order. Please execute earlier transactions first.') .
            '</div>',
          '#weight' => -10,
        ];
      }
      elseif (count($safe_transaction->getSignatures()) < $safe_account->getThreshold()) {
        $build['actions']['blocked_message'] = [
          '#markup' => '<div class="messages messages--warning">' .
            $this->t('This transaction needs @needed more signature(s) before it can be executed. (Currently @current of @threshold)', [
              '@needed' => $safe_account->getThreshold() - count($safe_transaction->getSignatures()),
              '@current' => count($safe_transaction->getSignatures()),
              '@threshold' => $safe_account->getThreshold(),
            ]) .
            '</div>',
          '#weight' => -10,
        ];
      }
    }

    $build['back_link'] = [
      '#type' => 'link',
      '#title' => $this->t('← Back to Safe Account'),
      '#url' => Url::fromRoute('safe_smart_accounts.user_account_manage', [
        'user' => $safe_account->getUser()->id(),
        'safe_account' => $safe_account->id(),
      ]),
      '#attributes' => ['class' => ['button']],
      '#weight' => 30,
    ];

    return $build;
  }

}