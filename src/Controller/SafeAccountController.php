<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Url;
use Drupal\user\UserInterface;
use Drupal\safe_smart_accounts\Entity\SafeAccount;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Controller for Safe Smart Account operations.
 */
class SafeAccountController extends ControllerBase {

  /**
   * The group treasury service (optional).
   *
   * @var object|null
   */
  protected $groupTreasuryService;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $instance = parent::create($container);

    // Optionally inject GroupTreasuryService if group_treasury module is enabled.
    if ($container->has('group_treasury.treasury_service')) {
      $instance->groupTreasuryService = $container->get('group_treasury.treasury_service');
    }

    return $instance;
  }

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

    // Add cache tags for all Safe entities to ensure page updates when entities change.
    $build['#cache']['tags'] = ['safe_account_list:' . $user->id()];

    // Attach card styling library.
    $build['#attached']['library'][] = 'safe_smart_accounts/safe_accounts_cards';

    // Load Safe accounts for this user.
    $safe_storage = $this->entityTypeManager()->getStorage('safe_account');

    // Get Safes where user is the owner.
    $owned_safes = $safe_storage->loadByProperties(['user_id' => $user->id()]);

    // Get user's Ethereum address.
    $ethereum_address = $user->get('field_ethereum_address')->value;
    $safe_accounts_with_roles = [];

    // Mark owned Safes.
    foreach ($owned_safes as $safe_id => $safe_account) {
      $safe_accounts_with_roles[$safe_id] = [
        'safe' => $safe_account,
        'role' => 'owner',
      ];
    }

    // If user has an Ethereum address, find Safes where they are a signer.
    if (!empty($ethereum_address)) {
      $config_service = \Drupal::service('safe_smart_accounts.configuration_service');
      $signer_safe_ids = $config_service->getSafesForSigner($ethereum_address);

      foreach ($signer_safe_ids as $safe_id) {
        // Skip if already marked as owner.
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

    // Ensure we're not using cached entities - reload from database.
    $safe_ids = array_keys($safe_accounts_with_roles);
    if (!empty($safe_ids)) {
      $safe_storage->resetCache($safe_ids);
      foreach ($safe_accounts_with_roles as $safe_id => $data) {
        $safe_accounts_with_roles[$safe_id]['safe'] = $safe_storage->load($safe_id);
      }
    }

    // Add cache tags for each Safe account.
    foreach ($safe_accounts_with_roles as $safe_id => $data) {
      $build['#cache']['tags'][] = 'safe_account:' . $safe_id;
    }

    // Categorize Safes into personal and treasury groups.
    $personal_safes = [];
    $treasury_safes = [];

    foreach ($safe_accounts_with_roles as $safe_id => $data) {
      $safe = $data['safe'];
      $role = $data['role'];

      // Check if this Safe is a Group treasury.
      $is_treasury = FALSE;
      $groups = [];

      if ($this->groupTreasuryService) {
        try {
          $groups = $this->groupTreasuryService->getGroupsForTreasury($safe);
          if (!empty($groups)) {
            $is_treasury = TRUE;
            // Add group cache tags.
            foreach ($groups as $group) {
              $build['#cache']['tags'][] = 'group:' . $group->id();
            }
          }
        }
        catch (\Exception $e) {
          // Silently skip if treasury service unavailable.
        }
      }

      if ($is_treasury) {
        $treasury_safes[$safe_id] = [
          'safe' => $safe,
          'role' => $role,
          'groups' => $groups,
        ];
      }
      else {
        $personal_safes[$safe_id] = [
          'safe' => $safe,
          'role' => $role,
        ];
      }
    }

    // Render Personal Safes section.
    if (!empty($personal_safes)) {
      $build['personal_safes'] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['safe-accounts-section', 'safe-accounts-section--personal']],
        '#weight' => 0,
      ];

      $build['personal_safes']['header'] = [
        '#type' => 'html_tag',
        '#tag' => 'div',
        '#attributes' => ['class' => ['safe-accounts-section__header']],
        '#value' => '<h3>' . $this->t('Personal Safe Accounts') . '</h3>',
      ];

      $build['personal_safes']['cards'] = $this->buildPersonalSafeCards($personal_safes, $user);
    }

    // Render Group Treasuries section.
    if (!empty($treasury_safes)) {
      $build['treasury_safes'] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['safe-accounts-section', 'safe-accounts-section--treasury']],
        '#weight' => 10,
      ];

      $build['treasury_safes']['header'] = [
        '#type' => 'html_tag',
        '#tag' => 'div',
        '#attributes' => ['class' => ['safe-accounts-section__header']],
        '#value' => '<h3>' . $this->t('Group Treasuries') . '</h3><div class="safe-accounts-section__description">' . $this->t('Safe accounts managed by groups you are a member of.') . '</div>',
      ];

      $build['treasury_safes']['cards'] = $this->buildTreasurySafeCards($treasury_safes, $user);
    }

    // Show empty state if no Safes at all.
    if (empty($personal_safes) && empty($treasury_safes)) {
      $build['empty'] = [
        '#type' => 'html_tag',
        '#tag' => 'div',
        '#attributes' => ['class' => ['safe-accounts-empty']],
        '#value' => '<p>' . $this->t('You do not have any Safe Smart Accounts yet.') . '</p>',
        '#weight' => 0,
      ];
    }

    // Add "Create New Safe Account" button.
    $build['create_new'] = [
      '#type' => 'container',
      '#attributes' => ['class' => ['safe-accounts-section__create-button']],
      '#weight' => 20,
    ];

    $build['create_new']['link'] = [
      '#type' => 'link',
      '#title' => $this->t('Create New Personal Safe'),
      '#url' => Url::fromRoute('safe_smart_accounts.user_account_create', ['user' => $user->id()]),
      '#attributes' => [
        'class' => ['button', 'button--primary'],
      ],
    ];

    // Add help text.
    $build['help'] = [
      '#type' => 'html_tag',
      '#tag' => 'div',
      '#attributes' => ['class' => ['safe-accounts-section__description']],
      '#value' => '<p>' . $this->t('Safe Smart Accounts provide enhanced security through multi-signature functionality. Personal Safes are owned and managed by you. Group Treasuries are shared Safes managed by group members.') . '</p>',
      '#weight' => 30,
    ];

    return $build;
  }

  /**
   * Builds render array for personal Safe account cards.
   *
   * @param array $personal_safes
   *   Array of personal Safe account data.
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   *
   * @return array
   *   A render array of Safe account cards.
   */
  protected function buildPersonalSafeCards(array $personal_safes, UserInterface $user): array {
    $cards = [
      '#type' => 'container',
      '#attributes' => ['class' => ['safe-accounts-grid']],
    ];

    foreach ($personal_safes as $safe_id => $data) {
      $safe = $data['safe'];
      $status = $safe->getStatus();

      // Load Safe configuration for signer count.
      $safe_config = $this->loadSafeConfiguration($safe);
      $signer_count = $safe_config ? count($safe_config->getSigners()) : 0;

      $card = [
        '#type' => 'container',
        '#attributes' => ['class' => ['safe-account-card', 'safe-account-card--personal']],
      ];

      // Card header with network.
      $card['header'] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['safe-account-card__header']],
      ];

      $card['header']['network'] = [
        '#type' => 'html_tag',
        '#tag' => 'span',
        '#attributes' => ['class' => ['safe-account-card__network']],
        '#value' => ucfirst($safe->getNetwork()),
      ];

      // Card body with Safe info.
      $card['body'] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['safe-account-card__body']],
      ];

      // Status.
      $status_class = 'safe-account-card__status--' . $status;
      $card['body']['status'] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['safe-account-card__info-row']],
      ];
      $card['body']['status']['label'] = [
        '#type' => 'html_tag',
        '#tag' => 'span',
        '#attributes' => ['class' => ['safe-account-card__info-label']],
        '#value' => $this->t('Status:'),
      ];
      $card['body']['status']['value'] = [
        '#type' => 'html_tag',
        '#tag' => 'span',
        '#attributes' => ['class' => ['safe-account-card__status', $status_class]],
        '#value' => ucfirst($status),
      ];

      // Threshold / Signers.
      $card['body']['threshold'] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['safe-account-card__info-row']],
      ];
      $card['body']['threshold']['label'] = [
        '#type' => 'html_tag',
        '#tag' => 'span',
        '#attributes' => ['class' => ['safe-account-card__info-label']],
        '#value' => $this->t('Signers:'),
      ];
      $card['body']['threshold']['value'] = [
        '#type' => 'html_tag',
        '#tag' => 'span',
        '#attributes' => ['class' => ['safe-account-card__info-value', 'safe-account-card__threshold']],
        '#value' => $this->t('@threshold of @total', [
          '@threshold' => $safe->getThreshold(),
          '@total' => $signer_count,
        ]),
      ];

      // Created date.
      $card['body']['created'] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['safe-account-card__info-row']],
      ];
      $card['body']['created']['label'] = [
        '#type' => 'html_tag',
        '#tag' => 'span',
        '#attributes' => ['class' => ['safe-account-card__info-label']],
        '#value' => $this->t('Created:'),
      ];
      $card['body']['created']['value'] = [
        '#type' => 'html_tag',
        '#tag' => 'span',
        '#attributes' => ['class' => ['safe-account-card__info-value']],
        '#value' => \Drupal::service('date.formatter')->format($safe->get('created')->value, 'medium'),
      ];

      // Card actions.
      $card['actions'] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['safe-account-card__actions']],
      ];

      $card['actions']['manage'] = [
        '#type' => 'link',
        '#title' => $this->t('Manage'),
        '#url' => Url::fromRoute('safe_smart_accounts.user_account_manage', [
          'user' => $user->id(),
          'safe_account' => $safe->id(),
        ]),
        '#attributes' => ['class' => ['button', 'button--small']],
      ];

      if ($status === 'active') {
        $card['actions']['new_tx'] = [
          '#type' => 'link',
          '#title' => $this->t('New Transaction'),
          '#url' => Url::fromRoute('safe_smart_accounts.transaction_create', [
            'user' => $user->id(),
            'safe_account' => $safe->id(),
          ]),
          '#attributes' => ['class' => ['button', 'button--small', 'button--secondary']],
        ];
      }

      $cards['card_' . $safe_id] = $card;
    }

    return $cards;
  }

  /**
   * Builds render array for Group treasury Safe account cards.
   *
   * @param array $treasury_safes
   *   Array of treasury Safe account data with groups.
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   *
   * @return array
   *   A render array of Safe account cards.
   */
  protected function buildTreasurySafeCards(array $treasury_safes, UserInterface $user): array {
    $cards = [
      '#type' => 'container',
      '#attributes' => ['class' => ['safe-accounts-grid']],
    ];

    foreach ($treasury_safes as $safe_id => $data) {
      $safe = $data['safe'];
      $status = $safe->getStatus();
      $groups = $data['groups'];

      // Load Safe configuration for signer count.
      $safe_config = $this->loadSafeConfiguration($safe);
      $signer_count = $safe_config ? count($safe_config->getSigners()) : 0;

      // Create a card for each group relationship.
      foreach ($groups as $group) {
        $card = [
          '#type' => 'container',
          '#attributes' => ['class' => ['safe-account-card', 'safe-account-card--treasury']],
        ];

        // Card header with group info.
        $card['header'] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['safe-account-card__header']],
        ];

        // Network badge.
        $card['header']['network'] = [
          '#type' => 'html_tag',
          '#tag' => 'span',
          '#attributes' => ['class' => ['safe-account-card__network']],
          '#value' => ucfirst($safe->getNetwork()),
        ];

        // Group info section.
        $card['group_info'] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['safe-account-card__group-info']],
        ];

        $card['group_info']['name'] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['safe-account-card__group-name']],
        ];

        $card['group_info']['name']['link'] = [
          '#type' => 'link',
          '#title' => $group->label(),
          '#url' => $group->toUrl(),
        ];

        // Group stats.
        $group_members_count = count($group->getMembers());
        $membership = $group->getMember($user);
        $is_admin = FALSE;
        $user_role_label = $this->t('Member');

        if ($membership) {
          $roles = $membership->getRoles();

          // Support both standard Group module and Open Social role naming conventions.
          // Standard: {bundle}-admin
          // Open Social: {bundle}-group_manager
          $bundle = $group->bundle();
          $admin_role_patterns = [
            $bundle . '-admin',
            $bundle . '-group_manager',
          ];

          foreach ($roles as $role) {
            if (in_array($role->id(), $admin_role_patterns, TRUE)) {
              $is_admin = TRUE;
              $user_role_label = $this->t('Admin (Signer)');
              break;
            }
          }
        }

        $card['group_info']['stats'] = [
          '#type' => 'html_tag',
          '#tag' => 'div',
          '#attributes' => ['class' => ['safe-account-card__group-stats']],
          '#value' => $this->t('@members members', ['@members' => $group_members_count]),
        ];

        // Card body with Safe info.
        $card['body'] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['safe-account-card__body']],
        ];

        // Status.
        $status_class = 'safe-account-card__status--' . $status;
        $card['body']['status'] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['safe-account-card__info-row']],
        ];
        $card['body']['status']['label'] = [
          '#type' => 'html_tag',
          '#tag' => 'span',
          '#attributes' => ['class' => ['safe-account-card__info-label']],
          '#value' => $this->t('Status:'),
        ];
        $card['body']['status']['value'] = [
          '#type' => 'html_tag',
          '#tag' => 'span',
          '#attributes' => ['class' => ['safe-account-card__status', $status_class]],
          '#value' => ucfirst($status),
        ];

        // Threshold / Total Signers.
        $card['body']['signers'] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['safe-account-card__info-row']],
        ];
        $card['body']['signers']['label'] = [
          '#type' => 'html_tag',
          '#tag' => 'span',
          '#attributes' => ['class' => ['safe-account-card__info-label']],
          '#value' => $this->t('Signers:'),
        ];
        $card['body']['signers']['value'] = [
          '#type' => 'html_tag',
          '#tag' => 'span',
          '#attributes' => ['class' => ['safe-account-card__info-value', 'safe-account-card__threshold']],
          '#value' => $this->t('@threshold of @total', [
            '@threshold' => $safe->getThreshold(),
            '@total' => $signer_count,
          ]),
        ];

        // Proposing members (same as group members count).
        $card['body']['proposers'] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['safe-account-card__info-row']],
        ];
        $card['body']['proposers']['label'] = [
          '#type' => 'html_tag',
          '#tag' => 'span',
          '#attributes' => ['class' => ['safe-account-card__info-label']],
          '#value' => $this->t('Proposers:'),
        ];
        $card['body']['proposers']['value'] = [
          '#type' => 'html_tag',
          '#tag' => 'span',
          '#attributes' => ['class' => ['safe-account-card__info-value']],
          '#value' => $this->t('@count members', ['@count' => $group_members_count]),
        ];

        // User's role.
        $role_class = $is_admin ? 'safe-account-card__role--admin' : '';
        $card['body']['role'] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['safe-account-card__info-row']],
        ];
        $card['body']['role']['label'] = [
          '#type' => 'html_tag',
          '#tag' => 'span',
          '#attributes' => ['class' => ['safe-account-card__info-label']],
          '#value' => $this->t('Your Role:'),
        ];
        $card['body']['role']['value'] = [
          '#type' => 'html_tag',
          '#tag' => 'span',
          '#attributes' => ['class' => ['safe-account-card__role', $role_class]],
          '#value' => $user_role_label,
        ];

        // Card actions.
        $card['actions'] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['safe-account-card__actions']],
        ];

        // Check if group_treasury routes exist.
        if (\Drupal::service('router.route_provider')->getRoutesByNames(['group_treasury.treasury'])) {
          $card['actions']['view_treasury'] = [
            '#type' => 'link',
            '#title' => $this->t('View Treasury'),
            '#url' => Url::fromRoute('group_treasury.treasury', ['group' => $group->id()]),
            '#attributes' => ['class' => ['button', 'button--small']],
          ];

          if ($status === 'active') {
            $card['actions']['propose_tx'] = [
              '#type' => 'link',
              '#title' => $this->t('Propose Transaction'),
              '#url' => Url::fromRoute('group_treasury.propose_transaction', ['group' => $group->id()]),
              '#attributes' => ['class' => ['button', 'button--small', 'button--secondary']],
            ];
          }
        }
        else {
          // Fallback to safe_smart_accounts routes.
          $card['actions']['manage'] = [
            '#type' => 'link',
            '#title' => $this->t('Manage'),
            '#url' => Url::fromRoute('safe_smart_accounts.user_account_manage', [
              'user' => $user->id(),
              'safe_account' => $safe->id(),
            ]),
            '#attributes' => ['class' => ['button', 'button--small']],
          ];
        }

        $cards['card_' . $safe_id . '_' . $group->id()] = $card;
      }
    }

    return $cards;
  }

  /**
   * Helper method to load SafeConfiguration entity for a Safe account.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   *
   * @return \Drupal\safe_smart_accounts\Entity\SafeConfiguration|null
   *   The SafeConfiguration entity, or NULL if not found.
   */
  protected function loadSafeConfiguration($safe_account) {
    $config_storage = $this->entityTypeManager()->getStorage('safe_configuration');
    $configs = $config_storage->loadByProperties([
      'safe_account_id' => $safe_account->id(),
    ]);

    return !empty($configs) ? reset($configs) : NULL;
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
            'user' => $user->id(),
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
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount|null $safe_account
   *   The Safe account entity (may be NULL when checking from list context).
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function manageAccess(UserInterface $user, SafeAccount $safe_account = NULL): AccessResultInterface {
    if (!$safe_account) {
      return AccessResult::forbidden('Safe account parameter required.');
    }

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
   * @param \Drupal\user\UserInterface $user
   *   The user entity (route context).
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount|null $safe_account
   *   The Safe account entity (may be NULL when checking from list context).
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function transactionAccess(UserInterface $user, SafeAccount $safe_account = NULL): AccessResultInterface {
    if (!$safe_account) {
      return AccessResult::forbidden('Safe account parameter required.');
    }

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
   * @param \Drupal\user\UserInterface $user
   *   The user entity (route context).
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param \Drupal\safe_smart_accounts\Entity\SafeTransaction $safe_transaction
   *   The Safe transaction entity.
   *
   * @return array
   *   A render array for the transaction view.
   */
  public function viewTransaction(UserInterface $user, SafeAccount $safe_account, $safe_transaction): array {
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