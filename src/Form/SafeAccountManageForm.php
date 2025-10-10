<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Url;
use Drupal\safe_smart_accounts\Service\UserSignerResolver;
use Drupal\safe_smart_accounts\Service\SafeConfigurationService;
use Drupal\safe_smart_accounts\Service\SafeTransactionService;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\user\UserInterface;
use Drupal\safe_smart_accounts\Entity\SafeAccount;
use Drupal\safe_smart_accounts\Entity\SafeConfiguration;

/**
 * Form for managing an existing Safe Smart Account.
 */
class SafeAccountManageForm extends FormBase {

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * The current user.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected AccountProxyInterface $currentUser;

  /**
   * The user signer resolver service.
   *
   * @var \Drupal\safe_smart_accounts\Service\UserSignerResolver
   */
  protected UserSignerResolver $signerResolver;

  /**
   * The Safe configuration service.
   *
   * @var \Drupal\safe_smart_accounts\Service\SafeConfigurationService
   */
  protected SafeConfigurationService $configurationService;

  /**
   * The Safe transaction service.
   *
   * @var \Drupal\safe_smart_accounts\Service\SafeTransactionService
   */
  protected SafeTransactionService $transactionService;

  /**
   * Constructs a SafeAccountManageForm object.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   The current user.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param \Drupal\safe_smart_accounts\Service\UserSignerResolver $signer_resolver
   *   The user signer resolver service.
   * @param \Drupal\safe_smart_accounts\Service\SafeConfigurationService $configuration_service
   *   The Safe configuration service.
   * @param \Drupal\safe_smart_accounts\Service\SafeTransactionService $transaction_service
   *   The Safe transaction service.
   */
  public function __construct(
    EntityTypeManagerInterface $entity_type_manager,
    AccountProxyInterface $current_user,
    MessengerInterface $messenger,
    UserSignerResolver $signer_resolver,
    SafeConfigurationService $configuration_service,
    SafeTransactionService $transaction_service,
  ) {
    $this->entityTypeManager = $entity_type_manager;
    $this->currentUser = $current_user;
    $this->messenger = $messenger;
    $this->signerResolver = $signer_resolver;
    $this->configurationService = $configuration_service;
    $this->transactionService = $transaction_service;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity_type.manager'),
      $container->get('current_user'),
      $container->get('messenger'),
      $container->get('safe_smart_accounts.user_signer_resolver'),
      $container->get('safe_smart_accounts.configuration_service'),
      $container->get('safe_smart_accounts.transaction_service')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'safe_account_manage_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, ?UserInterface $user = NULL, ?SafeAccount $safe_account = NULL): array {
    if (!$safe_account || !$user) {
      $form['error'] = [
        '#markup' => $this->t('Safe account not found or invalid user context.'),
      ];
      return $form;
    }

    // Load Safe configuration.
    $safe_config = $this->loadSafeConfiguration($safe_account);

    $form['#tree'] = TRUE;
    $form['safe_account_id'] = [
      '#type' => 'value',
      '#value' => $safe_account->id(),
    ];
    $form['user_id'] = [
      '#type' => 'value',
      '#value' => $user->id(),
    ];

    // Attach the safe deployment, transaction manager, and configuration manager JavaScript libraries.
    $form['#attached']['library'][] = 'safe_smart_accounts/safe_deployment';
    $form['#attached']['library'][] = 'safe_smart_accounts/transaction_manager';
    $form['#attached']['library'][] = 'safe_smart_accounts/configuration_manager';

    // Safe account overview.
    $form['overview'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Safe Account Overview'),
      '#weight' => -10,
    ];

    $form['overview']['info'] = [
      '#theme' => 'table',
      '#header' => [$this->t('Property'), $this->t('Value')],
      '#rows' => [
        [
          $this->t('Safe ID'),
          $safe_account->id(),
        ],
        [
          $this->t('Network'),
          ucfirst($safe_account->getNetwork()),
        ],
        [
          $this->t('Status'),
          ucfirst($safe_account->getStatus()),
        ],
        [
          $this->t('Safe Address'),
          $safe_account->getSafeAddress() ?: $this->t('Not yet deployed'),
        ],
        [
          $this->t('Current Threshold'),
          $safe_account->getThreshold(),
        ],
        [
          $this->t('Current Signers'),
          count($safe_config ? $safe_config->getSigners() : []),
        ],
        [
          $this->t('Created'),
          \Drupal::service('date.formatter')->format($safe_account->get('created')->value, 'medium'),
        ],
      ],
    ];

    // Only show management options if Safe is active or pending.
    if (in_array($safe_account->getStatus(), ['pending', 'active'], TRUE)) {

      // Signer management section.
      $form['signers'] = [
        '#type' => 'fieldset',
        '#title' => $this->t('Signer Management'),
        '#weight' => 0,
      ];

      // Get current signers, accounting for any removals in form state.
      $current_signers = $safe_config ? $safe_config->getSigners() : [];
      $removed_signers = $form_state->get('removed_signers') ?? [];
      $current_signers = array_values(array_diff($current_signers, $removed_signers));

      $form['signers']['current_signers_wrapper'] = [
        '#type' => 'container',
        '#prefix' => '<div id="current-signers-wrapper">',
        '#suffix' => '</div>',
      ];

      $form['signers']['current_signers_wrapper']['title'] = [
        '#markup' => '<h4>' . $this->t('Current Signers') . '</h4>',
      ];

      if (!empty($current_signers)) {
        $form['signers']['current_signers_wrapper']['signers'] = [
          '#type' => 'container',
          '#tree' => TRUE,
          '#attributes' => ['class' => ['safe-signers-list']],
        ];

        foreach ($current_signers as $index => $address) {
          $signer_label = $this->signerResolver->formatSignerLabel($address);

          $form['signers']['current_signers_wrapper']['signers'][$index] = [
            '#type' => 'container',
            '#attributes' => ['class' => ['signer-item-row']],
          ];

          $form['signers']['current_signers_wrapper']['signers'][$index]['label'] = [
            '#markup' => '<div class="signer-item">' . $signer_label . '</div>',
          ];

          $form['signers']['current_signers_wrapper']['signers'][$index]['remove'] = [
            '#type' => 'submit',
            '#value' => $this->t('Remove'),
            '#submit' => ['::removeCurrentSigner'],
            '#ajax' => [
              'callback' => '::updateCurrentSignersCallback',
              'wrapper' => 'current-signers-wrapper',
            ],
            '#name' => 'remove_current_signer_' . $index,
            '#signer_address' => $address,
            '#attributes' => ['class' => ['button--small', 'button--danger']],
          ];
        }

        $form['signers']['current_signers_wrapper']['description'] = [
          '#markup' => '<div class="description">' . $this->t('Addresses that can sign transactions for this Safe.') . '</div>',
        ];
      }
      else {
        $form['signers']['current_signers_wrapper']['empty'] = [
          '#markup' => '<p>' . $this->t('No signers configured. Add at least one signer below.') . '</p>',
        ];
      }

      $form['signers']['current_signers'] = [
        '#type' => 'value',
        '#value' => implode("\n", $current_signers),
      ];

      // Get the number of new signer fields from form state.
      $num_new_signers = $form_state->get('num_new_signers');
      if ($num_new_signers === NULL) {
        $num_new_signers = 1;
        $form_state->set('num_new_signers', $num_new_signers);
      }

      $form['signers']['new_signers'] = [
        '#type' => 'container',
        '#prefix' => '<div id="new-signers-wrapper">',
        '#suffix' => '</div>',
        '#tree' => TRUE,
      ];

      $form['signers']['new_signers']['description'] = [
        '#markup' => '<div class="description">' . $this->t('Add one or more new signers. Start typing a username to see suggestions.') . '</div>',
      ];

      for ($i = 0; $i < $num_new_signers; $i++) {
        $form['signers']['new_signers'][$i] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['new-signer-field-row']],
        ];

        $form['signers']['new_signers'][$i]['address'] = [
          '#type' => 'textfield',
          '#title' => $this->t('New Signer @num', ['@num' => $i + 1]),
          '#placeholder' => 'alice or 0x742d35Cc6634C0532925a3b8D8938d9e1Aac5C63',
          '#autocomplete_route_name' => 'safe_smart_accounts.signer_autocomplete',
          '#size' => 60,
        ];

        if ($num_new_signers > 1) {
          $form['signers']['new_signers'][$i]['remove'] = [
            '#type' => 'submit',
            '#value' => $this->t('Remove'),
            '#submit' => ['::removeNewSignerField'],
            '#ajax' => [
              'callback' => '::updateNewSignersCallback',
              'wrapper' => 'new-signers-wrapper',
            ],
            '#name' => 'remove_new_signer_' . $i,
            '#signer_delta' => $i,
            '#attributes' => ['class' => ['button--small', 'button--danger']],
          ];
        }
      }

      $form['signers']['add_another_signer'] = [
        '#type' => 'submit',
        '#value' => $this->t('Add another signer field'),
        '#submit' => ['::addNewSignerField'],
        '#ajax' => [
          'callback' => '::updateNewSignersCallback',
          'wrapper' => 'new-signers-wrapper',
        ],
        '#attributes' => ['class' => ['button--small']],
      ];

      // Threshold management.
      $form['threshold'] = [
        '#type' => 'fieldset',
        '#title' => $this->t('Signature Threshold'),
        '#weight' => 1,
      ];

      $form['threshold']['new_threshold'] = [
        '#type' => 'number',
        '#title' => $this->t('Required Signatures'),
        '#description' => $this->t('Number of signatures required to execute transactions.'),
        '#default_value' => $safe_account->getThreshold(),
        '#min' => 1,
        '#max' => 20,
        '#required' => TRUE,
      ];

      $form['threshold']['auto_adjust_threshold'] = [
        '#type' => 'checkbox',
        '#title' => $this->t('Auto-adjust threshold when adding/removing signers'),
        '#description' => $this->t('When enabled, the threshold will automatically increment/decrement with each signer addition/removal. When disabled, all operations will use the threshold specified above.'),
        '#default_value' => $safe_config ? $safe_config->getAutoAdjustThreshold() : FALSE,
      ];

      // Advanced settings.
      $form['advanced'] = [
        '#type' => 'details',
        '#title' => $this->t('Advanced Settings'),
        '#open' => FALSE,
        '#weight' => 2,
      ];

      $fallback_handler = $safe_config ? $safe_config->getFallbackHandler() : '';
      $form['advanced']['fallback_handler'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Fallback Handler'),
        '#description' => $this->t('Optional fallback handler address for the Safe.'),
        '#default_value' => $fallback_handler,
        '#placeholder' => '0x0000000000000000000000000000000000000000',
      ];

      $form['advanced']['modules'] = [
        '#type' => 'textarea',
        '#title' => $this->t('Enabled Modules'),
        '#description' => $this->t('List of module addresses enabled for this Safe. One address per line.'),
        '#default_value' => $safe_config ? implode("\n", $safe_config->getModules()) : '',
        '#rows' => 3,
      ];

      $form['actions'] = [
        '#type' => 'actions',
        '#weight' => 10,
      ];

      $form['actions']['save'] = [
        '#type' => 'submit',
        '#value' => $this->t('Save Configuration'),
        '#button_type' => 'primary',
      ];

      if ($safe_account->getStatus() === 'pending') {
        $form['actions']['deploy'] = [
          '#type' => 'submit',
          '#value' => $this->t('Deploy Safe'),
          '#button_type' => 'secondary',
          '#submit' => ['::deploySafe'],
          '#attributes' => [
            'class' => ['safe-deploy-button'],
            'data-safe-account-id' => $safe_account->id(),
            'data-user-id' => $user->id(),
          ],
        ];
      }
    }

    // Transaction management section.
    $form['transactions'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Recent Transactions'),
      '#weight' => 5,
      '#description' => $this->t('Transactions must be executed in sequential nonce order (0, 1, 2...). The next executable transaction is marked with <strong style="color: #0073aa;">→</strong>'),
    ];

    $transactions = $this->getRecentTransactions($safe_account);
    if (!empty($transactions)) {
      $form['transactions']['list'] = [
        '#theme' => 'table',
        '#header' => [
          $this->t('ID'),
          $this->t('Nonce'),
          $this->t('To'),
          $this->t('Value (ETH)'),
          $this->t('Status'),
          $this->t('Signatures'),
          $this->t('Created'),
          $this->t('Actions'),
        ],
        '#rows' => $this->buildTransactionRows($transactions, $safe_account),
      ];
    }
    else {
      $form['transactions']['empty'] = [
        '#markup' => $this->t('No transactions found for this Safe.'),
      ];
    }

    $form['transactions']['create_transaction'] = [
      '#type' => 'link',
      '#title' => $this->t('Create New Transaction'),
      '#url' => Url::fromRoute('safe_smart_accounts.transaction_create', [
        'safe_account' => $safe_account->id(),
      ]),
      '#attributes' => ['class' => ['button', 'button--primary']],
      '#access' => $safe_account->getStatus() === 'active',
    ];

    // Show status message for non-active Safes.
    if ($safe_account->getStatus() !== 'active') {
      $status_messages = [
        'pending' => $this->t('Safe account is being created. Transactions will be available once deployment is complete.'),
        'deploying' => $this->t('Safe account is being deployed. Transactions will be available once deployment is complete.'),
        'error' => $this->t('Safe account deployment failed. Please contact support or create a new Safe account.'),
      ];

      $status_message = $status_messages[$safe_account->getStatus()] ??
        $this->t('Safe account is not ready for transactions. Current status: @status', [
          '@status' => $safe_account->getStatus(),
        ]);

      $status_class = 'safe-status-' . $safe_account->getStatus();
      $form['transactions']['status_message'] = [
        '#markup' => '<div class="messages messages--warning ' . $status_class . '">' . $status_message . '</div>',
        '#weight' => -10,
      ];
    }

    // Navigation.
    $form['navigation'] = [
      '#type' => 'actions',
      '#weight' => 20,
    ];

    $form['navigation']['back'] = [
      '#type' => 'link',
      '#title' => $this->t('Back to Safe Accounts'),
      '#url' => Url::fromRoute('safe_smart_accounts.user_account_list', ['user' => $user->id()]),
      '#attributes' => ['class' => ['button']],
    ];

    return $form;
  }

  /**
   * AJAX callback to remove a current signer.
   */
  public function removeCurrentSigner(array &$form, FormStateInterface $form_state): void {
    $trigger = $form_state->getTriggeringElement();
    $signer_address = $trigger['#signer_address'];

    // Track removed signers in form state.
    $removed_signers = $form_state->get('removed_signers') ?? [];
    $removed_signers[] = $signer_address;
    $form_state->set('removed_signers', $removed_signers);

    $form_state->setRebuild();
  }

  /**
   * AJAX callback to return updated current signers.
   */
  public function updateCurrentSignersCallback(array &$form, FormStateInterface $form_state): array {
    return $form['signers']['current_signers_wrapper'];
  }

  /**
   * AJAX callback to add a new signer field.
   */
  public function addNewSignerField(array &$form, FormStateInterface $form_state): void {
    $num_new_signers = $form_state->get('num_new_signers');
    $num_new_signers++;
    $form_state->set('num_new_signers', $num_new_signers);
    $form_state->setRebuild();
  }

  /**
   * AJAX callback to remove a new signer field.
   */
  public function removeNewSignerField(array &$form, FormStateInterface $form_state): void {
    $trigger = $form_state->getTriggeringElement();
    $delta = $trigger['#signer_delta'];

    // Get current values.
    $values = $form_state->getUserInput();
    $new_signers = $values['signers']['new_signers'] ?? [];

    // Remove the signer at this delta.
    unset($new_signers[$delta]);

    // Re-index the array.
    $new_signers = array_values($new_signers);

    // Update form state.
    $values['signers']['new_signers'] = $new_signers;
    $form_state->setUserInput($values);

    // Decrease the count.
    $num_new_signers = $form_state->get('num_new_signers');
    if ($num_new_signers > 1) {
      $num_new_signers--;
      $form_state->set('num_new_signers', $num_new_signers);
    }

    $form_state->setRebuild();
  }

  /**
   * AJAX callback to return updated new signers fields.
   */
  public function updateNewSignersCallback(array &$form, FormStateInterface $form_state): array {
    return $form['signers']['new_signers'];
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $values = $form_state->getValues();

    // Skip validation if this is an AJAX request.
    $triggering_element = $form_state->getTriggeringElement();
    if (isset($triggering_element['#ajax'])) {
      return;
    }

    // Validate signers.
    $signers = $this->parseSignerAddresses($values['signers']['current_signers'] ?? '');

    // Process new signers from the dynamic fields.
    $new_signer_fields = $values['signers']['new_signers'] ?? [];
    foreach ($new_signer_fields as $delta => $field) {
      // Skip the description element.
      if ($delta === 'description') {
        continue;
      }

      $new_signer_input = trim($field['address'] ?? '');
      if (empty($new_signer_input)) {
        continue;
      }

      // Resolve username to address.
      $new_signer = $this->signerResolver->resolveToAddress($new_signer_input);

      if (!$new_signer) {
        $form_state->setErrorByName("signers][new_signers][$delta][address", $this->t('Could not resolve "@input" to a valid Ethereum address. Please enter a valid username or Ethereum address.', [
          '@input' => $new_signer_input,
        ]));
        return;
      }

      if (!$this->isValidEthereumAddress($new_signer)) {
        $form_state->setErrorByName("signers][new_signers][$delta][address", $this->t('Invalid Ethereum address format.'));
        return;
      }

      if (!in_array($new_signer, $signers, TRUE)) {
        $signers[] = $new_signer;
      }
      else {
        $form_state->setErrorByName("signers][new_signers][$delta][address", $this->t('This address is already a signer on this Safe.'));
        return;
      }
    }

    // Validate all signer addresses.
    foreach ($signers as $address) {
      if (!$this->isValidEthereumAddress($address)) {
        $form_state->setErrorByName('signers][current_signers', $this->t('Invalid Ethereum address: @address', [
          '@address' => $address,
        ]));
      }
    }

    // Validate we have at least one signer.
    if (count($signers) < 1) {
      $form_state->setErrorByName('signers', $this->t('At least one signer is required. You cannot remove all signers.'));
    }

    // Validate threshold.
    $threshold = (int) $values['threshold']['new_threshold'];
    if ($threshold > count($signers)) {
      $form_state->setErrorByName('threshold][new_threshold', $this->t('Threshold (@threshold) cannot be greater than the number of signers (@signers). Please add more signers or lower the threshold.', [
        '@threshold' => $threshold,
        '@signers' => count($signers),
      ]));
    }

    if ($threshold < 1) {
      $form_state->setErrorByName('threshold][new_threshold', $this->t('Threshold must be at least 1.'));
    }

    // Validate fallback handler if provided.
    $fallback_handler = trim($values['advanced']['fallback_handler'] ?? '');
    if (!empty($fallback_handler) && !$this->isValidEthereumAddress($fallback_handler)) {
      $form_state->setErrorByName('advanced][fallback_handler', $this->t('Invalid fallback handler address format.'));
    }

    // Validate modules.
    $modules = $this->parseSignerAddresses($values['advanced']['modules'] ?? '');
    foreach ($modules as $module) {
      if (!$this->isValidEthereumAddress($module)) {
        $form_state->setErrorByName('advanced][modules', $this->t('Invalid module address: @address', [
          '@address' => $module,
        ]));
      }
    }

    // Store validated values for submission.
    $form_state->set('validated_signers', $signers);
    $form_state->set('validated_modules', $modules);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $values = $form_state->getValues();
    $safe_account_id = $values['safe_account_id'];
    $user_id = $values['user_id'];

    try {
      // Load SafeAccount.
      $safe_account_storage = $this->entityTypeManager->getStorage('safe_account');
      $safe_account = $safe_account_storage->load($safe_account_id);

      if (!$safe_account) {
        throw new \Exception('Safe account not found.');
      }

      // Get new values.
      $new_threshold = (int) $values['threshold']['new_threshold'];
      $auto_adjust = $values['threshold']['auto_adjust_threshold'] ?? FALSE;
      $validated_signers = $form_state->get('validated_signers') ?: [];
      $validated_modules = $form_state->get('validated_modules') ?: [];

      // Update SafeConfiguration.
      $safe_config = $this->loadSafeConfiguration($safe_account);
      if (!$safe_config) {
        // Create new configuration if it doesn't exist.
        $safe_config_storage = $this->entityTypeManager->getStorage('safe_configuration');
        $safe_config = $safe_config_storage->create([
          'id' => 'safe_' . $safe_account->id(),
          'label' => $this->t('Configuration for Safe @id', ['@id' => $safe_account->id()]),
          'safe_account_id' => $safe_account->id(),
        ]);
      }

      // Save auto-adjust threshold setting to SafeConfiguration.
      $safe_config->setAutoAdjustThreshold((bool) $auto_adjust);

      // Get current configuration.
      $current_signers = $safe_config->getSigners() ?: [];
      $current_threshold = $safe_account->getThreshold();

      // For active Safes, create on-chain transactions for configuration changes.
      if ($safe_account->isActive()) {
        $transactions_created = $this->createConfigurationTransactions(
          $safe_account,
          $current_signers,
          $validated_signers,
          $current_threshold,
          $new_threshold
        );

        if ($transactions_created > 0) {
          $this->messenger->addStatus($this->t('Created @count configuration change transaction(s). These changes will take effect after the transactions are signed and executed on-chain.', [
            '@count' => $transactions_created,
          ]));
        }
        else {
          // No on-chain changes needed, update configuration directly.
          $this->updateConfigurationDirectly($safe_account, $safe_config, $validated_signers, $new_threshold, $validated_modules, $values);
          $this->messenger->addStatus($this->t('Safe configuration updated successfully.'));
        }
      }
      else {
        // For pending Safes, update configuration directly without blockchain transactions.
        $this->updateConfigurationDirectly($safe_account, $safe_config, $validated_signers, $new_threshold, $validated_modules, $values);
        $this->messenger->addStatus($this->t('Safe configuration updated successfully. These changes will be applied when the Safe is deployed.'));
      }

      // Redirect back to the manage form.
      $form_state->setRedirect('safe_smart_accounts.user_account_manage', [
        'user' => $user_id,
        'safe_account' => $safe_account_id,
      ]);

    }
    catch (\Exception $e) {
      \Drupal::logger('safe_smart_accounts')->error('Failed to update Safe configuration: @message', [
        '@message' => $e->getMessage(),
      ]);
      $this->messenger->addError($this->t('An error occurred while updating the Safe configuration. Please try again.'));
    }
  }

  /**
   * Submit handler for deploying the Safe.
   */
  public function deploySafe(array &$form, FormStateInterface $form_state): void {
    $values = $form_state->getValues();
    $safe_account_id = $values['safe_account_id'];
    $user_id = $values['user_id'];

    try {
      $safe_account_storage = $this->entityTypeManager->getStorage('safe_account');
      $safe_account = $safe_account_storage->load($safe_account_id);

      if (!$safe_account) {
        throw new \Exception('Safe account not found.');
      }

      // Check that the current user owns this Safe account.
      if ($safe_account->getUser()->id() !== $this->currentUser->id()) {
        throw new \Exception('You do not have permission to deploy this Safe account.');
      }

      // Verify that the user ID in the form matches the current user.
      if ($user_id !== $this->currentUser->id()) {
        throw new \Exception('Invalid user context for deployment request.');
      }

      // Check that the Safe account is in 'pending' status before deployment.
      if ($safe_account->getStatus() !== 'pending') {
        throw new \Exception('Safe account cannot be deployed in its current state: ' . $safe_account->getStatus());
      }

      // For MVP, we'll just update status to 'deploying'
      // In Phase 2, this will trigger actual blockchain deployment.
      $safe_account->setStatus('deploying');
      $safe_account->save();

      $this->messenger->addStatus($this->t('Safe deployment initiated. Please use your wallet to complete the deployment process. This may take a few minutes to complete.'));

      // Clear specific cache tags related to this safe account to ensure UI updates.
      $cache_tags = [
        'safe_account:' . $safe_account->id(),
        'safe_account_list:' . $safe_account->getUser()->id(),
        'safe_account_status:' . $safe_account->getStatus(),
        'safe_account_status:all',
      ];
      \Drupal::service('cache_tags.invalidator')->invalidateTags($cache_tags);

      // In the future, this would:
      // 1. Call SafeBlockchainService to deploy the Safe
      // 2. Update the safe_address when deployment completes
      // 3. Change status to 'active'.
    }
    catch (\Exception $e) {
      \Drupal::logger('safe_smart_accounts')->error('Failed to deploy Safe: @message', [
        '@message' => $e->getMessage(),
      ]);
      $this->messenger->addError($this->t('An error occurred while initiating Safe deployment: @error', ['@error' => $e->getMessage()]));
    }
  }

  /**
   * Loads the SafeConfiguration for a Safe account.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   *
   * @return \Drupal\safe_smart_accounts\Entity\SafeConfiguration|null
   *   The configuration or NULL if not found.
   */
  protected function loadSafeConfiguration(SafeAccount $safe_account): ?SafeConfiguration {
    $config_storage = $this->entityTypeManager->getStorage('safe_configuration');
    $query = $config_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('safe_account_id', $safe_account->id())
      ->range(0, 1);

    $result = $query->execute();
    if (!empty($result)) {
      return $config_storage->load(reset($result));
    }

    return NULL;
  }

  /**
   * Gets recent transactions for a Safe account.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   *
   * @return array
   *   Array of SafeTransaction entities.
   */
  protected function getRecentTransactions(SafeAccount $safe_account): array {
    $transaction_storage = $this->entityTypeManager->getStorage('safe_transaction');
    $query = $transaction_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('safe_account', $safe_account->id())
      ->sort('created', 'DESC')
      ->range(0, 10);

    $result = $query->execute();
    if (!empty($result)) {
      return $transaction_storage->loadMultiple($result);
    }

    return [];
  }

  /**
   * Builds table rows for transactions.
   *
   * @param array $transactions
   *   Array of SafeTransaction entities.
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   *
   * @return array
   *   Array of table rows.
   */
  protected function buildTransactionRows(array $transactions, SafeAccount $safe_account): array {
    $rows = [];
    $threshold = $safe_account->getThreshold();

    foreach ($transactions as $transaction) {
      $value_eth = number_format((float) $transaction->getValue() / 1e18, 4);
      $signature_count = count($transaction->getSignatures());
      $status = $transaction->getStatus();
      $nonce = $transaction->get('nonce')->value;
      $is_next_executable = $transaction->isNextExecutable();

      // Format nonce with indicator if this is the next executable transaction.
      $nonce_display = $nonce !== NULL && $nonce !== '' ? (string) $nonce : $this->t('Not set');
      if ($is_next_executable && $status !== 'executed') {
        $nonce_display = [
          '#markup' => '<strong style="color: #0073aa;">→ ' . $nonce . '</strong>',
        ];
      }

      // Create view link for the transaction.
      $view_url = Url::fromRoute('safe_smart_accounts.transaction_view', [
        'safe_account' => $transaction->getSafeAccount()->id(),
        'safe_transaction' => $transaction->id(),
      ]);

      $view_link = [
        '#type' => 'link',
        '#title' => $this->t('View'),
        '#url' => $view_url,
        '#attributes' => ['class' => ['button', 'button--small']],
      ];

      // Build action buttons based on transaction status.
      $action_buttons = [
        '#type' => 'container',
        '#attributes' => ['class' => ['transaction-actions']],
      ];

      // Add view link.
      $action_buttons['view'] = $view_link;

      // Add sign button if transaction is not executed and not cancelled.
      if (!in_array($status, ['executed', 'cancelled'], TRUE)) {
        $action_buttons['sign'] = [
          '#type' => 'button',
          '#value' => $this->t('Sign'),
          '#attributes' => [
            'class' => ['button', 'button--small', 'safe-transaction-sign'],
            'data-safe-account-id' => $safe_account->id(),
            'data-transaction-id' => $transaction->id(),
          ],
        ];
      }

      // Add execute button if transaction can be executed.
      // Now this properly checks nonce ordering via canExecute().
      if ($transaction->canExecute() && !$transaction->isExecuted()) {
        $action_buttons['execute'] = [
          '#type' => 'button',
          '#value' => $this->t('Execute'),
          '#attributes' => [
            'class' => ['button', 'button--small', 'button--primary', 'safe-transaction-execute'],
            'data-safe-account-id' => $safe_account->id(),
            'data-transaction-id' => $transaction->id(),
          ],
        ];
      }

      $rows[] = [
        $transaction->id(),
        ['data' => $nonce_display],
        substr($transaction->getToAddress(), 0, 10) . '...',
        $value_eth,
        ucfirst($status),
        "{$signature_count} / {$threshold}",
        \Drupal::service('date.formatter')->format($transaction->get('created')->value, 'short'),
        ['data' => $action_buttons],
      ];
    }

    return $rows;
  }

  /**
   * Parses signer addresses from textarea input.
   *
   * Accepts usernames or Ethereum addresses and resolves them to addresses.
   *
   * @param string $input
   *   The textarea input containing usernames or addresses.
   *
   * @return array
   *   Array of parsed Ethereum addresses.
   */
  protected function parseSignerAddresses(string $input): array {
    if (empty($input)) {
      return [];
    }

    $lines = explode("\n", $input);
    $addresses = [];

    foreach ($lines as $line) {
      $line = trim($line);
      if (empty($line)) {
        continue;
      }

      // Try to resolve as username or address.
      $resolved = $this->signerResolver->resolveToAddress($line);
      if ($resolved) {
        $addresses[] = $resolved;
      }
      else {
        // Keep original if not resolvable (will fail validation).
        $addresses[] = $line;
      }
    }

    return array_unique($addresses);
  }

  /**
   * Validates Ethereum address format.
   *
   * @param string $address
   *   The address to validate.
   *
   * @return bool
   *   TRUE if valid, FALSE otherwise.
   */
  protected function isValidEthereumAddress(string $address): bool {
    return preg_match('/^0x[a-fA-F0-9]{40}$/', $address) === 1;
  }

  /**
   * Creates on-chain transactions for configuration changes.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   * @param array $current_signers
   *   Current signer addresses.
   * @param array $new_signers
   *   New signer addresses.
   * @param int $current_threshold
   *   Current threshold.
   * @param int $new_threshold
   *   New threshold.
   *
   * @return int
   *   Number of transactions created.
   */
  protected function createConfigurationTransactions(
    SafeAccount $safe_account,
    array $current_signers,
    array $new_signers,
    int $current_threshold,
    int $new_threshold
  ): int {
    $transactions_created = 0;

    // Calculate signer changes.
    $changes = $this->configurationService->calculateSignerChanges($current_signers, $new_signers);

    // Get auto-adjust setting from SafeConfiguration.
    $safe_config = $this->loadSafeConfiguration($safe_account);
    $auto_adjust = $safe_config ? $safe_config->getAutoAdjustThreshold() : FALSE;

    // Create transactions for adding new signers.
    foreach ($changes['additions'] as $new_signer) {
      try {
        // Determine threshold based on SafeConfiguration setting.

        if ($auto_adjust) {
          // Auto-adjust: increment threshold with each addition.
          $is_last_addition = ($new_signer === end($changes['additions']));
          $threshold_for_addition = $is_last_addition && empty($changes['removals']) && $new_threshold !== $current_threshold
            ? $new_threshold
            : count($current_signers) + 1;
        }
        else {
          // Default: respect the user-specified threshold from the form.
          $threshold_for_addition = $new_threshold;
        }

        $tx_data = $this->configurationService->encodeAddOwnerWithThreshold(
          $safe_account,
          $new_signer,
          $threshold_for_addition
        );

        $transaction = $this->transactionService->createTransaction(
          $safe_account,
          $tx_data,
          (int) $this->currentUser->id()
        );

        if ($transaction) {
          $transactions_created++;
          $this->messenger->addStatus($this->t('Created transaction to add signer: @signer', [
            '@signer' => $this->signerResolver->formatSignerLabel($new_signer),
          ]));
        }
      }
      catch (\Exception $e) {
        \Drupal::logger('safe_smart_accounts')->error('Failed to create add signer transaction: @message', [
          '@message' => $e->getMessage(),
        ]);
      }
    }

    // Create transactions for removing signers.
    foreach ($changes['removals'] as $old_signer) {
      try {
        // Determine threshold based on SafeConfiguration setting.

        if ($auto_adjust) {
          // Auto-adjust: decrement threshold with each removal.
          $is_last_removal = ($old_signer === end($changes['removals']));
          $threshold_for_removal = $is_last_removal && $new_threshold !== $current_threshold
            ? $new_threshold
            : max(1, count($current_signers) - 1);
        }
        else {
          // Default: respect the user-specified threshold from the form.
          $threshold_for_removal = $new_threshold;
        }

        $tx_data = $this->configurationService->encodeRemoveOwner(
          $safe_account,
          $old_signer,
          $threshold_for_removal
        );

        $transaction = $this->transactionService->createTransaction(
          $safe_account,
          $tx_data,
          (int) $this->currentUser->id()
        );

        if ($transaction) {
          $transactions_created++;
          $this->messenger->addStatus($this->t('Created transaction to remove signer: @signer', [
            '@signer' => $this->signerResolver->formatSignerLabel($old_signer),
          ]));
        }
      }
      catch (\Exception $e) {
        \Drupal::logger('safe_smart_accounts')->error('Failed to create remove signer transaction: @message', [
          '@message' => $e->getMessage(),
        ]);
      }
    }

    // If only threshold changed (no signer changes), create changeThreshold transaction.
    if (empty($changes['additions']) && empty($changes['removals']) && $new_threshold !== $current_threshold) {
      try {
        $tx_data = $this->configurationService->encodeChangeThreshold(
          $safe_account,
          $new_threshold
        );

        $transaction = $this->transactionService->createTransaction(
          $safe_account,
          $tx_data,
          (int) $this->currentUser->id()
        );

        if ($transaction) {
          $transactions_created++;
          $this->messenger->addStatus($this->t('Created transaction to change threshold to @threshold', [
            '@threshold' => $new_threshold,
          ]));
        }
      }
      catch (\Exception $e) {
        \Drupal::logger('safe_smart_accounts')->error('Failed to create change threshold transaction: @message', [
          '@message' => $e->getMessage(),
        ]);
      }
    }

    return $transactions_created;
  }

  /**
   * Updates configuration directly (for pending Safes or when no on-chain changes needed).
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   * @param \Drupal\safe_smart_accounts\Entity\SafeConfiguration $safe_config
   *   The Safe configuration.
   * @param array $validated_signers
   *   Validated signer addresses.
   * @param int $new_threshold
   *   New threshold.
   * @param array $validated_modules
   *   Validated module addresses.
   * @param array $values
   *   Form values.
   */
  protected function updateConfigurationDirectly(
    SafeAccount $safe_account,
    SafeConfiguration $safe_config,
    array $validated_signers,
    int $new_threshold,
    array $validated_modules,
    array $values
  ): void {
    // Update threshold on SafeAccount.
    $safe_account->setThreshold($new_threshold);
    $safe_account->save();

    // Update SafeConfiguration.
    $safe_config->setSigners($validated_signers);
    $safe_config->setThreshold($new_threshold);
    $safe_config->setModules($validated_modules);

    $fallback_handler = trim($values['advanced']['fallback_handler'] ?? '');
    $safe_config->setFallbackHandler($fallback_handler);

    $safe_config->save();
  }

}
