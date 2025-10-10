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
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\user\UserInterface;

/**
 * Form for creating a new Safe Smart Account.
 */
class SafeAccountCreateForm extends FormBase {

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
   * Constructs a SafeAccountCreateForm object.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   The current user.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param \Drupal\safe_smart_accounts\Service\UserSignerResolver $signer_resolver
   *   The user signer resolver service.
   */
  public function __construct(
    EntityTypeManagerInterface $entity_type_manager,
    AccountProxyInterface $current_user,
    MessengerInterface $messenger,
    UserSignerResolver $signer_resolver,
  ) {
    $this->entityTypeManager = $entity_type_manager;
    $this->currentUser = $current_user;
    $this->messenger = $messenger;
    $this->signerResolver = $signer_resolver;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity_type.manager'),
      $container->get('current_user'),
      $container->get('messenger'),
      $container->get('safe_smart_accounts.user_signer_resolver')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'safe_account_create_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, ?UserInterface $user = NULL): array {
    // Check if user already has a Safe account on this network.
    if ($user) {
      $existing_safe = $this->checkExistingSafeAccount($user);
      if ($existing_safe) {
        $this->messenger->addWarning($this->t('You already have a Safe Smart Account on the @network network.', [
          '@network' => $existing_safe->getNetwork(),
        ]));
        return [
          '#markup' => $this->t('You already have a Safe Smart Account. <a href="@manage_url">Manage your Safe account</a>.', [
            '@manage_url' => Url::fromRoute('safe_smart_accounts.user_account_manage', [
              'user' => $user->id(),
              'safe_account' => $existing_safe->id(),
            ])->toString(),
          ]),
        ];
      }
    }

    $form['#tree'] = TRUE;

    $form['description'] = [
      '#markup' => '<div class="safe-create-description">' .
      '<h3>' . $this->t('Create Safe Smart Account') . '</h3>' .
      '<p>' . $this->t('A Safe Smart Account provides enhanced security through multi-signature functionality. You can add additional signers and require multiple signatures for transactions.') . '</p>' .
      '</div>',
    ];

    $form['network'] = [
      '#type' => 'select',
      '#title' => $this->t('Network'),
      '#description' => $this->t('Select the Ethereum network for your Safe Smart Account.'),
      '#options' => [
        'sepolia' => $this->t('Sepolia Testnet'),
        'hardhat' => $this->t('Hardhat Local'),
      ],
      '#default_value' => 'sepolia',
      '#required' => TRUE,
      // Enable network selection to allow Hardhat.
      '#disabled' => FALSE,
    ];

    $form['threshold'] = [
      '#type' => 'number',
      '#title' => $this->t('Signature Threshold'),
      '#description' => $this->t('Number of signatures required to execute transactions. Must be between 1 and the number of signers.'),
      '#default_value' => 1,
      '#min' => 1,
      '#max' => 10,
      '#required' => TRUE,
    ];

    $form['signers'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Signers'),
      '#description' => $this->t('Your Ethereum address will be automatically included as the first signer.'),
    ];

    // Get user's Ethereum address if available.
    $user_eth_address = '';
    if ($user && $user->hasField('field_ethereum_address')) {
      $user_eth_address = $user->get('field_ethereum_address')->value ?? '';
    }

    $form['signers']['primary_signer'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Primary Signer (Your Address)'),
      '#default_value' => $user_eth_address,
      '#disabled' => TRUE,
      '#description' => $this->t('This is your Ethereum address from SIWE authentication.'),
    ];

    // Get the number of signer fields from form state.
    $num_signers = $form_state->get('num_signers');
    if ($num_signers === NULL) {
      $num_signers = 1;
      $form_state->set('num_signers', $num_signers);
    }

    $form['signers']['additional_signers'] = [
      '#type' => 'container',
      '#title' => $this->t('Additional Signers'),
      '#prefix' => '<div id="signers-fieldset-wrapper">',
      '#suffix' => '</div>',
      '#tree' => TRUE,
    ];

    for ($i = 0; $i < $num_signers; $i++) {
      $form['signers']['additional_signers'][$i] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['signer-field-row']],
      ];

      $form['signers']['additional_signers'][$i]['address'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Signer @num', ['@num' => $i + 1]),
        '#description' => $i === 0 ? $this->t('Enter a username or Ethereum address. Start typing a username to see suggestions.') : '',
        '#placeholder' => 'alice or 0x742d35Cc6634C0532925a3b8D8938d9e1Aac5C63',
        '#autocomplete_route_name' => 'safe_smart_accounts.signer_autocomplete',
        '#size' => 60,
      ];

      if ($num_signers > 1) {
        $form['signers']['additional_signers'][$i]['remove'] = [
          '#type' => 'submit',
          '#value' => $this->t('Remove'),
          '#submit' => ['::removeSignerField'],
          '#ajax' => [
            'callback' => '::updateSignerFieldsCallback',
            'wrapper' => 'signers-fieldset-wrapper',
          ],
          '#name' => 'remove_signer_' . $i,
          '#signer_delta' => $i,
          '#attributes' => ['class' => ['button--small', 'button--danger']],
        ];
      }
    }

    $form['signers']['add_signer'] = [
      '#type' => 'submit',
      '#value' => $this->t('Add another signer'),
      '#submit' => ['::addSignerField'],
      '#ajax' => [
        'callback' => '::updateSignerFieldsCallback',
        'wrapper' => 'signers-fieldset-wrapper',
      ],
      '#attributes' => ['class' => ['button--small']],
    ];

    $form['advanced'] = [
      '#type' => 'details',
      '#title' => $this->t('Advanced Options'),
      '#open' => FALSE,
    ];

    $form['advanced']['salt_nonce'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Salt Nonce'),
      '#description' => $this->t('Optional salt nonce for deterministic Safe address generation. Leave empty for random generation.'),
      '#placeholder' => '0',
    ];

    $form['actions'] = [
      '#type' => 'actions',
    ];

    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Create Safe Smart Account'),
      '#button_type' => 'primary',
    ];

    $form['actions']['cancel'] = [
      '#type' => 'link',
      '#title' => $this->t('Cancel'),
      '#url' => $user ?
      Url::fromRoute('safe_smart_accounts.user_account_list', ['user' => $user->id()]) :
      Url::fromRoute('<front>'),
      '#attributes' => ['class' => ['button']],
    ];

    return $form;
  }

  /**
   * AJAX callback to add a signer field.
   */
  public function addSignerField(array &$form, FormStateInterface $form_state): void {
    $num_signers = $form_state->get('num_signers');
    $num_signers++;
    $form_state->set('num_signers', $num_signers);
    $form_state->setRebuild();
  }

  /**
   * AJAX callback to remove a signer field.
   */
  public function removeSignerField(array &$form, FormStateInterface $form_state): void {
    $trigger = $form_state->getTriggeringElement();
    $delta = $trigger['#signer_delta'];

    // Get current values.
    $values = $form_state->getUserInput();
    $signers = $values['signers']['additional_signers'] ?? [];

    // Remove the signer at this delta.
    unset($signers[$delta]);

    // Re-index the array.
    $signers = array_values($signers);

    // Update form state.
    $values['signers']['additional_signers'] = $signers;
    $form_state->setUserInput($values);

    // Decrease the count.
    $num_signers = $form_state->get('num_signers');
    if ($num_signers > 1) {
      $num_signers--;
      $form_state->set('num_signers', $num_signers);
    }

    $form_state->setRebuild();
  }

  /**
   * AJAX callback to return updated signer fields.
   */
  public function updateSignerFieldsCallback(array &$form, FormStateInterface $form_state): array {
    return $form['signers']['additional_signers'];
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

    // Validate threshold.
    $threshold = (int) $values['threshold'];
    $additional_signers = $this->parseSignerAddresses($values['signers']['additional_signers'] ?? []);
    // Primary signer + additional signers.
    $total_signers = 1 + count($additional_signers);

    if ($threshold > $total_signers) {
      $form_state->setErrorByName('threshold', $this->t('Threshold (@threshold) cannot be greater than the number of signers (@signers).', [
        '@threshold' => $threshold,
        '@signers' => $total_signers,
      ]));
    }

    if ($threshold < 1) {
      $form_state->setErrorByName('threshold', $this->t('Threshold must be at least 1.'));
    }

    // Validate additional signer addresses.
    foreach ($additional_signers as $address) {
      if (!$this->isValidEthereumAddress($address)) {
        $form_state->setErrorByName('signers][additional_signers', $this->t('Invalid Ethereum address: @address', [
          '@address' => $address,
        ]));
      }
    }

    // Check for duplicate addresses.
    $primary_signer = strtolower($values['signers']['primary_signer'] ?? '');
    foreach ($additional_signers as $address) {
      if (strtolower($address) === $primary_signer) {
        $form_state->setErrorByName('signers][additional_signers', $this->t('Additional signers cannot include your primary address.'));
        break;
      }
    }

    // Validate salt nonce if provided.
    $salt_nonce = $values['advanced']['salt_nonce'] ?? '';
    if (!empty($salt_nonce) && (!is_numeric($salt_nonce) || (int) $salt_nonce < 0)) {
      $form_state->setErrorByName('advanced][salt_nonce', $this->t('Salt nonce must be a non-negative integer.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $values = $form_state->getValues();
    $route_params = $form_state->getBuildInfo()['args'][0] ?? NULL;
    $user = $route_params instanceof UserInterface ? $route_params : NULL;

    if (!$user) {
      $this->messenger->addError($this->t('Unable to determine user context.'));
      return;
    }

    try {
      // Parse additional signers.
      $additional_signers = $this->parseSignerAddresses($values['signers']['additional_signers'] ?? []);
      $all_signers = [$values['signers']['primary_signer']];
      $all_signers = array_merge($all_signers, $additional_signers);

      // Create SafeAccount entity.
      $safe_account_storage = $this->entityTypeManager->getStorage('safe_account');
      $safe_account = $safe_account_storage->create([
        'user_id' => $user->id(),
        'network' => $values['network'],
        'threshold' => (int) $values['threshold'],
        'status' => 'pending',
      ]);
      $safe_account->save();

      // Get salt_nonce value, default to 0 if not provided.
      $salt_nonce = !empty($values['advanced']['salt_nonce']) ? (int) $values['advanced']['salt_nonce'] : 0;

      // Create SafeConfiguration entity.
      $safe_config_storage = $this->entityTypeManager->getStorage('safe_configuration');
      $safe_config = $safe_config_storage->create([
        'id' => 'safe_' . $safe_account->id(),
        'label' => $this->t('Configuration for Safe @id', ['@id' => $safe_account->id()]),
        'safe_account_id' => $safe_account->id(),
        'signers' => $all_signers,
        'threshold' => (int) $values['threshold'],
        'version' => '1.4.1',
        'salt_nonce' => $salt_nonce,
      ]);
      $safe_config->save();

      $this->messenger->addStatus($this->t('Safe Smart Account created successfully! Your Safe is currently pending deployment.'));

      // Redirect to the Safe account management page.
      $form_state->setRedirect('safe_smart_accounts.user_account_manage', [
        'user' => $user->id(),
        'safe_account' => $safe_account->id(),
      ]);

    }
    catch (\Exception $e) {
      \Drupal::logger('safe_smart_accounts')->error('Failed to create Safe account: @message', [
        '@message' => $e->getMessage(),
      ]);
      $this->messenger->addError($this->t('An error occurred while creating your Safe Smart Account. Please try again.'));
    }
  }

  /**
   * Checks if user already has a Safe account.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user to check.
   *
   * @return \Drupal\safe_smart_accounts\Entity\SafeAccount|null
   *   The existing Safe account or NULL.
   */
  protected function checkExistingSafeAccount(UserInterface $user): ?object {
    $safe_account_storage = $this->entityTypeManager->getStorage('safe_account');
    $query = $safe_account_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('user_id', $user->id())
     // Currently only supporting Sepolia.
      ->condition('network', 'sepolia')
      ->range(0, 1);

    $result = $query->execute();
    if (!empty($result)) {
      return $safe_account_storage->load(reset($result));
    }

    return NULL;
  }

  /**
   * Parses signer addresses from field values.
   *
   * Accepts usernames or Ethereum addresses and resolves them to addresses.
   *
   * @param array $signer_fields
   *   Array of signer field values from the form.
   *
   * @return array
   *   Array of parsed Ethereum addresses.
   */
  protected function parseSignerAddresses(array $signer_fields): array {
    $addresses = [];

    foreach ($signer_fields as $field) {
      $input = trim($field['address'] ?? '');
      if (empty($input)) {
        continue;
      }

      // Try to resolve as username or address.
      $resolved = $this->signerResolver->resolveToAddress($input);
      if ($resolved) {
        $addresses[] = $resolved;
      }
      else {
        // Keep original if not resolvable (will fail validation).
        $addresses[] = $input;
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

}
