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
use Drupal\Core\Ajax\AjaxResponse;
use Drupal\Core\Ajax\ReplaceCommand;
use Drupal\Core\Ajax\CssCommand;
use Drupal\Core\Ajax\HtmlCommand;
use Drupal\Core\Ajax\SettingsCommand;

/**
 * Form for creating a new Safe Smart Account.
 */
class SafeAccountCreateForm extends FormBase {

  use SafeAccountFormTrait;

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

    // Add AJAX wrapper for inline deployment
    $form['#prefix'] = '<div id="safe-create-form-wrapper">';
    $form['#suffix'] = '</div>';

    // Attach safe deployment library (includes CSS and JS)
    $form['#attached']['library'][] = 'safe_smart_accounts/safe_deployment';

    $form['description'] = [
      '#markup' => '<div class="safe-create-description">' .
      '<h3>' . $this->t('Create Safe Smart Account') . '</h3>' .
      '<p>' . $this->t('A Safe Smart Account provides enhanced security through multi-signature functionality. You can add additional signers and require multiple signatures for transactions.') . '</p>' .
      '</div>',
    ];

    // Deployment status container (hidden by default, shown after form submit)
    $form['deployment_status'] = [
      '#type' => 'container',
      '#attributes' => [
        'id' => 'safe-deployment-status-container',
        'class' => ['safe-deployment-status'],
        'style' => 'display: none;',
      ],
      '#weight' => -5,
    ];

    $form['deployment_status']['progress'] = [
      '#markup' => '
        <div class="deployment-progress">
          <h3>' . $this->t('Deploying Safe Smart Account') . '</h3>
          <div class="progress-steps">
            <div class="step" id="step-1" data-status="pending">
              <span class="step-icon">⏳</span>
              <span class="step-text">' . $this->t('Saving Safe configuration...') . '</span>
              <span class="step-details"></span>
            </div>
            <div class="step" id="step-2" data-status="pending">
              <span class="step-icon">🔐</span>
              <span class="step-text">' . $this->t('Waiting for transaction signature...') . '</span>
              <span class="step-details"></span>
            </div>
            <div class="step" id="step-3" data-status="pending">
              <span class="step-icon">🚀</span>
              <span class="step-text">' . $this->t('Waiting for blockchain confirmation...') . '</span>
              <span class="step-details"></span>
            </div>
            <div class="step" id="step-4" data-status="pending">
              <span class="step-icon">✅</span>
              <span class="step-text">' . $this->t('Deployment complete!') . '</span>
              <span class="step-details"></span>
            </div>
          </div>
        </div>
      ',
    ];

    // Hidden fields for JavaScript
    $form['deployment_status']['safe_account_id_hidden'] = [
      '#type' => 'hidden',
      '#attributes' => ['id' => 'safe-account-id-for-deployment'],
    ];

    $form['deployment_status']['user_id_hidden'] = [
      '#type' => 'hidden',
      '#attributes' => ['id' => 'user-id-for-deployment'],
    ];

    // Use trait method for network field
    $form['network'] = $this->buildNetworkField();

    // Use trait method for threshold field
    $form['threshold'] = $this->buildThresholdField();

    // Get user's Ethereum address if available
    $user_eth_address = '';
    if ($user && $user->hasField('field_ethereum_address')) {
      $user_eth_address = $user->get('field_ethereum_address')->value ?? '';
    }

    // Use trait method for signers fieldset with AJAX
    $form['signers'] = $this->buildSignersFieldset($form, $form_state, [
      'primary_signer' => $user_eth_address,
    ]);

    $form['advanced'] = [
      '#type' => 'details',
      '#title' => $this->t('Advanced Options'),
      '#open' => FALSE,
    ];

    // Use trait method for salt nonce field
    $form['advanced']['salt_nonce'] = $this->buildSaltNonceField();

    $form['actions'] = [
      '#type' => 'actions',
    ];

    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Create Safe Smart Account'),
      '#button_type' => 'primary',
      '#ajax' => [
        'callback' => '::submitFormAjax',
        'wrapper' => 'safe-create-form-wrapper',
        'progress' => [
          'type' => 'none', // We'll show custom progress
        ],
      ],
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

  // AJAX callbacks for signer management now provided by SafeAccountFormTrait

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

    // Validate threshold using trait method
    $threshold = (int) $values['threshold'];
    $additional_signers = $this->parseSignerAddresses(
      $values['signers']['additional_signers'] ?? [],
      $this->signerResolver
    );
    // Primary signer + additional signers
    $total_signers = 1 + count($additional_signers);

    $this->validateThreshold($form_state, 'threshold', $threshold, $total_signers);

    // Validate additional signer addresses using trait method
    foreach ($additional_signers as $address) {
      $this->validateEthereumAddress($form_state, 'signers][additional_signers', $address);
    }

    // Check for duplicate addresses.
    $primary_signer = strtolower($values['signers']['primary_signer'] ?? '');
    foreach ($additional_signers as $address) {
      if (strtolower($address) === $primary_signer) {
        $form_state->setErrorByName('signers][additional_signers', $this->t('Additional signers cannot include your primary address.'));
        break;
      }
    }

    // Validate salt nonce using trait method
    $salt_nonce = $values['advanced']['salt_nonce'] ?? '';
    $this->validateSaltNonce($form_state, 'advanced][salt_nonce', $salt_nonce);
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
      // Parse additional signers using trait method (pass UserSignerResolver)
      $additional_signers = $this->parseSignerAddresses(
        $values['signers']['additional_signers'] ?? [],
        $this->signerResolver
      );
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

      // Store the created Safe account ID for AJAX handler
      $form_state->set('created_safe_account_id', $safe_account->id());

      // Get salt_nonce value, generate unique value if not provided.
      // Use timestamp to ensure each Safe gets a unique nonce for CREATE2.
      $salt_nonce = !empty($values['advanced']['salt_nonce']) ? (int) $values['advanced']['salt_nonce'] : time();

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

      $this->messenger->addStatus($this->t('Safe Smart Account created successfully!'));

      // Don't redirect here for AJAX - deployment will happen inline
      // Redirect will happen after successful blockchain deployment via JavaScript
      // (Non-AJAX fallback: redirect immediately)
      $triggering_element = $form_state->getTriggeringElement();
      if (!isset($triggering_element['#ajax'])) {
        $form_state->setRedirect('safe_smart_accounts.user_account_manage', [
          'user' => $user->id(),
          'safe_account' => $safe_account->id(),
        ]);
      }

    }
    catch (\Exception $e) {
      \Drupal::logger('safe_smart_accounts')->error('Failed to create Safe account: @message', [
        '@message' => $e->getMessage(),
      ]);
      $this->messenger->addError($this->t('An error occurred while creating your Safe Smart Account. Please try again.'));
    }
  }

  /**
   * AJAX submit handler for creating Safe account.
   */
  public function submitFormAjax(array &$form, FormStateInterface $form_state): AjaxResponse {
    $response = new AjaxResponse();

    // If validation errors, return form with errors
    if ($form_state->hasAnyErrors()) {
      return $response->addCommand(new ReplaceCommand('#safe-create-form-wrapper', $form));
    }

    // NOTE: Don't call $this->submitForm() here!
    // Drupal automatically calls submitForm() before calling this AJAX callback.
    // Calling it again would create duplicate Safe entities.

    // Get the created Safe account ID from form_state storage
    // (This was set by submitForm() which Drupal already called)
    $safe_account_id = $form_state->get('created_safe_account_id');
    $user = $form_state->getBuildInfo()['args'][0] ?? NULL;

    if (!$safe_account_id || !$user) {
      // Error occurred, return form with error message
      $this->messenger->addError($this->t('Failed to create Safe account.'));
      return $response->addCommand(new ReplaceCommand('#safe-create-form-wrapper', $form));
    }

    // Use proper Drupal AJAX commands (no arbitrary JS execution)
    // Hide form elements via CSS
    $response->addCommand(new CssCommand('.safe-create-description', ['display' => 'none']));
    $response->addCommand(new CssCommand('#safe-create-form-wrapper fieldset', ['display' => 'none']));
    $response->addCommand(new CssCommand('.form-actions', ['display' => 'none']));

    // Hide specific form fields (Network, Threshold, Advanced Options)
    $response->addCommand(new CssCommand('[name="network"]', ['display' => 'none']));
    $response->addCommand(new CssCommand('.js-form-item-network', ['display' => 'none']));
    $response->addCommand(new CssCommand('[name="threshold"]', ['display' => 'none']));
    $response->addCommand(new CssCommand('.js-form-item-threshold', ['display' => 'none']));
    $response->addCommand(new CssCommand('#edit-advanced', ['display' => 'none']));

    // Show deployment status container
    $response->addCommand(new CssCommand('#safe-deployment-status-container', ['display' => 'block']));

    // Pass deployment trigger and data to JavaScript via drupalSettings
    // A Drupal behavior will handle step updates and trigger deployment
    $response->addCommand(new SettingsCommand([
      'safeSmartAccounts' => [
        'triggerDeployment' => TRUE,
        'safeAccountId' => $safe_account_id,
        'userId' => $user->id(),
      ],
    ], FALSE));

    return $response;
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

  // parseSignerAddresses() and validation methods now provided by SafeAccountFormTrait

}
