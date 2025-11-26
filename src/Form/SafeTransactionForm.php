<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\safe_smart_accounts\Entity\SafeAccount;
use Drupal\user\UserInterface;

/**
 * Form for creating Safe transactions.
 */
class SafeTransactionForm extends FormBase {

  use SafeTransactionFormTrait;

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
   * Constructs a SafeTransactionForm object.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   The current user.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   */
  public function __construct(
    EntityTypeManagerInterface $entity_type_manager,
    AccountProxyInterface $current_user,
    MessengerInterface $messenger
  ) {
    $this->entityTypeManager = $entity_type_manager;
    $this->currentUser = $current_user;
    $this->messenger = $messenger;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity_type.manager'),
      $container->get('current_user'),
      $container->get('messenger')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'safe_transaction_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, UserInterface $user = NULL, SafeAccount $safe_account = NULL): array {
    if (!$safe_account) {
      $form['error'] = [
        '#markup' => $this->t('Safe account not found.'),
      ];
      return $form;
    }

    $form['safe_account_id'] = [
      '#type' => 'value',
      '#value' => $safe_account->id(),
    ];

    // Transaction details
    $form['description'] = [
      '#markup' => '<div class="transaction-form-description">' .
        '<h3>' . $this->t('Create Safe Transaction') . '</h3>' .
        '<p>' . $this->t('Create a new transaction proposal for Safe #@id. This transaction will require @threshold signature(s) to execute.', [
          '@id' => $safe_account->id(),
          '@threshold' => $safe_account->getThreshold(),
        ]) . '</p>' .
        '</div>',
    ];

    // Transaction Details (collapsible, open by default)
    $form['basic'] = [
      '#type' => 'details',
      '#title' => $this->t('Transaction Details'),
      '#open' => TRUE,
      '#attributes' => ['class' => ['social-collapsible-fieldset']],
    ];

    // Use trait methods for transaction fields
    $form['basic']['to_address'] = $this->buildToAddressField();
    $form['basic']['value_eth'] = $this->buildValueField();
    $form['basic']['operation'] = $this->buildOperationField();

    // Advanced options
    $form['advanced'] = [
      '#type' => 'details',
      '#title' => $this->t('Advanced Options'),
      '#open' => FALSE,
      '#attributes' => ['class' => ['social-collapsible-fieldset']],
    ];

    // Use trait methods for advanced fields
    $form['advanced']['data'] = $this->buildDataField();
    $form['advanced']['gas_limit'] = $this->buildGasLimitField();

    // Transaction preview
    $form['preview'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Transaction Summary'),
      '#weight' => 10,
    ];

    $form['preview']['summary'] = [
      '#markup' => '<div id="transaction-summary">' .
        $this->t('Fill in the transaction details to see a summary here.') .
        '</div>',
    ];

    // Actions
    $form['actions'] = [
      '#type' => 'actions',
      '#weight' => 20,
    ];

    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Create Transaction Proposal'),
      '#button_type' => 'primary',
    ];

    $form['actions']['save_draft'] = [
      '#type' => 'submit',
      '#value' => $this->t('Save as Draft'),
      '#button_type' => 'secondary',
      '#submit' => ['::saveDraft'],
    ];

    $form['actions']['cancel'] = [
      '#type' => 'link',
      '#title' => $this->t('Cancel'),
      '#url' => $this->getSafeManageUrl($safe_account),
      '#attributes' => ['class' => ['button']],
    ];

    // Add JavaScript for dynamic summary updates
    $form['#attached']['library'][] = 'safe_smart_accounts/transaction_form';

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $values = $form_state->getValues();

    // Validate using trait methods
    $to_address = trim($values['basic']['to_address'] ?? '');
    $this->validateToAddress($form_state, 'basic][to_address', $to_address);

    $value_eth = trim($values['basic']['value_eth'] ?? '0');
    $this->validateValue($form_state, 'basic][value_eth', $value_eth);

    $data = trim($values['advanced']['data'] ?? '0x');
    $this->validateData($form_state, 'advanced][data', $data);

    $gas_limit = $values['advanced']['gas_limit'] ?? '';
    $this->validateGasLimit($form_state, 'advanced][gas_limit', $gas_limit);

    // Store converted values using trait method
    $form_state->set('value_wei', $this->ethToWei($value_eth));
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->createTransaction($form_state, 'pending');
  }

  /**
   * Submit handler for saving as draft.
   */
  public function saveDraft(array &$form, FormStateInterface $form_state): void {
    $this->createTransaction($form_state, 'draft');
  }

  /**
   * Creates a transaction with the specified status.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $status
   *   The transaction status.
   */
  protected function createTransaction(FormStateInterface $form_state, string $status): void {
    $values = $form_state->getValues();
    $safe_account_id = $values['safe_account_id'];

    try {
      // Load Safe account
      $safe_account_storage = $this->entityTypeManager->getStorage('safe_account');
      $safe_account = $safe_account_storage->load($safe_account_id);
      
      if (!$safe_account) {
        throw new \Exception('Safe account not found.');
      }

      // Prepare transaction data
      $value_wei = $form_state->get('value_wei');
      $data = trim($values['advanced']['data'] ?? '0x');
      $gas_estimate = !empty($values['advanced']['gas_limit']) ? (int) $values['advanced']['gas_limit'] : NULL;

      // Auto-assign next available nonce.
      $nonce = $this->getNextNonce($safe_account);

      // Create SafeTransaction entity
      $transaction_storage = $this->entityTypeManager->getStorage('safe_transaction');
      $transaction = $transaction_storage->create([
        'safe_account' => $safe_account->id(),
        'to_address' => trim($values['basic']['to_address']),
        'value' => (string) $value_wei,
        'data' => $data,
        'operation' => (int) $values['basic']['operation'],
        'gas_estimate' => $gas_estimate,
        'status' => $status,
        'nonce' => $nonce,
        'created_by' => $this->currentUser->id(),
        'signatures' => json_encode([]), // Empty signatures array
      ]);
      $transaction->save();

      $status_message = $status === 'draft' 
        ? $this->t('Transaction saved as draft.')
        : $this->t('Transaction proposal created successfully! It requires @threshold signature(s) to execute.', [
            '@threshold' => $safe_account->getThreshold(),
          ]);
      
      $this->messenger->addStatus($status_message);

      // Redirect back to Safe management page
      $form_state->setRedirect('safe_smart_accounts.user_account_manage', [
        'user' => $safe_account->getUser()->id(),
        'safe_account' => $safe_account->id(),
      ]);

    } catch (\Exception $e) {
      \Drupal::logger('safe_smart_accounts')->error('Failed to create Safe transaction: @message', [
        '@message' => $e->getMessage(),
      ]);
      $this->messenger->addError($this->t('An error occurred while creating the transaction. Please try again.'));
    }
  }

  /**
   * Gets the URL for managing the Safe account.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   *
   * @return \Drupal\Core\Url
   *   The URL object.
   */
  protected function getSafeManageUrl(SafeAccount $safe_account): Url {
    $user = $safe_account->getUser();
    if ($user) {
      return Url::fromRoute('safe_smart_accounts.user_account_manage', [
        'user' => $user->id(),
        'safe_account' => $safe_account->id(),
      ]);
    }
    
    return Url::fromRoute('<front>');
  }

  // ethToWei() and validation methods now provided by SafeTransactionFormTrait

  /**
   * Gets the next available nonce for a Safe account.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account.
   *
   * @return int
   *   The next nonce.
   */
  protected function getNextNonce(SafeAccount $safe_account): int {
    // Get all transactions for this Safe and manually find the highest nonce.
    // We can't use condition('nonce', '', '<>') because that doesn't work
    // properly for integer fields with value 0.
    $transaction_storage = $this->entityTypeManager->getStorage('safe_transaction');
    $query = $transaction_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('safe_account', $safe_account->id());

    $result = $query->execute();

    if (empty($result)) {
      // No transactions exist, start from 0.
      return 0;
    }

    // Load all transactions and find the highest non-NULL nonce.
    $transactions = $transaction_storage->loadMultiple($result);
    $highest_nonce = NULL;

    foreach ($transactions as $transaction) {
      $nonce_value = $transaction->get('nonce')->value;
      if ($nonce_value !== NULL && $nonce_value !== '') {
        $nonce_int = (int) $nonce_value;
        if ($highest_nonce === NULL || $nonce_int > $highest_nonce) {
          $highest_nonce = $nonce_int;
        }
      }
    }

    // If no transactions have nonces yet, start from 0.
    if ($highest_nonce === NULL) {
      return 0;
    }

    // Return next nonce after the highest.
    return $highest_nonce + 1;
  }

}