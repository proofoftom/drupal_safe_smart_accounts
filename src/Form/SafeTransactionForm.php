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

/**
 * Form for creating Safe transactions.
 */
class SafeTransactionForm extends FormBase {

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
  public function buildForm(array $form, FormStateInterface $form_state, SafeAccount $safe_account = NULL): array {
    if (!$safe_account) {
      $form['error'] = [
        '#markup' => $this->t('Safe account not found.'),
      ];
      return $form;
    }

    $form['#tree'] = TRUE;
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

    $form['basic'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Transaction Details'),
    ];

    $form['basic']['to_address'] = [
      '#type' => 'textfield',
      '#title' => $this->t('To Address'),
      '#description' => $this->t('The Ethereum address that will receive this transaction.'),
      '#placeholder' => '0x742d35Cc6634C0532925a3b8D8938d9e1Aac5C63',
      '#required' => TRUE,
      '#maxlength' => 42,
    ];

    $form['basic']['value_eth'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Value (ETH)'),
      '#description' => $this->t('Amount of ETH to send (e.g., 0.1 for 0.1 ETH). Supports up to 18 decimal places.'),
      '#default_value' => '0',
      '#required' => TRUE,
      '#size' => 30,
      '#maxlength' => 30,
      '#placeholder' => '0.1',
    ];

    $form['basic']['operation'] = [
      '#type' => 'select',
      '#title' => $this->t('Operation Type'),
      '#description' => $this->t('The type of transaction operation.'),
      '#options' => [
        0 => $this->t('Call - Regular transaction'),
        1 => $this->t('DelegateCall - Advanced (use with caution)'),
      ],
      '#default_value' => 0,
      '#required' => TRUE,
    ];

    // Advanced options
    $form['advanced'] = [
      '#type' => 'details',
      '#title' => $this->t('Advanced Options'),
      '#open' => FALSE,
    ];

    $form['advanced']['data'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Transaction Data'),
      '#description' => $this->t('Optional transaction data as hex string (e.g., contract function call data).'),
      '#default_value' => '0x',
      '#rows' => 4,
      '#placeholder' => '0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b8d8938d9e1aac5c630000000000000000000000000000000000000000000000000de0b6b3a7640000',
    ];

    $form['advanced']['gas_limit'] = [
      '#type' => 'number',
      '#title' => $this->t('Gas Limit'),
      '#description' => $this->t('Maximum gas to use for this transaction. Leave empty for automatic estimation.'),
      '#min' => 21000,
      '#max' => 10000000,
      '#placeholder' => '21000',
    ];

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

    // Validate to_address
    $to_address = trim($values['basic']['to_address'] ?? '');
    if (!$this->isValidEthereumAddress($to_address)) {
      $form_state->setErrorByName('basic][to_address', $this->t('Please enter a valid Ethereum address.'));
    }

    // Validate value
    $value_eth = trim($values['basic']['value_eth'] ?? '0');
    if (!$this->isValidEthValue($value_eth)) {
      $form_state->setErrorByName('basic][value_eth', $this->t('Value must be a valid non-negative number with up to 18 decimal places.'));
    }

    // Validate transaction data
    $data = trim($values['advanced']['data'] ?? '0x');
    if (!empty($data) && $data !== '0x' && !$this->isValidHexData($data)) {
      $form_state->setErrorByName('advanced][data', $this->t('Transaction data must be valid hex format (starting with 0x).'));
    }

    // Validate gas limit
    $gas_limit = $values['advanced']['gas_limit'] ?? '';
    if (!empty($gas_limit)) {
      if (!is_numeric($gas_limit) || (int) $gas_limit < 21000) {
        $form_state->setErrorByName('advanced][gas_limit', $this->t('Gas limit must be at least 21,000.'));
      }
    }

    // Store converted values
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

  /**
   * Converts ETH to wei.
   *
   * @param string $eth
   *   The ETH amount as a string.
   *
   * @return string
   *   The wei amount as string.
   */
  protected function ethToWei(string $eth): string {
    // Convert ETH to wei (multiply by 10^18)
    // Using bcmul with string input preserves precision
    $wei = bcmul($eth, '1000000000000000000', 0);
    return $wei;
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
   * Validates hex data format.
   *
   * @param string $data
   *   The hex data to validate.
   *
   * @return bool
   *   TRUE if valid, FALSE otherwise.
   */
  protected function isValidHexData(string $data): bool {
    return preg_match('/^0x[a-fA-F0-9]*$/', $data) === 1;
  }

  /**
   * Validates ETH value format.
   *
   * @param string $value
   *   The ETH value to validate.
   *
   * @return bool
   *   TRUE if valid, FALSE otherwise.
   */
  protected function isValidEthValue(string $value): bool {
    // Must be a valid number (integer or decimal)
    if (!is_numeric($value)) {
      return FALSE;
    }

    // Must be non-negative
    if (bccomp($value, '0', 18) < 0) {
      return FALSE;
    }

    // Check decimal places (max 18 for ETH)
    $parts = explode('.', $value);
    if (isset($parts[1]) && strlen($parts[1]) > 18) {
      return FALSE;
    }

    return TRUE;
  }

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