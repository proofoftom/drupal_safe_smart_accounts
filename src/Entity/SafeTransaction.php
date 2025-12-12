<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Entity;

use Drupal\Core\Entity\ContentEntityBase;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Field\BaseFieldDefinition;
use Drupal\user\UserInterface;

/**
 * Defines the Safe Transaction entity.
 *
 * @ContentEntityType(
 *   id = "safe_transaction",
 *   label = @Translation("Safe Transaction"),
 *   label_collection = @Translation("Safe Transactions"),
 *   handlers = {
 *     "view_builder" = "Drupal\Core\Entity\EntityViewBuilder",
 *     "list_builder" = "Drupal\safe_smart_accounts\SafeTransactionListBuilder",
 *     "access" = "Drupal\safe_smart_accounts\SafeTransactionAccessControlHandler",
 *     "form" = {
 *       "default" = "Drupal\safe_smart_accounts\Form\SafeTransactionForm",
 *       "add" = "Drupal\safe_smart_accounts\Form\SafeTransactionForm",
 *       "edit" = "Drupal\safe_smart_accounts\Form\SafeTransactionForm",
 *       "delete" = "Drupal\Core\Entity\ContentEntityDeleteForm",
 *     },
 *   },
 *   base_table = "safe_transaction",
 *   admin_permission = "administer safe smart accounts",
 *   entity_keys = {
 *     "id" = "id",
 *     "uuid" = "uuid",
 *   },
 *   links = {
 *     "canonical" = "/safe-accounts/{safe_account}/transactions/{safe_transaction}",
 *     "add-form" = "/safe-accounts/{safe_account}/transactions/create",
 *     "edit-form" = "/safe-accounts/{safe_account}/transactions/{safe_transaction}/edit",
 *     "delete-form" = "/safe-accounts/{safe_account}/transactions/{safe_transaction}/delete",
 *     "collection" = "/admin/content/safe-transactions",
 *   },
 *   field_ui_base_route = "safe_smart_accounts.admin_settings",
 * )
 */
class SafeTransaction extends ContentEntityBase implements SafeTransactionInterface {

  /**
   * {@inheritdoc}
   */
  public static function baseFieldDefinitions(EntityTypeInterface $entity_type): array {
    $fields = parent::baseFieldDefinitions($entity_type);

    $fields['safe_account'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('Safe Account'))
      ->setDescription(t('The Safe Smart Account this transaction belongs to.'))
      ->setSetting('target_type', 'safe_account')
      ->setRequired(TRUE)
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'entity_reference_label',
        'weight' => -5,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['safe_tx_hash'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Safe Transaction Hash'))
      ->setDescription(t('The Safe transaction hash (internal to Safe).'))
      ->setSettings([
        'max_length' => 66,
        'text_processing' => 0,
      ])
      ->setDefaultValue('')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'string',
        'weight' => -4,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['blockchain_tx_hash'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Blockchain Transaction Hash'))
      ->setDescription(t('The actual blockchain transaction hash when executed.'))
      ->setSettings([
        'max_length' => 66,
        'text_processing' => 0,
      ])
      ->setDefaultValue('')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'string',
        'weight' => -3,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['to_address'] = BaseFieldDefinition::create('string')
      ->setLabel(t('To Address'))
      ->setDescription(t('The recipient Ethereum address.'))
      ->setSettings([
        'max_length' => 42,
        'text_processing' => 0,
      ])
      ->setRequired(TRUE)
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'string',
        'weight' => -2,
      ])
      ->setDisplayOptions('form', [
        'type' => 'string_textfield',
        'weight' => -2,
      ])
      ->setDisplayConfigurable('form', TRUE)
      ->setDisplayConfigurable('view', TRUE);

    $fields['value'] = BaseFieldDefinition::create('decimal')
      ->setLabel(t('Value'))
      ->setDescription(t('ETH value in wei (18 decimal places).'))
      ->setSettings([
        'precision' => 28,
        'scale' => 0,
      ])
      ->setRequired(TRUE)
      ->setDefaultValue('0')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'number_decimal',
        'weight' => -1,
      ])
      ->setDisplayOptions('form', [
        'type' => 'number',
        'weight' => -1,
      ])
      ->setDisplayConfigurable('form', TRUE)
      ->setDisplayConfigurable('view', TRUE);

    $fields['data'] = BaseFieldDefinition::create('string_long')
      ->setLabel(t('Transaction Data'))
      ->setDescription(t('Transaction data as hex string.'))
      ->setDefaultValue('0x')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'basic_string',
        'weight' => 0,
      ])
      ->setDisplayOptions('form', [
        'type' => 'string_textarea',
        'weight' => 0,
        'settings' => [
          'rows' => 3,
        ],
      ])
      ->setDisplayConfigurable('form', TRUE)
      ->setDisplayConfigurable('view', TRUE);

    $fields['operation'] = BaseFieldDefinition::create('list_integer')
      ->setLabel(t('Operation'))
      ->setDescription(t('Transaction operation type.'))
      ->setSettings([
        'allowed_values' => [
          0 => 'Call',
          1 => 'DelegateCall',
        ],
      ])
      ->setRequired(TRUE)
      ->setDefaultValue(0)
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'number_integer',
        'weight' => 1,
      ])
      ->setDisplayOptions('form', [
        'type' => 'options_select',
        'weight' => 1,
      ])
      ->setDisplayConfigurable('form', TRUE)
      ->setDisplayConfigurable('view', TRUE);

    $fields['gas_estimate'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Gas Estimate'))
      ->setDescription(t('Estimated gas limit for the transaction.'))
      ->setSettings([
        'min' => 0,
      ])
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'number_integer',
        'weight' => 2,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['status'] = BaseFieldDefinition::create('list_string')
      ->setLabel(t('Status'))
      ->setDescription(t('Current status of the transaction.'))
      ->setSettings([
        'allowed_values' => [
          'draft' => 'Draft',
          'pending' => 'Pending',
          'executed' => 'Executed',
          'failed' => 'Failed',
          'cancelled' => 'Cancelled',
        ],
      ])
      ->setRequired(TRUE)
      ->setDefaultValue('draft')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'string',
        'weight' => 3,
      ])
      ->setDisplayOptions('form', [
        'type' => 'options_select',
        'weight' => 3,
      ])
      ->setDisplayConfigurable('form', TRUE)
      ->setDisplayConfigurable('view', TRUE);

    $fields['nonce'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Nonce'))
      ->setDescription(t('Safe nonce for transaction ordering.'))
      ->setSettings([
        'min' => 0,
      ])
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'number_integer',
        'weight' => 4,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['created_by'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('Created By'))
      ->setDescription(t('The user who proposed this transaction.'))
      ->setSetting('target_type', 'user')
      ->setRequired(TRUE)
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'entity_reference_label',
        'weight' => 5,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['created'] = BaseFieldDefinition::create('created')
      ->setLabel(t('Created'))
      ->setDescription(t('The time that the transaction was created.'))
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'timestamp',
        'weight' => 6,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['executed_at'] = BaseFieldDefinition::create('timestamp')
      ->setLabel(t('Executed At'))
      ->setDescription(t('The time that the transaction was executed.'))
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'timestamp',
        'weight' => 7,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['signatures'] = BaseFieldDefinition::create('string_long')
      ->setLabel(t('Signatures'))
      ->setDescription(t('JSON array of collected signatures.'))
      ->setDefaultValue('[]')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'basic_string',
        'weight' => 8,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['description'] = BaseFieldDefinition::create('string_long')
      ->setLabel(t('Description'))
      ->setDescription(t('Human-readable description of the transaction purpose.'))
      ->setDefaultValue('')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'basic_string',
        'weight' => 9,
      ])
      ->setDisplayOptions('form', [
        'type' => 'string_textarea',
        'weight' => 9,
        'settings' => [
          'rows' => 3,
        ],
      ])
      ->setDisplayConfigurable('form', TRUE)
      ->setDisplayConfigurable('view', TRUE);

    return $fields;
  }

  /**
   * Gets the associated Safe account.
   *
   * @return \Drupal\safe_smart_accounts\Entity\SafeAccount|null
   *   The Safe account entity or null if not set.
   */
  public function getSafeAccount(): ?SafeAccount {
    return $this->get('safe_account')->entity;
  }

  /**
   * Sets the associated Safe account.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   *
   * @return $this
   */
  public function setSafeAccount(SafeAccount $safe_account): static {
    $this->set('safe_account', $safe_account->id());
    return $this;
  }

  /**
   * Gets the transaction creator.
   *
   * @return \Drupal\user\UserInterface|null
   *   The user entity or null if not set.
   */
  public function getCreatedBy(): ?UserInterface {
    return $this->get('created_by')->entity;
  }

  /**
   * Sets the transaction creator.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   *
   * @return $this
   */
  public function setCreatedBy(UserInterface $user): static {
    $this->set('created_by', $user->id());
    return $this;
  }

  /**
   * Gets the to address.
   *
   * @return string
   *   The recipient address.
   */
  public function getToAddress(): string {
    return $this->get('to_address')->value;
  }

  /**
   * Gets the transaction value in wei.
   *
   * @return string
   *   The value in wei.
   */
  public function getValue(): string {
    return (string) $this->get('value')->value;
  }

  /**
   * Gets the transaction data.
   *
   * @return string
   *   The transaction data.
   */
  public function getData(): string {
    return $this->get('data')->value ?? '0x';
  }

  /**
   * Gets the operation type.
   *
   * @return int
   *   The operation type (0 for Call, 1 for DelegateCall).
   */
  public function getOperation(): int {
    return (int) $this->get('operation')->value;
  }

  /**
   * Gets the current status.
   *
   * @return string
   *   The status.
   */
  public function getStatus(): string {
    return $this->get('status')->value;
  }

  /**
   * Sets the status.
   *
   * @param string $status
   *   The status.
   *
   * @return $this
   */
  public function setStatus(string $status): static {
    $this->set('status', $status);
    return $this;
  }

  /**
   * Gets the signatures.
   *
   * @return array
   *   Array of signatures.
   */
  public function getSignatures(): array {
    $signatures = $this->get('signatures')->value;
    return $signatures ? json_decode($signatures, TRUE) : [];
  }

  /**
   * Sets the signatures.
   *
   * @param array $signatures
   *   Array of signatures.
   *
   * @return $this
   */
  public function setSignatures(array $signatures): static {
    $this->set('signatures', json_encode($signatures));
    return $this;
  }

  /**
   * Adds a signature.
   *
   * @param string $signature
   *   The signature to add.
   *
   * @return $this
   */
  public function addSignature(string $signature): static {
    $signatures = $this->getSignatures();
    $signatures[] = $signature;
    return $this->setSignatures($signatures);
  }

  /**
   * Checks if the transaction can be executed.
   *
   * A transaction can be executed if:
   * 1. It has enough signatures (meets threshold).
   * 2. Its nonce matches the Safe's current on-chain nonce (proper ordering).
   * 3. It's not already executed or cancelled.
   *
   * @return bool
   *   TRUE if the transaction can be executed.
   */
  public function canExecute(): bool {
    $safe_account = $this->getSafeAccount();
    if (!$safe_account) {
      return FALSE;
    }

    // Check if transaction is already executed or cancelled.
    $status = $this->getStatus();
    if (in_array($status, ['executed', 'cancelled'], TRUE)) {
      return FALSE;
    }

    // Check if we have enough signatures.
    $required_signatures = $safe_account->getThreshold();
    $collected_signatures = count($this->getSignatures());
    if ($collected_signatures < $required_signatures) {
      return FALSE;
    }

    // Check nonce ordering - this transaction must be next in line.
    return $this->isNextExecutable();
  }

  /**
   * Checks if this transaction is the next one that can be executed.
   *
   * This means its nonce matches the expected next nonce for the Safe.
   * Safe transactions must be executed in sequential nonce order (0, 1, 2...).
   *
   * @return bool
   *   TRUE if this transaction's nonce is next in the execution order.
   */
  public function isNextExecutable(): bool {
    $safe_account = $this->getSafeAccount();
    if (!$safe_account) {
      return FALSE;
    }

    // Already executed or cancelled transactions are not "next".
    $status = $this->getStatus();
    if (in_array($status, ['executed', 'cancelled'], TRUE)) {
      return FALSE;
    }

    $transaction_nonce = $this->get('nonce')->value;

    // If nonce is NULL, this transaction cannot be executed.
    if ($transaction_nonce === NULL || $transaction_nonce === '') {
      return FALSE;
    }

    $transaction_nonce = (int) $transaction_nonce;

    // Find the highest executed nonce for this Safe.
    // We need to load all executed transactions and find the highest nonce
    // manually because ->condition('nonce', '', '<>') doesn't work properly
    // for integer fields with value 0.
    $transaction_storage = \Drupal::entityTypeManager()->getStorage('safe_transaction');
    $query = $transaction_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('safe_account', $safe_account->id())
      ->condition('status', 'executed');

    $result = $query->execute();

    if (empty($result)) {
      // No executed transactions yet - next executable is nonce 0.
      return $transaction_nonce === 0;
    }

    // Load all executed transactions and find the highest nonce.
    $executed_transactions = $transaction_storage->loadMultiple($result);
    $highest_executed_nonce = NULL;

    foreach ($executed_transactions as $executed_tx) {
      $executed_nonce = $executed_tx->get('nonce')->value;
      if ($executed_nonce !== NULL && $executed_nonce !== '') {
        $executed_nonce_int = (int) $executed_nonce;
        if ($highest_executed_nonce === NULL || $executed_nonce_int > $highest_executed_nonce) {
          $highest_executed_nonce = $executed_nonce_int;
        }
      }
    }

    // If no executed transactions have nonces, next is 0.
    if ($highest_executed_nonce === NULL) {
      return $transaction_nonce === 0;
    }

    // This transaction is next if its nonce is exactly highest_executed + 1.
    return $transaction_nonce === ($highest_executed_nonce + 1);
  }

  /**
   * Checks if the transaction is in draft state.
   *
   * @return bool
   *   TRUE if the transaction is in draft state.
   */
  public function isDraft(): bool {
    return $this->getStatus() === 'draft';
  }

  /**
   * Checks if the transaction is executed.
   *
   * @return bool
   *   TRUE if the transaction is executed.
   */
  public function isExecuted(): bool {
    return $this->getStatus() === 'executed';
  }

  /**
   * Marks the transaction as executed.
   *
   * @param string $blockchain_tx_hash
   *   The blockchain transaction hash.
   *
   * @return $this
   */
  public function markExecuted(string $blockchain_tx_hash): static {
    $this->set('blockchain_tx_hash', $blockchain_tx_hash);
    $this->set('executed_at', \Drupal::time()->getRequestTime());
    $this->setStatus('executed');
    return $this;
  }

}
