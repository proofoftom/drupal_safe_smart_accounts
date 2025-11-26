<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Form;

use Drupal\Core\Form\FormStateInterface;

/**
 * Trait providing shared Safe transaction form fields and logic.
 *
 * This trait consolidates duplicated code from SafeTransactionForm and
 * TreasuryTransactionProposeForm, including:
 * - Transaction field builders (to address, value, data, operation, gas limit)
 * - Validation methods (hybrid pattern: isValid*() + validateField())
 * - Conversion methods (ETH to Wei)
 *
 * No expected properties required (all methods are pure helpers or accept parameters).
 *
 * Architecture:
 * - Base field builders accept $options array for customization
 * - Convenience wrapper methods provide context-specific defaults
 * - Validation provides both pure validators and Form API integrators
 */
trait SafeTransactionFormTrait {

  /**
   * Builds the "to address" field.
   *
   * @param array $options
   *   Optional overrides:
   *   - title: Field title (default: "To Address")
   *   - description: Field description
   *   - placeholder: Placeholder text
   *   - required: Whether field is required (default: TRUE)
   *   - maxlength: Maximum length (default: 42)
   *   - size: Field size (default: NULL)
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildToAddressField(array $options = []): array {
    $field = [
      '#type' => 'textfield',
      '#title' => $options['title'] ?? $this->t('To Address'),
      '#description' => $options['description'] ?? $this->t('The Ethereum address (0x...) that will receive this transaction. This can be a wallet address or a smart contract.'),
      '#placeholder' => $options['placeholder'] ?? '0x742d35Cc6634C0532925a3b8D8938d9e1Aac5C63',
      '#required' => $options['required'] ?? TRUE,
      '#maxlength' => $options['maxlength'] ?? 42,
    ];

    if (isset($options['size'])) {
      $field['#size'] = $options['size'];
    }

    return $field;
  }

  /**
   * Builds "to address" field with treasury-specific wording.
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildTreasuryToAddressField(): array {
    return $this->buildToAddressField([
      'title' => $this->t('Recipient Address'),
      'description' => $this->t('Ethereum address to send funds to (0x...)'),
      'size' => 60,
    ]);
  }

  /**
   * Builds the value (ETH amount) field.
   *
   * @param array $options
   *   Optional overrides:
   *   - title: Field title (default: "Value (ETH)")
   *   - description: Field description
   *   - placeholder: Placeholder text
   *   - default_value: Default value (default: "0")
   *   - required: Whether field is required (default: TRUE)
   *   - size: Field size (default: 30)
   *   - maxlength: Maximum length (default: 30)
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildValueField(array $options = []): array {
    return [
      '#type' => 'textfield',
      '#title' => $options['title'] ?? $this->t('Value (ETH)'),
      '#description' => $options['description'] ?? $this->t('Amount of ETH to send (e.g., 0.1 for 0.1 ETH). Supports up to 18 decimal places.'),
      '#default_value' => $options['default_value'] ?? '0',
      '#required' => $options['required'] ?? TRUE,
      '#size' => $options['size'] ?? 30,
      '#maxlength' => $options['maxlength'] ?? 30,
      '#placeholder' => $options['placeholder'] ?? '0.1',
    ];
  }

  /**
   * Builds value field with treasury-specific wording.
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildTreasuryValueField(): array {
    return $this->buildValueField([
      'title' => $this->t('Amount (ETH)'),
      'description' => $this->t('Amount of ETH to send (e.g., 0.1)'),
      'placeholder' => '0.0',
    ]);
  }

  /**
   * Builds the transaction data field.
   *
   * @param array $options
   *   Optional overrides:
   *   - title: Field title (default: "Transaction Data")
   *   - description: Field description
   *   - placeholder: Placeholder text
   *   - default_value: Default value (default: "0x")
   *   - rows: Number of textarea rows (default: 4)
   *   - required: Whether field is required (default: FALSE)
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildDataField(array $options = []): array {
    return [
      '#type' => 'textarea',
      '#title' => $options['title'] ?? $this->t('Transaction Data'),
      '#description' => $options['description'] ?? $this->t('Hex-encoded data for smart contract interactions. Leave as "0x" for simple ETH transfers. For contract calls, this contains the encoded function signature and parameters.'),
      '#default_value' => $options['default_value'] ?? '0x',
      '#rows' => $options['rows'] ?? 4,
      '#placeholder' => $options['placeholder'] ?? '0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b8d8938d9e1aac5c630000000000000000000000000000000000000000000000000de0b6b3a7640000',
      '#required' => $options['required'] ?? FALSE,
    ];
  }

  /**
   * Builds data field with treasury-specific wording.
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildTreasuryDataField(): array {
    return $this->buildDataField([
      'title' => $this->t('Data (optional)'),
      'description' => $this->t('Hex-encoded data for contract interaction. Leave empty for simple ETH transfers.'),
      'rows' => 3,
    ]);
  }

  /**
   * Builds the operation type field as select dropdown.
   *
   * @param array $options
   *   Optional overrides:
   *   - title: Field title (default: "Operation Type")
   *   - description: Field description
   *   - default_value: Default operation (default: 0)
   *   - required: Whether field is required (default: TRUE)
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildOperationField(array $options = []): array {
    return [
      '#type' => 'select',
      '#title' => $options['title'] ?? $this->t('Operation Type'),
      '#description' => $options['description'] ?? $this->t('<strong>Call</strong> (recommended): Execute a transaction as the Safe. Use for transfers and most contract interactions.<br><strong>DelegateCall</strong> (advanced): Execute code in the Safe\'s context. Only use if you understand the security implications.'),
      '#options' => [
        0 => $this->t('Call - Standard transaction'),
        1 => $this->t('DelegateCall - Advanced (use with extreme caution)'),
      ],
      '#default_value' => $options['default_value'] ?? 0,
      '#required' => $options['required'] ?? TRUE,
    ];
  }

  /**
   * Builds operation field as radio buttons (treasury variant).
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildOperationRadiosField(): array {
    return [
      '#type' => 'radios',
      '#title' => $this->t('Operation Type'),
      '#options' => [
        '0' => $this->t('Call (recommended) - Standard transaction for transfers and contract interactions'),
        '1' => $this->t('DelegateCall (advanced) - Execute code in the Safe\'s context. Use with extreme caution.'),
      ],
      '#default_value' => '0',
      '#description' => $this->t('Most transactions should use <strong>Call</strong>. DelegateCall is only needed for advanced use cases and carries significant security risks.'),
    ];
  }

  /**
   * Builds the gas limit field.
   *
   * @param array $options
   *   Optional overrides:
   *   - title: Field title (default: "Gas Limit")
   *   - description: Field description
   *   - placeholder: Placeholder text
   *   - min: Minimum gas (default: 21000)
   *   - max: Maximum gas (default: 10000000)
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildGasLimitField(array $options = []): array {
    return [
      '#type' => 'number',
      '#title' => $options['title'] ?? $this->t('Gas Limit'),
      '#description' => $options['description'] ?? $this->t('Maximum gas to use for this transaction. Leave empty for automatic estimation.'),
      '#min' => $options['min'] ?? 21000,
      '#max' => $options['max'] ?? 10000000,
      '#placeholder' => $options['placeholder'] ?? '21000',
    ];
  }

  /**
   * Converts ETH amount to Wei.
   *
   * @param string $eth
   *   The ETH amount as a string.
   *
   * @return string
   *   The wei amount as string (preserves precision).
   */
  protected function ethToWei(string $eth): string {
    // Convert ETH to wei (multiply by 10^18)
    // Using bcmul with string input preserves precision
    $wei = bcmul($eth, '1000000000000000000', 0);
    return $wei;
  }

  /**
   * Pure validator: Checks if a string is a valid Ethereum address.
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
   * Pure validator: Checks if a string is valid hex data.
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
   * Pure validator: Checks if a string is a valid ETH value.
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
   * Form integration helper: Validates to address and sets error.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $field_name
   *   The field name for error reporting (supports nested with '][').
   * @param string $address
   *   The address to validate.
   */
  protected function validateToAddress(FormStateInterface $form_state, string $field_name, string $address): void {
    if (!$this->isValidEthereumAddress($address)) {
      $form_state->setErrorByName($field_name, $this->t('Invalid Ethereum address format.'));
    }
  }

  /**
   * Form integration helper: Validates ETH value and sets error.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $field_name
   *   The field name for error reporting.
   * @param string $value
   *   The value to validate.
   */
  protected function validateValue(FormStateInterface $form_state, string $field_name, string $value): void {
    if (!$this->isValidEthValue($value)) {
      $form_state->setErrorByName($field_name, $this->t('Value must be a valid non-negative number with up to 18 decimal places.'));
    }
  }

  /**
   * Form integration helper: Validates transaction data and sets error.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $field_name
   *   The field name for error reporting.
   * @param string $data
   *   The data to validate.
   */
  protected function validateData(FormStateInterface $form_state, string $field_name, string $data): void {
    if (!empty($data) && $data !== '0x' && !$this->isValidHexData($data)) {
      $form_state->setErrorByName($field_name, $this->t('Transaction data must be valid hex format (starting with 0x).'));
    }
  }

  /**
   * Form integration helper: Validates gas limit and sets error.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $field_name
   *   The field name for error reporting.
   * @param mixed $gas_limit
   *   The gas limit to validate.
   */
  protected function validateGasLimit(FormStateInterface $form_state, string $field_name, $gas_limit): void {
    if (!empty($gas_limit)) {
      if (!is_numeric($gas_limit) || (int) $gas_limit < 21000) {
        $form_state->setErrorByName($field_name, $this->t('Gas limit must be at least 21,000.'));
      }
    }
  }

}
