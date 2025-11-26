<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\safe_smart_accounts\Service\UserSignerResolver;

/**
 * Trait providing shared Safe account form fields and logic.
 *
 * This trait consolidates duplicated code from SafeAccountCreateForm and
 * TreasuryCreateForm, including:
 * - Network, threshold, signers, and salt nonce field builders
 * - AJAX callbacks for dynamic signer management
 * - Validation methods (hybrid pattern: isValid*() + validateField())
 * - Helper methods for parsing and resolving signer addresses
 *
 * Expected properties in consuming classes:
 * - $this->entityTypeManager (EntityTypeManagerInterface)
 *
 * Architecture:
 * - Base field builders accept $options array for customization
 * - Convenience wrapper methods provide context-specific defaults
 * - AJAX methods include protected hooks for form-specific behavior
 * - Validation provides both pure validators and Form API integrators
 */
trait SafeAccountFormTrait {

  /**
   * Builds the network selection field.
   *
   * @param array $options
   *   Optional overrides:
   *   - title: Field title (default: "Network")
   *   - description: Field description
   *   - default_value: Default selected network (default: "sepolia")
   *   - required: Whether field is required (default: TRUE)
   *   - disabled: Whether field is disabled (default: FALSE)
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildNetworkField(array $options = []): array {
    return [
      '#type' => 'select',
      '#title' => $options['title'] ?? $this->t('Network'),
      '#description' => $options['description'] ?? $this->t('Select the Ethereum network for your Safe Smart Account.'),
      '#options' => [
        'sepolia' => $this->t('Sepolia Testnet'),
        'hardhat' => $this->t('Hardhat Local'),
      ],
      '#default_value' => $options['default_value'] ?? 'sepolia',
      '#required' => $options['required'] ?? TRUE,
      '#disabled' => $options['disabled'] ?? FALSE,
    ];
  }

  /**
   * Builds network field with treasury-specific description.
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildTreasuryNetworkField(): array {
    return $this->buildNetworkField([
      'description' => $this->t('Select the Ethereum network for the treasury Safe.'),
    ]);
  }

  /**
   * Builds the signature threshold field.
   *
   * @param array $options
   *   Optional overrides:
   *   - title: Field title (default: "Signature Threshold")
   *   - description: Field description
   *   - default_value: Default threshold (default: 1)
   *   - min: Minimum threshold (default: 1)
   *   - max: Maximum threshold (default: 10)
   *   - required: Whether field is required (default: TRUE)
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildThresholdField(array $options = []): array {
    return [
      '#type' => 'number',
      '#title' => $options['title'] ?? $this->t('Signature Threshold'),
      '#description' => $options['description'] ?? $this->t('Number of signatures required to execute transactions. Must be between 1 and the number of signers.'),
      '#default_value' => $options['default_value'] ?? 1,
      '#min' => $options['min'] ?? 1,
      '#max' => $options['max'] ?? 10,
      '#required' => $options['required'] ?? TRUE,
    ];
  }

  /**
   * Builds the signers fieldset with dynamic AJAX add/remove.
   *
   * @param array $form
   *   The complete form array (needed for AJAX wrapper ID).
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state object.
   * @param array $options
   *   Optional overrides:
   *   - title: Fieldset title (default: "Signers")
   *   - description: Fieldset description
   *   - primary_signer: Ethereum address to show as primary signer
   *   - primary_signer_title: Label for primary signer field
   *   - show_primary_signer: Whether to show primary signer field (default: TRUE)
   *   - admin_signers: Array of pre-populated admin signer addresses
   *   - admin_signers_title: Label for admin signers display
   *   - show_admin_warning: Whether to show "no admins" warning (default: FALSE)
   *   - placeholder: Placeholder text for signer fields
   *   - autocomplete_route: Route name for autocomplete
   *
   * @return array
   *   Form API fieldset definition.
   */
  protected function buildSignersFieldset(array &$form, FormStateInterface $form_state, array $options = []): array {
    $fieldset = [
      '#type' => 'fieldset',
      '#title' => $options['title'] ?? $this->t('Signers'),
      '#description' => $options['description'] ?? $this->t('Your Ethereum address will be automatically included as the first signer.'),
    ];

    // Show primary signer field (for user Safe accounts)
    if ($options['show_primary_signer'] ?? TRUE) {
      $fieldset['primary_signer'] = [
        '#type' => 'textfield',
        '#title' => $options['primary_signer_title'] ?? $this->t('Primary Signer (Your Address)'),
        '#default_value' => $options['primary_signer'] ?? '',
        '#disabled' => TRUE,
        '#description' => $this->t('This is your Ethereum address from SIWE authentication.'),
      ];
    }

    // Show admin signers display (for Group treasuries)
    $admin_signers = $options['admin_signers'] ?? [];
    if (!empty($admin_signers)) {
      $fieldset['admin_signers'] = [
        '#type' => 'item',
        '#title' => $options['admin_signers_title'] ?? $this->t('Group Admin Signers'),
        '#markup' => '<ul><li>' . implode('</li><li>', $admin_signers) . '</li></ul>',
      ];
    }
    elseif ($options['show_admin_warning'] ?? FALSE) {
      $fieldset['warning'] = [
        '#markup' => '<div class="messages messages--warning">' .
          $this->t('No group admins have Ethereum addresses configured. You must add signers manually.') .
          '</div>',
      ];
    }

    // Get the number of additional signer fields from form state
    $num_signers = $form_state->get('num_signers');
    if ($num_signers === NULL) {
      // Default to 1 signer field, or 0 if admin signers exist
      $num_signers = empty($admin_signers) ? 1 : 0;
      $form_state->set('num_signers', $num_signers);
    }

    // Build additional signers container with AJAX wrapper
    if ($num_signers > 0) {
      $fieldset['additional_signers'] = [
        '#type' => 'container',
        '#title' => $this->t('Additional Signers'),
        '#prefix' => '<div id="signers-fieldset-wrapper">',
        '#suffix' => '</div>',
        '#tree' => TRUE,
      ];

      for ($i = 0; $i < $num_signers; $i++) {
        $fieldset['additional_signers'][$i] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['signer-field-row']],
        ];

        $fieldset['additional_signers'][$i]['address'] = [
          '#type' => 'textfield',
          '#title' => $this->t('Signer @num', ['@num' => $i + 1]),
          '#description' => $i === 0 ? $this->t('Enter a username or Ethereum address. Start typing a username to see suggestions.') : '',
          '#placeholder' => $options['placeholder'] ?? 'alice or 0x742d35Cc6634C0532925a3b8D8938d9e1Aac5C63',
          '#autocomplete_route_name' => $options['autocomplete_route'] ?? 'safe_smart_accounts.signer_autocomplete',
          '#size' => 60,
        ];

        $fieldset['additional_signers'][$i]['remove'] = [
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
    else {
      // Empty wrapper for AJAX to target
      $fieldset['additional_signers'] = [
        '#prefix' => '<div id="signers-fieldset-wrapper">',
        '#suffix' => '</div>',
      ];
    }

    // Add signer button
    $fieldset['add_signer'] = [
      '#type' => 'submit',
      '#value' => $this->t('Add another signer'),
      '#submit' => ['::addSignerField'],
      '#ajax' => [
        'callback' => '::updateSignerFieldsCallback',
        'wrapper' => 'signers-fieldset-wrapper',
      ],
      '#attributes' => ['class' => ['button--small']],
    ];

    return $fieldset;
  }

  /**
   * Builds the salt nonce field (advanced option).
   *
   * @param array $options
   *   Optional overrides:
   *   - title: Field title (default: "Salt Nonce")
   *   - description: Field description
   *   - placeholder: Placeholder text (default: "0")
   *
   * @return array
   *   Form API field definition.
   */
  protected function buildSaltNonceField(array $options = []): array {
    return [
      '#type' => 'textfield',
      '#title' => $options['title'] ?? $this->t('Salt Nonce'),
      '#description' => $options['description'] ?? $this->t('Optional salt nonce for deterministic Safe address generation. Leave empty for random generation.'),
      '#placeholder' => $options['placeholder'] ?? '0',
    ];
  }

  /**
   * AJAX callback to add a signer field.
   *
   * Called by Form API when "Add another signer" button is clicked.
   * Increments signer count and triggers form rebuild.
   *
   * Override onSignerAdd() to add custom behavior.
   */
  public function addSignerField(array &$form, FormStateInterface $form_state): void {
    $num_signers = $form_state->get('num_signers');
    $num_signers++;
    $form_state->set('num_signers', $num_signers);
    $form_state->setRebuild();

    // Protected hook for forms to add custom behavior
    $this->onSignerAdd($form, $form_state);
  }

  /**
   * AJAX callback to remove a signer field.
   *
   * Called by Form API when a "Remove" button is clicked.
   * Removes the signer at the specified delta and re-indexes array.
   *
   * Override onSignerRemove() to add custom behavior.
   */
  public function removeSignerField(array &$form, FormStateInterface $form_state): void {
    $trigger = $form_state->getTriggeringElement();
    $delta = $trigger['#signer_delta'];

    // Get current values
    $values = $form_state->getUserInput();
    $signers = $values['signers']['additional_signers'] ?? [];

    // Remove the signer at this delta
    unset($signers[$delta]);

    // Re-index the array
    $signers = array_values($signers);

    // Update form state
    $values['signers']['additional_signers'] = $signers;
    $form_state->setUserInput($values);

    // Decrease the count
    $num_signers = $form_state->get('num_signers');
    if ($num_signers > 1) {
      $num_signers--;
      $form_state->set('num_signers', $num_signers);
    }

    $form_state->setRebuild();

    // Protected hook for forms to add custom behavior
    $this->onSignerRemove($form, $form_state, $delta);
  }

  /**
   * AJAX callback to return updated signer fields.
   *
   * Returns the signer container for AJAX replacement.
   *
   * Override alterSignerAjaxResponse() to modify response.
   *
   * @return array
   *   The updated signer fieldset element.
   */
  public function updateSignerFieldsCallback(array &$form, FormStateInterface $form_state): array {
    $element = $form['signers']['additional_signers'];
    return $this->alterSignerAjaxResponse($element);
  }

  /**
   * Protected hook: Called after a signer field is added.
   *
   * Override in forms to add custom behavior (e.g., logging, analytics).
   *
   * @param array $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   */
  protected function onSignerAdd(array &$form, FormStateInterface $form_state): void {
    // Default: no-op. Forms can override for custom behavior.
  }

  /**
   * Protected hook: Called after a signer field is removed.
   *
   * Override in forms to add custom behavior.
   *
   * @param array $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param int $delta
   *   The delta of the removed signer field.
   */
  protected function onSignerRemove(array &$form, FormStateInterface $form_state, int $delta): void {
    // Default: no-op. Forms can override for custom behavior.
  }

  /**
   * Protected hook: Alter AJAX response before returning signer fields.
   *
   * Override in forms to modify the AJAX response element.
   *
   * @param array $element
   *   The signer fieldset element being returned.
   *
   * @return array
   *   The modified element.
   */
  protected function alterSignerAjaxResponse(array $element): array {
    // Default: return unmodified. Forms can override to customize.
    return $element;
  }

  /**
   * Parses signer addresses from form field values.
   *
   * Accepts usernames or Ethereum addresses and resolves them to addresses
   * using the UserSignerResolver service.
   *
   * @param array $signer_fields
   *   Array of signer field values from the form.
   * @param \Drupal\safe_smart_accounts\Service\UserSignerResolver $signer_resolver
   *   The user signer resolver service (passed as parameter - critical path).
   *
   * @return array
   *   Array of parsed Ethereum addresses.
   */
  protected function parseSignerAddresses(array $signer_fields, UserSignerResolver $signer_resolver): array {
    $addresses = [];

    foreach ($signer_fields as $field) {
      $input = trim($field['address'] ?? '');
      if (empty($input)) {
        continue;
      }

      // Try to resolve as username or address
      $resolved = $signer_resolver->resolveToAddress($input);
      if ($resolved) {
        $addresses[] = $resolved;
      }
      else {
        // Keep original if not resolvable (will fail validation)
        $addresses[] = $input;
      }
    }

    return array_unique($addresses);
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
   * Form integration helper: Validates Ethereum address and sets error.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $field_name
   *   The field name for error reporting (supports nested with '][').
   * @param string $address
   *   The address to validate.
   */
  protected function validateEthereumAddress(FormStateInterface $form_state, string $field_name, string $address): void {
    if (!$this->isValidEthereumAddress($address)) {
      $form_state->setErrorByName($field_name, $this->t('Invalid Ethereum address: @address', [
        '@address' => $address,
      ]));
    }
  }

  /**
   * Form integration helper: Validates threshold against signer count.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $field_name
   *   The field name for error reporting.
   * @param int $threshold
   *   The threshold value to validate.
   * @param int $total_signers
   *   The total number of signers.
   */
  protected function validateThreshold(FormStateInterface $form_state, string $field_name, int $threshold, int $total_signers): void {
    if ($threshold > $total_signers) {
      $form_state->setErrorByName($field_name, $this->t('Threshold (@threshold) cannot be greater than the number of signers (@signers).', [
        '@threshold' => $threshold,
        '@signers' => $total_signers,
      ]));
    }

    if ($threshold < 1) {
      $form_state->setErrorByName($field_name, $this->t('Threshold must be at least 1.'));
    }
  }

  /**
   * Form integration helper: Validates salt nonce value.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $field_name
   *   The field name for error reporting.
   * @param string $salt_nonce
   *   The salt nonce value to validate.
   */
  protected function validateSaltNonce(FormStateInterface $form_state, string $field_name, string $salt_nonce): void {
    if (!empty($salt_nonce) && (!is_numeric($salt_nonce) || (int) $salt_nonce < 0)) {
      $form_state->setErrorByName($field_name, $this->t('Salt nonce must be a non-negative integer.'));
    }
  }

}
