<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Configuration form for Safe Smart Accounts module.
 */
class SafeSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['safe_smart_accounts.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'safe_smart_accounts_settings';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('safe_smart_accounts.settings');

    $form['#tree'] = TRUE;

    $form['description'] = [
      '#markup' => '<p>' . $this->t('Configure Safe Smart Accounts module settings. These settings control how the module interacts with Safe API services and blockchain networks.') . '</p>',
    ];

    // Network configuration (collapsible, open by default since most commonly accessed)
    $form['network'] = [
      '#type' => 'details',
      '#title' => $this->t('Network Configuration'),
      '#open' => TRUE,
      '#tree' => TRUE,
    ];

    $form['network']['sepolia'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Sepolia Testnet'),
      '#tree' => TRUE,
    ];

    $form['network']['sepolia']['name'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Network Name'),
      '#default_value' => $config->get('network.sepolia.name') ?: 'Sepolia Testnet',
      '#required' => TRUE,
    ];

    $form['network']['sepolia']['chain_id'] = [
      '#type' => 'number',
      '#title' => $this->t('Chain ID'),
      '#default_value' => $config->get('network.sepolia.chain_id') ?: 11155111,
      '#required' => TRUE,
    ];

    $form['network']['sepolia']['rpc_url'] = [
      '#type' => 'url',
      '#title' => $this->t('RPC URL'),
      '#default_value' => $config->get('network.sepolia.rpc_url') ?: 'https://rpc.sepolia.org',
      '#description' => $this->t('Ethereum JSON-RPC endpoint for blockchain interactions.'),
      '#required' => TRUE,
    ];

    $form['network']['sepolia']['safe_service_url'] = [
      '#type' => 'url',
      '#title' => $this->t('Safe Service URL'),
      '#default_value' => $config->get('network.sepolia.safe_service_url') ?: 'https://safe-transaction-sepolia.safe.global',
      '#description' => $this->t('Safe Transaction Service API endpoint.'),
      '#required' => TRUE,
    ];

    $form['network']['sepolia']['enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enabled'),
      '#default_value' => $config->get('network.sepolia.enabled') ?? TRUE,
    ];

    // Hardhat network configuration.
    $form['network']['hardhat'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Hardhat Local Network'),
      '#tree' => TRUE,
    ];

    $form['network']['hardhat']['name'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Network Name'),
      '#default_value' => $config->get('network.hardhat.name') ?: 'Hardhat Local',
      '#required' => TRUE,
    ];

    $form['network']['hardhat']['chain_id'] = [
      '#type' => 'number',
      '#title' => $this->t('Chain ID'),
      '#default_value' => $config->get('network.hardhat.chain_id') ?: 31337,
      '#required' => TRUE,
    ];

    $form['network']['hardhat']['rpc_url'] = [
      '#type' => 'url',
      '#title' => $this->t('RPC URL'),
      '#default_value' => $config->get('network.hardhat.rpc_url') ?: 'http://127.0.0.1:8545',
      '#description' => $this->t('Ethereum JSON-RPC endpoint for blockchain interactions.'),
      '#required' => TRUE,
    ];

    $form['network']['hardhat']['safe_service_url'] = [
      '#type' => 'url',
      '#title' => $this->t('Safe Service URL'),
      '#default_value' => $config->get('network.hardhat.safe_service_url') ?: 'http://127.0.0.1:8000',
      '#description' => $this->t('Safe Transaction Service API endpoint.'),
      '#required' => TRUE,
    ];

    $form['network']['hardhat']['enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enabled'),
      '#default_value' => $config->get('network.hardhat.enabled') ?? FALSE,
    ];

    // API configuration (collapsible, closed by default)
    $form['api'] = [
      '#type' => 'details',
      '#title' => $this->t('API Configuration'),
      '#open' => FALSE,
      '#tree' => TRUE,
    ];

    $form['api']['mock_mode'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable Mock Mode'),
      '#default_value' => $config->get('api.mock_mode') ?? TRUE,
      '#description' => $this->t('Use mock implementations for API calls. Disable for production use with real Safe API services.'),
    ];

    $form['api']['timeout'] = [
      '#type' => 'number',
      '#title' => $this->t('API Timeout (seconds)'),
      '#default_value' => $config->get('api.timeout') ?: 30,
      '#min' => 5,
      '#max' => 120,
      '#required' => TRUE,
    ];

    $form['api']['retry_attempts'] = [
      '#type' => 'number',
      '#title' => $this->t('Retry Attempts'),
      '#default_value' => $config->get('api.retry_attempts') ?: 3,
      '#min' => 0,
      '#max' => 10,
      '#required' => TRUE,
    ];

    $form['api']['cache_ttl'] = [
      '#type' => 'number',
      '#title' => $this->t('Cache TTL (seconds)'),
      '#default_value' => $config->get('api.cache_ttl') ?: 300,
      '#min' => 60,
      '#max' => 3600,
      '#description' => $this->t('How long to cache API responses.'),
      '#required' => TRUE,
    ];

    // Blockchain configuration (collapsible, closed by default)
    $form['blockchain'] = [
      '#type' => 'details',
      '#title' => $this->t('Blockchain Configuration'),
      '#open' => FALSE,
      '#tree' => TRUE,
    ];

    $form['blockchain']['mock_mode'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable Mock Mode'),
      '#default_value' => $config->get('blockchain.mock_mode') ?? TRUE,
      '#description' => $this->t('Use mock implementations for blockchain operations. Disable for production use with real blockchain interactions.'),
    ];

    $form['blockchain']['gas_price_strategy'] = [
      '#type' => 'select',
      '#title' => $this->t('Gas Price Strategy'),
      '#default_value' => $config->get('blockchain.gas_price_strategy') ?: 'medium',
      '#options' => [
        'slow' => $this->t('Slow (Low cost)'),
        'medium' => $this->t('Medium (Standard)'),
        'fast' => $this->t('Fast (Priority)'),
      ],
      '#description' => $this->t('Default gas price strategy for blockchain transactions.'),
    ];

    $form['blockchain']['confirmation_blocks'] = [
      '#type' => 'number',
      '#title' => $this->t('Required Confirmations'),
      '#default_value' => $config->get('blockchain.confirmation_blocks') ?: 12,
      '#min' => 1,
      '#max' => 50,
      '#description' => $this->t('Number of block confirmations required to consider a transaction final.'),
      '#required' => TRUE,
    ];

    // Monitoring configuration (collapsible, closed by default)
    $form['monitoring'] = [
      '#type' => 'details',
      '#title' => $this->t('Transaction Monitoring'),
      '#open' => FALSE,
      '#tree' => TRUE,
    ];

    $form['monitoring']['queue_interval'] = [
      '#type' => 'number',
      '#title' => $this->t('Queue Interval (seconds)'),
      '#default_value' => $config->get('monitoring.queue_interval') ?: 60,
      '#min' => 30,
      '#max' => 600,
      '#description' => $this->t('How often to check for transaction status updates.'),
      '#required' => TRUE,
    ];

    $form['monitoring']['batch_size'] = [
      '#type' => 'number',
      '#title' => $this->t('Batch Size'),
      '#default_value' => $config->get('monitoring.batch_size') ?: 50,
      '#min' => 10,
      '#max' => 200,
      '#description' => $this->t('Number of transactions to process in each monitoring batch.'),
      '#required' => TRUE,
    ];

    $form['monitoring']['max_retries'] = [
      '#type' => 'number',
      '#title' => $this->t('Max Retries'),
      '#default_value' => $config->get('monitoring.max_retries') ?: 5,
      '#min' => 1,
      '#max' => 20,
      '#description' => $this->t('Maximum number of times to retry failed monitoring operations.'),
      '#required' => TRUE,
    ];

    // UI configuration (collapsible, closed by default)
    $form['ui'] = [
      '#type' => 'details',
      '#title' => $this->t('User Interface'),
      '#open' => FALSE,
      '#tree' => TRUE,
    ];

    $form['ui']['show_toolbar_link'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Show Toolbar Link'),
      '#default_value' => $config->get('ui.show_toolbar_link') ?? TRUE,
      '#description' => $this->t('Show Safe Accounts link in the admin toolbar for SIWE authenticated users.'),
    ];

    $form['ui']['redirect_after_login'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Redirect After SIWE Login'),
      '#default_value' => $config->get('ui.redirect_after_login') ?? TRUE,
      '#description' => $this->t('Automatically redirect SIWE users to Safe account management after login.'),
    ];

    $form['ui']['transactions_per_page'] = [
      '#type' => 'number',
      '#title' => $this->t('Transactions Per Page'),
      '#default_value' => $config->get('ui.transactions_per_page') ?: 20,
      '#min' => 5,
      '#max' => 100,
      '#required' => TRUE,
    ];

    // Security configuration (collapsible, closed by default)
    $form['security'] = [
      '#type' => 'details',
      '#title' => $this->t('Security Settings'),
      '#open' => FALSE,
      '#tree' => TRUE,
    ];

    $form['security']['require_siwe_auth'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Require SIWE Authentication'),
      '#default_value' => $config->get('security.require_siwe_auth') ?? TRUE,
      '#description' => $this->t('Only allow SIWE authenticated users to access Safe Smart Account features.'),
    ];

    $form['security']['session_timeout'] = [
      '#type' => 'number',
      '#title' => $this->t('Session Timeout (hours)'),
      '#default_value' => $config->get('security.session_timeout') ?: 24,
      '#min' => 1,
      '#max' => 168,
      '#description' => $this->t('Maximum session duration for Safe operations.'),
      '#required' => TRUE,
    ];

    $form['security']['max_signers'] = [
      '#type' => 'number',
      '#title' => $this->t('Maximum Signers'),
      '#default_value' => $config->get('security.max_signers') ?: 20,
      '#min' => 1,
      '#max' => 50,
      '#description' => $this->t('Maximum number of signers allowed per Safe.'),
      '#required' => TRUE,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $values = $form_state->getValues();

    // Validate that confirmation blocks is reasonable.
    $confirmation_blocks = $values['blockchain']['confirmation_blocks'];
    if ($confirmation_blocks > 50) {
      $form_state->setErrorByName('blockchain][confirmation_blocks',
        $this->t('Confirmation blocks should not exceed 50 for reasonable transaction finality.'));
    }

    // Validate timeout is reasonable.
    $timeout = $values['api']['timeout'];
    if ($timeout < 5 || $timeout > 120) {
      $form_state->setErrorByName('api][timeout',
        $this->t('API timeout must be between 5 and 120 seconds.'));
    }

    // Validate URLs if not in mock mode.
    if (!$values['api']['mock_mode']) {
      $safe_service_url = $values['network']['sepolia']['safe_service_url'];
      if (empty($safe_service_url) || !filter_var($safe_service_url, FILTER_VALIDATE_URL)) {
        $form_state->setErrorByName('network][sepolia][safe_service_url',
          $this->t('Valid Safe Service URL is required when not in mock mode.'));
      }
    }

    if (!$values['blockchain']['mock_mode']) {
      $rpc_url = $values['network']['sepolia']['rpc_url'];
      if (empty($rpc_url) || !filter_var($rpc_url, FILTER_VALIDATE_URL)) {
        $form_state->setErrorByName('network][sepolia][rpc_url',
          $this->t('Valid RPC URL is required when not in mock mode.'));
      }
    }

    parent::validateForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $config = $this->config('safe_smart_accounts.settings');
    $values = $form_state->getValues();

    // Save all configuration values.
    $config->setData($values)->save();

    // Clear relevant caches.
    drupal_flush_all_caches();

    $this->messenger()->addStatus($this->t('Safe Smart Accounts configuration has been saved.'));

    parent::submitForm($form, $form_state);
  }

}
