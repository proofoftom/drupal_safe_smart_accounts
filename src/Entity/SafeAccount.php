<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Entity;

use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\ContentEntityBase;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Field\BaseFieldDefinition;
use Drupal\user\UserInterface;

/**
 * Defines the Safe Smart Account entity.
 *
 * @ContentEntityType(
 *   id = "safe_account",
 *   label = @Translation("Safe Smart Account"),
 *   label_collection = @Translation("Safe Smart Accounts"),
 *   handlers = {
 *     "view_builder" = "Drupal\Core\Entity\EntityViewBuilder",
 *     "list_builder" = "Drupal\safe_smart_accounts\SafeAccountListBuilder",
 *     "access" = "Drupal\safe_smart_accounts\SafeAccountAccessControlHandler",
 *     "form" = {
 *       "default" = "Drupal\safe_smart_accounts\Form\SafeAccountForm",
 *       "add" = "Drupal\safe_smart_accounts\Form\SafeAccountCreateForm",
 *       "edit" = "Drupal\safe_smart_accounts\Form\SafeAccountManageForm",
 *       "delete" = "Drupal\Core\Entity\ContentEntityDeleteForm",
 *     },
 *   },
 *   base_table = "safe_account",
 *   admin_permission = "administer safe smart accounts",
 *   entity_keys = {
 *     "id" = "id",
 *     "uuid" = "uuid",
 *     "owner" = "user_id",
 *   },
 *   links = {
 *     "canonical" = "/user/{user}/safe-accounts/{safe_account}",
 *     "add-form" = "/user/{user}/safe-accounts/create",
 *     "edit-form" = "/user/{user}/safe-accounts/{safe_account}/edit",
 *     "delete-form" = "/user/{user}/safe-accounts/{safe_account}/delete",
 *     "collection" = "/admin/content/safe-accounts",
 *   },
 *   field_ui_base_route = "safe_smart_accounts.admin_settings",
 * )
 */
class SafeAccount extends ContentEntityBase implements SafeAccountInterface {

  /**
   * {@inheritdoc}
   */
  public static function baseFieldDefinitions(EntityTypeInterface $entity_type): array {
    $fields = parent::baseFieldDefinitions($entity_type);

    $fields['user_id'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('Associated User'))
      ->setDescription(t('The Drupal user who owns this Safe account.'))
      ->setSetting('target_type', 'user')
      ->setRequired(TRUE)
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'entity_reference_label',
        'weight' => -4,
      ])
      ->setDisplayConfigurable('form', FALSE)
      ->setDisplayConfigurable('view', TRUE);

    $fields['safe_address'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Safe Address'))
      ->setDescription(t('The Ethereum address of the deployed Safe Smart Account (0x...).'))
      ->setSettings([
        'max_length' => 42,
        'text_processing' => 0,
      ])
      ->setDefaultValue('')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'string',
        'weight' => -3,
      ])
      ->setDisplayOptions('form', [
        'type' => 'string_textfield',
        'weight' => -3,
      ])
      ->setDisplayConfigurable('form', TRUE)
      ->setDisplayConfigurable('view', TRUE);

    $fields['network'] = BaseFieldDefinition::create('list_string')
      ->setLabel(t('Network'))
      ->setDescription(t('The Ethereum network where this Safe is deployed.'))
      ->setSettings([
        'allowed_values' => [
          'sepolia' => 'Sepolia Testnet',
          'hardhat' => 'Hardhat Local',
        ],
      ])
      ->setRequired(TRUE)
      ->setDefaultValue('sepolia')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'string',
        'weight' => -2,
      ])
      ->setDisplayOptions('form', [
        'type' => 'options_select',
        'weight' => -2,
      ])
      ->setDisplayConfigurable('form', TRUE)
      ->setDisplayConfigurable('view', TRUE);

    $fields['threshold'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Signature Threshold'))
      ->setDescription(t('Number of signatures required to execute transactions.'))
      ->setDefaultValue(1)
      ->setRequired(TRUE)
      ->setSettings([
        'min' => 1,
        'max' => 50,
      ])
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'number_integer',
        'weight' => -1,
      ])
      ->setDisplayOptions('form', [
        'type' => 'number',
        'weight' => -1,
      ])
      ->setDisplayConfigurable('form', TRUE)
      ->setDisplayConfigurable('view', TRUE);

    $fields['status'] = BaseFieldDefinition::create('list_string')
      ->setLabel(t('Status'))
      ->setDescription(t('Current status of the Safe Smart Account.'))
      ->setSettings([
        'allowed_values' => [
          'pending' => 'Pending Creation',
          'deploying' => 'Being Deployed',
          'active' => 'Active',
          'error' => 'Error',
        ],
      ])
      ->setRequired(TRUE)
      ->setDefaultValue('pending')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'string',
        'weight' => 0,
      ])
      ->setDisplayOptions('form', [
        'type' => 'options_select',
        'weight' => 0,
      ])
      ->setDisplayConfigurable('form', TRUE)
      ->setDisplayConfigurable('view', TRUE);

    $fields['deployment_tx_hash'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Deployment Transaction Hash'))
      ->setDescription(t('Transaction hash of the Safe deployment on the blockchain.'))
      ->setSettings([
        'max_length' => 66,
        'text_processing' => 0,
      ])
      ->setDefaultValue('')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'string',
        'weight' => 1,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['created'] = BaseFieldDefinition::create('created')
      ->setLabel(t('Created'))
      ->setDescription(t('The time that the Safe account entity was created.'))
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'timestamp',
        'weight' => 2,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['deployed_at'] = BaseFieldDefinition::create('timestamp')
      ->setLabel(t('Deployed At'))
      ->setDescription(t('The time that the Safe was successfully deployed to the blockchain.'))
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'timestamp',
        'weight' => 3,
      ])
      ->setDisplayConfigurable('view', TRUE);

    $fields['metadata'] = BaseFieldDefinition::create('string_long')
      ->setLabel(t('Metadata'))
      ->setDescription(t('JSON metadata from Safe API services.'))
      ->setDefaultValue('')
      ->setDisplayOptions('view', [
        'label' => 'above',
        'type' => 'basic_string',
        'weight' => 4,
      ])
      ->setDisplayConfigurable('view', TRUE);

    return $fields;
  }

  /**
   * Gets the associated user.
   *
   * @return \Drupal\user\UserInterface|null
   *   The user entity or null if not set.
   */
  public function getUser(): ?UserInterface {
    return $this->get('user_id')->entity;
  }

  /**
   * Sets the associated user.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user entity.
   *
   * @return $this
   */
  public function setUser(UserInterface $user): static {
    $this->set('user_id', $user->id());
    return $this;
  }

  /**
   * Gets the Safe address.
   *
   * @return string
   *   The Safe Smart Account address.
   */
  public function getSafeAddress(): string {
    return $this->get('safe_address')->value ?? '';
  }

  /**
   * Sets the Safe address.
   *
   * @param string $address
   *   The Safe Smart Account address.
   *
   * @return $this
   */
  public function setSafeAddress(string $address): static {
    $this->set('safe_address', $address);
    return $this;
  }

  /**
   * Gets the network.
   *
   * @return string
   *   The network identifier.
   */
  public function getNetwork(): string {
    return $this->get('network')->value;
  }

  /**
   * Gets the signature threshold.
   *
   * @return int
   *   The signature threshold.
   */
  public function getThreshold(): int {
    return (int) $this->get('threshold')->value;
  }

  /**
   * Sets the signature threshold.
   *
   * @param int $threshold
   *   The signature threshold.
   *
   * @return $this
   */
  public function setThreshold(int $threshold): static {
    $this->set('threshold', $threshold);
    return $this;
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
   * Checks if the Safe is active.
   *
   * @return bool
   *   TRUE if the Safe is active.
   */
  public function isActive(): bool {
    return $this->getStatus() === 'active';
  }

  /**
   * Marks the Safe as deployed.
   *
   * @param string $tx_hash
   *   The deployment transaction hash.
   * @param string $safe_address
   *   The deployed Safe address.
   *
   * @return $this
   */
  public function markDeployed(string $tx_hash, string $safe_address): static {
    // Validate Ethereum address format.
    if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $safe_address)) {
      throw new \InvalidArgumentException('Invalid Safe address format: ' . $safe_address);
    }

    // Validate transaction hash format.
    if (!preg_match('/^0x[a-fA-F0-9]{64}$/', $tx_hash)) {
      throw new \InvalidArgumentException('Invalid transaction hash format: ' . $tx_hash);
    }

    $this->set('deployment_tx_hash', $tx_hash);
    $this->set('safe_address', $safe_address);
    $this->set('deployed_at', \Drupal::time()->getRequestTime());
    $this->setStatus('active');
    return $this;
  }

  /**
   * {@inheritdoc}
   */
  public function postSave(EntityStorageInterface $storage, $update = TRUE): void {
    parent::postSave($storage, $update);

    // Invalidate cache tags when Safe account is updated.
    $cache_tags = [
      'safe_account:' . $this->id(),
      'safe_account_list:' . $this->getUser()->id(),
    ];

    // Add additional cache tags for status-specific caches.
    $cache_tags[] = 'safe_account_status:' . $this->getStatus();
    $cache_tags[] = 'safe_account_status:all';

    // Also invalidate cache for all signers on this Safe.
    $config_storage = \Drupal::entityTypeManager()->getStorage('safe_configuration');
    $configs = $config_storage->loadByProperties(['safe_account_id' => $this->id()]);
    foreach ($configs as $config) {
      foreach ($config->getSigners() as $signer_address) {
        // Find users with this Ethereum address.
        $user_storage = \Drupal::entityTypeManager()->getStorage('user');
        $users = $user_storage->loadByProperties([
          'field_ethereum_address' => strtolower($signer_address),
        ]);

        foreach ($users as $user) {
          $cache_tags[] = 'safe_account_list:' . $user->id();
        }
      }
    }

    \Drupal::service('cache_tags.invalidator')->invalidateTags($cache_tags);
  }

}
