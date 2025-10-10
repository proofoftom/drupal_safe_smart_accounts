<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts;

use Drupal\Core\Config\Entity\ConfigEntityListBuilder;
use Drupal\Core\Entity\EntityInterface;

/**
 * Defines a class to build a listing of Safe Configuration entities.
 */
class SafeConfigurationListBuilder extends ConfigEntityListBuilder {

  /**
   * {@inheritdoc}
   */
  public function buildHeader() {
    $header['label'] = $this->t('Label');
    $header['id'] = $this->t('Machine name');
    $header['safe_account'] = $this->t('Safe Account');
    $header['signers'] = $this->t('Signers');
    $header['threshold'] = $this->t('Threshold');
    $header['version'] = $this->t('Version');
    $header['updated'] = $this->t('Last Updated');
    return $header + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity) {
    /** @var \Drupal\safe_smart_accounts\Entity\SafeConfigurationInterface $entity */
    $row['label'] = $entity->label();
    $row['id'] = $entity->id();

    // Safe account reference.
    $safe_account = $entity->getSafeAccount();
    if ($safe_account) {
      $safe_address = $safe_account->getSafeAddress();
      $row['safe_account'] = $safe_address ? substr($safe_address, 0, 10) . '...' . substr($safe_address, -8) : $this->t('ID: @id', ['@id' => $safe_account->id()]);
    }
    else {
      $row['safe_account'] = $this->t('None');
    }

    // Number of signers.
    $signers = $entity->getSigners();
    $row['signers'] = count($signers);

    // Threshold.
    $row['threshold'] = $entity->getThreshold();

    // Version.
    $row['version'] = $entity->getVersion();

    // Last updated timestamp.
    $updated = $entity->getUpdated();
    $row['updated'] = $updated ? \Drupal::service('date.formatter')->format($updated, 'short') : $this->t('Never');

    return $row + parent::buildRow($entity);
  }

}
