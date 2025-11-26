<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts;

use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityListBuilder;

/**
 * Defines a class to build a listing of Safe Transaction entities.
 */
class SafeTransactionListBuilder extends EntityListBuilder {

  /**
   * {@inheritdoc}
   */
  public function buildHeader() {
    $header['id'] = $this->t('ID');
    $header['safe_account'] = $this->t('Safe Account');
    $header['status'] = $this->t('Status');
    $header['to_address'] = $this->t('To');
    $header['value'] = $this->t('Value (wei)');
    $header['nonce'] = $this->t('Nonce');
    $header['signatures'] = $this->t('Signatures');
    $header['created_by'] = $this->t('Created By');
    $header['created'] = $this->t('Created');
    return $header + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity) {
    /** @var \Drupal\safe_smart_accounts\Entity\SafeTransactionInterface $entity */
    $row['id'] = $entity->id();

    // Safe account.
    $safe_account = $entity->getSafeAccount();
    if ($safe_account) {
      $safe_address = $safe_account->getSafeAddress();
      $row['safe_account'] = $safe_address ? substr($safe_address, 0, 10) . '...' : $this->t('ID: @id', ['@id' => $safe_account->id()]);
    }
    else {
      $row['safe_account'] = $this->t('None');
    }

    // Status.
    $row['status'] = $entity->getStatus();

    // To address with truncation.
    $to_address = $entity->getToAddress();
    $row['to_address'] = substr($to_address, 0, 10) . '...' . substr($to_address, -8);

    // Value.
    $value = $entity->getValue();
    $row['value'] = $value !== '0' ? $value : '0';

    // Nonce.
    $nonce = $entity->get('nonce')->value;
    $row['nonce'] = $nonce !== NULL ? $nonce : $this->t('N/A');

    // Signatures count.
    $signatures = $entity->getSignatures();
    $threshold = $safe_account ? $safe_account->getThreshold() : '?';
    $row['signatures'] = count($signatures) . ' / ' . $threshold;

    // Created by.
    $creator = $entity->getCreatedBy();
    $row['created_by'] = $creator ? $creator->getDisplayName() : $this->t('Unknown');

    // Created timestamp.
    $row['created'] = \Drupal::service('date.formatter')->format(
      $entity->get('created')->value,
      'short'
    );

    return $row + parent::buildRow($entity);
  }

}
