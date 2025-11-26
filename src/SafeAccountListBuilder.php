<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts;

use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityListBuilder;

/**
 * Defines a class to build a listing of Safe Account entities.
 */
class SafeAccountListBuilder extends EntityListBuilder {

  /**
   * {@inheritdoc}
   */
  public function buildHeader() {
    $header['id'] = $this->t('ID');
    $header['safe_address'] = $this->t('Safe Address');
    $header['network'] = $this->t('Network');
    $header['status'] = $this->t('Status');
    $header['threshold'] = $this->t('Threshold');
    $header['owner'] = $this->t('Owner');
    $header['created'] = $this->t('Created');
    return $header + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity) {
    /** @var \Drupal\safe_smart_accounts\Entity\SafeAccountInterface $entity */
    $row['id'] = $entity->id();

    // Safe address with truncation for readability.
    $safe_address = $entity->getSafeAddress();
    $row['safe_address'] = $safe_address ? substr($safe_address, 0, 10) . '...' . substr($safe_address, -8) : $this->t('Not deployed');

    // Network.
    $row['network'] = $entity->getNetwork();

    // Status with color coding would be nice in the future.
    $row['status'] = $entity->getStatus();

    // Threshold.
    $row['threshold'] = $entity->getThreshold();

    // Owner.
    $owner = $entity->getUser();
    $row['owner'] = $owner ? $owner->getDisplayName() : $this->t('Unknown');

    // Created timestamp.
    $row['created'] = \Drupal::service('date.formatter')->format(
      $entity->get('created')->value,
      'short'
    );

    return $row + parent::buildRow($entity);
  }

}
