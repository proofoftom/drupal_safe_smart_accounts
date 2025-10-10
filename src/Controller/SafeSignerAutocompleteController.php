<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\safe_smart_accounts\Service\UserSignerResolver;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller for Safe signer autocomplete.
 */
class SafeSignerAutocompleteController extends ControllerBase {

  /**
   * The user signer resolver service.
   *
   * @var \Drupal\safe_smart_accounts\Service\UserSignerResolver
   */
  protected UserSignerResolver $signerResolver;

  /**
   * Constructs a SafeSignerAutocompleteController object.
   *
   * @param \Drupal\safe_smart_accounts\Service\UserSignerResolver $signer_resolver
   *   The user signer resolver service.
   */
  public function __construct(UserSignerResolver $signer_resolver) {
    $this->signerResolver = $signer_resolver;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('safe_smart_accounts.user_signer_resolver')
    );
  }

  /**
   * Autocomplete callback for signer usernames.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with autocomplete suggestions.
   */
  public function autocomplete(Request $request): JsonResponse {
    $search = $request->query->get('q', '');

    if (strlen($search) < 2) {
      return new JsonResponse([]);
    }

    $matches = $this->signerResolver->searchUsers($search, 10);

    return new JsonResponse($matches);
  }

}
