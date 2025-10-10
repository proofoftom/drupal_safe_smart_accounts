<?php

declare(strict_types=1);

namespace Drupal\safe_smart_accounts\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\safe_smart_accounts\Entity\SafeAccount;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Controller for Safe deployment API endpoints.
 */
class SafeDeploymentController extends ControllerBase {

  /**
   * The private temp store factory.
   *
   * @var \Drupal\Core\TempStore\PrivateTempStoreFactory
   */
  protected PrivateTempStoreFactory $tempStoreFactory;

  /**
   * The logger service.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected LoggerInterface $logger;

  /**
   * The route match service.
   *
   * @var \Drupal\Core\Routing\RouteMatchInterface
   */
  protected RouteMatchInterface $routeMatch;

  /**
   * Constructs a SafeDeploymentController object.
   *
   * @param \Drupal\Core\TempStore\PrivateTempStoreFactory $temp_store_factory
   *   The private temp store factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The logger service.
   * @param \Drupal\Core\Routing\RouteMatchInterface $route_match
   *   The route match service.
   */
  public function __construct(PrivateTempStoreFactory $temp_store_factory, LoggerInterface $logger, RouteMatchInterface $route_match) {
    $this->tempStoreFactory = $temp_store_factory;
    $this->logger = $logger;
    $this->routeMatch = $route_match;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('tempstore.private'),
      $container->get('logger.factory')->get('safe_smart_accounts'),
      $container->get('current_route_match')
    );
  }

  /**
   * Retrieves Safe configuration for deployment.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with Safe configuration data.
   */
  public function getConfiguration(SafeAccount $safe_account, Request $request): JsonResponse {
    // Check access for viewing the Safe account.
    $access = $this->checkSafeAccountAccess($safe_account, 'view');
    if (!$access->isAllowed()) {
      throw new AccessDeniedHttpException();
    }

    // Try to find the associated SafeConfiguration.
    $safe_config_storage = $this->entityTypeManager()->getStorage('safe_configuration');
    $configurations = $safe_config_storage->loadByProperties(['safe_account_id' => $safe_account->id()]);

    /** @var \Drupal\safe_smart_accounts\Entity\SafeConfiguration|null $safe_configuration */
    $safe_configuration = !empty($configurations) ? reset($configurations) : NULL;

    if (!$safe_configuration) {
      // If no configuration exists, return basic safe account configuration.
      $response_data = [
        'safe_account_id' => $safe_account->id(),
        'network' => $safe_account->getNetwork(),
        'threshold' => $safe_account->getThreshold(),
        'status' => $safe_account->getStatus(),
        'message' => 'No specific configuration found for this Safe account',
      ];
    }
    else {
      // Return the full configuration.
      $response_data = [
        'safe_account_id' => $safe_account->id(),
        'network' => $safe_account->getNetwork(),
        'signers' => $safe_configuration->getSigners(),
        'threshold' => $safe_configuration->getThreshold(),
        'modules' => $safe_configuration->getModules(),
        'fallback_handler' => $safe_configuration->getFallbackHandler(),
        'version' => $safe_configuration->getVersion(),
        'salt_nonce' => $safe_configuration->getSaltNonce(),
        'status' => $safe_account->getStatus(),
        'updated' => $safe_configuration->getUpdated(),
        'updated_by' => $safe_configuration->getUpdatedBy()?->getDisplayName() ?? 'Unknown',
      ];
    }

    return new JsonResponse($response_data);
  }

  /**
   * Updates Safe account entity with deployment results.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with update status.
   */
  public function updateDeployment(SafeAccount $safe_account, Request $request): JsonResponse {
    // Check access for managing the Safe account.
    $access = $this->checkSafeAccountAccess($safe_account, 'edit');
    if (!$access->isAllowed()) {
      throw new AccessDeniedHttpException();
    }

    // Check rate limiting.
    $rate_limit_result = $this->checkRateLimit($safe_account);
    if ($rate_limit_result !== TRUE) {
      return new JsonResponse([
        'error' => $rate_limit_result,
      ], 429);
    }

    // Get request data.
    $content = $request->getContent();
    if (empty($content)) {
      throw new BadRequestHttpException('Request body is empty');
    }

    $data = json_decode($content, TRUE);
    if (json_last_error() !== JSON_ERROR_NONE) {
      throw new BadRequestHttpException('Invalid JSON in request body');
    }

    // Validate required fields.
    $required_fields = ['deployment_tx_hash', 'safe_address'];
    foreach ($required_fields as $field) {
      if (!isset($data[$field])) {
        return new JsonResponse([
          'error' => "Missing required field: {$field}",
        ], 400);
      }
    }

    // Validate Ethereum addresses format.
    if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $data['safe_address'])) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Invalid Safe address format',
      ], 400);
    }

    if (!preg_match('/^0x[a-fA-F0-9]{64}$/', $data['deployment_tx_hash'])) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Invalid deployment transaction hash format',
      ], 400);
    }

    // Additional validation:
    // Check if safe address is already associated with another safe account.
    $existing_safe = $this->entityTypeManager()->getStorage('safe_account')->loadByProperties([
      'safe_address' => $data['safe_address'],
    ]);
    if (!empty($existing_safe)) {
      $existing_safe_id = reset($existing_safe)->id();
      if ($existing_safe_id != $safe_account->id()) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'This Safe address is already associated with another account',
        ], 400);
      }
    }

    // Additional validation: Check if the safe account is already deployed.
    if ($safe_account->getStatus() === 'active') {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Safe account is already deployed',
      ], 400);
    }

    // Additional validation: Check if safe account is already being deployed.
    if ($safe_account->getStatus() === 'deploying') {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Safe account is already being deployed',
      ], 400);
    }

    try {
      // Update the Safe account with deployment results.
      $safe_account->markDeployed($data['deployment_tx_hash'], $data['safe_address']);

      // If additional data is provided, save it to metadata.
      if (isset($data['metadata']) && is_array($data['metadata'])) {
        $safe_account->set('metadata', json_encode($data['metadata']));
      }

      // Save the entity.
      $safe_account->save();

      // Record successful deployment for rate limiting.
      $this->recordSuccessfulDeployment($safe_account);

      // Return success response.
      return new JsonResponse([
        'success' => TRUE,
        'message' => 'Safe account updated successfully',
        'safe_account_id' => $safe_account->id(),
        'safe_address' => $safe_account->getSafeAddress(),
        'status' => $safe_account->getStatus(),
        'deployment_tx_hash' => $safe_account->get('deployment_tx_hash')->value,
      ]);
    }
    catch (\Exception $e) {
      // Record failed deployment attempt for potential lockout.
      $this->recordFailedDeploymentAttempt($safe_account);

      $this->logger->error('Failed to update Safe deployment: @message', [
        '@message' => $e->getMessage(),
      ]);

      return new JsonResponse([
        'error' => 'Failed to update Safe account: ' . $e->getMessage(),
      ], 500);
    }
  }

  /**
   * Checks access for Safe account operations.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param string $operation
   *   The operation to check ('view', 'edit', 'delete').
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  protected function checkSafeAccountAccess(SafeAccount $safe_account, string $operation): AccessResultInterface {
    $current_user = $this->currentUser();

    // Check if the current user owns the Safe account.
    if ($safe_account->getUser()?->id() == $current_user->id()) {
      $permission = match($operation) {
        'view' => 'view own safe smart accounts',
        'edit' => 'manage own safe smart accounts',
        'delete' => 'delete own safe smart accounts',
        default => 'view own safe smart accounts',
      };

      if ($current_user->hasPermission($permission)) {
        return AccessResult::allowed()->addCacheableDependency($safe_account);
      }
    }

    // Check if the current user is an admin.
    if ($current_user->hasPermission('administer safe smart accounts')) {
      return AccessResult::allowed()->addCacheableDependency($safe_account);
    }

    return AccessResult::forbidden("User {$current_user->id()} does not have permission to {$operation} this Safe account.");
  }

  /**
   * Checks if the user has exceeded the rate limit for deployment operations.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   *
   * @return bool|string
   *   TRUE if rate limit is acceptable, error message if exceeded.
   */
  protected function checkRateLimit(SafeAccount $safe_account): bool|string {
    $current_user = $this->currentUser();
    $user_id = $current_user->id();
    $safe_id = $safe_account->id();

    // Get tempstore for rate limiting.
    $tempstore = $this->tempStoreFactory->get('safe_smart_accounts_rate_limit');

    // Generate key for this user and safe account.
    $key = "deploy_{$user_id}_{$safe_id}";

    // Get rate limit data.
    $rate_limit_data = $tempstore->get($key);

    // If no data exists, initialize it.
    if (!$rate_limit_data) {
      $rate_limit_data = [
        'attempts' => 0,
        'first_attempt' => time(),
        'lockout_until' => 0,
      ];
    }

    // Check if user is currently in lockout period.
    if ($rate_limit_data['lockout_until'] > time()) {
      $remaining_time = $rate_limit_data['lockout_until'] - time();
      return "Rate limit exceeded. Try again in {$remaining_time} seconds.";
    }

    // Check if we need to reset the window (1 hour)
    $hour_in_seconds = 3600;
    if (time() - $rate_limit_data['first_attempt'] > $hour_in_seconds) {
      // Reset the counter.
      $rate_limit_data = [
        'attempts' => 0,
        'first_attempt' => time(),
        'lockout_until' => 0,
      ];
    }

    // Increment attempts.
    $rate_limit_data['attempts']++;

    // Define rate limits.
    // Max 5 attempts per hour.
    $max_attempts_per_hour = 5;
    // 5 minutes lockout after too many attempts
    $lockout_duration = 300;
    // Lock out after 10 attempts in an hour.
    $max_attempts_before_lockout = 10;
    // Max 2 attempts per minute.
    $max_attempts_per_minute = 2;
    $minute_in_seconds = 60;

    // Check if attempts exceed minute limit.
    if ($rate_limit_data['attempts'] > $max_attempts_per_minute &&
      (time() - $rate_limit_data['first_attempt']) <= $minute_in_seconds) {
      return "Too many requests. Please wait before trying again.";
    }

    // Check if attempts exceed hour limit.
    if ($rate_limit_data['attempts'] > $max_attempts_per_hour) {
      // Check if we need to lock out the user.
      if ($rate_limit_data['attempts'] >= $max_attempts_before_lockout) {
        $rate_limit_data['lockout_until'] = time() + $lockout_duration;
        $tempstore->set($key, $rate_limit_data);
        return "Too many failed attempts. Account locked for {$lockout_duration} seconds.";
      }

      return "Rate limit exceeded. Maximum {$max_attempts_per_hour} attempts per hour.";
    }

    // Save updated rate limit data.
    $tempstore->set($key, $rate_limit_data);

    return TRUE;
  }

  /**
   * Records a successful deployment attempt for rate limiting purposes.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   */
  protected function recordSuccessfulDeployment(SafeAccount $safe_account): void {
    $current_user = $this->currentUser();
    $user_id = $current_user->id();
    $safe_id = $safe_account->id();

    // Get tempstore for rate limiting.
    $tempstore = $this->tempStoreFactory->get('safe_smart_accounts_rate_limit');

    // Generate key for this user and safe account.
    $key = "deploy_{$user_id}_{$safe_id}";

    // Reset the counter after successful deployment.
    $tempstore->set($key, [
      'attempts' => 0,
      'first_attempt' => time(),
      'lockout_until' => 0,
    ]);
  }

  /**
   * Records a failed deployment attempt for potential lockout.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   */
  protected function recordFailedDeploymentAttempt(SafeAccount $safe_account): void {
    $current_user = $this->currentUser();
    $user_id = $current_user->id();
    $safe_id = $safe_account->id();

    // Get tempstore for rate limiting.
    $tempstore = $this->tempStoreFactory->get('safe_smart_accounts_rate_limit');

    // Generate key for this user and safe account.
    $key = "deploy_{$user_id}_{$safe_id}";

    // Get rate limit data.
    $rate_limit_data = $tempstore->get($key);

    if ($rate_limit_data) {
      // Increment attempts.
      $rate_limit_data['attempts']++;
      $tempstore->set($key, $rate_limit_data);
    }
  }

  /**
   * Access callback for Safe deployment API endpoints.
   *
   * @param \Drupal\safe_smart_accounts\Entity\SafeAccount $safe_account
   *   The Safe account entity.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The user account to check access for.
   * @param string|null $operation
   *   The operation to check access for. If null, inferred from the route.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function safeDeploymentAccess(SafeAccount $safe_account, AccountInterface $account, ?string $operation = NULL): AccessResultInterface {
    // Determine operation from the route if not provided.
    if ($operation === NULL) {
      // Get the current route name to determine the operation.
      $route_name = $this->routeMatch->getRouteName();

      // Determine operation based on route name.
      if (strpos($route_name, 'update') !== FALSE) {
        // For update operations.
        $operation = 'edit';
      }
      elseif (strpos($route_name, 'configuration') !== FALSE) {
        // For view/get configuration operations.
        $operation = 'view';
      }
      else {
        // Default operation.
        $operation = 'view';
      }
    }

    // Check if the user owns the Safe account.
    if ($safe_account->getUser()?->id() == $account->id()) {
      $permission = match($operation) {
        'view' => 'view own safe smart accounts',
        'edit' => 'manage own safe smart accounts',
        'delete' => 'delete own safe smart accounts',
        default => 'view own safe smart accounts',
      };

      if ($account->hasPermission($permission)) {
        return AccessResult::allowed()->addCacheableDependency($safe_account);
      }
    }

    // Check if the user is an admin.
    if ($account->hasPermission('administer safe smart accounts')) {
      return AccessResult::allowed()->addCacheableDependency($safe_account);
    }

    return AccessResult::forbidden()->addCacheableDependency($safe_account);
  }

}
