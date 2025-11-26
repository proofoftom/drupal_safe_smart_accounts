# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Module Overview

Safe Smart Accounts is a Drupal 10.5+ custom module providing Safe Smart Account integration for SIWE-authenticated users. Enables users to deploy Safe accounts to Sepolia testnet, manage multi-signature configurations, create and execute transactions, all through Drupal's entity system with MetaMask integration.

## Essential Commands

### Module Management
```bash
ddev drush en safe_smart_accounts -y          # Enable module
ddev drush cache:rebuild                      # Clear caches (use after any entity/service changes)
ddev drush pm:uninstall safe_smart_accounts   # Uninstall module (removes entities)
```

### Development Workflow
```bash
ddev drush config:export -y                   # Export config after schema changes
ddev drush watchdog:show --type=safe_smart_accounts --count=20  # View module logs
ddev drush sql-query "SELECT * FROM safe_account WHERE user_id = X"  # Inspect entities
ddev drush cr                                 # Quick cache rebuild (alias)
```

### Debugging Database State
```bash
# Check Safe accounts for a user
ddev drush sql-query "SELECT id, safe_address, status, network FROM safe_account WHERE user_id = X"

# Check transactions for a Safe
ddev drush sql-query "SELECT id, nonce, to_address, value, status FROM safe_transaction WHERE safe_account = X ORDER BY nonce"

# Check configuration/signers
ddev drush sql-query "SELECT safe_account_id, signers, threshold FROM safe_configuration WHERE safe_account_id = X"

# Find duplicate nonces (indicates bug)
ddev drush sql-query "SELECT nonce, COUNT(*) as count FROM safe_transaction WHERE safe_account = X GROUP BY nonce HAVING count > 1"
```

## Architecture

### Three-Tier Entity Structure

**SafeAccount** - Core entity representing a deployed or pending Safe
- Status workflow: `pending` → `deploying` → `active` → `error`
- Fields: `safe_address`, `network`, `threshold`, `salt`, `deployment_tx_hash`
- One-to-many with SafeTransaction
- One-to-one with SafeConfiguration

**SafeTransaction** - Transaction proposals for a Safe account
- Status workflow: `draft` → `pending` → `executed` | `failed` | `cancelled`
- Fields: `nonce`, `to_address`, `value`, `data`, `signatures`, `tx_hash`
- Nonces must be sequential (0, 1, 2, ...) - enforced on-chain by Safe contract
- Stores collected signatures as JSON array

**SafeConfiguration** - Configuration state for a Safe
- Fields: `signers` (JSON array), `threshold`, `modules`, `fallback_handler`
- Automatically syncs after on-chain configuration changes
- Cache invalidation propagates to all signers when updated

### Service Layer

**SafeConfigurationService** (`safe_smart_accounts.configuration_service`)
- Manages Safe configuration entities and state synchronization
- `getSafesForSigner($address)` - Finds all Safes where address is a signer
- `detectConfigurationChange($tx_data)` - Parses transaction data for config changes
- `applyConfigurationChange($safe, $change)` - Updates database after on-chain execution
- Handles cache invalidation for all affected signers

**SafeTransactionService** (`safe_smart_accounts.transaction_service`)
- Creates and manages SafeTransaction entities
- Handles nonce management (queries next available nonce from Safe contract)
- Validates transaction data and signatures
- Post-execution synchronization with on-chain state

**SafeBlockchainService** (`safe_smart_accounts.blockchain_service`)
- Direct blockchain interactions (read-only via Alchemy/Infura RPC)
- Gets Safe contract state (owners, threshold, nonce)
- Validates on-chain configuration
- No transaction submission (handled client-side via MetaMask)

**UserSignerResolver** (`safe_smart_accounts.user_signer_resolver`)
- Resolves Drupal users to Ethereum addresses
- Requires `field_ethereum_address` from SIWE login module
- Used for access control and signer lookups

### JavaScript Architecture

**safe-deployment.js** - Safe deployment via MetaMask
- Uses CREATE2 for deterministic address calculation
- Deploys via SafeProxyFactory contract
- Communicates with `SafeDeploymentController` for config retrieval
- Updates Drupal entity status after deployment

**transaction-manager.js** - Transaction signing and execution
- Implements Safe's eth_sign signature flow (v = 31/32)
- Handles multi-signature collection
- Executes transactions when threshold met
- Updates SafeTransaction entities post-execution

**safe-configuration-manager.js** - Owner and threshold management
- Creates configuration change transactions
- Encodes addOwnerWithThreshold, removeOwner, changeThreshold calls
- Calculates linked list prevOwner for owner operations
- Syncs database state after on-chain execution

All JavaScript uses ethers.js v6 and integrates with MetaMask via `window.ethereum`.

## Critical Patterns

### Entity Lifecycle and Cache Invalidation

**ALWAYS use entity API methods, NEVER direct SQL for updates:**

```php
// ✅ CORRECT - Triggers postSave() hook and cache invalidation
$storage = \Drupal::entityTypeManager()->getStorage('safe_account');
$safe = $storage->load($id);
$safe->setStatus('active');
$safe->setSafeAddress($address);
$safe->save();  // Invalidates cache tags

// ❌ WRONG - Bypasses cache system, causes stale UI
ddev drush sql-query "UPDATE safe_account SET status = 'active' WHERE id = X";
```

**Cache Tag Pattern:**
- Entity-level: `safe_account:ID`, `safe_transaction:ID`, `safe_configuration:ID`
- List-level: `safe_account_list:USER_ID` (invalidated when user's Safes change)
- When SafeConfiguration changes, all signers' list tags are invalidated

**Implementation in Entity::postSave():**
```php
public function postSave(EntityStorageInterface $storage, $update = TRUE) {
  parent::postSave($storage, $update);

  // Invalidate entity-specific cache
  Cache::invalidateTags([$this->entityTypeId . ':' . $this->id()]);

  // Invalidate user's Safe list
  Cache::invalidateTags(['safe_account_list:' . $this->getOwnerId()]);

  // If signers changed, invalidate their lists too
  if ($this->hasField('signers')) {
    $config = /* load SafeConfiguration */;
    foreach ($config->getSigners() as $signer_address) {
      $user = /* resolve to Drupal user */;
      Cache::invalidateTags(['safe_account_list:' . $user->id()]);
    }
  }
}
```

### Safe Transaction Signing (CRITICAL)

Safe requires a specific signature flow different from standard Ethereum signing:

**The Correct Flow:**

1. **Get transaction hash from Safe contract:**
```javascript
const safeTxHash = await safeContract.getTransactionHash(
  to, value, data, operation, safeTxGas, baseGas, gasPrice,
  gasToken, refundReceiver, nonce
);
```

2. **Sign with personal_sign (eth_sign flow):**
```javascript
const signature = await signer.signMessage(ethers.getBytes(safeTxHash));
```

3. **Adjust v value for Safe's eth_sign recovery:**
```javascript
let { r, s, v } = ethers.Signature.from(signature);
// Safe uses v = 31/32 to signal eth_sign recovery (adds "\x19Ethereum Signed Message:\n32")
if (v === 27) v = 31;  // 0x1b → 0x1f
if (v === 28) v = 32;  // 0x1c → 0x20
const adjustedSignature = ethers.concat([r, s, ethers.toBeHex(v, 1)]);
```

**Why this matters:**
- Safe's `checkNSignatures` checks if `v > 30` to determine signature type
- v = 31/32 triggers `hashMessage()` before `ecrecover` (adds Ethereum prefix)
- v = 27/28 would be treated as raw signature (fails validation)
- Using `signTypedData()` instead of `signMessage()` causes GS026 errors

**Common GS026 Error Causes:**
- Wrong v value in signature (must be 31 or 32 for eth_sign)
- Transaction nonce mismatch (Safe's on-chain nonce vs signed nonce)
- Signatures not sorted by signer address when executing
- Attempting to execute nonces out of order

### Safe Configuration Management

Safe uses **function selectors** for configuration changes:

```php
'0x0d582f13' => 'addOwnerWithThreshold(address,uint256)'
'0xf8dc5dd9' => 'removeOwner(address,address,uint256)'
'0xe318b52b' => 'swapOwner(address,address,address)'
'0x694e80c3' => 'changeThreshold(uint256)'
```

**Linked List Pattern for Owners:**
- Safe owners stored as linked list with SENTINEL (0x0000...0001)
- Adding/removing requires `prevOwner` in the list
- JavaScript calculates prevOwner by querying current owners and finding predecessor

**Post-Execution Sync Pattern:**
```php
// In SafeTransactionController::executeTransaction()
public function executeTransaction(SafeTransaction $transaction): JsonResponse {
  // ... transaction execution via MetaMask ...

  // Detect if this was a configuration change
  $config_change = $this->configurationService->detectConfigurationChange($tx_data);

  if ($config_change) {
    // Update database to match on-chain state
    $this->configurationService->applyConfigurationChange($safe_account, $config_change);
  }

  return new JsonResponse(['success' => true]);
}
```

### Multi-role Access Control

Users can access Safes in two roles:
- **Owner**: Created the Safe (SafeAccount.user_id)
- **Signer**: Added as signer in SafeConfiguration

**Access Check Pattern:**
```php
// SafeAccountAccessControlHandler::checkAccess()
$user_address = $account->get('field_ethereum_address')->value;

// Check if user is owner
if ($entity->getOwnerId() === $account->id()) {
  return AccessResult::allowed();
}

// Check if user is signer
$config = /* load SafeConfiguration for this Safe */;
if (in_array(strtolower($user_address), array_map('strtolower', $config->getSigners()))) {
  return AccessResult::allowed();
}

return AccessResult::forbidden();
```

**Safe List Query:**
```php
// Get Safes where user is owner OR signer
$owned_safe_ids = $storage->getQuery()
  ->condition('user_id', $user->id())
  ->execute();

$signer_safe_ids = $this->configurationService->getSafesForSigner($user_ethereum_address);

$all_safe_ids = array_unique(array_merge($owned_safe_ids, $signer_safe_ids));
```

### SIWE Integration Hooks

Safe Smart Accounts hooks into SIWE login for smart redirects:

**hook_siwe_login_response_alter()** - For AJAX/JSON authentication:
```php
function safe_smart_accounts_siwe_login_response_alter(array &$response_data, UserInterface $user) {
  $safe_count = /* count user's Safes */;

  if ($safe_count === 0) {
    $response_data['redirect'] = '/user/' . $user->id() . '/safe-accounts/create';
  } else {
    $response_data['redirect'] = '/user/' . $user->id() . '/safe-accounts';
  }
}
```

**hook_user_login()** - For form-based authentication:
```php
function safe_smart_accounts_user_login(UserInterface $user) {
  // Set destination for form submissions
  $response = new RedirectResponse(Url::fromRoute('safe_smart_accounts.user_safes', [
    'user' => $user->id(),
  ])->toString());
  $response->send();
}
```

## Network Configuration

**Sepolia Testnet (Primary):**
- Chain ID: 11155111
- Safe Singleton: Canonical Safe deployment
- Uses SafeProxyFactory for CREATE2 deployment
- RPC: Configurable in `safe_smart_accounts.settings.yml`

**Hardhat Local (Development):**
- Chain ID: 31337
- Requires local Hardhat node with Safe contracts
- Contract addresses in config/install/safe_smart_accounts.settings.yml

**Adding New Networks:**
1. Add network config to `safe_smart_accounts.settings.yml`
2. Update `SafeAccount::baseFieldDefinitions()` allowed_values for network field
3. Add network-specific contract addresses
4. Update JavaScript to handle new chain ID

## Development Workflow

### Making Entity Changes

1. **Modify entity class** (e.g., `src/Entity/SafeAccount.php`)
2. **Clear cache**: `ddev drush cr`
3. **Test with entity API**, not SQL:
```php
$safe = \Drupal::entityTypeManager()->getStorage('safe_account')->load($id);
$safe->setStatus('active');
$safe->save();
```
4. **Verify cache invalidation** by checking UI updates
5. **Export config if schema changed**: `ddev drush config:export -y`

### Testing Blockchain Integration

1. **Deploy a Safe** via UI at `/user/{uid}/safe-accounts/create`
2. **Monitor deployment** via browser console and Sepolia Etherscan
3. **Check database sync**:
```bash
ddev drush sql-query "SELECT id, safe_address, status FROM safe_account WHERE id = X"
```
4. **Create transaction** at `/safe-accounts/{id}/transactions/create`
5. **Sign and execute** via MetaMask (watch for GS026 errors)
6. **Verify post-execution sync** in database

### Debugging JavaScript

All JavaScript logs to browser console with prefixes:
- `[Safe Deployment]` - Deployment flow
- `[Transaction Manager]` - Transaction signing/execution
- `[Safe Config]` - Configuration changes

**Common issues:**
- **"Please switch to Sepolia"** - MetaMask on wrong network
- **GS026 error** - Signature v value incorrect (should be 31/32)
- **Nonce too high** - Attempting to execute non-sequential nonce
- **Transaction reverted** - Check Etherscan for specific revert reason

## Common Pitfalls

1. **Direct SQL updates** - Bypasses cache invalidation, causes stale UI
2. **Wrong signature v values** - Must be 31/32 for Safe's eth_sign flow
3. **Non-sequential nonces** - Safe requires executing nonces in order (0, 1, 2, ...)
4. **Missing cache rebuilds** - Always rebuild after entity/service/form changes
5. **Forgetting config export** - Schema changes won't persist without export
6. **No on-chain verification** - Always verify Safe state on Etherscan after operations
7. **Skipping post-execution sync** - Database must update after on-chain config changes
8. **Hardcoded addresses** - Use configuration service for network-specific addresses
9. **Ignoring access control** - Both route-level and entity-level checks required
10. **ProxyCreation event parsing** - `proxy` parameter is NOT indexed in Safe's event

## Service Dependencies

```
Controllers
    ↓
SafeTransactionService ──→ SafeBlockchainService
    ↓                           ↓
    ↓                      RPC Provider
    ↓
SafeConfigurationService
    ↓
Entity Type Manager → Entities (SafeAccount, SafeTransaction, SafeConfiguration)
```

**Dependency Injection Pattern:**
All services use constructor injection via `.services.yml`. Never use `\Drupal::service()` in classes - always inject via constructor.

## Quality Assurance

Manual validation checklists in `validation/`:
- `SafeAccount_CRUD_Checklist.md`
- `SafeTransaction_Workflow_Checklist.md`
- `SafeConfiguration_Management_Checklist.md`
- `SIWE_Integration_Checklist.md`
- `Form_UX_Checklist.md`

**Testing protocol:**
1. Test with real MetaMask on Sepolia testnet
2. Verify database state matches blockchain state
3. Check cache invalidation by viewing UI updates
4. Test access control with multiple user roles (owner, signer, non-member)
5. Validate error handling (network errors, insufficient gas, etc.)

## Required Dependencies

**Drupal:**
- `drupal:user` (core)
- `siwe_login:siwe_login` (custom module)

**PHP:**
- PHP 8.3+ with GMP extension (for address checksum validation)

**JavaScript:**
- ethers.js v6 (loaded via CDN)
- MetaMask or compatible Web3 wallet

## Documentation References

- `README.md` - User-facing features and installation
- `SERVICE_INTERFACES.md` - Service architecture and contracts
- `USERGUIDE.md` - End-user workflow documentation
