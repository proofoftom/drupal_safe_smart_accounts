# Safe Smart Accounts Module

This module provides comprehensive Safe Smart Account integration for Drupal users authenticated via SIWE (Sign-In with Ethereum). It enables users to create, manage, and interact with Safe Smart Accounts directly from their Drupal interface.

## Features

### 🏦 **Safe Account Management**
- **Multi-network support**: Currently supports Sepolia testnet with architecture for expansion
- **Status-based workflows**: Pending → Deploying → Active → Error state management
- **User-friendly interface**: Professional dashboard with color-coded status indicators
- **Access control**: SIWE authentication integration with proper permissions

### 💸 **Transaction Management**
- **Transaction proposals**: Create and manage transaction proposals for Safe accounts
- **Multi-signature support**: Architecture ready for threshold-based approvals
- **Transaction history**: View detailed transaction information and status
- **Form validation**: Comprehensive ETH amount, address, and data validation

### 🔒 **Security & Authentication**
- **SIWE Integration**: Seamless integration with Sign-In with Ethereum authentication
- **Smart redirects**: Automatic redirect to Safe management after SIWE login
- **Access control**: Route and form-level security preventing unauthorized access
- **Cache optimization**: Automatic cache invalidation on entity status changes

## Installation

1. **Prerequisites**: Ensure SIWE Login module is installed and configured
2. **Enable module**: `ddev drush en safe_smart_accounts -y`
3. **Clear caches**: `ddev drush cache:rebuild`
4. **Configure settings**: Visit `/admin/config/safe-accounts/settings`

## SIWE Integration

The module automatically integrates with SIWE authentication flows:

- **Direct SIWE login**: Redirects to Safe account management via JSON response
- **Email verification flow**: Redirects after email verification completion  
- **Username creation flow**: Redirects after username creation completion
- **Smart detection**: Automatically handles AJAX vs form-based authentication

## User Workflows

### **New Users (No Safe Accounts)**
1. Complete SIWE authentication
2. Automatically redirected to Safe account creation
3. Fill out Safe creation form (network, threshold, signers)
4. Safe account entity created with "pending" status

### **Returning Users (Has Safe Accounts)**
1. Complete SIWE authentication  
2. Automatically redirected to Safe accounts list
3. View all Safe accounts with status indicators
4. Manage individual Safes or create new transactions

### **Transaction Creation**
1. From Safe accounts list or individual Safe page
2. Fill transaction form (recipient, amount, data)
3. Form validates inputs and converts ETH to wei
4. Transaction entity created with "draft" status
5. View transaction details and status

## Architecture

### **Phase 1: Entity Management (Current)**
- ✅ **Complete UI/UX workflow** with Drupal entities
- ✅ **Safe account creation and management**
- ✅ **Transaction proposal system**
- ✅ **Status-based conditional logic**
- ✅ **SIWE authentication integration**
- ✅ **Automatic cache invalidation**

### **Phase 2: Blockchain Integration (Next)**
- 🔄 **Actual Safe deployment to Sepolia**
- 🔄 **Transaction submission to blockchain**
- 🔄 **Real-time status monitoring**
- 🔄 **Queue-based background processing**

### **Phase 3: Advanced Features (Future)**
- 🔄 **Multi-network support**
- 🔄 **Gas estimation and optimization**
- 🔄 **Advanced Safe configurations**

## Entity Structure

### **SafeAccount Entity**
- `user_id`: Associated Drupal user
- `network`: Target blockchain network (sepolia)
- `safe_address`: Deployed Safe contract address
- `threshold`: Required signatures for transactions
- `status`: pending|deploying|active|error
- `metadata`: JSON storage for additional data

### **SafeTransaction Entity**  
- `safe_account`: Reference to SafeAccount
- `to_address`: Transaction recipient
- `value`: Transaction amount in wei
- `data`: Transaction data (hex)
- `operation`: Call (0) or DelegateCall (1)
- `status`: draft|pending|executed|failed|cancelled
- `signatures`: JSON array of collected signatures

### **SafeConfiguration Entity**
- `safe_account`: One-to-one with SafeAccount
- `signers`: JSON array of authorized addresses
- `modules`: JSON array of enabled Safe modules
- `fallback_handler`: Fallback handler address

## Manual Validation

Comprehensive testing checklists available in `validation/` directory:

- **SafeAccount_CRUD_Checklist.md**: Entity operations validation
- **SafeTransaction_Workflow_Checklist.md**: Transaction lifecycle testing
- **SafeConfiguration_Management_Checklist.md**: Configuration management validation
- **SIWE_Integration_Checklist.md**: Authentication integration testing
- **Form_UX_Checklist.md**: User experience validation

## Configuration

### **Network Settings**
```yaml
network:
  sepolia:
    name: 'Sepolia Testnet'
    chain_id: 11155111
    rpc_url: 'https://rpc.sepolia.org'
    safe_service_url: 'https://safe-transaction-sepolia.safe.global'
    enabled: true
```

### **API Settings**
```yaml
api:
  timeout: 30
  retry_attempts: 3
  cache_ttl: 300
```

### **Monitoring Settings**
```yaml
monitoring:
  queue_interval: 60
  batch_size: 50
  max_retries: 5
```

## Cache Management

The module implements sophisticated cache management:

- **Entity-level cache tags**: `safe_account:ID`, `safe_transaction:ID`
- **List-level cache tags**: `safe_account_list:USER_ID`
- **Automatic invalidation**: Status changes immediately reflect in UI
- **Performance optimized**: Granular cache invalidation prevents unnecessary rebuilds

## URLs and Routes

- `/user/{user_id}/safe-accounts` - User's Safe accounts list
- `/user/{user_id}/safe-accounts/create` - Create new Safe account
- `/user/{user_id}/safe-accounts/{safe_id}` - Manage specific Safe account  
- `/safe-accounts/{safe_id}/transactions/create` - Create transaction
- `/safe-accounts/{safe_id}/transactions/{tx_id}` - View transaction details
- `/admin/config/safe-accounts/settings` - Module configuration

## Development Notes

### **Entity Testing Best Practices**
Always use proper entity methods for testing:
```php
// ✅ CORRECT - Triggers cache invalidation
$safe = $storage->load($id);
$safe->setStatus('active');
$safe->save();

// ❌ AVOID - Bypasses cache system  
drush sqlq "UPDATE safe_account SET status = 'active'";
```

### **Status Transitions**
```php
// Proper status transition with cache invalidation
$safe_account->markDeployed($tx_hash, $safe_address);
$safe_account->save(); // Automatically invalidates caches
```

### **Access Control Patterns**
```php
// Route access considers Safe status
public function transactionAccess(SafeAccount $safe_account): AccessResultInterface {
  if ($safe_account->getStatus() !== 'active') {
    return AccessResult::forbidden('Safe account must be active');
  }
  // ... additional checks
}
```

## Troubleshooting

### **Common Issues**

**Cache Not Updating After Status Changes**
- Ensure using entity `save()` methods instead of direct SQL
- Check `postSave()` hook is properly invalidating cache tags
- Use `ddev drush cache:rebuild` if needed during development

**Transaction Creation Disabled**
- Check Safe account status (must be 'active')
- Verify SIWE authentication is working
- Confirm user has proper permissions

**SIWE Redirect Not Working**
- For direct SIWE: Check `hook_siwe_login_response_alter()` implementation
- For email/username flows: Check `hook_user_login()` destination setting
- Verify both hooks are working for comprehensive coverage

## Contributing

1. **Manual testing**: Use validation checklists for all changes
2. **Entity methods**: Always use proper Drupal entity lifecycle methods
3. **Cache awareness**: Consider cache invalidation impacts
4. **SIWE integration**: Test all authentication flows
5. **Documentation**: Update READMEs and validation checklists

## Constitutional Compliance

✅ **MVP-First Development**: Phase 1 delivers complete working functionality  
✅ **Testable Increments**: Each component independently testable via manual validation  
✅ **Human-Centered QA**: Comprehensive manual testing checklists provided  
✅ **Quality Gates**: Validation required before blockchain integration  
✅ **Rapid Prototyping**: Entity-first approach enables quick iteration