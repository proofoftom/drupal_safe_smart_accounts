# Manual Validation Checklist: SafeConfiguration Entity Management

## Configuration Creation Validation
- [ ] SafeConfiguration entities can be created for SafeAccounts
- [ ] Required fields validate (safe_account, signers, threshold, version)
- [ ] Signers array accepts valid JSON with Ethereum addresses
- [ ] Threshold must not exceed signer count
- [ ] Version field accepts valid version strings
- [ ] Updated timestamp is set automatically
- [ ] Updated_by references authenticated user

## Configuration Update Validation
- [ ] Existing configurations can be modified
- [ ] Signer list updates save correctly
- [ ] Threshold updates validate against signer count
- [ ] Module list updates work (JSON array)
- [ ] Fallback handler address updates validate
- [ ] Updated timestamp changes on modifications

## Signer Management Validation
- [ ] Signers can be added to configuration
- [ ] Signers can be removed from configuration
- [ ] Minimum one signer must remain
- [ ] All signer addresses must be valid Ethereum addresses
- [ ] Duplicate signers are prevented
- [ ] Signer order is preserved

## Threshold Management Validation
- [ ] Threshold can be increased up to signer count
- [ ] Threshold can be decreased to minimum 1
- [ ] Threshold cannot exceed number of signers
- [ ] Threshold must be positive integer
- [ ] Threshold updates require proper validation

## Configuration Relationships Validation
- [ ] SafeConfiguration → SafeAccount relationship works (1:1)
- [ ] SafeConfiguration → User (updated_by) relationship works
- [ ] Configuration updates link to modifying user
- [ ] Only one configuration per SafeAccount

## Module and Handler Validation
- [ ] Modules array accepts valid JSON
- [ ] Module addresses validate as Ethereum addresses
- [ ] Fallback handler accepts valid Ethereum address
- [ ] Empty modules array is acceptable
- [ ] Module order is preserved

## Version and Metadata Validation
- [ ] Version field accepts semantic version strings
- [ ] Version updates track Safe contract version
- [ ] Configuration history is maintained
- [ ] Metadata changes are logged appropriately

## Access Control Validation
- [ ] Only Safe owners can modify configuration
- [ ] SIWE authentication required for changes
- [ ] Users cannot modify other users' configurations
- [ ] Admin users can view all configurations
- [ ] Proper error messages for unauthorized access