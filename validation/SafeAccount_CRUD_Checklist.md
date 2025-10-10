# Manual Validation Checklist: SafeAccount Entity CRUD Operations

## Entity Creation Validation
- [ ] SafeAccount entity can be created programmatically
- [ ] Required fields (user_id, network, threshold, status) validate correctly
- [ ] Optional fields (safe_address, deployment_tx_hash) accept null values
- [ ] Entity saves to database without errors
- [ ] UUID is automatically generated
- [ ] Created timestamp is set automatically
- [ ] Default threshold value is 1
- [ ] Default status is 'pending'
- [ ] Network defaults to 'sepolia'

## Entity Reading Validation
- [ ] SafeAccount entities can be loaded by ID
- [ ] SafeAccount entities can be loaded by user and network
- [ ] Entity fields return correct data types
- [ ] Relationships to User entity work correctly
- [ ] Query operations work (find by user, status, network)
- [ ] Entity displays correctly in admin lists

## Entity Update Validation
- [ ] Existing SafeAccount entities can be modified
- [ ] Field updates save correctly to database
- [ ] Status transitions work (pending → deploying → active/error)
- [ ] Threshold updates validate (must be positive integer)
- [ ] Safe address updates work when deployment completes
- [ ] Metadata JSON field accepts valid JSON

## Entity Delete Validation
- [ ] SafeAccount entities can be deleted
- [ ] Dependent SafeTransaction entities are handled correctly
- [ ] Dependent SafeConfiguration entities are handled correctly
- [ ] User can create new SafeAccount after deletion
- [ ] Database constraints are respected

## Validation Rules Testing
- [ ] User can have only one SafeAccount per network (constraint works)
- [ ] Invalid Ethereum addresses are rejected
- [ ] Threshold must be positive integer
- [ ] Status field only accepts valid values (pending, deploying, active, error)
- [ ] Network field only accepts supported values
- [ ] Required fields cannot be null

## Access Control Validation
- [ ] Users can only access their own SafeAccount entities
- [ ] Anonymous users cannot access SafeAccount entities
- [ ] Admin users can access all SafeAccount entities
- [ ] SIWE authentication is required for Safe operations
- [ ] Proper error messages for unauthorized access