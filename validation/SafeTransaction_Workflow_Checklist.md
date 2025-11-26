# Manual Validation Checklist: SafeTransaction Entity Workflows

## Transaction Creation Validation
- [ ] SafeTransaction entities can be created for existing SafeAccounts
- [ ] Required fields validate (safe_account, to_address, value, operation, created_by)
- [ ] To address accepts valid Ethereum addresses only
- [ ] Value accepts non-negative decimal values
- [ ] Operation field accepts 0 (Call) or 1 (DelegateCall)
- [ ] Status defaults to 'draft'
- [ ] Created timestamp is set automatically
- [ ] Created_by references authenticated user

## Transaction Workflow Validation
- [ ] Transaction status can transition: draft → pending → executed/failed/cancelled
- [ ] Invalid status transitions are prevented
- [ ] Multiple transactions can exist for one SafeAccount
- [ ] Transaction nonce is managed correctly
- [ ] Signature collection workflow functions

## Transaction Data Validation
- [ ] Transaction data field accepts hex strings
- [ ] Gas estimate field accepts positive integers
- [ ] Safe transaction hash is unique when set
- [ ] Blockchain transaction hash is unique when set
- [ ] JSON signatures field validates as proper JSON array

## Transaction Relationships Validation
- [ ] SafeTransaction → SafeAccount relationship works
- [ ] SafeTransaction → User (created_by) relationship works
- [ ] Multiple transactions per SafeAccount supported
- [ ] Transaction queries work (by Safe, by user, by status)
- [ ] Cascade delete behavior works correctly

## Multi-Signature Workflow Validation
- [ ] Transaction proposals can be created
- [ ] Signatures can be added to pending transactions
- [ ] Signature count tracking works correctly
- [ ] Threshold requirements are enforced
- [ ] Transaction execution only works with sufficient signatures

## Transaction State Management Validation
- [ ] Draft transactions can be modified
- [ ] Pending transactions cannot be modified
- [ ] Executed transactions are immutable
- [ ] Failed transactions maintain error information
- [ ] Cancelled transactions cannot be reactivated

## Access Control Validation
- [ ] Only Safe signers can create transactions
- [ ] Only Safe signers can sign transactions
- [ ] Transaction creators can cancel draft transactions
- [ ] Users can only access transactions for their Safes
- [ ] Admin users can view all transactions