# Manual Validation Checklist: SIWE Authentication Integration

## SIWE User Authentication Validation
- [ ] SIWE module is properly detected and integrated
- [ ] Users must have SIWE authentication to access Safe features
- [ ] Ethereum address field is populated from SIWE login
- [ ] Session validation works with SIWE tokens
- [ ] Logout from SIWE clears Safe session access

## Safe Account Creation Access Control
- [ ] Only SIWE authenticated users can create Safe accounts
- [ ] User's Ethereum address is used as Safe owner
- [ ] Non-SIWE users cannot access Safe creation forms
- [ ] Anonymous users are redirected to SIWE login
- [ ] Error messages guide users to complete SIWE authentication

## User Account Integration
- [ ] Safe accounts display in user account pages
- [ ] SIWE user profile shows associated Safe accounts
- [ ] User can navigate from profile to Safe management
- [ ] Safe account creation link appears for SIWE users
- [ ] Non-SIWE users see instructions to enable SIWE

## Ethereum Address Validation
- [ ] SIWE Ethereum address matches Safe account owner
- [ ] Address format validation works correctly
- [ ] Address case insensitive comparison works
- [ ] Invalid addresses are rejected with clear messages
- [ ] Address changes in SIWE profile update Safe access

## Session and Permission Validation
- [ ] SIWE session timeout respects Safe account access
- [ ] Re-authentication required after session expiry
- [ ] Permissions integrate with Drupal role system
- [ ] Safe-specific permissions work with SIWE roles
- [ ] Cross-site request forgery protection works

## Multi-User Safe Access Validation
- [ ] Multiple SIWE users can be Safe signers
- [ ] Signer permissions work independently of Safe creator
- [ ] Non-signer SIWE users cannot access Safe operations
- [ ] Signer addition/removal respects SIWE authentication
- [ ] Safe sharing between SIWE users works correctly

## Error Handling and User Experience
- [ ] Clear error messages for authentication failures
- [ ] Graceful handling of SIWE service unavailability
- [ ] User guidance for incomplete SIWE setup
- [ ] Proper redirects after authentication
- [ ] Mobile-friendly SIWE integration in Safe workflows