# Manual Validation Checklist: Form Workflows and User Experience

## Safe Account Creation Form Validation
- [ ] Form renders correctly for SIWE authenticated users
- [ ] Network selection works (Sepolia default)
- [ ] Threshold field validates (positive integer, default 1)
- [ ] Additional signers field accepts valid Ethereum addresses
- [ ] Form submission creates SafeAccount entity correctly
- [ ] Success message appears after creation
- [ ] User redirected to Safe management page
- [ ] Form validation errors are clear and actionable

## Safe Account Management Form Validation
- [ ] Form loads existing Safe account data
- [ ] Signer list displays current configuration
- [ ] Add signer field validates Ethereum addresses
- [ ] Remove signer functionality works correctly
- [ ] Threshold adjustment validates against signer count
- [ ] Form submission updates SafeConfiguration entity
- [ ] Changes save successfully with confirmation message
- [ ] Form prevents invalid threshold/signer combinations

## Transaction Creation Form Validation
- [ ] Form accessible only to Safe signers
- [ ] Recipient address field validates Ethereum format
- [ ] Amount field accepts decimal values with wei conversion
- [ ] Transaction data field accepts hex strings
- [ ] Operation type selection works (Call/DelegateCall)
- [ ] Form submission creates SafeTransaction entity
- [ ] Draft transaction appears in transaction list
- [ ] Gas estimation provided (if applicable)

## Form User Experience Validation
- [ ] All forms are responsive on mobile devices
- [ ] Loading states show during form processing
- [ ] Error messages are user-friendly and specific
- [ ] Help text explains complex concepts (threshold, etc.)
- [ ] Forms integrate with Drupal's standard styling
- [ ] CSRF protection works on all forms
- [ ] JavaScript enhancements work properly
- [ ] Forms degrade gracefully without JavaScript

## Navigation and Workflow Validation
- [ ] User can navigate between forms logically
- [ ] Breadcrumbs show current location in workflow
- [ ] Back buttons work correctly
- [ ] Cancel operations return to appropriate pages
- [ ] Deep links work for form URLs
- [ ] Forms respect user permissions
- [ ] Access denied messages are helpful
- [ ] Multi-step processes maintain state

## Form Validation and Feedback
- [ ] Client-side validation provides immediate feedback
- [ ] Server-side validation catches all edge cases
- [ ] Validation messages appear near relevant fields
- [ ] Success messages are clear and actionable
- [ ] Error recovery guidance is provided
- [ ] Form remembers user input after validation errors
- [ ] Autocomplete works appropriately
- [ ] Tab order is logical for keyboard navigation

## Accessibility and Usability
- [ ] Forms work with screen readers
- [ ] Keyboard navigation is complete
- [ ] Color contrast meets accessibility standards
- [ ] Form labels are descriptive and helpful
- [ ] Error states are announced to screen readers
- [ ] Forms work in high contrast mode
- [ ] Text can be scaled to 200% without breaking layout