# Safe Smart Accounts User Guide

Welcome to Safe Smart Accounts! This guide will help you understand and use your Safe Smart Account for enhanced Ethereum security.

## What is a Safe Smart Account?

A Safe Smart Account is a multi-signature wallet that provides enhanced security for your Ethereum transactions. Unlike regular wallets, Safe accounts require multiple signatures to execute transactions, protecting your funds even if one key is compromised.

## Getting Started

### Prerequisites
- You must be authenticated with SIWE (Sign-In with Ethereum)
- Your Ethereum wallet must be connected
- You need an Ethereum address to create a Safe

### Creating Your First Safe

1. **Navigate to Safe Accounts**: After logging in with SIWE, click "Safe Accounts" in the toolbar or visit your user account page
2. **Click "Create Safe Smart Account"**: This will open the Safe creation form
3. **Configure Your Safe**:
   - **Network**: Currently supports Sepolia testnet only
   - **Threshold**: Number of signatures required (start with 1 for single-user Safes)
   - **Additional Signers**: Add other Ethereum addresses that can sign transactions

4. **Review and Create**: Your Safe will be created in "pending" status until deployed

## Managing Your Safe

### Safe Overview
Your Safe management page shows:
- **Safe ID and Status**: Current deployment status
- **Network and Address**: Where your Safe is deployed
- **Threshold and Signers**: Current security configuration
- **Recent Transactions**: Latest transaction activity

### Adding Signers
1. Go to your Safe management page
2. In the "Signer Management" section, add Ethereum addresses to "Current Signers"
3. Or use "Add New Signer" field for a single address
4. Adjust the threshold as needed (cannot exceed number of signers)
5. Click "Save Configuration"

### Removing Signers
1. Edit the "Current Signers" field to remove addresses
2. Ensure threshold is not greater than remaining signers
3. Save your changes

## Creating Transactions

### Basic Transactions
1. From your Safe management page, click "Create New Transaction"
2. Fill in transaction details:
   - **To Address**: Recipient's Ethereum address
   - **Value**: Amount of ETH to send
   - **Operation Type**: Usually "Call" for regular transactions

3. **Advanced Options** (optional):
   - **Transaction Data**: For contract interactions
   - **Gas Limit**: Manual gas limit override
   - **Nonce**: For custom transaction ordering

4. Choose "Create Transaction Proposal" or "Save as Draft"

### Understanding Transaction Status
- **Draft**: Transaction saved but not proposed
- **Pending**: Waiting for required signatures
- **Executed**: Transaction completed on blockchain
- **Failed**: Transaction failed during execution
- **Cancelled**: Transaction cancelled by creator

## Multi-Signature Workflow

### For Single-Signer Safes (Threshold = 1)
- Your transactions execute immediately when created
- Provides gas optimization and advanced features

### For Multi-Signer Safes (Threshold > 1)
1. **Propose Transaction**: One signer creates the transaction
2. **Collect Signatures**: Other signers must approve the transaction
3. **Execute Transaction**: Once threshold is met, any signer can execute
4. **Monitor Status**: Track execution on the blockchain

## Understanding Costs

### Sepolia Testnet (Current)
- All transactions use test ETH (no real value)
- Get Sepolia ETH from faucets for testing

### Future Mainnet Deployment
- Real ETH costs for:
  - Safe deployment (~$10-50)
  - Transaction execution (~$5-20)
  - Configuration changes (~$10-30)

## Security Best Practices

### Signer Management
- **Use Hardware Wallets**: For signing important transactions
- **Verify Addresses**: Double-check all Ethereum addresses
- **Backup Signers**: Have reliable co-signers available
- **Regular Review**: Periodically review and update signers

### Transaction Safety
- **Start Small**: Test with small amounts first
- **Double-Check Recipients**: Verify addresses before sending
- **Use Appropriate Thresholds**: Balance security with usability
- **Monitor Activity**: Regularly review transaction history

## Troubleshooting

### Common Issues

#### "SIWE authentication required"
- Ensure you're logged in with your Ethereum wallet
- Your user account must have an Ethereum address

#### "Safe deployment failed"
- Check if you have sufficient Sepolia ETH
- Network congestion may cause delays
- Try again in a few minutes

#### "Transaction rejected"
- Verify all signers have approved
- Check if nonce is correct
- Ensure Safe has sufficient balance

#### "Cannot access Safe"
- Verify you're logged in with the correct Ethereum address
- Check if you're listed as a signer
- Contact Safe owner to add you as signer

### Getting Help
- Check transaction status on blockchain explorer
- Review error messages carefully
- Consult Safe Smart Accounts documentation
- Contact system administrator if issues persist

## Advanced Features

### Contract Interactions
Use the "Transaction Data" field to:
- Call smart contract functions
- Interact with DeFi protocols
- Execute complex operations

### Batch Operations
Plan to group multiple transactions for gas efficiency (future feature)

### Module Integration
Support for Safe modules and guards (future feature)

## Network Information

### Sepolia Testnet
- **Chain ID**: 11155111
- **RPC URL**: https://rpc.sepolia.org
- **Block Explorer**: https://sepolia.etherscan.io
- **Safe Service**: https://safe-transaction-sepolia.safe.global

### Getting Test ETH
Use Sepolia faucets:
- https://sepoliafaucet.com/
- https://faucet.sepolia.dev/
- Request from the community

## Privacy and Data

### What We Store
- Safe configuration (signers, threshold)
- Transaction proposals and history
- User associations with Safes

### What We Don't Store
- Private keys or seed phrases
- Personal information beyond Ethereum addresses
- Transaction data on external networks

### SIWE Integration
Your Ethereum address from SIWE login is used to:
- Associate you with your Safe accounts
- Verify your authorization to sign transactions
- Provide access control for Safe operations

## Future Roadmap

### Coming Soon
- Mainnet Ethereum support
- Advanced transaction batching
- Enhanced mobile experience
- Integration with popular DeFi protocols

### Long-term Plans
- Multi-network support (Polygon, Arbitrum)
- Advanced Safe module integrations
- Governance and DAO features
- Enhanced analytics and reporting

---

*Need more help? Visit our documentation or contact support through your user account page.*