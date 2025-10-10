/**
 * Safe Smart Accounts - Transaction Manager
 *
 * Handles signing and executing Safe transactions via MetaMask
 */

(function (Drupal, drupalSettings) {
  "use strict";

  /**
   * Behavior for Safe transaction management.
   */
  Drupal.behaviors.safeTransactionManager = {
    attach: function (context, settings) {
      // Attach to sign transaction buttons
      const signButtons = context.querySelectorAll(
        ".safe-transaction-sign:not(.safe-tx-processed)"
      );
      signButtons.forEach(function (button) {
        button.classList.add("safe-tx-processed");
        button.addEventListener("click", handleSignTransaction);
      });

      // Attach to execute transaction buttons
      const executeButtons = context.querySelectorAll(
        ".safe-transaction-execute:not(.safe-tx-processed)"
      );
      executeButtons.forEach(function (button) {
        button.classList.add("safe-tx-processed");
        button.addEventListener("click", handleExecuteTransaction);
      });
    },
  };

  /**
   * Handles signing a Safe transaction.
   */
  async function handleSignTransaction(event) {
    event.preventDefault();
    const button = event.currentTarget;
    const safeAccountId = button.getAttribute("data-safe-account-id");
    const transactionId = button.getAttribute("data-transaction-id");

    if (!safeAccountId || !transactionId) {
      showErrorMessage("Missing required transaction information");
      return;
    }

    // Disable button
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Signing...";
    button.classList.add("safe-tx-loading");

    try {
      // Check for Web3 provider
      if (typeof window.ethereum === "undefined") {
        throw new Error("Please install MetaMask or another Web3 wallet");
      }

      // Request account access
      const accounts = await window.ethereum.request({
        method: "eth_requestAccounts",
      });
      const userAddress = accounts[0];
      const checksumAddress = ethers.getAddress(userAddress);

      // Create ethers provider
      const provider = new ethers.BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();

      // Get network and verify
      const network = await provider.getNetwork();
      const chainId = Number(network.chainId);

      // Verify we're on Sepolia testnet (chainId 11155111)
      if (chainId !== 11155111) {
        throw new Error("Please switch to Sepolia testnet in your wallet");
      }

      // Fetch transaction data from Drupal
      showLoadingMessage("Fetching transaction data...");
      const txData = await getTransactionData(safeAccountId, transactionId);

      if (!txData) {
        throw new Error("Could not retrieve transaction data");
      }

      // Verify user is a signer
      const userAddressLower = checksumAddress.toLowerCase();
      const signersLower = txData.signers.map((s) => s.toLowerCase());
      if (!signersLower.includes(userAddressLower)) {
        throw new Error("You are not authorized to sign this transaction");
      }

      // Check if user has already signed
      const existingSignatures = txData.signatures || [];
      const alreadySigned = existingSignatures.some(
        (sig) => sig.signer.toLowerCase() === userAddressLower
      );
      if (alreadySigned) {
        throw new Error("You have already signed this transaction");
      }

      // Get Safe transaction hash from the contract
      showLoadingMessage("Building transaction hash...");
      const safeContract = new ethers.Contract(
        txData.safe_address,
        [
          `function getTransactionHash(
            address to,
            uint256 value,
            bytes data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address refundReceiver,
            uint256 _nonce
          ) view returns (bytes32)`
        ],
        provider
      );

      const safeTxHash = await safeContract.getTransactionHash(
        txData.to,
        txData.value,
        txData.data || "0x",
        txData.operation || 0,
        0, // safeTxGas
        0, // baseGas
        0, // gasPrice
        ethers.ZeroAddress, // gasToken
        ethers.ZeroAddress, // refundReceiver
        txData.nonce
      );

      console.log("Safe transaction hash:", safeTxHash);
      console.log("Transaction parameters:", {
        to: txData.to,
        value: txData.value,
        data: txData.data || "0x",
        operation: txData.operation || 0,
        nonce: txData.nonce,
        safe_address: txData.safe_address
      });

      // Sign the Safe transaction hash with eth_sign
      showLoadingMessage("Please sign the transaction in your wallet...");
      const signature = await signer.signMessage(ethers.getBytes(safeTxHash));

      console.log("Signature created:", signature);

      // Adjust v value for Safe's eth_sign flow (27→31, 28→32)
      const adjustedSignature = adjustVForSafe(signature);

      // Submit signature to Drupal
      showLoadingMessage("Submitting signature...");
      const result = await submitSignature(
        safeAccountId,
        transactionId,
        adjustedSignature,
        checksumAddress
      );

      if (result.success) {
        showSuccessMessage(
          `Signature added successfully! (${result.signature_count} of ${result.threshold})`
        );

        // Reload page to show updated signature status
        setTimeout(() => {
          window.location.reload();
        }, 2000);
      } else {
        throw new Error(result.error || "Failed to submit signature");
      }
    } catch (error) {
      console.error("Transaction signing failed:", error);
      showErrorMessage(`Signing failed: ${error.message}`);
    } finally {
      // Re-enable button
      button.disabled = false;
      button.textContent = originalText;
      button.classList.remove("safe-tx-loading");
      removeLoadingMessage();
    }
  }

  /**
   * Handles executing a Safe transaction.
   */
  async function handleExecuteTransaction(event) {
    event.preventDefault();
    const button = event.currentTarget;
    const safeAccountId = button.getAttribute("data-safe-account-id");
    const transactionId = button.getAttribute("data-transaction-id");

    if (!safeAccountId || !transactionId) {
      showErrorMessage("Missing required transaction information");
      return;
    }

    // Disable button
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Executing...";
    button.classList.add("safe-tx-loading");

    try {
      // Check for Web3 provider
      if (typeof window.ethereum === "undefined") {
        throw new Error("Please install MetaMask or another Web3 wallet");
      }

      // Request account access
      const accounts = await window.ethereum.request({
        method: "eth_requestAccounts",
      });

      // Create ethers provider
      const provider = new ethers.BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();

      // Get network and verify
      const network = await provider.getNetwork();
      const chainId = Number(network.chainId);

      // Verify we're on Sepolia testnet
      if (chainId !== 11155111) {
        throw new Error("Please switch to Sepolia testnet in your wallet");
      }

      // Fetch transaction data from Drupal
      showLoadingMessage("Fetching transaction data...");
      const txData = await getTransactionData(safeAccountId, transactionId);

      if (!txData) {
        throw new Error("Could not retrieve transaction data");
      }

      // Verify transaction can be executed
      if (!txData.can_execute) {
        throw new Error(
          `Transaction needs ${txData.threshold} signatures but only has ${txData.signatures.length}`
        );
      }

      // Build Safe contract interface
      const safeABI = [
        `function execTransaction(
          address to,
          uint256 value,
          bytes data,
          uint8 operation,
          uint256 safeTxGas,
          uint256 baseGas,
          uint256 gasPrice,
          address gasToken,
          address refundReceiver,
          bytes signatures
        ) returns (bool success)`,
      ];

      const safeContract = new ethers.Contract(
        txData.safe_address,
        safeABI,
        signer
      );

      // Pack signatures for Safe execution
      // Safe expects signatures sorted by signer address in ascending order
      console.log("Raw transaction signatures before packing:", txData.signatures);
      const packedSignatures = packSignatures(txData.signatures);

      console.log("Executing transaction with parameters:", {
        transactionId: txData.transaction_id,
        to: txData.to,
        value: txData.value,
        data: txData.data || "0x",
        operation: txData.operation || 0,
        nonce: txData.nonce,
        signatures: packedSignatures,
        signaturesLength: packedSignatures.length
      });

      // Execute transaction on blockchain
      showLoadingMessage("Please confirm the execution in your wallet...");
      const tx = await safeContract.execTransaction(
        txData.to,
        txData.value,
        txData.data || "0x",
        txData.operation || 0,
        0, // safeTxGas - 0 means estimate
        0, // baseGas
        0, // gasPrice
        ethers.ZeroAddress, // gasToken
        ethers.ZeroAddress, // refundReceiver
        packedSignatures
      );

      showLoadingMessage("Waiting for blockchain confirmation...");
      const receipt = await tx.wait();

      // Update Drupal with execution result
      const result = await markTransactionExecuted(
        safeAccountId,
        transactionId,
        tx.hash
      );

      if (result.success) {
        showSuccessMessage(
          `Transaction executed successfully! Tx: ${tx.hash.substring(0, 10)}...`
        );

        // Reload page to show executed status
        setTimeout(() => {
          window.location.reload();
        }, 3000);
      } else {
        throw new Error(result.error || "Failed to update transaction status");
      }
    } catch (error) {
      console.error("Transaction execution failed:", error);

      // Parse Safe-specific error codes
      const errorMessage = parseSafeError(error);
      showErrorMessage(`Execution failed: ${errorMessage}`);
    } finally {
      // Re-enable button
      button.disabled = false;
      button.textContent = originalText;
      button.classList.remove("safe-tx-loading");
      removeLoadingMessage();
    }
  }

  /**
   * Fetches transaction data from Drupal API.
   */
  async function getTransactionData(safeAccountId, transactionId) {
    try {
      const response = await fetch(
        `/safe-accounts/${safeAccountId}/transactions/${transactionId}/data`,
        {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "same-origin",
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Error fetching transaction data:", error);
      return null;
    }
  }

  /**
   * Adjusts the v value in a signature for Safe's eth_sign flow.
   * Safe requires v values to be 31/32 instead of 27/28 for eth_sign.
   *
   * @param {string} signature - The signature in hex format (0x + 130 chars)
   * @returns {string} - The adjusted signature
   */
  function adjustVForSafe(signature) {
    let sig = signature;
    if (sig.startsWith("0x")) {
      sig = sig.slice(2);
    }

    // Extract the v value (last byte)
    const vHex = sig.slice(128, 130);
    let v = parseInt(vHex, 16);

    // Adjust v: 27 → 31 (0x1b → 0x1f), 28 → 32 (0x1c → 0x20)
    if (v === 27) {
      v = 31;
    } else if (v === 28) {
      v = 32;
    }

    // Reconstruct signature with adjusted v
    const adjustedSig = "0x" + sig.slice(0, 128) + v.toString(16).padStart(2, '0');

    console.log("Adjusted signature v value:", {
      original: vHex,
      adjusted: v.toString(16),
      signature: adjustedSig.slice(0, 20) + "..."
    });

    return adjustedSig;
  }

  /**
   * Packs signatures for Safe contract execution.
   *
   * Safe expects signatures in a specific format:
   * - Sorted by signer address (ascending order)
   * - Concatenated as bytes (r, s, v for each signature)
   * - Signatures should already have v adjusted to 31/32 (from adjustVForSafe)
   */
  function packSignatures(signatures) {
    // Sort signatures by signer address
    const sortedSignatures = [...signatures].sort((a, b) => {
      const addrA = a.signer.toLowerCase();
      const addrB = b.signer.toLowerCase();
      return addrA < addrB ? -1 : addrA > addrB ? 1 : 0;
    });

    // Process each signature - just concatenate them
    const processedSigs = sortedSignatures.map((sig) => {
      let sigHex = sig.signature;

      // Remove 0x prefix if present
      if (sigHex.startsWith("0x")) {
        sigHex = sigHex.slice(2);
      }

      // Signature should be 130 hex chars (65 bytes: r=32, s=32, v=1)
      if (sigHex.length !== 130) {
        console.error(`Invalid signature length: ${sigHex.length}`, sig);
        throw new Error(`Invalid signature length for ${sig.signer}`);
      }

      return sigHex;
    });

    // Concatenate all signatures
    const packed = "0x" + processedSigs.join("");

    console.log("Packed signatures:", {
      count: sortedSignatures.length,
      signers: sortedSignatures.map(s => s.signer),
      packed: packed,
      length: packed.length
    });

    return packed;
  }

  /**
   * Submits signature to Drupal API.
   */
  async function submitSignature(
    safeAccountId,
    transactionId,
    signature,
    signerAddress
  ) {
    try {
      // Fetch CSRF token
      const tokenResponse = await fetch("/session/token?_=" + Date.now(), {
        credentials: "same-origin",
        cache: "no-cache",
      });

      if (!tokenResponse.ok) {
        throw new Error("Failed to retrieve CSRF token");
      }

      const csrfToken = await tokenResponse.text();

      // Submit signature
      const response = await fetch(
        `/safe-accounts/${safeAccountId}/transactions/${transactionId}/sign`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken,
          },
          credentials: "same-origin",
          body: JSON.stringify({
            signature: signature,
            signer: signerAddress,
          }),
        }
      );

      const responseData = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: responseData.error || `HTTP error! status: ${response.status}`,
        };
      }

      return responseData;
    } catch (error) {
      console.error("Error submitting signature:", error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Marks transaction as executed in Drupal.
   */
  async function markTransactionExecuted(
    safeAccountId,
    transactionId,
    blockchainTxHash
  ) {
    try {
      // Fetch CSRF token
      const tokenResponse = await fetch("/session/token?_=" + Date.now(), {
        credentials: "same-origin",
        cache: "no-cache",
      });

      if (!tokenResponse.ok) {
        throw new Error("Failed to retrieve CSRF token");
      }

      const csrfToken = await tokenResponse.text();

      // Submit execution result
      const response = await fetch(
        `/safe-accounts/${safeAccountId}/transactions/${transactionId}/execute`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken,
          },
          credentials: "same-origin",
          body: JSON.stringify({
            blockchain_tx_hash: blockchainTxHash,
          }),
        }
      );

      const responseData = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: responseData.error || `HTTP error! status: ${response.status}`,
        };
      }

      return responseData;
    } catch (error) {
      console.error("Error marking transaction as executed:", error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Parses Safe contract errors and returns user-friendly messages.
   *
   * @param {Error} error - The error object from ethers.js
   * @returns {string} - User-friendly error message
   */
  function parseSafeError(error) {
    const errorString = error.message || error.toString();

    // Common Safe error codes
    const safeErrors = {
      'GS010': 'Not enough gas to execute Safe transaction',
      'GS011': 'Could not pay gas costs with ether',
      'GS012': 'Could not pay gas costs with token',
      'GS013': 'Safe balance too low - insufficient ETH in the Safe to cover transaction value and gas costs',
      'GS020': 'Signatures data too short',
      'GS021': 'Invalid contract signature location: inside static part',
      'GS022': 'Invalid contract signature location: length not present',
      'GS023': 'Invalid contract signature location: data not complete',
      'GS024': 'Invalid contract signature provided',
      'GS025': 'Hash has not been approved',
      'GS026': 'Invalid owner provided',
      'GS030': 'Only owners can approve a hash',
      'GS031': 'Method can only be called from this contract'
    };

    // Check if error message contains any Safe error code
    for (const [code, message] of Object.entries(safeErrors)) {
      if (errorString.includes(code)) {
        return `${message} (${code})`;
      }
    }

    // Check for common ethers.js error patterns
    if (errorString.includes('insufficient funds')) {
      return 'Insufficient funds in your wallet to pay for gas fees';
    }

    if (errorString.includes('user rejected')) {
      return 'Transaction was rejected in your wallet';
    }

    if (errorString.includes('nonce')) {
      return 'Transaction nonce error - another transaction may need to be executed first';
    }

    // Return original error message if no match
    return error.message || 'Unknown error occurred';
  }

  // Helper functions for user feedback

  function showLoadingMessage(message) {
    if (typeof Drupal !== "undefined" && Drupal.message) {
      removeLoadingMessage();
      Drupal.message({
        text: message,
        type: "warning",
        id: "safe-transaction-loading",
      });
    } else {
      console.log(message);
    }
  }

  function showSuccessMessage(message) {
    if (typeof Drupal !== "undefined" && Drupal.message) {
      Drupal.message({ text: message, type: "status" });
    } else {
      alert(message);
    }
  }

  function showErrorMessage(message) {
    if (typeof Drupal !== "undefined" && Drupal.message) {
      Drupal.message({ text: message, type: "error" });
    } else {
      alert(message);
    }
  }

  function removeLoadingMessage() {
    if (typeof Drupal !== "undefined" && Drupal.message) {
      const messages = document.querySelectorAll(
        '.messages[data-drupal-message-id="safe-transaction-loading"]'
      );
      messages.forEach((msg) => msg.remove());
    }
  }
})(Drupal, drupalSettings);