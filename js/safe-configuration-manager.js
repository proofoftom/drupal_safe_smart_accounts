/**
 * Safe Smart Accounts - Configuration Manager
 *
 * Handles Safe configuration updates (signers and threshold) via on-chain transactions
 */

(function (Drupal, drupalSettings) {
  "use strict";

  /**
   * Behavior for Safe configuration management.
   */
  Drupal.behaviors.safeConfigurationManager = {
    attach: function (context, settings) {
      // Attach to configuration update forms
      const configForms = context.querySelectorAll(
        "#safe-account-manage-form:not(.safe-config-processed)"
      );

      configForms.forEach(function (form) {
        form.classList.add("safe-config-processed");

        // Intercept form submission to check for configuration changes
        const saveButton = form.querySelector('input[name="op"][value="Save Configuration"]');
        if (saveButton) {
          saveButton.addEventListener("click", handleConfigurationSave);
        }
      });
    },
  };

  /**
   * Handles configuration save with on-chain transaction creation.
   */
  async function handleConfigurationSave(event) {
    // For now, we let the form submit normally
    // In a future iteration, we could intercept here to show a preview
    // of the on-chain transactions that will be created
  }

  /**
   * Creates a configuration change transaction.
   *
   * @param {string} safeAccountId - The Safe account ID
   * @param {string} changeType - Type of change (add_owner, remove_owner, change_threshold)
   * @param {object} changeData - Data for the change
   * @returns {Promise<object>} The created transaction
   */
  async function createConfigurationTransaction(
    safeAccountId,
    changeType,
    changeData
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

      // Create transaction via API
      const response = await fetch(
        `/safe-accounts/${safeAccountId}/configuration/create-transaction`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken,
          },
          credentials: "same-origin",
          body: JSON.stringify({
            change_type: changeType,
            change_data: changeData,
          }),
        }
      );

      const responseData = await response.json();

      if (!response.ok) {
        throw new Error(
          responseData.error || `HTTP error! status: ${response.status}`
        );
      }

      return responseData;
    } catch (error) {
      console.error("Error creating configuration transaction:", error);
      throw error;
    }
  }

  /**
   * Executes a configuration change on-chain.
   *
   * This follows the same flow as regular Safe transactions:
   * 1. Get transaction data
   * 2. Collect signatures (may already exist)
   * 3. Execute on-chain
   *
   * @param {string} safeAccountId - The Safe account ID
   * @param {string} transactionId - The transaction ID
   */
  async function executeConfigurationChange(safeAccountId, transactionId) {
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

      // Fetch transaction data
      showLoadingMessage("Fetching configuration change transaction...");
      const txData = await getTransactionData(safeAccountId, transactionId);

      if (!txData) {
        throw new Error("Could not retrieve transaction data");
      }

      // Verify we have enough signatures
      const existingSignatures = txData.signatures || [];
      if (existingSignatures.length < txData.threshold) {
        throw new Error(
          `Not enough signatures: ${existingSignatures.length}/${txData.threshold}`
        );
      }

      // Execute the transaction on-chain
      showLoadingMessage("Executing configuration change on-chain...");
      const result = await executeTransactionOnChain(
        signer,
        txData,
        existingSignatures
      );

      showSuccessMessage("Configuration change executed successfully!");

      // Update the backend with execution status
      await updateTransactionStatus(
        safeAccountId,
        transactionId,
        "executed",
        result.txHash
      );

      // Reload the page to show updated configuration
      setTimeout(() => {
        window.location.reload();
      }, 2000);
    } catch (error) {
      console.error("Configuration change execution failed:", error);
      showErrorMessage(`Execution failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Executes a Safe transaction on-chain.
   *
   * @param {object} signer - Ethers signer
   * @param {object} txData - Transaction data
   * @param {array} signatures - Array of signatures
   * @returns {Promise<object>} Execution result
   */
  async function executeTransactionOnChain(signer, txData, signatures) {
    // Safe contract ABI for execTransaction
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

    // Sort signatures by signer address (ascending)
    const sortedSignatures = signatures.sort((a, b) => {
      return a.signer.toLowerCase() < b.signer.toLowerCase() ? -1 : 1;
    });

    // Pack signatures: r (32 bytes) + s (32 bytes) + v (1 byte) for each signature
    let packedSignatures = "0x";
    for (const sig of sortedSignatures) {
      // Remove 0x prefix from each component
      const r = sig.r.startsWith("0x") ? sig.r.slice(2) : sig.r;
      const s = sig.s.startsWith("0x") ? sig.s.slice(2) : sig.s;

      // v is a single byte (2 hex chars), already in the correct format (31 or 32)
      const v = sig.v.toString(16).padStart(2, "0");

      packedSignatures += r + s + v;
    }

    console.log("Executing Safe transaction with signatures:", {
      to: txData.to,
      value: txData.value,
      data: txData.data || "0x",
      operation: txData.operation || 0,
      nonce: txData.nonce,
      packedSignatures: packedSignatures,
      signatureCount: sortedSignatures.length,
    });

    // Execute the transaction
    const tx = await safeContract.execTransaction(
      txData.to,
      txData.value,
      txData.data || "0x",
      txData.operation || 0,
      0, // safeTxGas
      0, // baseGas
      0, // gasPrice
      ethers.ZeroAddress, // gasToken
      ethers.ZeroAddress, // refundReceiver
      packedSignatures
    );

    console.log("Transaction sent:", tx.hash);

    // Wait for confirmation
    showLoadingMessage("Waiting for blockchain confirmation...");
    const receipt = await tx.wait();

    console.log("Transaction confirmed:", {
      hash: receipt.hash,
      blockNumber: receipt.blockNumber,
      gasUsed: receipt.gasUsed.toString(),
    });

    return { txHash: receipt.hash };
  }

  /**
   * Fetches transaction data from the backend.
   *
   * @param {string} safeAccountId - The Safe account ID
   * @param {string} transactionId - The transaction ID
   * @returns {Promise<object>} Transaction data
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

      const responseData = await response.json();

      if (!response.ok) {
        throw new Error(
          responseData.error || `HTTP error! status: ${response.status}`
        );
      }

      return responseData;
    } catch (error) {
      console.error("Error fetching transaction data:", error);
      throw error;
    }
  }

  /**
   * Updates transaction status in the backend.
   *
   * @param {string} safeAccountId - The Safe account ID
   * @param {string} transactionId - The transaction ID
   * @param {string} status - New status
   * @param {string} txHash - Execution transaction hash
   * @returns {Promise<object>} Update result
   */
  async function updateTransactionStatus(
    safeAccountId,
    transactionId,
    status,
    txHash
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

      // Update status via API
      const response = await fetch(
        `/safe-accounts/${safeAccountId}/transactions/${transactionId}/status`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken,
          },
          credentials: "same-origin",
          body: JSON.stringify({
            status: status,
            execution_tx_hash: txHash,
          }),
        }
      );

      const responseData = await response.json();

      if (!response.ok) {
        throw new Error(
          responseData.error || `HTTP error! status: ${response.status}`
        );
      }

      return responseData;
    } catch (error) {
      console.error("Error updating transaction status:", error);
      throw error;
    }
  }

  // Helper functions for UI messaging
  function showLoadingMessage(message) {
    if (typeof Drupal !== "undefined" && Drupal.message) {
      removeLoadingMessage();
      Drupal.message({
        text: message,
        type: "warning",
        id: "safe-config-loading",
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
        '.messages[data-drupal-message-id="safe-config-loading"]'
      );
      messages.forEach((msg) => msg.remove());
    }
  }

  // Export functions for use by other scripts
  window.SafeConfigurationManager = {
    createConfigurationTransaction,
    executeConfigurationChange,
  };
})(Drupal, drupalSettings);
