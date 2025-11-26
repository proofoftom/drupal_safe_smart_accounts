/**
 * Safe Smart Accounts - Safe Deployment using MetaMask
 */

(function (Drupal, drupalSettings) {
  "use strict";

  /**
   * Behavior for Safe deployment functionality.
   */
  Drupal.behaviors.safeDeployment = {
    attach: function (context, settings) {
      // Find and attach to the deploy safe button if it exists
      // The form has a submit button with value 'Deploy Safe' but no specific class
      const deployButtons = context.querySelectorAll(
        "input[value='Deploy Safe'], button[value='Deploy Safe']"
      );

      deployButtons.forEach(function (button) {
        // Prevent multiple event listeners on page updates
        if (button.hasAttribute("data-safe-deploy-processed")) {
          return;
        }

        button.setAttribute("data-safe-deploy-processed", "true");

        // Add the safe-deploy-button class so it can be easily identified
        button.classList.add("safe-deploy-button");

        // Add data attributes for safe account ID and user ID
        // These will be available from the form values
        const safeAccountIdInput = document.querySelector(
          'input[name="safe_account_id"]'
        );
        const userIdInput = document.querySelector('input[name="user_id"]');

        if (safeAccountIdInput && userIdInput) {
          button.setAttribute("data-safe-account-id", safeAccountIdInput.value);
          button.setAttribute("data-user-id", userIdInput.value);
        }

        button.addEventListener("click", handleDeploySafe);
      });

      // Function to handle the Safe deployment process
      async function handleDeploySafe(event) {
        // Prevent the default form submission
        event.preventDefault();
        event.stopPropagation();

        const button = event.currentTarget;
        const safeAccountId = button.getAttribute("data-safe-account-id");
        const userId = button.getAttribute("data-user-id");

        if (!safeAccountId || !userId) {
          console.error("Missing required attributes for Safe deployment");
          showErrorMessage("Missing required information for Safe deployment");
          return;
        }

        // Disable the button to prevent multiple clicks
        const originalText = button.value || button.textContent;
        button.disabled = true;
        button.textContent = "Deploying...";
        if (button.value) {
          button.value = "Deploying...";
        }

        // Add loading class for visual feedback
        button.classList.add("safe-deploy-loading");

        // Show a loading message
        showLoadingMessage(
          "Deploying Safe Smart Account to Sepolia testnet..."
        );

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

          // Create ethers provider from window.ethereum
          const provider = new ethers.BrowserProvider(window.ethereum);

          // Get network information
          const network = await provider.getNetwork();
          const chainId = Number(network.chainId);

          // Verify we're on Sepolia testnet (chainId 11155111 for Sepolia)
          if (chainId !== 11155111) {
            throw new Error("Please switch to Sepolia testnet in your wallet");
          }

          // Get the Safe configuration from Drupal
          const safeConfig = await getSafeConfiguration(safeAccountId);
          if (!safeConfig) {
            throw new Error("Could not retrieve Safe configuration");
          }

          // Update UI to show wallet interaction required
          showLoadingMessage(
            "Please confirm the deployment transaction in your wallet..."
          );

          // Deploy the Safe using the SafeDeployer class from specs
          const safeDeployer = new SafeDeployer(
            provider,
            await provider.getSigner()
          );

          // Deploy the Safe with the configuration
          const deployResult = await safeDeployer.deploySafe(
            safeConfig.signers || [checksumAddress],
            safeConfig.threshold || 1,
            safeConfig.salt_nonce || 0
          );

          const safeAddress = deployResult.safeAddress;
          const txHash = deployResult.txHash;

          // Update UI to show blockchain confirmation required
          showLoadingMessage("Waiting for blockchain confirmation...");

          // Update the Drupal entity with deployment results
          const deploymentResult = await updateSafeAccountEntity(
            safeAccountId,
            safeAddress,
            "deployed",
            txHash
          );

          if (deploymentResult.success) {
            // Update UI to show success
            showSuccessMessage(
              `Safe deployed successfully at address: ${safeAddress}`
            );

            // Update the page to reflect the new status
            updatePageStatus(safeAddress, "active");

            // Optionally reload the page after a delay
            setTimeout(() => {
              window.location.reload();
            }, 20);
          } else {
            throw new Error(
              deploymentResult.error ||
                "Failed to update Safe account in Drupal"
            );
          }
        } catch (error) {
          console.error("Safe deployment failed:", error);
          showErrorMessage(`Deployment failed: ${error.message}`);
        } finally {
          // Re-enable the button
          button.disabled = false;
          button.textContent = originalText;
          if (button.value) {
            button.value = originalText;
          }

          // Remove loading class
          button.classList.remove("safe-deploy-loading");

          // Remove loading message
          removeLoadingMessage();
        }
      }

      // Helper function to show loading message
      function showLoadingMessage(message) {
        // Use Drupal's messaging system if available
        if (typeof Drupal !== "undefined" && Drupal.message) {
          // Remove any existing loading messages
          removeLoadingMessage();
          Drupal.message({
            text: message,
            type: "warning",
            id: "safe-deployment-loading",
          });
        } else {
          // Fallback to console
          console.log(message);
        }
      }

      // Helper function to show success message
      function showSuccessMessage(message) {
        // Use Drupal's messaging system if available
        if (typeof Drupal !== "undefined" && Drupal.message) {
          Drupal.message({ text: message, type: "status" });
        } else {
          // Fallback to alert or console
          alert(message);
        }
      }

      // Helper function to show error message
      function showErrorMessage(message) {
        // Use Drupal's messaging system if available
        if (typeof Drupal !== "undefined" && Drupal.message) {
          Drupal.message({ text: message, type: "error" });
        } else {
          // Fallback to alert or console
          alert(message);
        }
      }

      // Helper function to remove loading message
      function removeLoadingMessage() {
        if (typeof Drupal !== "undefined" && Drupal.message) {
          // This is a custom implementation - Drupal core doesn't have a direct remove function
          // We'll implement a custom removal mechanism
          const messages = document.querySelectorAll(
            '.messages[data-drupal-message-id="safe-deployment-loading"]'
          );
          messages.forEach((msg) => msg.remove());
        }
      }

      // Helper function to update page status after deployment
      function updatePageStatus(safeAddress, status) {
        // Update status display elements
        const statusElements = document.querySelectorAll(".safe-status");
        statusElements.forEach((element) => {
          element.textContent = status;
          element.className = `safe-status safe-status-${status}`;
        });

        // Update address display elements
        const addressElements = document.querySelectorAll(".safe-address");
        addressElements.forEach((element) => {
          element.textContent = safeAddress;
          element.title = safeAddress; // Add full address as tooltip
        });

        // Update any deployment buttons to reflect new state
        const deployButtons = document.querySelectorAll(".safe-deploy-button");
        deployButtons.forEach((button) => {
          button.style.display = "none"; // Hide deploy button after successful deployment
        });
      }
    },
  };

  // SafeDeployer class implementation based on the spec
  class SafeDeployer {
    constructor(provider, signer) {
      this.provider = provider;
      this.signer = signer;

      // Safe contract addresses for Sepolia
      this.safeAddresses = {
        // Safe Master Implementation - the "headquarters" contract
        SAFE_SINGLETON: "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552",

        // Safe Proxy Factory - creates new Safe proxies
        SAFE_PROXY_FACTORY: "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2",

        // Fallback Handler - handles unknown function calls
        COMPATIBILITY_FALLBACK_HANDLER:
          "0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4",
      };

      // ABI for the Safe Proxy Factory (only the functions we need)
      this.safeProxyFactoryABI = [
        "function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns (address proxy)",
      ];

      // ABI for Safe setup (we need this to encode the initialization data)
      this.safeABI = [
        `function setup(
          address[] calldata _owners,
          uint256 _threshold,
          address to,
          bytes calldata data,
          address fallbackHandler,
          address paymentToken,
          uint256 payment,
          address paymentReceiver
        )`,
      ];

      // Create contract instances
      this.proxyFactory = new ethers.Contract(
        this.safeAddresses.SAFE_PROXY_FACTORY,
        this.safeProxyFactoryABI,
        signer
      );
    }

    /**
     * Calculate the address where the Safe will be deployed
     * This is useful for preparing transactions before deployment
     */
    async predictSafeAddress(owners, threshold, saltNonce = 0) {
      // First, we encode the setup call that initializes the Safe
      const setupData = this.encodeSetupCall(owners, threshold);

      // The Safe address is deterministic based on:
      // 1. The singleton address (master implementation)
      // 2. The initialization data
      // 3. The salt nonce
      // 4. The factory address

      // This uses CREATE2 opcode for deterministic addresses
      const initCode = ethers.concat([
        // This is the proxy creation bytecode with constructor args
        "0x608060405234801561001057600080fd5b506040516101e63803806101e68339818101604052810190610032919061007a565b600073ffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156100a3576040517f08c379a00000000000000000000000000000000815260040161009a90610146565b60405180910390fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050610166565b600080fd5b600073ffffffffffffffffffffffffffffffff82169050919050565b6000610118826100ed565b9050919050565b610128161010d565b811461013357600080fd5b50565b600815190506101458161011f565b92915050565b6000602082840312156101615761016061007a565b5b600061016f84828501610136565b91505092915050565b610071806101956000396000f3fe608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e00000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d600803e60008114156070573d6000fd5b3d6000f3fea2646970667358221220d1429297349653a4918076d650332de1a1068c5f3e07c5c82360c277770b955264736f6c63430008120033",
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address"],
          [this.safeAddresses.SAFE_SINGLETON]
        ),
      ]);

      const salt = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "uint256"],
          [ethers.keccak256(setupData), saltNonce]
        )
      );

      // CREATE2 address calculation: keccak256(0xff + factory + salt + keccak256(initCode))
      const predictedAddress = ethers.getCreate2Address(
        this.safeAddresses.SAFE_PROXY_FACTORY,
        salt,
        ethers.keccak256(initCode)
      );

      return predictedAddress;
    }

    /**
     * Encode the setup call for Safe initialization
     * This is the data that tells the Safe how to configure itself
     */
    encodeSetupCall(owners, threshold) {
      // Validate inputs
      if (!Array.isArray(owners) || owners.length === 0) {
        throw new Error("Owners must be a non-empty array");
      }
      if (threshold < 1 || threshold > owners.length) {
        throw new Error("Threshold must be between 1 and the number of owners");
      }

      // Create interface for encoding
      const safeInterface = new ethers.Interface(this.safeABI);

      // Encode the setup call with our parameters
      return safeInterface.encodeFunctionData("setup", [
        owners, // _owners: Array of owner addresses
        threshold, // _threshold: Number of required signatures
        ethers.ZeroAddress, // to: Address for optional setup call (none)
        "0x", // data: Data for optional setup call (none)
        this.safeAddresses.COMPATIBILITY_FALLBACK_HANDLER, // fallbackHandler: Handles unknown calls
        ethers.ZeroAddress, // paymentToken: Token for deployment payment (none)
        0, // payment: Amount to pay for deployment (0)
        ethers.ZeroAddress, // paymentReceiver: Who receives payment (none)
      ]);
    }

    /**
     * Deploy a new Safe with the specified owners and threshold
     */
    async deploySafe(owners, threshold, saltNonce = 0) {
      console.log("🔧 Preparing Safe deployment...");
      console.log(`   Owners: ${owners.length}`);
      console.log(`   Threshold: ${threshold}`);

      try {
        // Step 1: Encode the initialization data
        const setupData = this.encodeSetupCall(owners, threshold);
        console.log("✅ Encoded setup data");

        // Step 2: Predict where the Safe will be deployed
        const predictedAddress = await this.predictSafeAddress(
          owners,
          threshold,
          saltNonce
        );
        console.log(`🔮 Predicted Safe address: ${predictedAddress}`);

        // Step 3: Check if a Safe already exists at this address
        const existingCode = await this.provider.getCode(predictedAddress);
        if (existingCode !== "0x") {
          console.log("⚠️  Safe already exists at this address");
          return { safeAddress: predictedAddress, txHash: null };
        }

        // Step 4: Deploy the Safe proxy
        console.log("🚀 Deploying Safe...");
        const tx = await this.proxyFactory.createProxyWithNonce(
          this.safeAddresses.SAFE_SINGLETON, // Address of the master Safe implementation
          setupData, // Initialization data we encoded
          saltNonce // Nonce for deterministic address generation
        );

        console.log(`📝 Transaction sent: ${tx.hash}`);

        // Step 5: Wait for deployment confirmation
        const receipt = await tx.wait();
        console.log(`✅ Safe deployed successfully!`);
        console.log(`   Gas used: ${receipt.gasUsed.toString()}`);

        // Step 6: Get the actual deployed Safe address from the receipt logs
        // The ProxyCreation event is emitted by the SafeProxyFactory
        // Look for the ProxyCreation event in the logs
        let actualSafeAddress = predictedAddress; // fallback to predicted

        try {
          // Create an interface to parse the ProxyCreation event
          // Note: The proxy parameter is NOT indexed in SafeProxyFactory v1.4.1
          const iface = new ethers.Interface([
            "event ProxyCreation(address proxy, address singleton)",
          ]);

          for (const log of receipt.logs) {
            try {
              // Try to parse this log as a ProxyCreation event
              const parsed = iface.parseLog({
                topics: log.topics,
                data: log.data,
              });

              if (parsed && parsed.name === "ProxyCreation") {
                // The proxy parameter is the first argument
                actualSafeAddress = ethers.getAddress(parsed.args.proxy);
                console.log(
                  `   Safe address from ProxyCreation event: ${actualSafeAddress}`
                );
                break;
              }
            } catch (e) {
              // This log wasn't a ProxyCreation event, continue
              continue;
            }
          }

          // If we still have the predicted address, it means we didn't find the event
          // Use fallback method: find first contract address that's not a known factory
          if (actualSafeAddress === predictedAddress) {
            console.warn(
              `   ProxyCreation event not found, using fallback method`
            );

            const knownAddresses = [
              this.safeAddresses.SAFE_PROXY_FACTORY.toLowerCase(),
              this.safeAddresses.SAFE_SINGLETON.toLowerCase(),
            ];

            for (const log of receipt.logs) {
              const logAddress = log.address.toLowerCase();
              if (!knownAddresses.includes(logAddress)) {
                try {
                  actualSafeAddress = ethers.getAddress(log.address);
                  console.log(
                    `   Safe address from fallback detection: ${actualSafeAddress}`
                  );
                  break;
                } catch (e) {
                  continue;
                }
              }
            }
          }
        } catch (e) {
          console.warn(`   Could not parse ProxyCreation event: ${e.message}`);
        }

        console.log(`   Deployed Safe address: ${actualSafeAddress}`);

        return { safeAddress: actualSafeAddress, txHash: tx.hash };
      } catch (error) {
        console.error("❌ Safe deployment failed:", error.message);
        throw error;
      }
    }
  }

  /**
   * Helper function to get Safe configuration from Drupal.
   * Shared by both deployment flows (button and create form).
   */
  async function getSafeConfiguration(safeAccountId) {
    try {
      const response = await fetch(
        `/safe-accounts/${safeAccountId}/configuration`,
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
        console.error(
          "[Safe Deployment] Failed to fetch configuration:",
          responseData.error || response.status
        );
        return null;
      }

      return responseData;
    } catch (error) {
      console.error(
        "[Safe Deployment] Error fetching Safe configuration:",
        error
      );
      return null;
    }
  }

  /**
   * Helper function to update the Safe Account entity in Drupal.
   * Shared by both deployment flows (button and create form).
   */
  async function updateSafeAccountEntity(
    safeAccountId,
    safeAddress,
    status,
    txHash
  ) {
    try {
      // Fetch CSRF token from Drupal's REST endpoint
      const tokenResponse = await fetch("/session/token?_=" + Date.now(), {
        credentials: "same-origin",
        cache: "no-cache",
      });

      if (!tokenResponse.ok) {
        throw new Error("Failed to retrieve CSRF token");
      }

      const csrfToken = await tokenResponse.text();

      // Make the POST request with CSRF token
      const response = await fetch(
        `/safe-accounts/${safeAccountId}/update-deployment`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken,
          },
          credentials: "same-origin",
          body: JSON.stringify({
            safe_address: safeAddress,
            status: status,
            deployment_tx_hash: txHash,
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
      console.error(
        "[Safe Deployment] Error updating Safe account entity:",
        error
      );
      return { success: false, error: error.message };
    }
  }

  /**
   * Deploy a newly created Safe account (called from create form).
   */
  async function deployCreatedSafe(safeAccountId, userId) {
    try {
      // Update step 2 - MetaMask prompt
      updateDeploymentStep(
        2,
        "in-progress",
        "Waiting for MetaMask signature...",
        "Please check your wallet"
      );

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

      // Get network information
      const network = await provider.getNetwork();
      const chainId = Number(network.chainId);

      // Verify we're on Sepolia testnet
      if (chainId !== 11155111) {
        throw new Error("Please switch to Sepolia testnet in your wallet");
      }

      // Get the Safe configuration from Drupal
      const safeConfig = await getSafeConfiguration(safeAccountId);
      if (!safeConfig) {
        throw new Error("Could not retrieve Safe configuration");
      }

      // Prepare SafeDeployer for encoding and prediction
      const safeDeployer = new SafeDeployer(
        provider,
        await provider.getSigner()
      );

      // Prepare deployment parameters
      const owners = safeConfig.signers || [checksumAddress];
      const threshold = safeConfig.threshold || 1;
      const saltNonce = safeConfig.salt_nonce || 0;

      // Encode setup data and predict address
      const setupData = safeDeployer.encodeSetupCall(owners, threshold);
      const predictedAddress = await safeDeployer.predictSafeAddress(
        owners,
        threshold,
        saltNonce
      );

      console.log("[Safe Deployment] Predicted address:", predictedAddress);

      // Send the deployment transaction - this triggers MetaMask prompt
      const tx = await safeDeployer.proxyFactory.createProxyWithNonce(
        safeDeployer.safeAddresses.SAFE_SINGLETON,
        setupData,
        saltNonce
      );

      // Transaction submitted! User has signed in MetaMask
      const txHash = tx.hash;
      console.log("[Safe Deployment] Transaction submitted:", txHash);

      // Mark step 2 complete now that user has submitted the transaction
      updateDeploymentStep(2, "completed", "Transaction submitted");

      // Update step 3 - Deploying to blockchain
      updateDeploymentStep(
        3,
        "in-progress",
        "Deploying to Sepolia testnet...",
        "Transaction sent, waiting for confirmation..."
      );

      // Show Etherscan link immediately
      const etherscanUrl = `https://sepolia.etherscan.io/tx/${txHash}`;
      updateDeploymentStep(
        3,
        "in-progress",
        "Waiting for blockchain confirmation...",
        `<a href="${etherscanUrl}" target="_blank" rel="noopener noreferrer">View on Etherscan</a> (Est. 30 seconds)`
      );

      // Now wait for the transaction to be mined
      const receipt = await tx.wait();
      console.log("[Safe Deployment] Transaction confirmed on blockchain");

      // Get the actual Safe address from the receipt
      let safeAddress = predictedAddress;
      try {
        const iface = new ethers.Interface([
          "event ProxyCreation(address proxy, address singleton)",
        ]);
        for (const log of receipt.logs) {
          try {
            const parsed = iface.parseLog({
              topics: log.topics,
              data: log.data,
            });
            if (parsed && parsed.name === "ProxyCreation") {
              safeAddress = ethers.getAddress(parsed.args.proxy);
              console.log(
                "[Safe Deployment] Safe address from event:",
                safeAddress
              );
              break;
            }
          } catch (e) {
            continue;
          }
        }
      } catch (e) {
        console.warn(
          "[Safe Deployment] Could not parse ProxyCreation event:",
          e.message
        );
      }

      // Update the Drupal entity
      const deploymentResult = await updateSafeAccountEntity(
        safeAccountId,
        safeAddress,
        "deployed",
        txHash
      );

      if (deploymentResult.success) {
        updateDeploymentStep(
          3,
          "completed",
          "Deployment confirmed on blockchain"
        );
        updateDeploymentStep(
          4,
          "completed",
          "Safe deployed successfully!",
          `Address: ${safeAddress}<br><a href="${etherscanUrl}" target="_blank" rel="noopener noreferrer">View on Etherscan</a>`
        );

        // Redirect to management page after 2 seconds
        setTimeout(() => {
          window.location.href = `/user/${userId}/safe-accounts/${safeAccountId}`;
        }, 2000);
      } else {
        throw new Error(
          deploymentResult.error || "Failed to update Safe account in Drupal"
        );
      }
    } catch (error) {
      console.error("[Safe Deployment] Deployment failed:", error);
      const currentStep = getCurrentStep();
      updateDeploymentStep(
        currentStep,
        "error",
        `Deployment failed: ${error.message}`
      );
    }
  }

  /**
   * Update a deployment step's status.
   */
  function updateDeploymentStep(stepNumber, status, message, details = "") {
    const step = document.getElementById(`step-${stepNumber}`);
    if (!step) return;

    step.setAttribute("data-status", status);

    const icon = step.querySelector(".step-icon");
    const text = step.querySelector(".step-text");
    const detailsEl = step.querySelector(".step-details");

    // Update icon based on status
    if (status === "completed") {
      icon.textContent = "✅";
    } else if (status === "in-progress") {
      icon.textContent = "⏳";
    } else if (status === "error") {
      icon.textContent = "❌";
    }

    // Update text
    if (message) {
      text.textContent = message;
    }

    // Update details
    if (details && detailsEl) {
      detailsEl.innerHTML = details;
    }
  }

  /**
   * Get the current step number based on status.
   */
  function getCurrentStep() {
    for (let i = 1; i <= 4; i++) {
      const step = document.getElementById(`step-${i}`);
      if (step && step.getAttribute("data-status") === "in-progress") {
        return i;
      }
    }
    return 1; // Default to step 1
  }

  /**
   * Drupal behavior to handle deployment trigger from AJAX form submission.
   * Watches for drupalSettings.safeSmartAccounts.triggerDeployment flag.
   */
  Drupal.behaviors.safeDeploymentTrigger = {
    attach: function (context, settings) {
      // Check if deployment should be triggered
      if (settings.safeSmartAccounts?.triggerDeployment) {
        console.log(
          "[Safe Deployment] Deployment trigger detected in drupalSettings"
        );

        // Clear the flag so this doesn't re-trigger on subsequent AJAX calls
        delete settings.safeSmartAccounts.triggerDeployment;

        // Update step 1 to completed status
        const step1 = document.getElementById("step-1");
        if (step1) {
          step1.setAttribute("data-status", "completed");
          const icon = step1.querySelector(".step-icon");
          const text = step1.querySelector(".step-text");
          if (icon) icon.textContent = "✅";
          if (text) text.textContent = "Safe account configuration saved";
        }

        // Dispatch event to trigger deployment
        document.dispatchEvent(
          new CustomEvent("safeAccountCreated", {
            detail: {
              safeAccountId: settings.safeSmartAccounts.safeAccountId,
              userId: settings.safeSmartAccounts.userId,
            },
          })
        );
      }
    },
  };

  /**
   * Listen for Safe account creation event from create form (AJAX).
   * Uses vanilla JavaScript (no jQuery) since Drupal 10 removed jQuery from core.
   */
  document.addEventListener("safeAccountCreated", async function (event) {
    console.log(
      "[Safe Deployment] Safe account created, starting deployment...",
      event.detail
    );

    const safeAccountId = event.detail.safeAccountId;
    const userId = event.detail.userId;

    if (!safeAccountId || !userId) {
      console.error("[Safe Deployment] Missing required data for deployment");
      updateDeploymentStep(2, "error", "Missing required information");
      return;
    }

    // Start deployment automatically
    await deployCreatedSafe(safeAccountId, userId);
  });

  // Export helper functions for use by other modules (e.g., group_treasury)
  Drupal.safeDeployment = Drupal.safeDeployment || {};
  Drupal.safeDeployment.updateDeploymentStep = updateDeploymentStep;
  Drupal.safeDeployment.getCurrentStep = getCurrentStep;
  Drupal.safeDeployment.getSafeConfiguration = getSafeConfiguration;
  Drupal.safeDeployment.updateSafeAccountEntity = updateSafeAccountEntity;
  Drupal.safeDeployment.SafeDeployer = SafeDeployer;
})(Drupal, drupalSettings);
