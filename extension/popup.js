/**
 * SecurePass Extension - Popup Script
 * Provides UI interactions for the password generator and analyzer
 */

document.addEventListener('DOMContentLoaded', function() {
  // Initialize classes from utils.js
  const passwordGenerator = new PasswordGenerator();
  const passwordStrengthChecker = new PasswordStrengthChecker();
  const hibpChecker = new HIBPChecker();
  const passwordHasher = new PasswordHasher();
  
  // Load saved options
  loadOptions();
  
  // Initialize UI
  setupTabNavigation();
  setupPasswordGenerator();
  setupPasswordAnalyzer();
  setupOptionsSaving();
  setupCredentialsSaving(); // New function
  
  // Generate an initial password
  generatePassword();
  
  // Function to handle tab navigation
  function setupTabNavigation() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
      button.addEventListener('click', () => {
        const tabName = button.getAttribute('data-tab');
        
        // Update active state for buttons
        tabButtons.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Show the selected tab content
        tabContents.forEach(content => {
          content.classList.remove('active');
          if (content.id === tabName) {
            content.classList.add('active');
          }
        });
        
        // Special handling for passwords tab - load saved passwords when clicked
        if (tabName === 'passwords') {
          loadSavedPasswords();
        }
      });
    });
  }
  
  // Setup password generator functionality
  function setupPasswordGenerator() {
    const lengthSlider = document.getElementById('password-length');
    const lengthValue = document.getElementById('length-value');
    const useLowercase = document.getElementById('use-lowercase');
    const useUppercase = document.getElementById('use-uppercase');
    const useDigits = document.getElementById('use-digits');
    const useSpecial = document.getElementById('use-special');
    const refreshButton = document.getElementById('refresh-password');
    const copyButton = document.getElementById('copy-password');
    const hibpButton = document.getElementById('check-hibp');
    const saveButton = document.getElementById('save-password');
    
    // Update length value when slider changes
    lengthSlider.addEventListener('input', () => {
      lengthValue.textContent = lengthSlider.value;
    });
    
    // Generate new password when any option changes
    [lengthSlider, useLowercase, useUppercase, useDigits, useSpecial].forEach(element => {
      element.addEventListener('change', generatePassword);
    });
    
    // Generate new password when refresh button is clicked
    refreshButton.addEventListener('click', generatePassword);
    
    // Copy password to clipboard
    copyButton.addEventListener('click', () => {
      const passwordField = document.getElementById('generated-password');
      passwordField.select();
      document.execCommand('copy');
      
      showToast('Password copied to clipboard!');
      
      // Check if clear clipboard option is enabled
      chrome.storage.sync.get(['clearClipboard', 'clearClipboardTime'], function(options) {
        if (options.clearClipboard) {
          const timeInSeconds = parseInt(options.clearClipboardTime) || 30;
          setTimeout(() => {
            navigator.clipboard.writeText('').catch(err => {
              console.error('Could not clear clipboard:', err);
            });
            showToast('Clipboard cleared for security');
          }, timeInSeconds * 1000);
        }
      });
    });
    
    // Check with HIBP
    hibpButton.addEventListener('click', async () => {
      const passwordField = document.getElementById('generated-password');
      const hibpResult = document.getElementById('hibp-result');
      
      hibpResult.innerHTML = '<div style="text-align: center;">Checking database...</div>';
      hibpResult.classList.remove('hidden');
      
      const result = await hibpChecker.checkPassword(passwordField.value);
      
      if (result.isError) {
        hibpResult.innerHTML = '<div class="hibp-error">Error connecting to the database. Please try again later.</div>';
      } else if (result.isCompromised) {
        hibpResult.innerHTML = `
          <div class="hibp-compromised">
            WARNING: This password has been found in ${result.count.toLocaleString()} data breaches!
            <p>This password is not secure. Please generate a new one.</p>
          </div>
        `;
      } else {
        hibpResult.innerHTML = '<div class="hibp-safe">Good news! This password has not been found in any known data breaches.</div>';
      }
    });
    
    // Save password hash
    saveButton.addEventListener('click', async () => {
      const password = document.getElementById('generated-password').value;
      
      // Create save dialog
      const dialog = document.createElement('div');
      dialog.className = 'password-save-form';
      dialog.innerHTML = `
        <label for="save-name">Save as (e.g. "Gmail", "Bank"):</label>
        <input type="text" id="save-name" placeholder="Enter an identifier">
        <button id="confirm-save" class="action-button">Save Password Hash</button>
        <button id="cancel-save" class="action-button" style="background:#64748b;">Cancel</button>
      `;
      
      // Append dialog to container
      const container = document.querySelector('.container');
      container.appendChild(dialog);
      
      // Focus the input field
      document.getElementById('save-name').focus();
      
      // Handle confirm button
      document.getElementById('confirm-save').addEventListener('click', async () => {
        const identifier = document.getElementById('save-name').value.trim();
        
        if (!identifier) {
          showToast('Please enter an identifier');
          return;
        }
        
        try {
          // Get selected hash method from options
          const hashMethod = await new Promise(resolve => {
            chrome.storage.sync.get('hashAlgorithm', (data) => {
              resolve(data.hashAlgorithm || 'pbkdf2');
            });
          });
          
          // Hash the password
          const hashResult = await passwordHasher.storePassword(identifier, password, hashMethod);
          
          // Save to storage
          await passwordHasher.saveToStorage(identifier, hashResult);
          
          showToast('Password hash saved successfully!');
          container.removeChild(dialog);
        } catch (error) {
          console.error('Error saving password:', error);
          showToast('Error saving password hash');
        }
      });
      
      // Handle cancel button
      document.getElementById('cancel-save').addEventListener('click', () => {
        container.removeChild(dialog);
      });
    });
  }
  
  // Generate a password based on current settings
  function generatePassword() {
    const lengthSlider = document.getElementById('password-length');
    const useLowercase = document.getElementById('use-lowercase');
    const useUppercase = document.getElementById('use-uppercase');
    const useDigits = document.getElementById('use-digits');
    const useSpecial = document.getElementById('use-special');
    const passwordField = document.getElementById('generated-password');
    
    const options = {
      length: parseInt(lengthSlider.value),
      useLowercase: useLowercase.checked,
      useUppercase: useUppercase.checked,
      useDigits: useDigits.checked,
      useSpecial: useSpecial.checked
    };
    
    const password = passwordGenerator.generate(options);
    passwordField.value = password;
    
    // Update strength indicator
    updatePasswordStrength(password, 'strength-indicator', 'strength-text');
    
    // Auto-check with HIBP if enabled
    chrome.storage.sync.get('autoCheckHibp', (data) => {
      if (data.autoCheckHibp) {
        document.getElementById('check-hibp').click();
      }
    });
  }
  
  // Setup password analyzer functionality
  function setupPasswordAnalyzer() {
    const analyzeButton = document.getElementById('analyze-password');
    const passwordInput = document.getElementById('password-to-check');
    const toggleButton = document.getElementById('toggle-visibility');
    const hibpButton = document.getElementById('check-hibp-existing');
    
    // Analyze button click handler
    analyzeButton.addEventListener('click', () => {
      const password = passwordInput.value;
      if (!password) {
        showToast('Please enter a password to analyze');
        return;
      }
      
      const result = passwordStrengthChecker.checkStrength(password);
      displayAnalysisResults(result);
    });
    
    // Toggle password visibility
    toggleButton.addEventListener('click', () => {
      if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleButton.innerHTML = '<span class="icon">👁️‍🗨️</span>';
      } else {
        passwordInput.type = 'password';
        toggleButton.innerHTML = '<span class="icon">👁️</span>';
      }
    });
    
    // Check with HIBP
    hibpButton.addEventListener('click', async () => {
      const password = passwordInput.value;
      if (!password) {
        showToast('Please enter a password to check');
        return;
      }
      
      const hibpResult = document.getElementById('hibp-result-existing');
      
      hibpResult.innerHTML = '<div style="text-align: center;">Checking database...</div>';
      hibpResult.classList.remove('hidden');
      
      const result = await hibpChecker.checkPassword(password);
      
      if (result.isError) {
        hibpResult.innerHTML = '<div class="hibp-error">Error connecting to the database. Please try again later.</div>';
      } else if (result.isCompromised) {
        hibpResult.innerHTML = `
          <div class="hibp-compromised">
            WARNING: This password has been found in ${result.count.toLocaleString()} data breaches!
            <p>This password is not secure and should be changed immediately.</p>
          </div>
        `;
      } else {
        hibpResult.innerHTML = '<div class="hibp-safe">Good news! This password has not been found in any known data breaches.</div>';
      }
    });
  }
  
  // Display analysis results
  function displayAnalysisResults(result) {
    const analysisResult = document.getElementById('analysis-result');
    const analysisDetails = document.getElementById('analysis-details');
    const analysisFeedback = document.getElementById('analysis-feedback');
    
    analysisResult.classList.remove('hidden');
    
    // Update strength indicator
    updatePasswordStrength(null, 'analysis-strength-indicator', 'analysis-strength-text', result);
    
    // Display details
    analysisDetails.innerHTML = `
      <table class="details-table">
        <tr>
          <td>Length:</td>
          <td>${result.details.length} characters</td>
        </tr>
        <tr>
          <td>Uppercase Letters:</td>
          <td>${result.details.hasUppercase ? '<span class="check-icon">✓</span>' : '<span class="x-icon">✗</span>'}</td>
        </tr>
        <tr>
          <td>Lowercase Letters:</td>
          <td>${result.details.hasLowercase ? '<span class="check-icon">✓</span>' : '<span class="x-icon">✗</span>'}</td>
        </tr>
        <tr>
          <td>Numbers:</td>
          <td>${result.details.hasDigits ? '<span class="check-icon">✓</span>' : '<span class="x-icon">✗</span>'}</td>
        </tr>
        <tr>
          <td>Special Characters:</td>
          <td>${result.details.hasSpecial ? '<span class="check-icon">✓</span>' : '<span class="x-icon">✗</span>'}</td>
        </tr>
        <tr>
          <td>Entropy:</td>
          <td>${result.details.entropy.toFixed(2)} bits</td>
        </tr>
      </table>
    `;
    
    // Display feedback
    let feedbackHtml = '';
    result.feedback.forEach(item => {
      let cssClass = '';
      if (typeof item === 'object') {
        switch(item.type) {
          case 'good': cssClass = 'feedback-good'; break;
          case 'warning': cssClass = 'feedback-warning'; break;
          case 'bad': cssClass = 'feedback-bad'; break;
          case 'info': cssClass = 'feedback-info'; break;
        }
        feedbackHtml += `<div class="feedback-item ${cssClass}">${item.message}</div>`;
      } else {
        feedbackHtml += `<div class="feedback-item">${item}</div>`;
      }
    });
    analysisFeedback.innerHTML = feedbackHtml;
  }
  
  // Update password strength indicator
  function updatePasswordStrength(password, indicatorId, textId, existingResult = null) {
    const indicator = document.getElementById(indicatorId);
    const text = document.getElementById(textId);
    
    let result;
    if (existingResult) {
      result = existingResult;
    } else {
      result = passwordStrengthChecker.checkStrength(password);
    }
    
    // Remove all classes
    indicator.className = 'strength-indicator';
    
    // Add class based on strength
    let strengthClass;
    switch (result.strength) {
      case 'Very Strong': strengthClass = 'very-strong'; break;
      case 'Strong': strengthClass = 'strong'; break;
      case 'Moderate': strengthClass = 'moderate'; break;
      case 'Weak': strengthClass = 'weak'; break;
      default: strengthClass = 'very-weak';
    }
    
    indicator.classList.add(strengthClass);
    text.textContent = `${result.strength} (${result.score}/100)`;
  }
  
  // Setup options saving
  function setupOptionsSaving() {
    const saveButton = document.getElementById('save-options');
    
    saveButton.addEventListener('click', () => {
      const hashAlgorithm = document.getElementById('hash-algorithm').value;
      const pbkdf2Iterations = parseInt(document.getElementById('pbkdf2-iterations').value);
      const geminiApiKey = document.getElementById('gemini-api-key').value.trim();
      const autoCheckHibp = document.getElementById('auto-check-hibp').checked;
      const offerGeneration = document.getElementById('offer-generation').checked;
      const clearClipboard = document.getElementById('clear-clipboard').checked;
      const clearClipboardTime = document.getElementById('clear-clipboard-time').value;
      
      // Validate iterations
      if (pbkdf2Iterations < 10000) {
        showToast('PBKDF2 iterations must be at least 10,000');
        return;
      }
      
      chrome.storage.sync.set({
        hashAlgorithm,
        pbkdf2Iterations,
        geminiApiKey,
        autoCheckHibp,
        offerGeneration,
        clearClipboard,
        clearClipboardTime
      }, function() {
        showToast('Options saved!');
      });
    });
  }
  
  // Load saved options
  function loadOptions() {
    chrome.storage.sync.get({
      // Default values
      hashAlgorithm: 'pbkdf2',
      pbkdf2Iterations: 100000,
      geminiApiKey: '',
      autoCheckHibp: true,
      offerGeneration: true,
      clearClipboard: false,
      clearClipboardTime: '30'
    }, function(items) {
      document.getElementById('hash-algorithm').value = items.hashAlgorithm;
      document.getElementById('pbkdf2-iterations').value = items.pbkdf2Iterations;
      document.getElementById('gemini-api-key').value = items.geminiApiKey || '';
      document.getElementById('auto-check-hibp').checked = items.autoCheckHibp;
      document.getElementById('offer-generation').checked = items.offerGeneration;
      document.getElementById('clear-clipboard').checked = items.clearClipboard;
      document.getElementById('clear-clipboard-time').value = items.clearClipboardTime;
    });
  }
  
  // Show toast message
  function showToast(message) {
    // Remove existing toast if any
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
      document.body.removeChild(existingToast);
    }
    
    // Create new toast
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    
    // Show toast
    setTimeout(() => {
      toast.classList.add('show');
    }, 10);
    
    // Hide toast after 3 seconds
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => {
        if (document.body.contains(toast)) {
          document.body.removeChild(toast);
        }
      }, 300);
    }, 3000);
  }
  
  // Setup website credentials saving
  function setupCredentialsSaving() {
    const saveCredentialsButton = document.getElementById('save-credentials');
    
    saveCredentialsButton.addEventListener('click', async () => {
      const urlInput = document.getElementById('website-url');
      const usernameInput = document.getElementById('username');
      const passwordInput = document.getElementById('generated-password');
      
      const url = urlInput.value.trim();
      const username = usernameInput.value.trim();
      const password = passwordInput.value;
      
      if (!url) {
        showToast('Please enter a website URL');
        return;
      }
      
      if (!username) {
        showToast('Please enter a username or email');
        return;
      }
      
      if (!password) {
        showToast('No password generated');
        return;
      }
      
      try {
        // Encrypt password before storing
        const { key, salt } = await passwordHasher.hashPasswordPBKDF2(password);
        
        const credential = {
          url: url,
          username: username,
          encryptedPassword: { key, salt },
          createdAt: new Date().toISOString()
        };
        
        // Save to chrome storage
        await new Promise((resolve, reject) => {
          chrome.storage.sync.get('savedCredentials', (data) => {
            const savedCredentials = data.savedCredentials || {};
            const id = `cred_${Date.now()}`;
            savedCredentials[id] = credential;
            
            chrome.storage.sync.set({ savedCredentials }, () => {
              if (chrome.runtime.lastError) {
                reject(chrome.runtime.lastError);
              } else {
                resolve();
              }
            });
          });
        });
        
        showToast('Credentials saved successfully!');
        urlInput.value = '';
        usernameInput.value = '';
        
        // Refresh the passwords list if on that tab
        if (document.getElementById('passwords').classList.contains('active')) {
          loadSavedPasswords();
        }
        
      } catch (error) {
        console.error('Error saving credentials:', error);
        showToast('Failed to save credentials');
      }
    });
  }
  
  // Load saved passwords
  async function loadSavedPasswords() {
    const passwordListElement = document.getElementById('password-list');
    
    try {
      const data = await new Promise((resolve) => {
        chrome.storage.sync.get('savedCredentials', (data) => {
          resolve(data.savedCredentials || {});
        });
      });
      
      if (Object.keys(data).length === 0) {
        passwordListElement.innerHTML = '<div class="no-passwords-message">No saved passwords yet</div>';
        return;
      }
      
      let html = '';
      for (const [id, credential] of Object.entries(data)) {
        html += `
          <div class="password-item" data-id="${id}">
            <div class="password-item-title">${credential.username}</div>
            <div class="password-item-url">${credential.url}</div>
            <div class="password-item-actions">
              <button class="password-action-btn autofill">Autofill</button>
              <button class="password-action-btn copy">Copy Password</button>
              <button class="password-action-btn delete">Delete</button>
            </div>
          </div>
        `;
      }
      
      passwordListElement.innerHTML = html;
      
      // Add event listeners to buttons
      document.querySelectorAll('.password-action-btn.autofill').forEach(button => {
        button.addEventListener('click', async (e) => {
          const id = e.target.closest('.password-item').dataset.id;
          const credential = data[id];
          
          // Send message to content script to autofill
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tab) {
            chrome.tabs.sendMessage(tab.id, {
              action: 'autofill',
              data: {
                url: credential.url,
                username: credential.username
              }
            });
            
            // Retrieve and decrypt password
            await chrome.runtime.sendMessage({
              action: 'getPassword',
              id: id
            }, (response) => {
              if (response && response.success) {
                chrome.tabs.sendMessage(tab.id, {
                  action: 'fillPassword',
                  password: response.password
                });
              }
            });
            
            window.close(); // Close popup after autofill
          }
        });
      });
      
      document.querySelectorAll('.password-action-btn.copy').forEach(button => {
        button.addEventListener('click', async (e) => {
          const id = e.target.closest('.password-item').dataset.id;
          
          await chrome.runtime.sendMessage({
            action: 'getPassword',
            id: id
          }, (response) => {
            if (response && response.success) {
              navigator.clipboard.writeText(response.password);
              showToast('Password copied to clipboard!');
            } else {
              showToast('Failed to retrieve password');
            }
          });
        });
      });
      
      document.querySelectorAll('.password-action-btn.delete').forEach(button => {
        button.addEventListener('click', async (e) => {
          const id = e.target.closest('.password-item').dataset.id;
          
          if (confirm('Are you sure you want to delete this credential?')) {
            await chrome.storage.sync.get('savedCredentials', (data) => {
              const savedCredentials = data.savedCredentials || {};
              delete savedCredentials[id];
              
              chrome.storage.sync.set({ savedCredentials }, () => {
                loadSavedPasswords();
                showToast('Credential deleted');
              });
            });
          }
        });
      });
      
    } catch (error) {
      console.error('Error loading passwords:', error);
      passwordListElement.innerHTML = '<div class="error-message">Failed to load passwords</div>';
    }
  }
  
  // Initialize tab navigation
  function initializeTabs() {
    setupTabNavigation();
  }
  
  // Update init function to include new setup
  function init() {
    loadOptions();
    initializeTabs(); // Use initializeTabs instead of setupTabNavigation
    setupPasswordGenerator();
    setupPasswordAnalyzer();
    setupOptionsSaving();
    setupCredentialsSaving(); 
    generatePassword();
  }

  // Start
  init();
});
