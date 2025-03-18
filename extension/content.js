/**
 * SecurePass Extension - Content Script
 * Handles in-page password generation and autofill
 */

// Check for password fields and add generation button
function setupPasswordFields() {
  chrome.storage.sync.get('offerGeneration', (data) => {
    // If password generation in forms is disabled, don't proceed
    if (data.offerGeneration === false) return;
    
    // Find all password fields
    const passwordFields = document.querySelectorAll('input[type="password"]');
    
    passwordFields.forEach(field => {
      // Skip fields that already have our button
      if (field.dataset.securepassSetup) return;
      field.dataset.securepassSetup = 'true';
      
      // Create generation button
      const button = document.createElement('button');
      button.innerText = '🔒 Generate';
      button.style.position = 'absolute';
      button.style.fontSize = '12px';
      button.style.padding = '2px 8px';
      button.style.background = '#2563eb';
      button.style.color = 'white';
      button.style.border = 'none';
      button.style.borderRadius = '3px';
      button.style.cursor = 'pointer';
      button.style.zIndex = '10000';
      button.style.display = 'none';
      
      // Position button near the password field
      document.body.appendChild(button);
      
      // Show button when field is focused
      field.addEventListener('focus', () => {
        const rect = field.getBoundingClientRect();
        button.style.top = `${window.scrollY + rect.bottom + 5}px`;
        button.style.left = `${window.scrollX + rect.left}px`;
        button.style.display = 'block';
      });
      
      // Hide button when field loses focus
      field.addEventListener('blur', () => {
        // Small delay to allow button click
        setTimeout(() => {
          button.style.display = 'none';
        }, 200);
      });
      
      // Handle button click
      button.addEventListener('click', (e) => {
        e.preventDefault();
        
        // Show password generation options
        const rect = field.getBoundingClientRect();
        const tooltip = document.createElement('div');
        tooltip.className = 'password-gen-tooltip';
        tooltip.style.position = 'absolute';
        tooltip.style.top = `${window.scrollY + rect.bottom + 35}px`;
        tooltip.style.left = `${window.scrollX + rect.left}px`;
        tooltip.style.background = 'white';
        tooltip.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.2)';
        tooltip.style.padding = '10px';
        tooltip.style.borderRadius = '5px';
        tooltip.style.zIndex = '10001';
        
        tooltip.innerHTML = `
          <div style="font-weight: bold; margin-bottom: 8px;">Generate Password</div>
          <div style="margin-bottom: 8px;">
            <label style="display: block; margin-bottom: 5px;">Length:
              <input type="range" id="pass-length" min="8" max="32" value="16" style="width: 100%">
              <span id="length-value">16</span>
            </label>
          </div>
          <div style="margin-bottom: 8px;">
            <label><input type="checkbox" id="use-lowercase" checked> a-z</label>
            <label style="margin-left: 8px;"><input type="checkbox" id="use-uppercase" checked> A-Z</label>
            <label style="margin-left: 8px;"><input type="checkbox" id="use-digits" checked> 0-9</label>
            <label style="margin-left: 8px;"><input type="checkbox" id="use-special" checked> !@#</label>
          </div>
          <div style="display: flex; justify-content: space-between; margin-top: 10px;">
            <button id="generate-btn" style="background: #2563eb; color: white; border: none; border-radius: 3px; padding: 5px 10px; cursor: pointer;">Generate</button>
            <button id="cancel-btn" style="background: #6b7280; color: white; border: none; border-radius: 3px; padding: 5px 10px; cursor: pointer;">Cancel</button>
          </div>
        `;
        
        document.body.appendChild(tooltip);
        
        // Update length value display when slider changes
        const lengthSlider = document.getElementById('pass-length');
        const lengthValue = document.getElementById('length-value');
        lengthSlider.addEventListener('input', () => {
          lengthValue.textContent = lengthSlider.value;
        });
        
        // Handle generate button click
        document.getElementById('generate-btn').addEventListener('click', () => {
          const length = parseInt(lengthSlider.value);
          const useLowercase = document.getElementById('use-lowercase').checked;
          const useUppercase = document.getElementById('use-uppercase').checked;
          const useDigits = document.getElementById('use-digits').checked;
          const useSpecial = document.getElementById('use-special').checked;
          
          chrome.runtime.sendMessage({
            action: 'generatePassword',
            options: {
              length,
              useLowercase,
              useUppercase,
              useDigits,
              useSpecial
            }
          }, (response) => {
            if (response && response.success) {
              field.value = response.password;
              // Trigger input event to notify the page that the field has changed
              field.dispatchEvent(new Event('input', { bubbles: true }));
              field.dispatchEvent(new Event('change', { bubbles: true }));
              
              // Show save credentials dialog
              const url = window.location.origin;
              
              // Get username from likely field
              const usernameField = findUsernameField(field);
              const username = usernameField ? usernameField.value : '';
              
              if (url && username) {
                const saveDialog = document.createElement('div');
                saveDialog.style.position = 'fixed';
                saveDialog.style.top = '20px';
                saveDialog.style.right = '20px';
                saveDialog.style.background = 'white';
                saveDialog.style.padding = '15px';
                saveDialog.style.borderRadius = '5px';
                saveDialog.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.2)';
                saveDialog.style.zIndex = '10002';
                
                saveDialog.innerHTML = `
                  <div style="margin-bottom: 10px;">
                    <strong>Save credentials for ${new URL(url).hostname}?</strong>
                  </div>
                  <div style="margin-bottom: 5px;">Username: ${username}</div>
                  <div style="display: flex; justify-content: space-between;">
                    <button id="save-creds-btn" style="background: #2563eb; color: white; border: none; border-radius: 3px; padding: 5px 10px; cursor: pointer;">Save</button>
                    <button id="dismiss-save-btn" style="background: #6b7280; color: white; border: none; border-radius: 3px; padding: 5px 10px; cursor: pointer;">Dismiss</button>
                  </div>
                `;
                
                document.body.appendChild(saveDialog);
                
                document.getElementById('save-creds-btn').addEventListener('click', () => {
                  chrome.runtime.sendMessage({
                    action: 'saveCredentials',
                    data: {
                      url,
                      username,
                      password: response.password
                    }
                  });
                  
                  document.body.removeChild(saveDialog);
                });
                
                document.getElementById('dismiss-save-btn').addEventListener('click', () => {
                  document.body.removeChild(saveDialog);
                });
                
                // Auto close after 10 seconds
                setTimeout(() => {
                  if (document.body.contains(saveDialog)) {
                    document.body.removeChild(saveDialog);
                  }
                }, 10000);
              }
            }
            
            document.body.removeChild(tooltip);
          });
        });
        
        // Handle cancel button click
        document.getElementById('cancel-btn').addEventListener('click', () => {
          document.body.removeChild(tooltip);
        });
      });
    });
  });
}

// Find likely username field based on password field location
function findUsernameField(passwordField) {
  // Try to find a username field that's in the same form
  if (passwordField.form) {
    const inputs = passwordField.form.querySelectorAll('input[type="text"], input[type="email"]');
    for (const input of inputs) {
      if (input.offsetTop < passwordField.offsetTop) {
        return input;
      }
    }
  }
  
  // If no form or no username field in form, look for nearby input fields
  const possibleFields = document.querySelectorAll('input[type="text"], input[type="email"]');
  
  for (const field of possibleFields) {
    // Check if this field is visually above the password field
    if (field.offsetTop < passwordField.offsetTop && 
        Math.abs(field.offsetLeft - passwordField.offsetLeft) < 100) {
      return field;
    }
  }
  
  return null;
}

// Handle messages from popup or background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'autofill') {
    // Find username field and fill it
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length === 0) return;
    
    // Use the first password field and find its username field
    const passwordField = passwordFields[0];
    const usernameField = findUsernameField(passwordField);
    
    if (usernameField) {
      usernameField.value = message.data.username;
      usernameField.dispatchEvent(new Event('input', { bubbles: true }));
      usernameField.dispatchEvent(new Event('change', { bubbles: true }));
    }
    
    sendResponse({ success: true });
  }
  
  if (message.action === 'fillPassword') {
    // Fill password field
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length === 0) return;
    
    // Use the first password field
    const passwordField = passwordFields[0];
    passwordField.value = message.password;
    passwordField.dispatchEvent(new Event('input', { bubbles: true }));
    passwordField.dispatchEvent(new Event('change', { bubbles: true }));
    
    sendResponse({ success: true });
  }
});

// Run on page load
setupPasswordFields();

// Also set up a mutation observer to handle dynamically added fields
const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    if (mutation.addedNodes.length) {
      setupPasswordFields();
    }
  }
});

observer.observe(document.body, { childList: true, subtree: true });
