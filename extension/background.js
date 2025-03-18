/**
 * SecurePass Extension - Background Service Worker
 * Handles background tasks and API communication
 */

// Listen for installation
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    // Set up default settings on install
    chrome.storage.sync.set({
      hashAlgorithm: 'pbkdf2',
      pbkdf2Iterations: 100000,
      autoCheckHibp: true,
      clearClipboard: false,
      clearClipboardTime: '30',
      savedPasswords: {}
    });
  }
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkHIBP') {
    checkHaveIBeenPwned(message.password)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ isError: true, error: error.message }));
    return true; // Keep the message channel open for async response
  }
  
  if (message.action === 'getPasswordList') {
    getPasswordList()
      .then(list => sendResponse(list))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }
  
  if (message.action === 'deletePassword') {
    deletePassword(message.identifier)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
  
  // Handle password decryption and retrieval
  if (message.action === 'getPassword') {
    getDecryptedPassword(message.id)
      .then(password => sendResponse({ success: true, password }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
  
  // Handle password generation request from content script
  if (message.action === 'generatePassword') {
    generatePassword(message.options)
      .then(password => sendResponse({ success: true, password }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
  
  // Handle credential saving from content script
  if (message.action === 'saveCredentials') {
    saveCredentialsToStorage(message.data)
      .then(result => sendResponse({ success: true }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
});

// Helper function for HIBP check
async function checkHaveIBeenPwned(password) {
  try {
    // Calculate SHA-1 hash
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    
    // Split the hash for k-anonymity
    const prefix = hashHex.substring(0, 5);
    const suffix = hashHex.substring(5);
    
    // Send request to HIBP API
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: {
        'User-Agent': 'SecurePass-Browser-Extension'
      }
    });
    
    if (!response.ok) {
      throw new Error(`API request failed with status: ${response.status}`);
    }
    
    const text = await response.text();
    const lines = text.split('\n');
    
    // Check if the hash suffix is in the response
    for (const line of lines) {
      const [hashSuffix, count] = line.split(':');
      if (hashSuffix.toUpperCase() === suffix) {
        return { isCompromised: true, count: parseInt(count), isError: false };
      }
    }
    
    return { isCompromised: false, count: 0, isError: false };
  } catch (error) {
    console.error('HIBP check error:', error);
    return { isCompromised: false, count: 0, isError: true, errorMessage: error.message };
  }
}

// Get list of saved password identifiers
async function getPasswordList() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(null, (items) => {
      const passwordList = [];
      for (const key in items) {
        if (key.startsWith('secure_pass_')) {
          passwordList.push({
            identifier: key.replace('secure_pass_', ''),
            method: items[key].method,
            createdAt: items[key].createdAt || new Date().toISOString()
          });
        }
      }
      resolve(passwordList);
    });
  });
}

// Delete a stored password hash
async function deletePassword(identifier) {
  return new Promise((resolve, reject) => {
    const storageKey = `secure_pass_${identifier}`;
    chrome.storage.sync.remove(storageKey, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve({ success: true });
      }
    });
  });
}

// Get decrypted password from storage
async function getDecryptedPassword(id) {
  const data = await new Promise((resolve, reject) => {
    chrome.storage.sync.get('savedCredentials', (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(result.savedCredentials || {});
      }
    });
  });
  
  const credential = data[id];
  if (!credential) {
    throw new Error('Credential not found');
  }
  
  // This is a simplified approach - in a real implementation, 
  // you would need to properly decrypt the password using the encryption key
  // For this demo, we'll just simulate retrieving the password
  
  // In reality, we'd use something like:
  // return decryptPassword(credential.encryptedPassword.key, credential.encryptedPassword.salt);
  
  // For now, return a placeholder since we don't have the actual encryption implemented
  return "••••••••"; // Placeholder for actual decryption logic
}

// Generate a password with the specified options
async function generatePassword(options = {}) {
  const defaults = {
    length: 16,
    useLowercase: true,
    useUppercase: true,
    useDigits: true,
    useSpecial: true
  };
  
  const config = { ...defaults, ...options };
  
  // Define character sets
  const charSets = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    special: '!@#$%^&*()_+-=[]{}|;:,.<>?/~`'
  };
  
  let charPool = '';
  if (config.useLowercase) charPool += charSets.lowercase;
  if (config.useUppercase) charPool += charSets.uppercase;
  if (config.useDigits) charPool += charSets.digits;
  if (config.useSpecial) charPool += charSets.special;
  
  // Ensure we have at least one character type
  if (charPool === '') {
    charPool = charSets.lowercase + charSets.uppercase + charSets.digits + charSets.special;
  }
  
  // Generate password
  const password = [];
  
  // Ensure at least one character of each type if selected
  if (config.useLowercase) {
    password.push(charSets.lowercase[Math.floor(Math.random() * charSets.lowercase.length)]);
  }
  if (config.useUppercase) {
    password.push(charSets.uppercase[Math.floor(Math.random() * charSets.uppercase.length)]);
  }
  if (config.useDigits) {
    password.push(charSets.digits[Math.floor(Math.random() * charSets.digits.length)]);
  }
  if (config.useSpecial) {
    password.push(charSets.special[Math.floor(Math.random() * charSets.special.length)]);
  }
  
  // Fill the rest with random characters
  const remainingLength = Math.max(0, config.length - password.length);
  for (let i = 0; i < remainingLength; i++) {
    password.push(charPool[Math.floor(Math.random() * charPool.length)]);
  }
  
  // Shuffle the password
  for (let i = password.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [password[i], password[j]] = [password[j], password[i]];
  }
  
  return password.join('');
}

// Save credentials to storage
async function saveCredentialsToStorage(data) {
  return new Promise((resolve, reject) => {
    chrome.storage.sync.get('savedCredentials', (result) => {
      const savedCredentials = result.savedCredentials || {};
      const id = `cred_${Date.now()}`;
      
      // In a real implementation, we would encrypt the password here
      savedCredentials[id] = {
        url: data.url,
        username: data.username,
        encryptedPassword: { 
          // Simulate encryption - in a real implementation this would be encrypted
          key: btoa(data.password),
          salt: btoa(Math.random().toString())
        },
        createdAt: new Date().toISOString()
      };
      
      chrome.storage.sync.set({ savedCredentials }, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve({ success: true });
        }
      });
    });
  });
}
