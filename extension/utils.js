/**
 * Password Generator and Analyzer utilities
 * Ported from Python implementation to JavaScript
 */

class PasswordGenerator {
  constructor() {
    this.charSets = {
      lowercase: 'abcdefghijklmnopqrstuvwxyz',
      uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      digits: '0123456789',
      special: '!@#$%^&*()_+-=[]{}|;:,.<>?/~`'
    };
  }

  generate(options = {}) {
    const {
      length = 16,
      useLowercase = true,
      useUppercase = true,
      useDigits = true,
      useSpecial = true
    } = options;

    // Validate length
    let passwordLength = Math.max(8, length);

    // Validate char types
    const useChars = {
      lowercase: useLowercase,
      uppercase: useUppercase,
      digits: useDigits,
      special: useSpecial
    };
    
    // If no char type selected, use all
    if (!Object.values(useChars).some(val => val)) {
      Object.keys(useChars).forEach(key => useChars[key] = true);
    }

    // Build character pool
    let charPool = '';
    if (useChars.lowercase) charPool += this.charSets.lowercase;
    if (useChars.uppercase) charPool += this.charSets.uppercase;
    if (useChars.digits) charPool += this.charSets.digits;
    if (useChars.special) charPool += this.charSets.special;

    // Ensure at least one of each selected char type
    const password = [];
    const selectedTypes = Object.keys(useChars).filter(key => useChars[key]);
    
    for (const type of selectedTypes) {
      const char = this.getRandomChar(this.charSets[type]);
      password.push(char);
    }

    // Fill remaining with random chars
    const remainingLength = passwordLength - password.length;
    for (let i = 0; i < remainingLength; i++) {
      password.push(this.getRandomChar(charPool));
    }

    // Shuffle the password characters
    return this.shuffleArray(password).join('');
  }

  getRandomChar(charSet) {
    return charSet[Math.floor(Math.random() * charSet.length)];
  }

  shuffleArray(array) {
    const newArray = [...array];
    for (let i = newArray.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [newArray[i], newArray[j]] = [newArray[j], newArray[i]];
    }
    return newArray;
  }
}

class PasswordStrengthChecker {
  constructor() {
    this.commonPasswords = [
      'password', '123456', 'qwerty', 'admin', 'welcome',
      'login', 'abc123', 'admin123', 'letmein', '123456789',
      'password1', '12345678', 'football', 'iloveyou', 'monkey',
      '654321', 'sunshine', 'master', '666666', '1234567890'
    ];
    
    this.keyboardPatterns = [
      'qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '1qaz2wsx',
      'qwertyuiop', 'asdfghjkl', 'zxcvbnm'
    ];
    
    this.commonSequences = [
      '123', '321', 'abc', 'cba', 'xyz', 'zyx',
      'qwe', 'ewq', 'asd', 'dsa', 'zxc', 'cxz'
    ];
  }

  checkStrength(password) {
    if (!password) {
      return {
        score: 0,
        strength: 'Very Weak',
        feedback: [{type: 'bad', message: "Password is empty"}],
        details: {
          length: 0,
          hasUppercase: false,
          hasLowercase: false,
          hasDigits: false,
          hasSpecial: false,
          entropy: 0
        }
      };
    }
    
    // Check password characteristics
    const length = password.length;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasDigits = /[0-9]/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);
    
    const entropy = this.calculateEntropy(password);
    
    let feedback = [];
    let score = 0;
    
    // Length check
    if (length < 8) {
      feedback.push({
        type: 'bad',
        message: 'Password is too short (minimum 8 characters recommended)'
      });
    } else if (length >= 12) {
      feedback.push({
        type: 'good',
        message: 'Good password length (12+ characters)'
      });
      score += 25;
    } else {
      feedback.push({
        type: 'warning',
        message: 'Acceptable password length (8-11 characters)'
      });
      score += 15;
    }
    
    // Character variety
    let varietyScore = 0;
    if (hasUppercase) varietyScore += 10;
    if (hasLowercase) varietyScore += 10;
    if (hasDigits) varietyScore += 10;
    if (hasSpecial) varietyScore += 15;
    
    if (varietyScore >= 35) {
      feedback.push({
        type: 'good',
        message: 'Excellent character variety'
      });
    } else if (varietyScore >= 20) {
      feedback.push({
        type: 'warning',
        message: 'Moderate character variety - consider adding more types'
      });
    } else {
      feedback.push({
        type: 'bad',
        message: 'Poor character variety - use a mix of uppercase, lowercase, numbers, and symbols'
      });
    }
    score += varietyScore;
    
    // Check for common passwords
    if (this.commonPasswords.includes(password.toLowerCase())) {
      feedback.push({
        type: 'bad',
        message: 'This is a commonly used password and can be easily guessed'
      });
      score = Math.max(score - 40, 0);
    }
    
    // Check for keyboard patterns
    if (this.keyboardPatterns.some(pattern => password.toLowerCase().includes(pattern))) {
      feedback.push({
        type: 'bad',
        message: 'Contains keyboard pattern which weakens security'
      });
      score = Math.max(score - 20, 0);
    }
    
    // Check for common sequences
    if (this.commonSequences.some(seq => password.toLowerCase().includes(seq))) {
      feedback.push({
        type: 'warning',
        message: 'Contains predictable sequence of characters'
      });
      score = Math.max(score - 15, 0);
    }
    
    // Check for repeated characters
    if (/(.)\1{2,}/.test(password)) {
      feedback.push({
        type: 'warning',
        message: 'Contains repeated character sequences'
      });
      score = Math.max(score - 10, 0);
    }
    
    // Entropy scoring
    if (entropy > 60) {
      score += 20;
      feedback.push({
        type: 'good',
        message: 'High entropy - password has excellent randomness'
      });
    } else if (entropy > 40) {
      score += 10;
      feedback.push({
        type: 'good',
        message: 'Good entropy - password has good randomness'
      });
    } else {
      feedback.push({
        type: 'warning',
        message: 'Low entropy - password is not random enough'
      });
    }
    
    // Determine strength category
    let strength;
    if (score >= 80) {
      strength = 'Very Strong';
    } else if (score >= 60) {
      strength = 'Strong';
    } else if (score >= 40) {
      strength = 'Moderate';
    } else if (score >= 20) {
      strength = 'Weak';
    } else {
      strength = 'Very Weak';
    }
    
    score = Math.min(100, score);
    
    if (score < 80) {
      feedback.push({
        type: 'info',
        message: this.generateRecommendation(hasUppercase, hasLowercase, hasDigits, hasSpecial, length)
      });
    }
    
    return {
      score,
      strength,
      feedback,
      details: {
        length,
        hasUppercase,
        hasLowercase,
        hasDigits,
        hasSpecial,
        entropy
      }
    };
  }

  calculateEntropy(password) {
    if (!password) return 0;
    
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;
    
    return password.length * Math.log2(poolSize || 1);
  }

  generateRecommendation(hasUpper, hasLower, hasDigits, hasSpecial, length) {
    const recommendation = 'Consider improving your password by: ';
    const improvements = [];
    
    if (length < 12) improvements.push('increasing length to at least 12 characters');
    if (!hasUpper) improvements.push('adding uppercase letters');
    if (!hasLower) improvements.push('adding lowercase letters');
    if (!hasDigits) improvements.push('adding numbers');
    if (!hasSpecial) improvements.push('adding special characters');
    
    if (improvements.length === 0) {
      return 'Try adding more random characters to further strengthen your password';
    }
    
    return recommendation + improvements.join(', ');
  }
}

class HIBPChecker {
  async checkPassword(password) {
    try {
      const sha1Hash = await this.sha1(password);
      const prefix = sha1Hash.substring(0, 5);
      const suffix = sha1Hash.substring(5);
      
      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: {
          'User-Agent': 'SecurePass-Browser-Extension'
        }
      });
      
      if (!response.ok) {
        throw new Error(`HIBP API error: ${response.status}`);
      }
      
      const text = await response.text();
      const lines = text.split('\n');
      
      for (const line of lines) {
        const [hashSuffix, count] = line.split(':');
        if (hashSuffix.toLowerCase() === suffix.toLowerCase()) {
          return { isCompromised: true, count: parseInt(count), isError: false };
        }
      }
      
      return { isCompromised: false, count: 0, isError: false };
    } catch (error) {
      console.error('HIBP check error:', error);
      return { isCompromised: false, count: 0, isError: true };
    }
  }
  
  async sha1(str) {
    const msgBuffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }
}

class PasswordHasher {
  constructor() {
    this.storedHashes = {};
    // Load bcrypt or equivalent library in real implementation
    // For browser extension, we can use SubtleCrypto for PBKDF2
  }
  
  async hashPasswordPBKDF2(password, iterations = 100000) {
    try {
      const encoder = new TextEncoder();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );
      
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt']
      );
      
      const exportedKey = await crypto.subtle.exportKey('raw', key);
      const keyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedKey)));
      const saltBase64 = btoa(String.fromCharCode(...new Uint8Array(salt)));
      
      return { key: keyBase64, salt: saltBase64 };
    } catch (error) {
      console.error('PBKDF2 hashing error:', error);
      throw error;
    }
  }
  
  async storePassword(identifier, password, method = 'pbkdf2') {
    if (method === 'pbkdf2') {
      const { key, salt } = await this.hashPasswordPBKDF2(password);
      const result = { method: 'pbkdf2', key, salt };
      this.storedHashes[identifier] = result;
      return result;
    } else {
      throw new Error('Only PBKDF2 is supported in the browser extension');
    }
  }
  
  async saveToStorage(identifier, hashResult) {
    try {
      const storageKey = `secure_pass_${identifier}`;
      await chrome.storage.sync.set({ [storageKey]: hashResult });
      return true;
    } catch (error) {
      console.error('Error saving hash to storage:', error);
      return false;
    }
  }
}

// Export the classes
window.PasswordGenerator = PasswordGenerator;
window.PasswordStrengthChecker = PasswordStrengthChecker;
window.HIBPChecker = HIBPChecker;
window.PasswordHasher = PasswordHasher;
