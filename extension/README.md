# SecurePass Browser Extension

A robust password generator and strength checker with advanced security features.

## Features

- **Strong Password Generator**: Create secure passwords with customizable options
- **Password Strength Analyzer**: Check how strong your passwords are
- **Breach Database Check**: Verify if your password has been found in known data breaches
- **Secure Hashing**: Store password hashes securely using PBKDF2
- **Security Insights**: Get detailed feedback on improving your password security

## Installation

### Developer Mode
1. Download or clone this repository
2. Open Chrome/Edge and navigate to `chrome://extensions`
3. Enable "Developer mode" in the top right corner
4. Click "Load unpacked" and select the extension directory
5. The SecurePass extension should now appear in your toolbar

### From Chrome Web Store
*(Coming soon)*

## Using the Extension

### Generate Passwords
1. Click on the SecurePass icon in your browser toolbar
2. Use the sliders and checkboxes to customize your password
3. Click the refresh button to generate a new password
4. Click the copy button to copy the password to your clipboard

### Analyze Passwords
1. Click on the "Analyze" tab
2. Enter the password you want to analyze
3. Click "Analyze Password" to see detailed strength information
4. Click "Check Have I Been Pwned" to verify if the password has been compromised

### Settings
1. Click on the "Options" tab
2. Customize security settings:
   - Hashing algorithm parameters
   - Auto-check with Have I Been Pwned
   - Clipboard security settings

## Security Notes

- This extension never sends your plaintext passwords to any server
- All password checks are performed using k-anonymity (only the first 5 characters of a hashed password are sent)
- All password hashing is performed locally in your browser
- Saved password hashes are stored in your browser's secure storage

## Development

This extension is built with vanilla JavaScript, HTML, and CSS with no external dependencies.

```
extension/
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
├── background.js
├── manifest.json
├── popup.css
├── popup.html
├── popup.js
└── utils.js
```

## License

MIT License
