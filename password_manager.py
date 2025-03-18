import string
import random
import hashlib
import requests
import re
import math
import time
from typing import Dict, List, Tuple, Optional, Any
import argparse
import getpass
import google.generativeai as genai
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress
import os
import base64
from dotenv import load_dotenv
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

load_dotenv()

console = Console()

class PasswordGenerator:
    def __init__(self):
        self.char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'special': '!@#$%^&*()_+-=[]{}|;:,.<>?/~`'
        }
    
    def generate(self, length: int = 16, 
                 use_lowercase: bool = True,
                 use_uppercase: bool = True, 
                 use_digits: bool = True,
                 use_special: bool = True) -> str:
        if length < 8:
            console.print("[yellow]Warning: Short passwords are less secure. Using minimum length of 8.[/yellow]")
            length = 8
            
        if not any([use_lowercase, use_uppercase, use_digits, use_special]):
            console.print("[yellow]Warning: No character types selected. Using all character types.[/yellow]")
            use_lowercase = use_uppercase = use_digits = use_special = True
        
        char_pool = ""
        if use_lowercase:
            char_pool += self.char_sets['lowercase']
        if use_uppercase:
            char_pool += self.char_sets['uppercase']
        if use_digits:
            char_pool += self.char_sets['digits']
        if use_special:
            char_pool += self.char_sets['special']
        
        password = []
        if use_lowercase:
            password.append(random.choice(self.char_sets['lowercase']))
        if use_uppercase:
            password.append(random.choice(self.char_sets['uppercase']))
        if use_digits:
            password.append(random.choice(self.char_sets['digits']))
        if use_special:
            password.append(random.choice(self.char_sets['special']))
            
        remaining_length = length - len(password)
        password.extend(random.choices(char_pool, k=remaining_length))
        
        random.shuffle(password)
        
        return ''.join(password)


class PasswordHasher:
    def __init__(self):
        self.stored_hashes = {}
    
    def hash_password_bcrypt(self, password: str, rounds: int = 12) -> str:
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    
    def verify_bcrypt(self, password: str, hashed_password: str) -> bool:
        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    
    def hash_password_pbkdf2(self, password: str, iterations: int = 100000) -> Tuple[str, str]:
        salt = os.urandom(16)
        password_bytes = password.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        
        key = kdf.derive(password_bytes)
        key_b64 = base64.b64encode(key).decode('utf-8')
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        
        return key_b64, salt_b64
    
    def verify_pbkdf2(self, password: str, stored_key: str, stored_salt: str, iterations: int = 100000) -> bool:
        password_bytes = password.encode('utf-8')
        key = base64.b64decode(stored_key)
        salt = base64.b64decode(stored_salt)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        
        try:
            kdf.verify(password_bytes, key)
            return True
        except Exception:
            return False
    
    def store_password(self, identifier: str, password: str, method: str = "bcrypt") -> Dict[str, Any]:
        if method == "bcrypt":
            hashed = self.hash_password_bcrypt(password)
            result = {"method": "bcrypt", "hash": hashed}
            self.stored_hashes[identifier] = result
            return result
        elif method == "pbkdf2":
            key, salt = self.hash_password_pbkdf2(password)
            result = {"method": "pbkdf2", "key": key, "salt": salt}
            self.stored_hashes[identifier] = result
            return result
        else:
            raise ValueError("Unknown hashing method")
    
    def verify_password(self, identifier: str, password: str) -> bool:
        if identifier not in self.stored_hashes:
            return False
        
        stored = self.stored_hashes[identifier]
        
        if stored["method"] == "bcrypt":
            return self.verify_bcrypt(password, stored["hash"])
        elif stored["method"] == "pbkdf2":
            return self.verify_pbkdf2(password, stored["key"], stored["salt"])
        else:
            return False
    
    def save_to_file(self, password: str, method: str, filename: str = None) -> str:
        if filename is None:
            filename = f"password_{int(time.time())}.txt"
        
        hash_result = self.store_password("file_save", password, method)
        
        try:
            with open(filename, 'w') as f:
                f.write(f"Generated Password Hash\n")
                f.write(f"----------------------\n")
                f.write(f"Algorithm: {method.upper()}\n")
                
                if method == "bcrypt":
                    f.write(f"Hash: {hash_result['hash']}\n")
                elif method == "pbkdf2":
                    f.write(f"Key: {hash_result['key']}\n")
                    f.write(f"Salt: {hash_result['salt']}\n")
                
                f.write(f"\nGenerated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            return filename
        except Exception as e:
            console.print(f"[red]Error saving to file: {str(e)}[/red]")
            return None


class HIBPChecker:
    def __init__(self):
        self.api_url = "https://api.pwnedpasswords.com/range/"
        self.headers = {
            "User-Agent": "Password-Strength-Tool-Python"
        }
    
    def check_password(self, password: str) -> Tuple[bool, int, bool]:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        try:
            with console.status("[bold blue]Checking if password has been compromised...[/bold blue]"):
                response = requests.get(f"{self.api_url}{prefix}", headers=self.headers)
                response.raise_for_status()
                
                hash_counts = {}
                for line in response.text.splitlines():
                    hash_suffix, count = line.split(':')
                    hash_counts[hash_suffix] = int(count)
                
                if suffix in hash_counts:
                    return True, hash_counts[suffix], False
                return False, 0, False
                
        except Exception as e:
            return False, 0, True


class PasswordStrengthChecker:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'login', 'abc123', 'admin123', 'letmein', '123456789',
            'password1', '12345678', 'football', 'iloveyou', 'monkey',
            '654321', 'sunshine', 'master', '666666', '1234567890'
        ]
        
        self.keyboard_patterns = [
            'qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '1qaz2wsx',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm'
        ]
        
        self.common_sequences = [
            '123', '321', 'abc', 'cba', 'xyz', 'zyx',
            'qwe', 'ewq', 'asd', 'dsa', 'zxc', 'cxz'
        ]
    
    def check_strength(self, password: str) -> Dict[str, Any]:
        if not password:
            return {
                'score': 0,
                'strength': 'Very Weak',
                'feedback': ["Password is empty"],
                'details': {
                    'length': 0,
                    'has_uppercase': False,
                    'has_lowercase': False,
                    'has_digits': False,
                    'has_special': False,
                    'entropy': 0
                }
            }
        
        length = len(password)
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_digits = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))
        
        entropy = self._calculate_entropy(password)
        
        feedback = []
        score = 0
        
        if length < 8:
            feedback.append({
                'type': 'bad',
                'message': 'Password is too short (minimum 8 characters recommended)'
            })
        elif length >= 12:
            feedback.append({
                'type': 'good',
                'message': 'Good password length (12+ characters)'
            })
            score += 25
        else:
            feedback.append({
                'type': 'warning',
                'message': 'Acceptable password length (8-11 characters)'
            })
            score += 15
        
        variety_score = 0
        if has_uppercase:
            variety_score += 10
        if has_lowercase:
            variety_score += 10
        if has_digits:
            variety_score += 10
        if has_special:
            variety_score += 15
        
        if variety_score >= 35:
            feedback.append({
                'type': 'good',
                'message': 'Excellent character variety'
            })
        elif variety_score >= 20:
            feedback.append({
                'type': 'warning',
                'message': 'Moderate character variety - consider adding more types'
            })
        else:
            feedback.append({
                'type': 'bad',
                'message': 'Poor character variety - use a mix of uppercase, lowercase, numbers, and symbols'
            })
        score += variety_score
        
        if password.lower() in self.common_passwords:
            feedback.append({
                'type': 'bad',
                'message': 'This is a commonly used password and can be easily guessed'
            })
            score = max(score - 40, 0)
        
        if any(pattern in password.lower() for pattern in self.keyboard_patterns):
            feedback.append({
                'type': 'bad',
                'message': 'Contains keyboard pattern which weakens security'
            })
            score = max(score - 20, 0)
        
        if any(seq in password.lower() for seq in self.common_sequences):
            feedback.append({
                'type': 'warning',
                'message': 'Contains predictable sequence of characters'
            })
            score = max(score - 15, 0)
        
        if re.search(r'(.)\1{2,}', password):
            feedback.append({
                'type': 'warning',
                'message': 'Contains repeated character sequences'
            })
            score = max(score - 10, 0)
        
        if entropy > 60:
            score += 20
            feedback.append({
                'type': 'good',
                'message': 'High entropy - password has excellent randomness'
            })
        elif entropy > 40:
            score += 10
            feedback.append({
                'type': 'good',
                'message': 'Good entropy - password has good randomness'
            })
        else:
            feedback.append({
                'type': 'warning',
                'message': 'Low entropy - password is not random enough'
            })
        
        if score >= 80:
            strength = 'Very Strong'
        elif score >= 60:
            strength = 'Strong'
        elif score >= 40:
            strength = 'Moderate'
        elif score >= 20:
            strength = 'Weak'
        else:
            strength = 'Very Weak'
        
        score = min(100, score)
        
        if score < 80:
            feedback.append({
                'type': 'info',
                'message': self._generate_recommendation(has_uppercase, has_lowercase, has_digits, has_special, length)
            })
        
        return {
            'score': score,
            'strength': strength,
            'feedback': feedback,
            'details': {
                'length': length,
                'has_uppercase': has_uppercase,
                'has_lowercase': has_lowercase,
                'has_digits': has_digits,
                'has_special': has_special,
                'entropy': entropy
            }
        }
    
    def _calculate_entropy(self, password: str) -> float:
        if not password:
            return 0
        
        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += 26
        if re.search(r'[A-Z]', password):
            pool_size += 26
        if re.search(r'[0-9]', password):
            pool_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            pool_size += 33
        
        entropy = len(password) * math.log2(pool_size or 1)
        return entropy
    
    def _generate_recommendation(self, has_upper: bool, has_lower: bool, 
                               has_digits: bool, has_special: bool, length: int) -> str:
        recommendation = 'Consider improving your password by: '
        improvements = []
        
        if length < 12:
            improvements.append('increasing length to at least 12 characters')
        if not has_upper:
            improvements.append('adding uppercase letters')
        if not has_lower:
            improvements.append('adding lowercase letters')
        if not has_digits:
            improvements.append('adding numbers')
        if not has_special:
            improvements.append('adding special characters')
        
        if not improvements:
            return 'Try adding more random characters to further strengthen your password'
        
        return recommendation + ', '.join(improvements)


class GeminiPasswordAnalyzer:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            console.print("[yellow]Warning: Gemini API key not found. Advanced analysis will be disabled.[/yellow]")
            self.enabled = False
            return
        
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash-latest')
            self.enabled = True
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to initialize Gemini API: {str(e)}[/yellow]")
            self.enabled = False
    
    def analyze_password_policy(self, password_info: Dict) -> Optional[Dict]:
        if not self.enabled:
            return None
        
        try:
            prompt = f"""
            I need you to analyze this password information (the actual password is NOT included) 
            and provide security insights:
            
            Length: {password_info['details']['length']}
            Has uppercase: {password_info['details']['has_uppercase']}
            Has lowercase: {password_info['details']['has_lowercase']}
            Has digits: {password_info['details']['has_digits']}
            Has special chars: {password_info['details']['has_special']}
            Entropy: {password_info['details']['entropy']:.2f}
            Overall strength score: {password_info['score']}
            
            Based on this data only:
            1. Provide 2-3 specific recommendations to improve this password's security
            2. Explain any potential vulnerabilities this password might have
            3. Suggest a password pattern (NOT an actual password) that would be more secure
            
            Format your response as: {{
                "recommendations": ["rec1", "rec2", ...],
                "vulnerabilities": ["vuln1", "vuln2", ...],
                "improved_pattern": "description of better pattern"
            }}
            
            Only respond with valid JSON, no other text.
            """
            
            with console.status("[bold blue]Getting advanced AI analysis...[/bold blue]"):
                response = self.model.generate_content(prompt)
                
                result = response.text
                
                if result.startswith('```json'):
                    result = result.strip('```json').strip('```').strip()
                
                import json
                return json.loads(result)
                
        except Exception as e:
            console.print(f"[yellow]Gemini analysis failed: {str(e)}[/yellow]")
            return None


def display_strength_results(result: Dict, hibp_result: Optional[Tuple[bool, int, bool]] = None,
                           gemini_analysis: Optional[Dict] = None, hash_result: Optional[Dict] = None,
                           saved_file: Optional[str] = None):
    details_table = Table(show_header=True)
    details_table.add_column("Property", style="cyan")
    details_table.add_column("Value", style="white")
    
    details_table.add_row("Length", str(result['details']['length']))
    details_table.add_row("Uppercase Letters", "✓" if result['details']['has_uppercase'] else "✗")
    details_table.add_row("Lowercase Letters", "✓" if result['details']['has_lowercase'] else "✗")
    details_table.add_row("Numbers", "✓" if result['details']['has_digits'] else "✗")
    details_table.add_row("Special Characters", "✓" if result['details']['has_special'] else "✗")
    details_table.add_row("Entropy", f"{result['details']['entropy']:.2f} bits")
    
    strength_color = {
        "Very Strong": "bright_green",
        "Strong": "green",
        "Moderate": "yellow",
        "Weak": "red",
        "Very Weak": "bright_red"
    }.get(result['strength'], "white")
    
    strength_panel = Panel(
        f"[bold {strength_color}]{result['strength']} ({result['score']}/100)[/bold {strength_color}]",
        title="Password Strength"
    )
    
    hibp_panel = None
    if hibp_result:
        is_compromised, count, is_error = hibp_result
        if is_error:
            error_panel = Panel(
                "[bold red]SERVER ERROR[/bold red] Could not connect to database service",
                title="Service Status", border_style="red"
            )
            console.print(error_panel)
        else:
            if is_compromised:
                hibp_text = Text(f"COMPROMISED! Found in {count:,} data breaches")
                hibp_panel = Panel(hibp_text, title="Have I Been Pwned Check", border_style="red")
            else:
                hibp_text = Text("SAFE! Not found in known data breaches")
                hibp_panel = Panel(hibp_text, title="Have I Been Pwned Check", border_style="green")
    
    feedback_items = []
    for item in result['feedback']:
        if isinstance(item, dict):
            if item['type'] == 'good':
                feedback_items.append(f"[green]✓ {item['message']}[/green]")
            elif item['type'] == 'warning':
                feedback_items.append(f"[yellow]⚠ {item['message']}[/yellow]")
            elif item['type'] == 'bad':
                feedback_items.append(f"[red]✗ {item['message']}[/red]")
            elif item['type'] == 'info':
                feedback_items.append(f"[blue]ℹ {item['message']}[/blue]")
        else:
            feedback_items.append(item)
    
    feedback_text = "\n".join(feedback_items)
    feedback_panel = Panel(feedback_text, title="Analysis & Feedback")
    
    gemini_panel = None
    if gemini_analysis:
        gemini_content = []
        
        gemini_content.append("[bold cyan]Recommendations:[/bold cyan]")
        for rec in gemini_analysis.get('recommendations', []):
            gemini_content.append(f"• {rec}")
        
        if gemini_analysis.get('vulnerabilities'):
            gemini_content.append("\n[bold magenta]Potential Vulnerabilities:[/bold magenta]")
            for vuln in gemini_analysis.get('vulnerabilities', []):
                gemini_content.append(f"• {vuln}")
        
        if gemini_analysis.get('improved_pattern'):
            gemini_content.append("\n[bold green]Suggested Pattern:[/bold green]")
            gemini_content.append(gemini_analysis.get('improved_pattern'))
        
        gemini_panel = Panel("\n".join(gemini_content), title="AI-Powered Analysis (Gemini)", 
                           border_style="magenta")
    
    hash_panel = None
    if hash_result:
        hash_content = []
        if hash_result["method"] == "bcrypt":
            hash_content.append(f"[bold cyan]bcrypt hash:[/bold cyan] {hash_result['hash']}")
        elif hash_result["method"] == "pbkdf2":
            hash_content.append(f"[bold cyan]PBKDF2 key:[/bold cyan] {hash_result['key']}")
            hash_content.append(f"[bold cyan]Salt:[/bold cyan] {hash_result['salt']}")
        
        if saved_file:
            hash_content.append(f"\n[green]✓ Hash saved to file:[/green] {saved_file}")
        
        hash_panel = Panel("\n".join(hash_content), title="Secure Password Hash", border_style="cyan")
    
    console.print()
    console.print(strength_panel)
    console.print(details_table)
    if hibp_panel:
        console.print(hibp_panel)
    console.print(feedback_panel)
    if gemini_panel:
        console.print(gemini_panel)
    if hash_panel:
        console.print(hash_panel)


def main():
    console.print(Panel.fit(
        "[bold cyan]Password Generator & Strength Checker[/bold cyan]\n"
        "Featuring Have I Been Pwned integration and Gemini AI analysis",
        border_style="blue"
    ))
    
    parser = argparse.ArgumentParser(description="Password Generator and Strength Checker")
    parser.add_argument("--generate", "-g", action="store_true", help="Generate a new password")
    parser.add_argument("--length", "-l", type=int, default=16, help="Password length (default: 16)")
    parser.add_argument("--no-lowercase", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-uppercase", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-special", action="store_true", help="Exclude special characters")
    parser.add_argument("--check-hibp", action="store_true", help="Check against Have I Been Pwned database")
    parser.add_argument("--check-only", action="store_true", help="Only check an existing password")
    parser.add_argument("--use-gemini", action="store_true", help="Use Gemini AI for advanced analysis")
    parser.add_argument("--hash", choices=["bcrypt", "pbkdf2"], help="Generate secure hash of the password")
    parser.add_argument("--save", action="store_true", help="Save password hash to file")
    args = parser.parse_args()
    
    password_generator = PasswordGenerator()
    strength_checker = PasswordStrengthChecker()
    hibp_checker = HIBPChecker()
    gemini_analyzer = GeminiPasswordAnalyzer() if args.use_gemini else None
    password_hasher = PasswordHasher()
    
    password = None
    if args.check_only:
        password = getpass.getpass("Enter password to check: ")
    elif args.generate:
        password = password_generator.generate(
            length=args.length,
            use_lowercase=not args.no_lowercase,
            use_uppercase=not args.no_uppercase,
            use_digits=not args.no_digits,
            use_special=not args.no_special
        )
        console.print(f"[green]Generated password:[/green] {password}")
    else:
        console.print("[cyan]Menu:[/cyan]")
        console.print("1. Generate new password")
        console.print("2. Check existing password")
        choice = input("Choose an option (1/2): ").strip()
        
        if choice == "1":
            console.print("\n[cyan]Password generation options:[/cyan]")
            length = int(input("Password length (8-64): ") or "16")
            use_lowercase = input("Include lowercase letters? (Y/n): ").lower() != "n"
            use_uppercase = input("Include uppercase letters? (Y/n): ").lower() != "n"
            use_digits = input("Include numbers? (Y/n): ").lower() != "n"
            use_special = input("Include special characters? (Y/n): ").lower() != "n"
            
            password = password_generator.generate(
                length=length,
                use_lowercase=use_lowercase,
                use_uppercase=use_uppercase,
                use_digits=use_digits,
                use_special=use_special
            )
            console.print(f"[green]Generated password:[/green] {password}")
        else:
            password = getpass.getpass("Enter password to check: ")
    
    if not password:
        console.print("[red]No password provided. Exiting.[/red]")
        return
    
    result = strength_checker.check_strength(password)
    
    hibp_result = None
    if args.check_hibp or input("\nCheck if password has been compromised? (Y/n): ").lower() != "n":
        hibp_result = hibp_checker.check_password(password)
    
    gemini_analysis = None
    if gemini_analyzer and gemini_analyzer.enabled and args.use_gemini:
        gemini_analysis = gemini_analyzer.analyze_password_policy(result)
    
    hash_result = None
    saved_file = None
    hash_method = args.hash
    
    if not hash_method:
        console.print("\n[cyan]Encryption options:[/cyan]")
        console.print("1. bcrypt (industry standard for passwords)")
        console.print("2. PBKDF2 (key derivation function)")
        console.print("3. No encryption")
        
        hash_choice = input("Select encryption method (1/2/3): ").strip()
        
        if hash_choice == "1":
            hash_method = "bcrypt"
        elif hash_choice == "2":
            hash_method = "pbkdf2"
    
    if hash_method in ["bcrypt", "pbkdf2"]:
        hash_result = password_hasher.store_password("current", password, method=hash_method)
        
        save_to_file = args.save
        if not args.save and input(f"\nSave {hash_method} hash to file? (y/N): ").lower() == "y":
            save_to_file = True
            
        if save_to_file:
            custom_filename = input("Enter filename (leave blank for auto-generated): ").strip()
            saved_file = password_hasher.save_to_file(
                password, 
                hash_method, 
                filename=custom_filename if custom_filename else None
            )
    
    display_strength_results(result, hibp_result, gemini_analysis, hash_result, saved_file)


if __name__ == "__main__":
    main()