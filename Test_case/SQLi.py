import requests
import time

BASE_URL = "http://hod.gr2:5000"

class SQLInjectionTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def test_login_sql_injection(self):
        """Test SQL Injection trong login"""
        print("\n" + "="*50)
        print("🧪 TESTING LOGIN SQL INJECTION")
        print("="*50)
        
        test_cases = [
            # Basic SQL Injection
            {"username": "admin' --", "password": "anything", "name": "Basic Comment Bypass"},
            {"username": "' OR '1'='1' --", "password": "anything", "name": "OR Condition Bypass"},
            {"username": "admin", "password": "' OR '1'='1' --", "name": "Password Field Injection"},
            
            # Union-based SQL Injection
            {"username": "' UNION SELECT * FROM users --", "password": "test", "name": "Union Select Attack"},
            {"username": "admin' UNION SELECT 1,2,3,4,5,6,7 --", "password": "test", "name": "Union Column Enumeration"},
            
            # Error-based SQL Injection
            {"username": "admin' AND 1=CAST((SELECT version()) AS INT) --", "password": "test", "name": "Error-based Enumeration"},
            
            # Time-based Blind SQL Injection
            {"username": "admin' AND SLEEP(5) --", "password": "test", "name": "Time-based Blind Injection"},
            
            # Stacked Queries
            {"username": "admin'; DROP TABLE users --", "password": "test", "name": "Stacked Query Attack"},
            
            # Alternative Encoding
            {"username": "admin'/**/OR/**/1=1/**/--", "password": "test", "name": "Obfuscated with Comments"},
            {"username": "admin'%20OR%201=1--", "password": "test", "name": "URL Encoded Injection"},
        ]
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n🔍 Test {i}: {test_case['name']}")
            print(f"   Payload: username='{test_case['username']}'")
            
            response = self.session.post(
                f"{BASE_URL}/",
                data={
                    'username': test_case['username'],
                    'password': test_case['password']
                },
                allow_redirects=False
            )
            
            self._analyze_response(response, test_case['name'])
            
    def test_search_sql_injection(self):
        """Test SQL Injection trong search"""
        print("\n" + "="*50)
        print("🧪 TESTING SEARCH SQL INJECTION") 
        print("="*50)
        
        # First login with normal user
        self.session.post(f"{BASE_URL}/", data={
            'username': 'user1',
            'password': 'pass123'
        })
        
        test_cases = [
            # Union-based attacks
            {"payload": "' UNION SELECT * FROM users --", "name": "Union Extract Users"},
            {"payload": "' UNION SELECT username, password, NULL, NULL, NULL, NULL, NULL FROM users --", "name": "Union Extract Credentials"},
            {"payload": "' UNION SELECT name, NULL, NULL, NULL, NULL, NULL, NULL FROM sqlite_master WHERE type='table' --", "name": "Union Extract Table Names"},
            
            # Boolean-based blind
            {"payload": "' OR EXISTS(SELECT * FROM users WHERE username='admin') --", "name": "Boolean Blind - Check Admin"},
            {"payload": "' OR LENGTH(password) > 5 --", "name": "Boolean Blind - Password Length"},
            
            # System table extraction
            {"payload": "' UNION SELECT sql, NULL, NULL, NULL, NULL, NULL, NULL FROM sqlite_master --", "name": "Extract Table Schemas"},
            
            # Data extraction
            {"payload": "test' UNION SELECT id, username, password, NULL, NULL, NULL, NULL FROM users --", "name": "Extract User Data"},
            
            # Dangerous operations
            {"payload": "'; DROP TABLE documents --", "name": "Drop Table Attempt"},
            {"payload": "'; DELETE FROM documents --", "name": "Delete Data Attempt"},
        ]
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n🔍 Test {i}: {test_case['name']}")
            print(f"   Payload: '{test_case['payload']}'")
            
            response = self.session.get(
                f"{BASE_URL}/search",
                params={'q': test_case['payload']}
            )
            
            self._analyze_response(response, test_case['name'])
    
    def _analyze_response(self, response, test_name):
        """Phân tích response và đưa ra kết luận"""
        print(f"   Status Code: {response.status_code}")
        print(f"   Response Length: {len(response.text)} bytes")
        
        # Check for security indicators
        if response.status_code == 200:
            if "security violation" in response.text.lower() or "sql injection" in response.text.lower():
                print("   🛡️  RESULT: SQL Injection DETECTED AND BLOCKED - ✅ SECURE")
            elif "error" in response.text.lower() and "sql" in response.text.lower():
                print("   💥 RESULT: SQL Error Exposed - ❌ VULNERABLE")
            elif "blocked" in response.text.lower() or "invalid" in response.text.lower():
                print("   🛡️  RESULT: Input Blocked - ✅ SECURE")
            elif len(response.text) < 1000 and "not found" in response.text.lower():
                print("   🛡️  RESULT: Empty/Error Response - ✅ LIKELY SECURE")
            else:
                # Check if we got unexpected data (potential success)
                if "admin" in response.text and "password" in response.text:
                    print("   💀 RESULT: SENSITIVE DATA EXPOSED - ❌ CRITICAL VULNERABILITY")
                else:
                    print("   ⚠️  RESULT: Unexpected Response - NEEDS MANUAL REVIEW")
        elif response.status_code == 302:
            print("   🔀 RESULT: Redirect - Check if login was successful")
        elif response.status_code == 429:
            print("   🚫 RESULT: Rate Limited - ✅ SECURE")
        else:
            print(f"   ❓ RESULT: Unexpected Status Code - {response.status_code}")

if __name__ == "__main__":
    tester = SQLInjectionTester(BASE_URL)
    
    print("🚀 STARTING SQL INJECTION TEST SUITE")
    print("📝 Testing: Parameterized Queries, Input Validation, SQLi Detection")
    
    # Run tests - chỉ chạy login và search
    tester.test_login_sql_injection()
    time.sleep(1)  # Avoid rate limiting
    
    tester.test_search_sql_injection()
    
    print("\n" + "="*50)
    print("🎯 SQL INJECTION TESTING COMPLETE")
    print("="*50)