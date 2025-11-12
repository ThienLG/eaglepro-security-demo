import requests
import time
import threading

BASE_URL = "http://hod.gr2:5000"

class SecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url
        
    def test_security_headers(self):
        """Test các Security Headers"""
        print("\n" + "="*50)
        print("🧪 TESTING SECURITY HEADERS")
        print("="*50)
        
        endpoints = ["/", "/dashboard", "/search", "/admin/documents"]
        
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY', 
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        for endpoint in endpoints:
            print(f"\n🔍 Testing endpoint: {endpoint}")
            response = requests.get(f"{self.base_url}{endpoint}", allow_redirects=False)
            
            print(f"   Status: {response.status_code}")
            
            for header, expected_value in required_headers.items():
                actual_value = response.headers.get(header)
                if actual_value:
                    if actual_value == expected_value:
                        print(f"   ✅ {header}: {actual_value}")
                    else:
                        print(f"   ⚠️  {header}: {actual_value} (expected: {expected_value})")
                else:
                    print(f"   ❌ {header}: MISSING")
            
            # Check CSP separately (might be complex)
            csp = response.headers.get('Content-Security-Policy')
            if csp:
                print(f"   ✅ Content-Security-Policy: PRESENT ({len(csp)} chars)")
            else:
                print(f"   ⚠️  Content-Security-Policy: MISSING")
    
    def test_login_rate_limiting(self):
        """Test Rate Limiting trên login"""
        print("\n" + "="*50)
        print("🧪 TESTING LOGIN RATE LIMITING")
        print("="*50)
        
        print("🚀 Sending rapid login attempts...")
        
        # Test 1: Rapid requests từ cùng IP
        for i in range(1, 6):  # 5 attempts
            response = requests.post(
                f"{self.base_url}/",
                data={'username': f'test{i}', 'password': 'wrongpassword'},
                allow_redirects=False
            )
            
            print(f"   Attempt {i}: Status {response.status_code}", end="")
            
            if response.status_code == 429:
                print(" - 🚫 RATE LIMITED")
                reset_time = response.headers.get('Retry-After')
                if reset_time:
                    print(f"      Retry-After: {reset_time} seconds")
                break
            elif response.status_code == 302:
                print(" - 🔀 Redirect (unexpected success?)")
            else:
                print(" - ✅ Allowed")
            
            time.sleep(0.5)  # Small delay between requests
        
        # Test 2: Wait and retry
        print("\n⏰ Waiting 15 seconds for rate limit reset...")
        time.sleep(15)
        
        response = requests.post(
            f"{self.base_url}/",
            data={'username': 'test_after_wait', 'password': 'wrongpassword'},
            allow_redirects=False
        )
        
        if response.status_code != 429:
            print("   ✅ Rate limit reset working - request allowed after wait")
        else:
            print("   ❌ Rate limit NOT reset after wait period")
    
    def test_search_rate_limiting(self):
        """Test Rate Limiting trên search"""
        print("\n" + "="*50)
        print("🧪 TESTING SEARCH RATE LIMITING")
        print("="*50)
        
        # First login to get session
        session = requests.Session()
        login_response = session.post(
            f"{self.base_url}/",
            data={'username': 'user1', 'password': 'pass123'},
            allow_redirects=False
        )
        
        if login_response.status_code != 302:
            print("   ❌ Failed to login for search testing")
            return
        
        print("🚀 Sending rapid search requests...")
        
        blocked_attempt = None
        for i in range(1, 15):  # 14 attempts (limit should be 10/minute)
            response = session.get(
                f"{self.base_url}/search",
                params={'q': f'test {i}'}
            )
            
            print(f"   Search {i}: Status {response.status_code}", end="")
            
            if response.status_code == 429:
                print(" - 🚫 RATE LIMITED")
                blocked_attempt = i
                break
            elif "too many search" in response.text.lower():
                print(" - 🚫 RATE LIMITED (in response text)")
                blocked_attempt = i
                break
            else:
                print(" - ✅ Allowed")
            
            time.sleep(0.3)  # Small delay
        
        if blocked_attempt and blocked_attempt <= 11:  # Should block around 11th request
            print(f"   ✅ Rate limiting triggered at request #{blocked_attempt}")
        else:
            print("   ⚠️  Rate limiting might not be working correctly")
    
    def test_concurrent_rate_limiting(self):
        """Test Rate Limiting với concurrent requests"""
        print("\n" + "="*50)
        print("🧪 TESTING CONCURRENT RATE LIMITING")
        print("="*50)
        
        results = []
        
        def make_request(request_id):
            try:
                response = requests.post(
                    f"{self.base_url}/",
                    data={'username': f'concurrent_{request_id}', 'password': 'test'},
                    timeout=5
                )
                results.append((request_id, response.status_code))
            except Exception as e:
                results.append((request_id, f"Error: {e}"))
        
        # Tạo multiple concurrent requests
        threads = []
        for i in range(8):  # 8 concurrent requests
            thread = threading.Thread(target=make_request, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Chờ tất cả threads hoàn thành
        for thread in threads:
            thread.join()
        
        # Phân tích kết quả
        allowed = 0
        blocked = 0
        errors = 0
        
        for request_id, status in results:
            if status == 429:
                print(f"   Request {request_id}: 🚫 RATE LIMITED")
                blocked += 1
            elif status == 302 or status == 200:
                print(f"   Request {request_id}: ✅ Allowed (Status {status})")
                allowed += 1
            else:
                print(f"   Request {request_id}: ❓ Unexpected: {status}")
                errors += 1
        
        print(f"\n   📊 Summary: {allowed} allowed, {blocked} blocked, {errors} errors")
        
        if blocked > 0:
            print("   ✅ Concurrent rate limiting is working")
        else:
            print("   ⚠️  No requests were blocked - check concurrent rate limiting")

if __name__ == "__main__":
    tester = SecurityTester(BASE_URL)
    
    print("🚀 STARTING SECURITY HEADERS & RATE LIMITING TEST SUITE")
    print("📝 Testing: Security Headers, Rate Limiting")
    
    # Run tests
    tester.test_security_headers()
    time.sleep(2)
    
    tester.test_login_rate_limiting() 
    time.sleep(2)
    
    tester.test_search_rate_limiting()
    time.sleep(2)
    
    tester.test_concurrent_rate_limiting()
    
    print("\n" + "="*50)
    print("🎯 SECURITY HEADERS & RATE LIMITING TESTING COMPLETE")
    print("="*50)