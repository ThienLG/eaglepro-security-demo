# database.py - SQLite Version với Hidden Files và VULNERABILITIES CHO DEMO
import os
import sqlite3
import random
from datetime import datetime

def get_db_connection():
   """Kết nối đến SQLite database"""
   conn = sqlite3.connect('eaglepro.db')
   conn.row_factory = sqlite3.Row  # Để truy cập theo tên cột
   return conn

def init_db():
   """Khởi tạo SQLite database và seed data"""
   conn = get_db_connection()
   cursor = conn.cursor()
   
   # Tạo tables
   cursor.execute('''
      CREATE TABLE IF NOT EXISTS users (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         username TEXT UNIQUE NOT NULL,
         password TEXT NOT NULL,
         full_name TEXT,
         avatar TEXT,
         is_admin BOOLEAN DEFAULT FALSE,
         department TEXT,
         position TEXT
      )
   ''')
    
   cursor.execute('''
      CREATE TABLE IF NOT EXISTS documents (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         user_id INTEGER NOT NULL,
         title TEXT NOT NULL,
         content TEXT,
         doc_type TEXT,
         sensitivity TEXT,
         created_date TEXT,
         file_size TEXT,
         file_format TEXT,
         FOREIGN KEY (user_id) REFERENCES users (id)
      )
   ''')
    
   # Tạo bảng hidden_files
   cursor.execute('''
      CREATE TABLE IF NOT EXISTS hidden_files (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         user_id INTEGER NOT NULL,
         title TEXT NOT NULL,
         content TEXT,
         created_date TEXT,
         last_modified TEXT,
         is_encrypted BOOLEAN DEFAULT FALSE,
         FOREIGN KEY (user_id) REFERENCES users (id),
         UNIQUE(user_id)
      )
    ''')
    # KIỂM TRA XEM ĐÃ CÓ DỮ LIỆU CHƯA - CHỈ SEED KHI CHƯA CÓ DỮ LIỆU
   cursor.execute("SELECT COUNT(*) FROM users")
   user_count = cursor.fetchone()[0]
   
   # Demo users
   if user_count == 0:
      users = [
         ('admin', 'admin123', 'System Administrator', 'admin_avatar.png', 1, 'IT', 'System Admin'),
         ('HusThien_IA', 'Thie2104n', 'HusThi IA', 'husthi_avatar.png', 0, 'AI Research', 'Senior AI Researcher'),
         ('Collie_Min', 'Minh1304', 'Collie Minh', 'collie_avatar.png', 0, 'Security', 'Security Analyst'),
         ('LazyBeo', 'iloveyou', 'LazyBeo', 'lazybeo_avatar.png', 0, 'Research', 'Research Specialist'),
         ('user1', 'pass123', 'John Doe', 'normal.png', 0, 'Title Insurance', 'Underwriter'),
         ('user2', 'pass123', 'Jane Smith', 'normal.png', 0, 'Escrow Services', 'Escrow Officer'),
         ('michael_chen', 'pass123', 'Michael Chen', 'normal.png', 0, 'IT', 'Developer'),
         ('sarah_wilson', 'pass123', 'Sarah Wilson', 'normal.png', 0, 'HR', 'HR Manager')
      ]
   
      for user in users:
         cursor.execute(
            "INSERT INTO users (username, password, full_name, avatar, is_admin, department, position) VALUES (?, ?, ?, ?, ?, ?, ?)",
            user
         )
      
      # Documents data với nội dung đầy đủ
      documents_data = [
         # Documents về mèo
                  (1, 'The Secret Life of Cats - Research Paper',
            '''A comprehensive study on feline behavior and psychology.

               KEY FINDINGS:
               1. Cats have 9 different vocalizations
               2. They sleep 12-16 hours daily  
               3. Purring has healing properties
               4. Whiskers are precision measurement tools

               "Until one has loved an animal, a part of one's soul remains unawakened." - Anatole France

               Recommended images: cat_sleeping.jpg, whiskers_diagram.png''',
            'Research Paper', 'Confidential', '2024-01-15', '4.2 MB', 'PDF'),
            
         (2, 'Feline Nutrition Guide - Internal Use',
            '''PROPRIETARY FEEDING GUIDELINES:

               KITTEN STAGE (0-12 months):
               - High protein: 35% minimum
               - Frequent meals: 3-4 times daily
               - Essential fatty acids: Omega-3,6

               ADULT STAGE (1-7 years):  
               - Maintenance diet: 25-30% protein
               - Weight management crucial
               - Hydration emphasis

               SENIOR STAGE (7+ years):
               - Joint support: Glucosamine
               - Reduced phosphorus
               - Enhanced digestibility

               CONFIDENTIAL: Do not distribute outside organization.''',
            'Nutrition Guide', 'Private', '2024-01-18', '2.1 MB', 'DOC'),
         
         # Documents bài hát - GIỮ NGUYÊN NỘI DUNG
         (6, 'Yesterday - Beatles Lyrics Analysis',
            '''YESTERDAY - THE BEATLES
               [Full Lyrics]

               Yesterday, all my troubles seemed so far away
               Now it looks as though they're here to stay
               Oh, I believe in yesterday

               Suddenly, I'm not half the man I used to be
               There's a shadow hanging over me
               Oh, yesterday came suddenly

               Why she had to go I don't know, she wouldn't say
               I said something wrong, now I long for yesterday

               ANALYSIS:
               - Released: 1965 on "Help!" album
               - Most covered song in history: ~2,200 versions
               - McCartney dreamt the melody, initially called "Scrambled Eggs"''',
            'Music Analysis', 'Low', '2024-01-20', '1.8 MB', 'TXT'),
            
         (23, 'Bohemian Rhapsody - Queen Sheet Music',
            '''BOHEMIAN RHAPSODY - QUEEN
               [Partial Sheet Music - Piano Intro]

               Is this the real life?
               Is this just fantasy?
               Caught in a landslide
               No escape from reality

               Open your eyes
               Look up to the skies and see
               I'm just a poor boy, I need no sympathy
               Because I'm easy come, easy go
               Little high, little low

               STRUCTURE ANALYSIS:
               - Intro (0:00-0:49)
               - Ballad (0:50-2:17) 
               - Guitar Solo (2:18-3:02)
               - Opera (3:03-4:07)
               - Hard Rock (4:08-4:55)
               - Outro (4:56-5:55)''',
            'Sheet Music', 'Medium', '2024-01-22', '3.5 MB', 'PDF'),
         
         # Documents văn học - GIỮ NGUYÊN NỘI DUNG
         (10, 'The Raven - Edgar Allan Poe',
            '''THE RAVEN - EDGAR ALLAN POE
               [Complete Poem]

               Once upon a midnight dreary, while I pondered, weak and weary,
               Over many a quaint and curious volume of forgotten lore—
               While I nodded, nearly napping, suddenly there came a tapping,
               As of some one gently rapping, rapping at my chamber door.
               "'Tis some visitor," I muttered, "tapping at my chamber door—
                           Only this and nothing more."

               [Continues for 18 stanzas...]

               LITERARY ANALYSIS:
               - Published: 1845
               - Meter: Trochaic octameter
               - Themes: Mourning, Death, Memory
               - Symbolism: Raven = Mournful remembrance''',
            'Poetry', 'Low', '2024-01-25', '2.3 MB', 'DOC'),
            
         (20, 'Shakespeare Sonnet 18 Analysis',
            '''SONNET 18 - WILLIAM SHAKESPEARE
               Shall I compare thee to a summer's day?
               Thou art more lovely and more temperate:
               Rough winds do shake the darling buds of May,
               And summer's lease hath all too short a date:

               Sometime too hot the eye of heaven shines,
               And often is his gold complexion dimm'd;
               And every fair from fair sometime declines,
               By chance or nature's changing course untrimm'd;

               But thy eternal summer shall not fade,
               Nor lose possession of that fair thou ow'st;
               Nor shall Death brag thou wander'st in his shade,
               When in eternal lines to time thou grow'st:

               So long as men can breathe or eyes can see,
               So long lives this, and this gives life to thee.

               ANALYSIS:
               - Structure: 14 lines, iambic pentameter
               - Rhyme scheme: ABAB CDCD EFEF GG
               - Theme: Immortality through poetry''',
            'Literary Analysis', 'Low', '2024-01-28', '1.6 MB', 'PDF'),
         
         # Documents công nghệ - GIỮ NGUYÊN NỘI DUNG
         (14, 'AI Neural Networks - Technical Documentation',
            '''NEURAL NETWORK ARCHITECTURE DOCUMENTATION

               MODEL SPECIFICATIONS:
               - Layers: 12 transformer blocks
               - Parameters: 110 million
               - Training Data: 50TB text corpus
               - Framework: PyTorch 2.0

               ARCHITECTURE OVERVIEW:
               Input → Embedding → Transformer Blocks → Output

               PERFORMANCE METRICS:
               - Accuracy: 98.7%
               - Inference Speed: 8,542 docs/min
               - Training Time: 48 hours

               CONFIDENTIAL: Proprietary architecture - Do not share.''',
            'Technical Docs', 'High', '2024-02-01', '5.7 MB', 'PDF'),
            
         (3, 'Blockchain Implementation Guide',
            '''ENTERPRISE BLOCKCHAIN IMPLEMENTATION

               CORE COMPONENTS:
               1. Distributed Ledger Technology
               2. Smart Contracts
               3. Consensus Mechanism
               4. Cryptographic Hashing

               USE CASES:
               - Supply Chain Tracking
               - Digital Identity
               - Smart Contracts
               - Asset Tokenization

               SECURITY CONSIDERATIONS:
               - 51% Attack Prevention
               - Private vs Public Chains
               - Regulatory Compliance

               INTERNAL USE ONLY''',
            'Technical Guide', 'Confidential', '2024-02-03', '4.8 MB', 'PDF'),
         
         # Documents First American related - GIỮ NGUYÊN NỘI DUNG
         (18, 'First American Security Breach Analysis',
            '''FIRST AMERICAN FINANCIAL CORPORATION
               SECURITY INCIDENT REPORT - CLASSIFIED

               INCIDENT DATE: May 24, 2019
               DOCUMENTS EXPOSED: 885 Million
               DATA TYPES: Bank transactions, SSN, mortgage documents

               ROOT CAUSE: IDOR Vulnerability
               - No authentication on document endpoints
               - Sequential document IDs exposed
               - No access control validation

               BUSINESS IMPACT:
               - SEC Fine: $1,000,000
               - Class action lawsuits
               - Reputational damage

               LESSONS LEARNED:
               1. Implement proper authorization
               2. Use non-sequential IDs
               3. Regular security audits''',
            'Security Report', 'Top Secret', '2024-02-05', '3.2 MB', 'PDF'),
            
         (5, 'EaglePro Security Assessment',
            '''EAGLEPRO PLATFORM SECURITY ASSESSMENT

               FINDINGS:
               🔴 CRITICAL: IDOR in /document/{id} endpoint
               🟡 MEDIUM: Missing rate limiting on login
               🟢 LOW: Insufficient logging

               VULNERABILITY DETAILS:
               - Location: Document access endpoints
               - Impact: Unauthorized data access
               - Exploitation: Changing document IDs

               RECOMMENDATIONS:
               1. Implement access control checks
               2. Use UUIDs instead of sequential IDs
               3. Add comprehensive logging

               STATUS: UNRESOLVED''',
            'Security Audit', 'Top Secret', '2024-02-07', '2.9 MB', 'PDF'),
         
         # Thêm các documents ngẫu nhiên khác - GIỮ NGUYÊN NỘI DUNG
         (22, 'Company Financial Projections 2024',
            '''FINANCIAL PROJECTIONS & FORECASTING

               REVENUE STREAMS:
               - Title Insurance: $2.1B
               - Escrow Services: $1.4B  
               - Technology Solutions: $0.3B

               EXPENSE BREAKDOWN:
               - Personnel: 45%
               - Technology: 25%
               - Marketing: 15%
               - Operations: 15%

               PROJECTED GROWTH: 12% YoY

               CONFIDENTIAL: Internal projections only''',
            'Financial Report', 'Confidential', '2024-02-09', '1.7 MB', 'XLS'),
            
         (13, 'Employee Wellness Program',
            '''CORPORATE WELLNESS INITIATIVE

               PROGRAM COMPONENTS:
               - Mental Health Support
               - Fitness Challenges
               - Nutritional Guidance
               - Stress Management

               PARTICIPATION METRICS:
               - Employee Engagement: 78%
               - Health Cost Reduction: 12%
               - Productivity Increase: 15%

               SUCCESS STORIES:
               - Reduced absenteeism by 23%
               - Improved employee satisfaction scores

               INTERNAL DOCUMENT''',
            'HR Policy', 'Medium', '2024-02-11', '2.4 MB', 'PDF'),
         
         (7, 'Machine Learning Model Documentation',
            '''AUTOMATED DOCUMENT CLASSIFIER

               MODEL: BERT-based Transformer
               TRAINING DATA: 1M+ documents
               ACCURACY: 99.2%

               FEATURES:
               - Multi-label classification
               - Confidence scoring
               - Explainable AI outputs

               DEPLOYMENT:
               - API Endpoint: /api/classify
               - Response Time: <200ms
               - Availability: 99.99%

               PROPRIETARY TECHNOLOGY''',
            'Technical Documentation', 'High', '2024-02-13', '6.1 MB', 'PDF'),
            
         (4, 'Customer Satisfaction Survey Results',
            '''Q1 2024 CUSTOMER SATISFACTION ANALYSIS

               OVERALL SCORES:
               - Customer Satisfaction: 4.7/5.0
               - Net Promoter Score: 62
               - Customer Effort Score: 2.1/5.0

               KEY INSIGHTS:
               - 94% satisfaction with digital platform
               - Escrow process rated most improved
               - Response time identified as area for improvement

               RECOMMENDATIONS:
               1. Enhance mobile experience
               2. Streamline document submission
               3. Improve communication timelines''',
            'Survey Results', 'Medium', '2024-02-15', '3.8 MB', 'PDF'),
         
         (21, 'Cybersecurity Training Materials',
            '''EMPLOYEE CYBERSECURITY AWARENESS

               TRAINING MODULES:
               1. Phishing Identification
               2. Password Security
               3. Data Handling Procedures
               4. Incident Reporting

               BEST PRACTICES:
               - Use password managers
               - Enable 2FA everywhere
               - Verify email senders
               - Encrypt sensitive data

               COMPLIANCE REQUIREMENTS:
               - GDPR, CCPA, SOX
               - Data retention policies
               - Access control standards

               MANDATORY TRAINING''',
            'Training Materials', 'High', '2024-02-17', '5.2 MB', 'PPT'),
            
         (19, 'Office Relocation Planning',
            '''CORPORATE HEADQUARTERS RELOCATION

               NEW LOCATION: 2260 E. Imperial Highway
               FLOOR SPACE: 150,000 sq ft
               EMPLOYEES: 1,200
               MOVE DATE: Q3 2024

               DEPARTMENT ALLOCATIONS:
               - Executive: Floor 5
               - IT: Floor 4
               - Operations: Floors 2-3
               - Support: Floor 1

               TIMELINE:
               - Planning: Complete
               - Construction: In progress
               - Move: August 2024

               CONFIDENTIAL: Pre-announcement''',
            'Facilities Plan', 'Confidential', '2024-02-19', '4.5 MB', 'DOC'),
         
         (8, 'Software Development Lifecycle',
            '''AGILE SOFTWARE DEVELOPMENT

               SPRINT PROCESS:
               - Planning: 2 days
               - Development: 10 days
               - Review: 1 day
               - Retrospective: 1 day

               TOOLCHAIN:
               - Version Control: Git
               - CI/CD: Jenkins
               - Monitoring: Datadog
               - Documentation: Confluence

               QUALITY METRICS:
               - Code Coverage: 85%+
               - Test Automation: 90%+
               - Deployment Frequency: Daily

               INTERNAL PROCESS DOCUMENT''',
            'Development Guide', 'Medium', '2024-02-21', '2.8 MB', 'PDF'),
            
         (11, 'Market Research - Real Estate Trends',
            '''2024 REAL ESTATE MARKET ANALYSIS

               KEY TRENDS:
               - Remote work driving suburban growth
               - Interest rate impact on affordability
               - Technology adoption accelerating
               - Sustainability becoming differentiator

               MARKET SEGMENTS:
               - Residential: Stable growth
               - Commercial: Office space challenges
               - Industrial: E-commerce driving demand

               PREDICTIONS:
               - Moderate price appreciation
               - Increased digital transactions
               - Regulatory changes expected

               PROPRIETARY RESEARCH''',
            'Market Analysis', 'High', '2024-02-23', '3.9 MB', 'PDF'),
         
         (17, 'Data Privacy Compliance Framework',
            '''GLOBAL DATA PRIVACY COMPLIANCE

               REGULATIONS COVERED:
               - GDPR (Europe)
               - CCPA (California)
               - PIPEDA (Canada)
               - LGPD (Brazil)

               COMPLIANCE REQUIREMENTS:
               - Data mapping and classification
               - Consent management
               - Data subject rights processing
               - Breach notification procedures

               IMPLEMENTATION STATUS:
               - Phase 1: Complete
               - Phase 2: In progress
               - Phase 3: Planning

               LEGAL & COMPLIANCE''',
            'Compliance Framework', 'Confidential', '2024-02-25', '4.7 MB', 'PDF'),
            
         (24, 'IT Infrastructure Upgrade Proposal',
            '''TECHNOLOGY INFRASTRUCTURE MODERNIZATION

               CURRENT STATE:
               - 12 physical servers
               - 45 virtual machines
               - 10 Gbps network
               - 450 TB storage

               PROPOSED UPGRADES:
               - Cloud migration (60%)
               - Network upgrade to 40 Gbps
               - SSD storage implementation
               - Enhanced security stack

               BUDGET: $1.2M
               TIMELINE: 12 months
               ROI: 3.2 years

               EXECUTIVE APPROVAL REQUIRED''',
            'IT Proposal', 'High', '2024-02-27', '5.8 MB', 'PDF'),
         
         (15, 'Employee Performance Review System',
            '''PERFORMANCE MANAGEMENT FRAMEWORK

               REVIEW CYCLES:
               - Quarterly check-ins
               - Annual comprehensive review
               - 360-degree feedback

               EVALUATION CRITERIA:
               - Goal achievement
               - Competency development
               - Collaboration and teamwork
               - Innovation and initiative

               CALIBRATION PROCESS:
               - Manager alignment sessions
               - Performance rating normalization
               - Talent identification

               HR CONFIDENTIAL''',
            'HR System', 'Confidential', '2024-03-01', '2.6 MB', 'PDF'),
            
         (9, 'Digital Transformation Strategy',
            '''ENTERPRISE DIGITAL TRANSFORMATION

               STRATEGIC PILLARS:
               1. Customer Experience Modernization
               2. Operational Efficiency
               3. Data-Driven Decision Making
               4. Innovation Culture

               KEY INITIATIVES:
               - API-first architecture
               - Microservices migration
               - AI/ML integration
               - Mobile-first design

               SUCCESS METRICS:
               - Digital adoption rate
               - Process automation %
               - Customer satisfaction
               - Employee engagement

               EXECUTIVE STRATEGY''',
            'Strategy Document', 'Top Secret', '2024-03-03', '6.3 MB', 'PDF'),
         
         (12, 'Business Continuity Plan',
            '''DISASTER RECOVERY & BUSINESS CONTINUITY

               CRITICAL SYSTEMS:
               - EaglePro Document Management
               - Customer Relationship Management
               - Financial Processing Systems
               - Communication Infrastructure

               RECOVERY OBJECTIVES:
               - RTO: 4 hours (critical systems)
               - RPO: 1 hour (data loss)
               - Availability: 99.99%

               TESTING SCHEDULE:
               - Quarterly: Component testing
               - Semi-annual: Full DR drill
               - Annual: Business continuity test

               CRITICAL OPERATIONS DOCUMENT''',
            'Continuity Plan', 'Top Secret', '2024-03-05', '4.9 MB', 'PDF'),
            
         (25, 'Vendor Management Policy',
            '''THIRD-PARTY VENDOR GOVERNANCE

               VENDOR CLASSIFICATION:
               - Strategic: Long-term partners
               - Tactical: Project-based
               - Commodity: Standard services

               RISK ASSESSMENT:
               - Security reviews required
               - Compliance verification
               - Financial stability checks
               - Reference validation

               PERFORMANCE MANAGEMENT:
               - Quarterly business reviews
               - SLA monitoring and reporting
               - Continuous improvement plans

               PROCUREMENT POLICY''',
         'Vendor Policy', 'Confidential', '2024-03-07', '3.4 MB', 'PDF'),
         
         (16, 'Innovation Lab Project Portfolio',
            '''RESEARCH & DEVELOPMENT PORTFOLIO

               ACTIVE PROJECTS:
               1. AI-Powered Document Analysis
               2. Blockchain for Title Records
               3. Predictive Analytics Platform
               4. Voice Interface Development

               INNOVATION PIPELINE:
               - 12 projects in discovery
               - 8 projects in development
               - 4 projects in pilot
               - 2 projects in production

               INVESTMENT ALLOCATION:
               - Core innovation: 60%
               - Emerging tech: 30%
               - Research: 10%

               R&D CONFIDENTIAL''',
         'Project Portfolio', 'Top Secret', '2024-03-09', '5.1 MB', 'PDF')
      ]
      
   # PHẦN ĐÃ SỬA: Phân bố thủ công documents cho users
   # Tạo mapping document_id -> user_id
      doc_to_user = {
               1: 2,    # Document 1 -> User 2
               2: 5,    # Document 2 -> User 5
               3: 3,    # Document 3 -> User 3
               4: 3,    # Document 4 -> User 3
               5: 1,    # Document 5 -> User 1
               6: 4,    # Document 6 -> User 4
               7: 2,    # Document 7 -> User 2
               8: 2,    # Document 8 -> User 2
               9: 5,    # Document 9 -> User 5
               10: 1,   # Document 10 -> User 1
               11: 5,   # Document 11 -> User 5
               12: 1,   # Document 12 -> User 1
               13: 4,   # Document 13 -> User 4
               14: 3,   # Document 14 -> User 3
               15: 1,   # Document 15 -> User 1 
               16: 3,   # Document 16 -> User 3
               17: 2,   # Document 17 -> User 2
               18: 5,   # Document 18 -> User 5
               19: 4,   # Document 19 -> User 4
               20: 3,   # Document 20 -> User 3
               21: 3,   # Document 21 -> User 3
               22: 5,   # Document 22 -> User 5
               23: 5,   # Document 23 -> User 5
               24: 2,   # Document 24 -> User 2
               25: 1    # Document 25 -> User 1
      }

      # Tạo user_assignments dựa trên thứ tự documents trong documents_data
      user_assignments = []
      for doc in documents_data:
         doc_id = doc[0]  # Lấy ID từ tuple document
         user_id = doc_to_user.get(doc_id, 1)  # Mặc định user 1 nếu không tìm thấy
         user_assignments.append(user_id)
      
      # Insert documents
      for i, doc in enumerate(documents_data):
         user_id = user_assignments[i]
         cursor.execute(
               "INSERT INTO documents (id, user_id, title, content, doc_type, sensitivity, created_date, file_size, file_format) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
               (doc[0], user_id, doc[1], doc[2], doc[3], doc[4], doc[5], doc[6], doc[7])
         )
      
      # Tạo hidden files cho 3 user đặc biệt
      special_users = ['HusThien_IA', 'Collie_Min', 'LazyBeo']
      for username in special_users:
         cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
         user = cursor.fetchone()
         if user:
               hidden_content = f"""# 🔒 Hidden File - {username}

               Chào mừng bạn đến với file ẩn đặc biệt!

               Đây là không gian riêng tư của bạn. Bạn có thể:
               - Ghi chú bí mật
               - Lưu thông tin quan trọng  
               - Viết nhật ký
               - Lưu ý công việc

               Nội dung này sẽ được lưu tự động mỗi khi bạn chỉnh sửa.

               ## Tính năng đặc biệt:
               ✅ Chỉ hiển thị với tài khoản của bạn
               ✅ Tự động lưu vào database
               ✅ Truy cập được từ mọi nơi
               ✅ Hoàn toàn bí mật

               Hãy bắt đầu viết gì đó thú vị đi! 🎉"""
                           
               cursor.execute(
                  "INSERT INTO hidden_files (user_id, title, content, created_date, last_modified) VALUES (?, ?, ?, ?, ?)",
                  (user['id'], '🔒 My Secret File', hidden_content, 
                  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                  datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
               )
      
 
      print("✅ SQLite database initialized with:")
      print("   - 8 users")
      print("   - 25 documents") 
      print("   - Hidden files for 3 special users")
   else:
      print("✅ Database already exists, skipping initialization.")
   conn.commit()
   conn.close()

def get_hidden_file(user_id):
   """Lấy hidden file của user"""
   conn = get_db_connection()
   cursor = conn.cursor()
   cursor.execute('SELECT * FROM hidden_files WHERE user_id = ?', (user_id,))
   hidden_file = cursor.fetchone()
   conn.close()
   return hidden_file

def update_hidden_file(user_id, title, content):
   """Cập nhật hidden file"""
   conn = get_db_connection()
   cursor = conn.cursor()
   cursor.execute(
      'UPDATE hidden_files SET title = ?, content = ?, last_modified = ? WHERE user_id = ?',
      (title, content, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id)
   )
   conn.commit()
   conn.close()

# ❌ VULNERABLE FUNCTIONS FOR SQL INJECTION DEMO
##
'''
def vulnerable_login(username, password):
    """Vulnerable login function for SQL Injection demo"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ❌ VULNERABLE: Direct string concatenation - SQL Injection vulnerable
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"🚨 VULNERABLE QUERY: {query}")  # For demo purposes
    
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

def vulnerable_search_documents(search_term):
    """Vulnerable search function for SQL Injection demo"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ❌ VULNERABLE: Direct string concatenation in LIKE query
    query = f"SELECT * FROM documents WHERE title LIKE '%{search_term}%' OR content LIKE '%{search_term}%'"
    print(f"🚨 VULNERABLE SEARCH QUERY: {query}")
    
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

def vulnerable_get_user_by_id(user_id):
    """Vulnerable user retrieval by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ❌ VULNERABLE: No input validation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

def vulnerable_get_documents_by_user(user_id):
    """Vulnerable document retrieval by user ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ❌ VULNERABLE: String formatting in query
    query = f"SELECT * FROM documents WHERE user_id = {user_id}"
    cursor.execute(query)
    documents = cursor.fetchall()
    conn.close()
    return documents

def vulnerable_admin_query(sql_query):
    """Extremely vulnerable direct SQL execution - FOR DEMO ONLY"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ❌❌❌ EXTREMELY VULNERABLE: Direct SQL execution
    cursor.execute(sql_query)
    
    if sql_query.strip().upper().startswith('SELECT'):
        results = cursor.fetchall()
    else:
        conn.commit()
        results = [{'message': 'Query executed successfully'}]
    
    conn.close()
    return results
'''
# database.py - PHIÊN BẢN AN TOÀN

def safe_login(username, password):
    """Login function an toàn sử dụng parameterized queries"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ✅ AN TOÀN: Parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

def safe_search_documents(search_term):
    """Search function an toàn"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ✅ AN TOÀN: Parameterized query với LIKE
    query = """
        SELECT d.*, u.username
        FROM documents d
        JOIN users u ON d.user_id = u.id
        WHERE d.title LIKE ? 
        OR d.content LIKE ?
        OR d.doc_type LIKE ?
    """
    search_pattern = f"%{search_term}%"
    cursor.execute(query, (search_pattern, search_pattern, search_pattern))
    results = cursor.fetchall()
    conn.close()
    return results

def safe_get_user_by_id(user_id):
    """Lấy user by ID an toàn"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ✅ AN TOÀN: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def safe_get_documents_by_user(user_id):
    """Lấy documents của user an toàn"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ✅ AN TOÀN: Parameterized query
    query = "SELECT * FROM documents WHERE user_id = ?"
    cursor.execute(query, (user_id,))
    documents = cursor.fetchall()
    conn.close()
    return documents

def safe_admin_query(sql_query):
    """Admin query với validation cơ bản"""
    # 🛡️ Block dangerous operations in demo environment
    dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'ALTER', 'CREATE', 'TRUNCATE']
    
    if any(keyword in sql_query.upper() for keyword in dangerous_keywords):
        return [{'error': 'Write operations are disabled in demo mode'}]
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(sql_query)
        if sql_query.strip().upper().startswith('SELECT'):
            results = cursor.fetchall()
        else:
            conn.commit()
            results = [{'message': 'Query executed successfully (read-only mode)'}]
    except Exception as e:
        results = [{'error': str(e)}]
    finally:
        conn.close()
    
    return results