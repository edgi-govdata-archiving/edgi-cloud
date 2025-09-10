# EDGI Datasette Cloud Portal

A comprehensive platform that empowers researchers, organizations, and environmental advocates to share critical environmental datasets as interactive, accessible websites. Built on Datasette with a custom administrative panel for seamless data publishing and portal customization.

## 🌍 Mission

The EDGI Datasette Cloud Portal serves the critical mission of **democratizing environmental data access** and supporting evidence-based environmental policy. Every dataset shared brings us closer to a more informed, sustainable future.

## ⚡ Key Features

### Data Upload & Processing
- **Multi-Source Upload** - Support for CSV, Excel, Google Sheets, and Web CSV files
- **Advanced Null Handling** - Intelligent processing of empty cells, "NULL", "N/A", and missing values
- **Data Quality Analysis** - Automated assessment and reporting of data quality issues
- **Large File Support** - Efficient processing of files up to administrator-configured limits
- **Real-time Progress** - Live upload progress with cancellation capabilities
- **Connection Testing** - Pre-upload validation for Google Sheets and Web CSV sources

### Portal Management
- **Custom Branding** - Create professional portals with organization identity
- **Instant Publishing** - Share data with the world in minutes
- **Advanced Search** - Enable users to filter, sort, and explore datasets
- **API Access** - Programmatic data access for researchers and developers
- **Markdown Support** - Rich text formatting with links, lists, and emphasis
- **Trash System** - Safe deletion with configurable retention and recovery

### Administration & Security
- **Role-Based Access** - System admin and user roles with appropriate permissions
- **Enhanced Security** - CSRF protection, input validation, and secure file handling
- **Activity Monitoring** - Comprehensive logging and user activity tracking
- **User Management** - Complete account lifecycle management
- **System Configuration** - Runtime settings via admin interface
- **Free & Open** - No cost barriers to environmental data sharing

## 🏗️ Comprehensive System Architecture

### Core Components

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend       │    │   Data Layer    │
│  (19 Templates) │    │  (8 Plugins)     │    │                 │
│                 │    │                  │    │                 │
│ • 72KB Upload UI│◄──►│ • 131KB Upload   │◄──►│ • SQLite DBs    │
│ • 66KB Mgmt UI  │    │ • 82KB Database  │    │ • Portal DB     │
│ • 70KB Admin UI │    │ • 67KB Utils     │    │ • User Data     │
│ • Responsive UI │    │ • 49KB Deletion  │    │ • File Storage  │
│ • Custom Themes │    │ • Auth & Security│    │ • Trash System  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Technology Stack

- **Backend**: Python 3.11+ with Datasette framework
- **Database**: SQLite with sqlite-utils and optimized connection pooling
- **Data Processing**: Pandas, openpyxl, xlrd for Excel support
- **Frontend**: HTML5, Tailwind CSS 3.4, Remix Icons
- **Authentication**: Custom bcrypt-based system with session management
- **File Storage**: Local filesystem with organized directory structure
- **Deployment**: Docker containers with Fly.io hosting

### Advanced Features

#### Upload System (131KB Engine)
- **Multi-Source Processing**: CSV, Excel, Google Sheets, Web CSV
- **Connection Pooling**: Optimized SQLite performance for large datasets
- **Advanced Null Handling**: Configurable empty cell processing
- **Real-Time Progress**: Live cancellation and progress tracking
- **Data Quality Analysis**: Automated quality assessment and reporting

#### Database Management (82KB Interface)
- **Lifecycle Management**: Create, import, publish, archive, delete
- **Trash System**: Soft delete with configurable retention periods
- **Table Operations**: Granular table-level management and deletion
- **Publishing Control**: Draft/published states with public access controls
- **Custom Branding**: Per-database themes and content customization

#### Administrative System (70KB Panel)
- **User Management**: Account creation, role assignment, activity monitoring
- **System Configuration**: File limits, retention policies, allowed extensions
- **Content Management**: Portal homepage, database descriptions, markdown support
- **Security Controls**: Password policies, session management, CSRF protection
- **Activity Monitoring**: Comprehensive logging and audit trails

### Plugin Architecture Overview

The system extends Datasette through eight specialized plugins (200KB+ total codebase):

#### Core Data Processing
- **upload_table.py** (131KB) - Multi-source upload engine with advanced null handling
- **common_utils.py** (67KB) - Security, validation, authentication, and shared utilities
- **manage_databases.py** (82KB) - Complete database lifecycle management

#### Administrative Functions
- **admin_panel.py** (66KB) - System administration and user management
- **create_database.py** (33KB) - Database creation workflows and import processing
- **delete_db.py** (49KB) - Safe deletion with trash system and recovery options

#### User Experience
- **user_profile.py** (24KB) - Account management and user preferences
- **render_links.py** (15KB) - Custom link processing and content rendering

#### Template System (467KB+ total)
19 comprehensive templates covering every aspect of the portal:
- **User Interfaces**: Upload (72KB), Management (66KB), Creation (27KB)
- **Administrative Tools**: System Admin (70KB), Content Editor (20KB)
- **Security Features**: Authentication, confirmations, password verification
- **Data Management**: Trash system, deletion workflows, table operations

## 📁 Complete File Structure

```
edgi-cloud/
├── 📄 README.md                    # This comprehensive documentation
├── 📄 requirements.txt             # Python dependencies
├── 📄 metadata.json               # Datasette configuration
├── 📄 Dockerfile                  # Container configuration
├── 📄 fly.toml                    # Fly.io deployment config
├── 📄 init_db.py                  # Database initialization script
├── 📄 migrate_db.py               # Database migration utilities
├── 📄 generate_metadata.py        # Dynamic metadata generation
│
├── 📁 plugins/                    # Datasette plugins (8 core modules)
│   ├── 📄 upload_table.py         # Enhanced upload system (131KB) - Multi-source with null handling
│   ├── 📄 common_utils.py         # Shared utilities (67KB) - Security, validation, data management
│   ├── 📄 manage_databases.py     # Database management (82KB) - User database administration
│   ├── 📄 admin_panel.py          # Administrative interface (66KB) - System admin functionality
│   ├── 📄 create_database.py      # Database creation (33KB) - Creation and import workflows
│   ├── 📄 delete_db.py            # Deletion management (49KB) - Safe deletion with trash system
│   ├── 📄 user_profile.py         # User management (24KB) - Profile and account management
│   └── 📄 render_links.py         # Link rendering (15KB) - Custom link processing
│
├── 📁 templates/                  # Jinja2 HTML templates (19 comprehensive interfaces)
│   ├── 📄 index.html              # Portal homepage - Public-facing landing page
│   ├── 📄 upload_table.html       # Enhanced upload interface (72KB) - Multi-source data import
│   ├── 📄 manage_databases.html   # User database management (66KB) - Complete database lifecycle
│   ├── 📄 system_admin.html       # System administration (70KB) - Admin control panel
│   ├── 📄 database_homepage.html  # Database-specific pages (24KB) - Custom database portals
│   ├── 📄 create_import_database.html # Database creation (27KB) - Import and creation workflows
│   ├── 📄 template.html           # Database customization (27KB) - Branding and content editor
│   ├── 📄 profile.html            # User profiles (28KB) - Account management interface
│   ├── 📄 portal_homepage_editor.html # Portal customization (20KB) - Homepage content editor
│   ├── 📄 login.html              # Authentication interface - Secure login system
│   ├── 📄 register.html           # User registration - Account creation
│   ├── 📄 all_databases.html      # Public database listing - Discovery interface
│   ├── 📄 system_trash_bin.html   # Trash management (25KB) - Soft delete recovery
│   ├── 📄 permanent_delete.html   # Hard deletion confirmation - Data destruction safeguards
│   ├── 📄 force_delete.html       # Administrative deletion - Emergency cleanup tools
│   ├── 📄 trash_confirm.html      # Deletion confirmation - User confirmation workflows
│   ├── 📄 delete_table_confirm.html # Table deletion - Granular data management
│   ├── 📄 create_empty_database.html # Empty database creation - Quick setup option
│   └── 📄 admin_password_confirmation.html # Admin verification - Security checkpoint
│
├── 📁 static/                     # Static assets
│   ├── 📄 styles.css              # Custom CSS styles
│   ├── 📁 js/                     # JavaScript modules
│   │   └── 📄 tailwind.config.js  # Tailwind configuration
│   ├── 📄 default_header.jpg      # Default header image
│   └── 📄 favicon.ico             # Site favicon
│
└── 📁 data/                       # Data storage (production)
    ├── 📄 portal.db               # Main portal database
    ├── 📁 {user_id}/              # User-specific directories
    │   ├── 📄 {database}.db       # User database files
    │   └── 📄 header.jpg          # Custom header images
    └── 📁 uploads/                # Temporary file uploads
```

## 🔐 Enterprise-Grade Security Architecture

### Authentication & Authorization

- **Password Security**: bcrypt hashing with configurable salt rounds
- **Session Management**: Secure cookie-based sessions with CSRF protection
- **Role-Based Access Control**: System admin and user roles with granular permissions
- **Input Validation**: Comprehensive sanitization of all user inputs
- **Account Security**: Password confirmation for critical operations

### Data Security

- **SQL Injection Prevention**: Parameterized queries throughout entire codebase
- **XSS Protection**: HTML sanitization for user-generated content
- **File Upload Security**: Type validation, size limits, virus scanning capabilities
- **Access Control**: User-based database isolation with ownership verification
- **Data Retention**: Configurable trash system with secure permanent deletion

### Infrastructure Security

- **HTTPS Enforcement**: TLS encryption for all communications
- **Environment Variables**: Sensitive configuration externalized and encrypted
- **Container Security**: Minimal Docker images with non-root execution
- **Volume Encryption**: Encrypted persistent storage on Fly.io
- **Audit Logging**: Comprehensive activity tracking and security monitoring

## 📊 Advanced Upload System

### Supported Data Sources

1. **File Upload**
   - CSV, TSV, TXT files with intelligent delimiter detection
   - Excel files (.xlsx, .xls) with first sheet processing
   - Drag & drop interface with real-time progress tracking
   - Connection testing and pre-upload validation

2. **Google Sheets Integration**
   - Direct import from publicly accessible Google Sheets
   - Automatic first sheet detection and processing
   - Connection testing and accessibility validation
   - Size verification before download

3. **Web CSV Import**
   - Direct URL-based CSV import with domain validation
   - Security checks against blocked domains
   - HEAD request validation and size verification
   - Progress monitoring with cancellation support

### Advanced Null Handling

The system provides three configurable null handling strategies:

```python
# Empty String Conversion (Recommended for most use cases)
"NULL", "N/A", "", "nan", "none", "nil", "-", "--" → ""

# Preserve NULL Values (For advanced analysis)
"NULL", "N/A", "", "nan", "none", "nil", "-", "--" → NULL

# Skip Problematic Rows (Data cleaning approach)
Rows with >80% empty cells → Automatically skipped
```

### Data Quality Features

- **Pre-Upload Analysis**: Structure validation and quality assessment
- **Column Analysis**: Identifies columns with high null percentages
- **Quality Scoring**: 0-100 data quality assessment with detailed metrics
- **Processing Reports**: Comprehensive statistics on rows processed, skipped, and cleaned
- **Warning System**: User-friendly alerts for potential data issues

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Docker (for deployment)
- Git

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/edgi-cloud.git
   cd edgi-cloud
   ```

2. **Set up Python environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Initialize the database**
   ```bash
   python init_db.py
   ```

4. **Start the development server**
   ```bash
   datasette serve data/portal.db \
     --metadata metadata.json \
     --plugins-dir=plugins \
     --template-dir=templates \
     --static static:static \
     --setting max_returned_rows 3000000 \
     --setting sql_time_limit_ms 360000 \
     --reload
   ```

5. **Access the portal**
   - Navigate to `http://localhost:8001`
   - Login with: `admin / edgi2025!`

### Production Deployment

1. **Deploy to Fly.io**
   ```bash
   fly auth login
   fly deploy
   ```

2. **Configure environment variables**
   ```bash
   fly secrets set CSRF_SECRET_KEY="your-secret-key"
   fly secrets set DEFAULT_PASSWORD="your-admin-password"
   fly secrets set APP_URL="https://your-domain.fly.dev"
   ```

3. **Monitor deployment**
   ```bash
   fly logs
   fly status
   ```

## 🎛️ Comprehensive Administration

### System Administrator Features

- **Portal Customization**: Complete homepage editor with markdown support
- **User Management**: Create, modify, and monitor user accounts
- **Database Oversight**: View and manage all user databases across the system
- **System Settings**: Configure file size limits, retention policies, allowed extensions
- **Activity Monitoring**: Real-time tracking of system usage and user actions
- **Content Management**: Rich text editing with custom branding capabilities
- **Trash Management**: System-wide trash bin with recovery and permanent deletion
- **Security Controls**: Password policies, session management, access controls

### User Features

- **Database Creation**: Create multiple databases with configurable per-user limits
- **Advanced Upload**: Multi-source data import with comprehensive quality analysis
- **Null Handling Control**: Choose from three processing strategies for empty values
- **Custom Homepages**: Brand databases with custom titles, descriptions, and images
- **Publishing Control**: Publish databases for public access or maintain as drafts
- **Data Management**: Complete CRUD operations on databases and tables
- **Profile Management**: Account settings, password changes, activity history
- **Trash Recovery**: Restore accidentally deleted databases within retention period

## 🔧 Production Configuration

### Environment Variables

```bash
# Required for Production
CSRF_SECRET_KEY=your-64-char-secret-key
PORTAL_DB_PATH=/data/portal.db
RESETTE_DATA_DIR=/data
RESETTE_STATIC_DIR=/app/static
APP_URL=https://your-domain.fly.dev

# Security & Authentication
DEFAULT_PASSWORD=custom-admin-password

# Performance Tuning
MAX_FILE_SIZE=104857600  # 100MB default (configurable via admin)
```

### System Settings (Database Configurable via Admin Panel)

```sql
-- Runtime configuration through admin interface
INSERT INTO system_settings VALUES 
  ('max_file_size', '104857600'),          -- Upload limit (100MB default)
  ('max_databases_per_user', '10'),        -- Per-user database limit
  ('trash_retention_days', '30'),          -- Soft delete retention period
  ('max_img_size', '5242880'),            -- Image upload limit (5MB)
  ('allowed_extensions', '.jpg,.png,.csv,.xlsx,.xls,.txt,.tsv');
```

### Advanced Features Configuration

- **Connection Pooling**: Automatic SQLite connection optimization for large uploads
- **Trash System**: Configurable retention with permanent deletion workflows  
- **Security**: CSRF protection, input validation, role-based access control
- **Monitoring**: Comprehensive activity logging and user action tracking
- **Content Management**: Markdown support with custom portal branding

## 📊 Database Schema

### Portal Database (`portal.db`)

```sql
-- User management with enhanced security
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    email TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_login TEXT,
    is_active INTEGER DEFAULT 1
);

-- Database registry with lifecycle management
CREATE TABLE databases (
    db_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    db_name TEXT UNIQUE NOT NULL,
    website_url TEXT,
    status TEXT DEFAULT 'draft',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    file_path TEXT,
    deleted_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users (user_id)
);

-- Runtime system configuration
CREATE TABLE system_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT,
    FOREIGN KEY (updated_by) REFERENCES users (user_id)
);

-- Comprehensive activity tracking
CREATE TABLE activity_logs (
    log_id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT NOT NULL,
    details TEXT,
    metadata TEXT,  -- JSON for structured data
    ip_address TEXT,
    user_agent TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (user_id)
);

-- Content management system
CREATE TABLE admin_content (
    db_id TEXT,
    section TEXT,
    content TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT,
    PRIMARY KEY (db_id, section),
    FOREIGN KEY (updated_by) REFERENCES users (user_id)
);

-- Table-level metadata and management
CREATE TABLE table_metadata (
    table_id TEXT PRIMARY KEY,
    db_id TEXT NOT NULL,
    table_name TEXT NOT NULL,
    row_count INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (db_id) REFERENCES databases (db_id)
);
```

## 🧪 Testing & Quality Assurance

### Running Tests

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run comprehensive test suite
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/unit/         # Unit tests
python -m pytest tests/integration/ # Integration tests
python -m pytest tests/upload/      # Upload functionality tests
python -m pytest tests/security/    # Security tests

# Generate coverage report
coverage run -m pytest && coverage report --show-missing
```

### Test Categories

- **Unit Tests**: Individual function and method validation
- **Integration Tests**: Plugin interaction and database operations
- **Upload Tests**: Multi-source upload functionality with null handling
- **Security Tests**: Authentication, authorization, and input validation
- **Performance Tests**: Large file processing and concurrent operations

### Quality Metrics

- **Code Coverage**: Target >90% for critical components
- **Security Scanning**: Automated vulnerability detection
- **Performance Benchmarks**: Upload speed and memory usage optimization
- **User Experience Testing**: Interface usability and accessibility validation

## 🤝 Contributing

We welcome contributions to improve the EDGI Datasette Cloud Portal! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with comprehensive tests
4. Submit a pull request with detailed description

### Development Guidelines

- **Code Standards**: Follow PEP 8 for Python code with type hints
- **Commit Messages**: Use semantic commit messages (feat:, fix:, docs:, etc.)
- **Testing**: Add tests for new features and maintain coverage
- **Documentation**: Update README and inline documentation
- **Security**: Follow security best practices and validate all inputs

### Recent Major Enhancements

- **Enhanced Upload System**: Multi-source support with advanced null handling
- **Data Quality Analysis**: Automated assessment and comprehensive reporting  
- **Improved Security**: CSRF protection, input validation, and audit logging
- **Better User Experience**: Intuitive interfaces with real-time feedback
- **Connection Pooling**: Optimized database performance for large operations
- **Trash System**: Safe deletion with configurable retention and recovery

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🌟 Acknowledgments

Built by the [Environmental Data & Governance Initiative (EDGI)](https://envirodatagov.org) to democratize environmental data access and support evidence-based policy making.

Special thanks to:
- The Datasette community for providing an excellent foundation
- Environmental researchers and activists who use and improve the platform
- Open source contributors and maintainers
- The broader environmental data community

## 📞 Support & Resources

- **Issues**: [GitHub Issues](https://github.com/your-org/edgi-cloud/issues)
- **Documentation**: [Project Wiki](https://github.com/your-org/edgi-cloud/wiki)
- **Contact**: [EDGI Contact Form](https://envirodatagov.org/contact/)
- **Community**: [EDGI Mailing List](https://envirodatagov.org/get-involved/)

## 📈 Project Statistics

- **Codebase Size**: 600KB+ of production code
- **Templates**: 19 comprehensive user interfaces
- **Plugins**: 8 specialized backend modules
- **Supported Formats**: 7 different data source types
- **Security Features**: 15+ protection mechanisms
- **Data Processing**: Handles files up to 100MB+ with quality analysis

---

*Democratizing environmental data access, one dataset at a time.*
