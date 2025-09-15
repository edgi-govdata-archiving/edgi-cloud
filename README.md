# EDGI Cloud Portal

A comprehensive platform that empowers researchers, organizations, and environmental advocates to share critical environmental datasets as interactive, accessible websites. Built on Datasette with a custom administrative panel for seamless data publishing and portal customization.

## 🌍 Mission

The EDGI Cloud Portal serves the critical mission of **democratizing environmental data access** and supporting evidence-based environmental policy. Every dataset shared brings us closer to a more informed, sustainable future.

## 🚀 Recent Updates (September 2025)

### Markdown Support Enhancement (#57)
- **Full GitHub Flavored Markdown** - Complete implementation with headers, lists, links, bold, italic, code blocks
- **Dynamic Rendering** - Custom render_links.py plugin for runtime markdown processing
- **Protected URLs** - Smart markdown processing that preserves URL integrity
- **Metadata Generation** - Added generate_metadata.py for dynamic configuration

### Security & User Management (#54)
- **Forced Password Change** - New users must change password on first login
- **Enhanced Authentication** - Improved session management and password policies
- **User Activity Tracking** - Comprehensive logging of user actions

### Preview & Access Control (#53)
- **Unpublished Database Preview** - Owners can preview databases before publishing
- **Portal Homepage Preview** - Test customizations before going live
- **Access Verification** - Improved permission checking for preview features

### Upload System Improvements (#50-52)
- **JSONL Support** - Added JSON Lines format for streaming data
- **Progress Tracking** - Real-time upload progress with cancellation
- **Null Value Handling** - Three configurable strategies for empty cells
- **File Validation** - Pre-upload size and format checking
- **Cancel Feature** - Abort long-running uploads gracefully
- **Excel Processing** - Fixed Excel file handling with proper null processing

### Database Import Enhancements
- **Name Validation** - Check database name availability before import
- **Size Validation** - Verify file size limits before processing
- **Error Messages** - User-friendly feedback for validation failures

## ⚡ Key Features

### Data Upload & Processing
- **Multi-Source Upload** - CSV, Excel (.xlsx, .xls), JSONL, Google Sheets, and Web CSV
- **Advanced Null Handling** - Three strategies: empty string, preserve NULL, or skip rows
- **Data Quality Analysis** - Automated assessment and reporting
- **Large File Support** - Efficient processing with progress tracking
- **Real-time Progress** - Live upload progress with cancellation
- **Connection Testing** - Pre-upload validation for remote sources

### Content Management
- **GitHub Flavored Markdown** - Full markdown support for rich content
  ```markdown
  # Headers
  **Bold text** and *italic text*
  [Links](https://example.com)
  
  ## Lists
  - Bullet points
  1. Numbered lists
  
  `code blocks` and more!
  ```
- **Dynamic Rendering** - Markdown processed at runtime, not just at startup
- **Custom Homepages** - Database-specific branding and descriptions

### Portal Management
- **Custom Branding** - Professional portals with organization identity
- **Instant Publishing** - Share data with preview before publishing
- **Advanced Search** - Filter, sort, and explore datasets
- **API Access** - Programmatic data access for developers
- **Trash System** - Safe deletion with recovery options

### Administration & Security
- **Role-Based Access** - System admin and user roles
- **Password Policies** - Forced change on first login
- **Activity Monitoring** - Comprehensive logging
- **User Management** - Complete account lifecycle
- **System Configuration** - Runtime settings via admin interface

## 🏗️ System Architecture

### Core Components

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend       │    │   Data Layer    │
│  (19 Templates) │    │  (9 Plugins)     │    │                 │
│                 │    │                  │    │                 │
│ • Upload UI     │◄──►│ • Upload Engine  │◄──►│ • SQLite DBs    │
│ • Management UI │    │ • Database Mgmt  │    │ • Portal DB     │
│ • Admin Panel   │    │ • Markdown Render│    │ • User Data     │
│ • Preview Mode  │    │ • Auth System    │    │ • File Storage  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Technology Stack

- **Backend**: Python 3.11+ with Datasette framework
- **Database**: SQLite with sqlite-utils
- **Data Processing**: Pandas, openpyxl for Excel
- **Frontend**: HTML5, Tailwind CSS 3.4
- **Markdown**: Custom GitHub Flavored Markdown processor
- **Authentication**: bcrypt with session management
- **Deployment**: Docker containers on Fly.io

## 📁 Project Structure

```
edgi-cloud/
├── 📄 README.md                   # This documentation
├── 📄 requirements.txt            # Python dependencies
├── 📄 Dockerfile                  # Container configuration
├── 📄 fly.toml                    # Fly.io deployment
├── 📄 init_db.py                  # Database initialization
├── 📄 migrate_db.py               # Database migrations
│
├── 📁 plugins/                    # Datasette plugins (9 modules)
│   ├── 📄 upload_table.py         # Multi-source upload with progress
│   ├── 📄 common_utils.py         # Shared utilities & markdown processor
│   ├── 📄 manage_databases.py     # Database lifecycle management
│   ├── 📄 admin_panel.py          # System administration
│   ├── 📄 create_database.py      # Database creation workflows
│   ├── 📄 delete_db.py            # Deletion with trash system
│   ├── 📄 user_profile.py         # User account management
│   ├── 📄 render_links.py         # Dynamic markdown rendering
│   └── 📄 generate_metadata.py    # Metadata generation
│
├── 📁 templates/                  # User interfaces (19 templates)
│   └── [Template files for all UI components]
│
├── 📁 static/                     # Static assets
│   ├── 📄 styles.css              # Custom styles
│   └── 📁 js/                     # JavaScript modules
│
└── 📁 data/                       # Data storage
    ├── 📄 portal.db               # Main portal database
    └── 📁 {user_id}/              # User databases
```

## 🔐 Security Features

### Recent Security Enhancements
- **Forced Password Change** - New users must set their own password
- **Preview Access Control** - Strict permission checking for unpublished content
- **Upload Validation** - Pre-upload checks for file size and format
- **Session Management** - Enhanced cookie-based authentication

### Core Security
- **Password Security**: bcrypt hashing
- **CSRF Protection**: Token validation
- **Input Validation**: Comprehensive sanitization
- **SQL Injection Prevention**: Parameterized queries
- **XSS Protection**: HTML sanitization

## 📊 Upload System Features

### Supported Formats (September 2025)
- **CSV/TSV** - With intelligent delimiter detection
- **Excel** - .xlsx and .xls with null handling
- **JSONL** - JSON Lines for streaming data
- **Google Sheets** - Public sheets import
- **Web CSV** - Direct URL import

### Null Handling Options
```python
# Option 1: Convert to empty string (default)
NULL, N/A, nan → ""

# Option 2: Preserve as database NULL
NULL, N/A, nan → NULL

# Option 3: Skip problematic rows
Rows with >80% empty → Skip
```

### Upload Features
- **Progress Tracking** - Real-time percentage display
- **Cancellation** - Abort uploads mid-process
- **Size Validation** - Check before processing
- **Quality Analysis** - Data quality scoring
- **Error Recovery** - Graceful failure handling

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Git
- Docker (for deployment)

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/edgi-govdata-archiving/edgi-cloud.git
   cd edgi-cloud
   ```

2. **Set up Python environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Initialize database**
   ```bash
   python init_db.py
   python migrate_db.py  # Apply latest schema updates
   ```

4. **Generate metadata**
   ```bash
   python plugins/generate_metadata.py
   ```

5. **Start development server**
   ```bash
   datasette serve data/portal.db \
     --metadata metadata.json \
     --plugins-dir=plugins \
     --template-dir=templates \
     --static static:static \
     --reload
   ```

6. **Access the portal**
   - Navigate to `http://localhost:8001`
   - Default login: `admin / edgi2025!`
   - Change password on first login

### Production Deployment

1. **Deploy to Fly.io**
   ```bash
   fly deploy
   ```

2. **Set secrets**
   ```bash
   fly secrets set CSRF_SECRET_KEY="your-secret-key"
   fly secrets set DEFAULT_PASSWORD="secure-password"
   ```

## 🎛️ Administration

### System Admin Features
- **User Management** - Create users with forced password change
- **Portal Customization** - Full markdown editor for homepage
- **Database Oversight** - Preview and manage all databases
- **System Settings** - Configure limits and policies
- **Activity Monitoring** - Track user actions
- **Trash Management** - Recover deleted databases

### User Features
- **Database Creation** - Import or create new databases
- **Upload Data** - Multiple formats with progress tracking
- **Markdown Content** - Rich text descriptions with GitHub Flavored Markdown
- **Preview Mode** - Test before publishing
- **Publishing Control** - Draft and published states
- **Profile Management** - Password changes and settings

## 🔧 Configuration

### Environment Variables
```bash
CSRF_SECRET_KEY=your-secret-key
PORTAL_DB_PATH=/data/portal.db
RESETTE_DATA_DIR=/data
DEFAULT_PASSWORD=initial-admin-password
APP_URL=https://your-domain.fly.dev
```

### System Settings (Configurable via Admin)
- `max_file_size` - Upload size limit
- `max_databases_per_user` - Database quota
- `trash_retention_days` - Recovery period
- `allowed_extensions` - Permitted file types

## 🧪 Testing

```bash
# Run tests
python -m pytest tests/

# With coverage
coverage run -m pytest
coverage report
```

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

### Recent Contributors
- Enhanced markdown support implementation
- Upload system improvements
- Security enhancements
- Preview functionality

## 📈 Version History

### September 2025 Updates
- **v2.5.0** - Full GitHub Flavored Markdown support
- **v2.4.0** - Forced password change for new users
- **v2.3.0** - Preview mode for unpublished content
- **v2.2.0** - JSONL upload support
- **v2.1.0** - Enhanced null value handling
- **v2.0.0** - Upload cancellation and progress tracking

## 📜 License

MIT License - see LICENSE file for details

## 🌟 Acknowledgments

Built by the [Environmental Data & Governance Initiative (EDGI)](https://envirodatagov.org) to democratize environmental data access.

Special thanks to:
- The Datasette community
- Environmental researchers and activists
- Open source contributors

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/edgi-govdata-archiving/edgi-cloud/issues)
- **Documentation**: [Wiki](https://github.com/edgi-govdata-archiving/edgi-cloud/wiki)
- **Contact**: [EDGI](https://envirodatagov.org/contact/)

---

*Democratizing environmental data access, one dataset at a time.*