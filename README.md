# EDGI Datasette Cloud Portal

A comprehensive platform that empowers researchers, organizations, and environmental advocates to share critical environmental datasets as interactive, accessible websites. Built on Datasette with a custom administrative panel for seamless data publishing and portal customization.

## 🌍 Mission

The EDGI Datasette Cloud Portal serves the critical mission of **democratizing environmental data access** and supporting evidence-based environmental policy. Every dataset shared brings us closer to a more informed, sustainable future.

## ⚡ Key Features

- **Easy CSV Upload** - Transform spreadsheets into interactive databases
- **Custom Branding** - Create professional portals with organization identity
- **Instant Publishing** - Share data with the world in minutes
- **Advanced Search** - Enable users to filter, sort, and explore datasets
- **API Access** - Programmatic data access for researchers and developers
- **Markdown Support** - Rich text formatting with links, lists, and emphasis
- **Role-Based Access** - System admin and user roles with appropriate permissions
- **Free & Open** - No cost barriers to environmental data sharing

## 🏗️ System Architecture

### Core Components

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend       │    │   Data Layer    │
│                 │    │                  │    │                 │
│ • HTML Templates│◄──►│ • Datasette Core │◄──►│ • SQLite DBs    │
│ • Tailwind CSS  │    │ • Custom Plugin  │    │ • Portal DB     │
│ • JavaScript    │    │ • Flask Routes   │    │ • User Data     │
│ • Responsive UI │    │ • Auth System    │    │ • File Storage  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Technology Stack

- **Backend**: Python 3.11+ with Datasette framework
- **Database**: SQLite with sqlite-utils for data management
- **Frontend**: HTML5, Tailwind CSS 3.4, Remix Icons
- **Authentication**: Custom bcrypt-based system with session management
- **File Storage**: Local filesystem with organized directory structure
- **Deployment**: Docker containers with Fly.io hosting

### Plugin Architecture

The system extends Datasette through a comprehensive plugin (`datasette_admin_panel.py`) that provides:

- Custom route handlers for administrative functions
- Template overrides for enhanced UI/UX
- Authentication middleware and role management
- File upload and processing capabilities
- Markdown parsing and content management

## 📁 File Structure

```
edgi-cloud/
├── 📄 README.md                    # This file
├── 📄 requirements.txt             # Python dependencies
├── 📄 metadata.json               # Datasette configuration
├── 📄 Dockerfile                  # Container configuration
├── 📄 fly.toml                    # Fly.io deployment config
├── 📄 init_db.py                  # Database initialization script
│
├── 📁 plugins/                    # Datasette plugins
│   └── 📄 datasette_admin_panel.py # Main administrative plugin
│
├── 📁 templates/                  # Jinja2 HTML templates
│   ├── 📄 index.html              # Portal homepage
│   ├── 📄 database_homepage.html   # Database-specific homepage
│   ├── 📄 template.html           # Database customization editor
│   ├── 📄 system_admin.html       # System administration panel
│   ├── 📄 manage_databases.html    # User database management
│   ├── 📄 login.html              # Authentication interface
│   ├── 📄 register.html           # User registration
│   └── 📄 all_databases.html      # Public database listing
│
├── 📁 static/                     # Static assets
│   ├── 📄 styles.css              # Custom CSS styles
│   ├── 📄 tailwind.config.js      # Tailwind configuration
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

## 🔐 Security Architecture

### Authentication & Authorization

- **Password Security**: bcrypt hashing with salt rounds
- **Session Management**: Secure cookie-based sessions with CSRF protection
- **Role-Based Access Control**: System admin and user roles with distinct permissions
- **Input Validation**: Comprehensive sanitization of all user inputs

### Data Security

- **SQL Injection Prevention**: Parameterized queries throughout
- **XSS Protection**: HTML sanitization for user-generated content
- **File Upload Security**: Type validation, size limits, and safe storage
- **Access Control**: User-based database isolation

### Infrastructure Security

- **HTTPS Enforcement**: TLS encryption for all communications
- **Environment Variables**: Sensitive configuration externalized
- **Container Security**: Minimal Docker images with non-root execution
- **Volume Encryption**: Encrypted persistent storage on Fly.io

### Security Headers & Middleware

```python
# CSRF Protection
CSRF_SECRET_KEY = os.getenv('CSRF_SECRET_KEY')

# File Upload Limits
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {'.jpg', '.png', '.csv', '.txt'}

# Database Limits
MAX_DATABASES_PER_USER = 5
```

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
   datasette data/portal.db \
     --metadata metadata.json \
     --plugins-dir=plugins \
     --template-dir=templates \
     --static static:static \
     --reload
   ```

5. **Access the portal**
   - Navigate to `http://localhost:8001`
   - Login with: `admin / edgi2025!`

### Production Deployment

1. **Deploy to Fly.io**
   ```bash
   fly deploy
   ```

2. **Configure environment variables**
   ```bash
   fly secrets set CSRF_SECRET_KEY="your-secret-key"
   fly secrets set DEFAULT_PASSWORD="your-admin-password"
   ```

## 🎛️ Administration

### System Administrator Features

- **Portal Customization**: Edit homepage title, description, header image, and footer
- **User Management**: Create and manage user accounts
- **Database Oversight**: View and manage all user databases
- **Activity Monitoring**: Track system usage and user actions
- **Content Management**: Full markdown support with links, lists, and formatting

### User Features

- **Database Creation**: Create up to 5 databases per user
- **CSV Upload**: Transform spreadsheets into searchable databases
- **Custom Homepages**: Brand databases with custom titles, descriptions, and images
- **Publishing Control**: Publish databases for public access or keep as drafts
- **Data Management**: Edit, delete, and organize database content

## 🔧 Configuration

### Environment Variables

```bash
# Required
CSRF_SECRET_KEY=your-64-char-secret-key
PORTAL_DB_PATH=/data/portal.db
EDGI_DATA_DIR=/data
EDGI_STATIC_DIR=/static

# Optional
DEFAULT_PASSWORD=custom-admin-password
APP_URL=https://your-domain.com
```

### Customization

- **Themes**: Modify `static/tailwind.config.js` for color schemes
- **Branding**: Update templates and static assets
- **Features**: Extend `datasette_admin_panel.py` for new functionality

## 📊 Database Schema

### Portal Database (`portal.db`)

```sql
-- User management
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT,
    email TEXT,
    created_at TEXT
);

-- Database registry
CREATE TABLE databases (
    db_id TEXT PRIMARY KEY,
    user_id TEXT,
    db_name TEXT UNIQUE,
    website_url TEXT,
    status TEXT,
    created_at TEXT,
    file_path TEXT
);

-- Content management
CREATE TABLE admin_content (
    db_id TEXT,
    section TEXT,
    content TEXT,
    updated_at TEXT,
    updated_by TEXT,
    PRIMARY KEY (db_id, section)
);

-- Activity tracking
CREATE TABLE activity_logs (
    log_id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT,
    details TEXT,
    timestamp TEXT
);
```

## 🤝 Contributing

We welcome contributions to improve the EDGI Datasette Cloud Portal! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

### Development Guidelines

- Follow PEP 8 for Python code
- Use semantic commit messages
- Add tests for new features
- Update documentation as needed

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🌟 Acknowledgments

Built by the [Environmental Data & Governance Initiative (EDGI)](https://envirodatagov.org) in partnership with [Public Environmental Data Partners](https://screening-tools.com/).

Special thanks to:
- The Datasette community for the excellent foundation
- Environmental researchers and activists using the platform
- Contributors and maintainers

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/edgi-cloud/issues)
- **Documentation**: [Project Wiki](https://github.com/your-org/edgi-cloud/wiki)
- **Contact**: [EDGI Contact Form](https://envirodatagov.org/contact/)

---

*Democratizing environmental data access, one dataset at a time.* 🌍