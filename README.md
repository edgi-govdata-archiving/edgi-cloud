# EDGI Datasette Cloud Portal

> **Upload your data, customize your portal, and make environmental information accessible to the public.**

A user-friendly platform that enables researchers and organizations to share environmental datasets as interactive websites powered by [Datasette](https://datasette.io/). Transform CSV files into searchable, explorable databases with custom branding and public access.

[![Deployed on Fly.io](https://img.shields.io/badge/deployed%20on-Fly.io-blueviolet)](https://fly.io/)
[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://python.org/)
[![Datasette](https://img.shields.io/badge/powered%20by-Datasette-green)](https://datasette.io/)

## 🌍 Mission

Making environmental data accessible to everyone. The EDGI Datasette Cloud Portal democratizes environmental data sharing by providing an easy-to-use platform for researchers, organizations, and activists to publish their datasets as interactive, searchable websites.

## ✨ Key Features

### 📊 **Easy Data Upload**
- **Secure CSV Upload**: Upload environmental datasets up to 10MB with built-in validation
- **Auto-Type Detection**: Automatically detects column types (INTEGER, REAL, TEXT)
- **Batch Processing**: Handles large datasets efficiently with progress tracking
- **Data Validation**: Real-time CSV validation and error reporting

### 🎨 **Custom Data Portals**
- **Homepage Customization**: Create branded landing pages with custom images and descriptions
- **Markdown Support**: Rich text formatting with link support `[text](url)`
- **Header Images**: Upload custom header images with proper attribution
- **SEO Optimization**: Custom titles and descriptions for better discoverability

### 🔒 **Enterprise Security**
- **CSRF Protection**: Complete Cross-Site Request Forgery protection on all forms
- **Role-Based Access**: System admin and user roles with appropriate permissions
- **Secure File Upload**: Validated file types and size limits
- **Database Ownership**: Users can only manage their own databases
- **Audit Logging**: Complete activity tracking for security and compliance

### 🚀 **Instant Publishing**
- **Draft Mode**: Work privately before publishing
- **One-Click Publishing**: Make databases publicly accessible instantly
- **Auto-Generated APIs**: RESTful JSON APIs for all published data
- **Multiple Export Formats**: CSV, JSON, and more export options
- **Search & Filter**: Built-in full-text search and advanced filtering

## 🏗️ Architecture

### Technology Stack
- **Backend**: Python with Datasette framework
- **Database**: SQLite with extension support
- **Frontend**: Tailwind CSS with Remix Icon
- **Security**: bcrypt password hashing, CSRF tokens
- **Deployment**: Fly.io cloud platform
- **File Storage**: Local filesystem with configurable paths

### Core Components
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Frontend  │    │  Admin Panel    │    │  CSV Upload     │
│                 │    │                 │    │                 │
│ • User Dashboard│◄──►│ • User Mgmt     │◄──►│ • File Upload   │
│ • Database List │    │ • System Admin  │    │ • Type Detection│
│ • Custom Pages  │    │ • Activity Logs │    │ • Validation    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Core Engine   │
                    │                 │
                    │ • Datasette     │
                    │ • SQLite        │
                    │ • Authentication│
                    │ • CSRF Security │
                    └─────────────────┘
```

## 🚀 Quick Start

### For Users

1. **Register**: Create your account at the portal
2. **Create Database**: Set up your environmental database
3. **Upload Data**: Add CSV files through the secure upload interface
4. **Customize**: Brand your portal with images and descriptions
5. **Publish**: Make your data publicly accessible with one click

### For Developers

#### Prerequisites
- Python 3.8+
- Node.js (for Tailwind CSS)
- SQLite3

#### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/edgi-datasette-cloud.git
cd edgi-datasette-cloud

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
export EDGI_DATA_DIR="/path/to/data"
export EDGI_STATIC_DIR="/path/to/static"
export PORTAL_DB_PATH="/path/to/portal.db"

# Initialize the database
python init_db.py

# Run the development server
datasette serve portal.db --plugins-dir=plugins --template-dir=templates
```

#### Environment Configuration

```bash
# Required environment variables
EDGI_DATA_DIR=/data/databases          # Database storage location
EDGI_STATIC_DIR=/static               # Static files location  
PORTAL_DB_PATH=/data/portal.db        # Main portal database
FLY_APP_NAME=your-app-name           # For dynamic URL generation
```

## 🛡️ Security Features

### Authentication & Authorization
- **bcrypt Password Hashing**: Industry-standard password security
- **Role-Based Access Control**: Separate admin and user permissions
- **Session Management**: Secure cookie-based authentication
- **Database Ownership**: Users can only access their own databases

### CSRF Protection
- **Complete Form Protection**: All POST requests require valid CSRF tokens
- **AJAX Security**: Secure AJAX endpoints with token validation
- **Token Generation**: Cryptographically signed tokens with expiration
- **Automatic Validation**: Server-side token verification on all submissions

### File Upload Security
- **File Type Validation**: Only CSV files accepted
- **Size Limits**: Configurable upload limits (default 10MB)
- **Content Validation**: CSV structure and data validation
- **Secure Storage**: Files stored outside web-accessible directories

## 📊 Use Cases

### Environmental Research
- **Air Quality Monitoring**: Share pollution measurements and trends
- **Water Quality Data**: Publish watershed and drinking water analyses
- **Climate Data**: Distribute temperature, precipitation, and weather data
- **Biodiversity Studies**: Share species occurrence and habitat data

### Government & NGOs
- **Public Health Data**: Environmental health impact assessments
- **Compliance Monitoring**: Regulatory compliance and violation data
- **Community Engagement**: Public participation in environmental monitoring
- **Policy Support**: Data-driven environmental policy development

### Academic Institutions
- **Research Publication**: Share research datasets with proper attribution
- **Student Projects**: Enable student-led environmental monitoring
- **Collaboration**: Multi-institutional data sharing platforms
- **Education**: Interactive environmental data for teaching

## 🎯 User Experience

### Intuitive Interface
- **Clean Design**: Modern, accessible interface with Tailwind CSS
- **Responsive Layout**: Works seamlessly on desktop and mobile devices
- **Clear Navigation**: Logical workflow from upload to publication
- **Real-time Feedback**: Immediate validation and progress indicators

### Workflow Optimization
```
Upload CSV → Validate Data → Preview Results → Customize Portal → Publish
     ↓            ↓              ↓              ↓            ↓
  Drag/Drop    Auto-detect    Table preview   Brand page   Public URL
```

### Accessibility Features
- **Keyboard Navigation**: Full keyboard accessibility
- **Screen Reader Support**: Semantic HTML with proper ARIA labels
- **High Contrast**: Accessible color schemes
- **Clear Typography**: Readable fonts and appropriate sizing

## 🔧 Configuration

### Database Settings
```python
# Maximum databases per user
MAX_DATABASES_PER_USER = 5

# Maximum file upload size
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Allowed file extensions
ALLOWED_EXTENSIONS = {'.csv', '.txt'}
```

### Security Configuration
```python
# CSRF token expiration
CSRF_TOKEN_EXPIRY = 3600  # 1 hour

# Password requirements
MIN_PASSWORD_LENGTH = 8

# Session timeout
SESSION_TIMEOUT = 3600  # 1 hour
```

## 📈 Monitoring & Analytics

### Activity Logging
- **User Actions**: Complete audit trail of user activities
- **System Events**: Database creation, publishing, and modifications
- **Security Events**: Failed logins, permission violations
- **Performance Metrics**: Upload times, query performance

### System Health
- **Database Monitoring**: SQLite performance and integrity checks
- **File System**: Storage usage and availability monitoring
- **Application Metrics**: Request rates, response times, error rates

## 🚀 Deployment

### Fly.io Deployment

```bash
# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Login to Fly.io
fly auth login

# Deploy the application
fly deploy --remote-only --no-cache

# Set environment variables
fly secrets set EDGI_DATA_DIR=/data
fly secrets set PORTAL_DB_PATH=/data/portal.db
```

### Docker Deployment

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["datasette", "serve", "portal.db", "--host", "0.0.0.0", "--port", "8000"]
```

## 🤝 Contributing

We welcome contributions from the environmental data community!

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make changes with proper tests
4. Submit a pull request with detailed description

### Code Standards
- **Python**: Follow PEP 8 style guidelines
- **JavaScript**: ES6+ with proper error handling
- **HTML/CSS**: Semantic markup with accessibility considerations
- **Security**: All contributions must maintain security standards

### Testing
```bash
# Run security tests
python test_security.py

# Test CSV upload functionality
python test_csv_upload.py

# Validate CSRF protection
python test_csrf.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[EDGI](https://envirodatagov.org/)**: Environmental Data & Governance Initiative
- **[Datasette](https://datasette.io/)**: Simon Willison's excellent data publication platform
- **[Public Environmental Data Partners](https://screening-tools.com/)**: Collaborative environmental data efforts
- **Environmental Research Community**: For inspiration and feedback

## 📞 Support

- **Documentation**: [docs.example.com](https://docs.example.com)
- **Issues**: [GitHub Issues](https://github.com/your-org/edgi-datasette-cloud/issues)
- **Community**: [Discord Server](https://discord.gg/your-server)
- **Email**: support@your-domain.com

---

**Made with ❤️ by EDGI and Public Environmental Data Partners**

*Empowering environmental transparency through accessible data sharing.*