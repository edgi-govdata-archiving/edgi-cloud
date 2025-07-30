#!/usr/bin/env python3
"""
EDGI Cloud Portal - Complete Initialization Script
Run this script to set up everything needed for the portal
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# Configuration
PROJECT_DIR = "C:\MS Data Science - WMU\EDGI\edgi-cloud"
STATIC_DIR = os.path.join(PROJECT_DIR, "static")
TEMPLATES_DIR = os.path.join(PROJECT_DIR, "templates")
DATA_DIR = os.path.join(PROJECT_DIR, "data")

def check_python_version():
    """Check if Python 3.9+ is installed."""
    if sys.version_info < (3, 9):
        print("❌ Python 3.9 or higher is required")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} detected")

def install_dependencies():
    """Install required Python packages."""
    print("📦 Installing dependencies...")
    
    packages = [
        "datasette",
        "datasette-upload-csvs",
        "sqlite-utils",
        "bcrypt",
        "bleach",
        "pandas",
        "multipart",
        "uuid"
    ]
    
    for package in packages:
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", package], 
                         check=True, capture_output=True)
            print(f"   ✅ {package}")
        except subprocess.CalledProcessError as e:
            print(f"   ❌ Failed to install {package}: {e}")
            return False
    
    return True

def create_directories():
    """Create necessary directories."""
    print("📁 Creating directories...")
    
    directories = [
        PROJECT_DIR,
        STATIC_DIR,
        os.path.join(STATIC_DIR, "js"),
        TEMPLATES_DIR,
        DATA_DIR
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"   ✅ {directory}")

def create_static_files():
    """Create static files."""
    print("🎨 Creating static files...")
    
    # Create default header image (placeholder)
    default_header_path = os.path.join(STATIC_DIR, "default_header.jpg")
    if not os.path.exists(default_header_path):
        # Create a simple placeholder image using PIL if available
        try:
            from PIL import Image, ImageDraw, ImageFont
            img = Image.new('RGB', (1200, 400), color='#005EA2')
            draw = ImageDraw.Draw(img)
            
            # Try to load a font, fall back to default if not available
            try:
                font = ImageFont.truetype("arial.ttf", 48)
            except:
                font = ImageFont.load_default()
            
            text = "EDGI Environmental Data Portal"
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            
            x = (1200 - text_width) // 2
            y = (400 - text_height) // 2
            
            draw.text((x, y), text, fill='white', font=font)
            img.save(default_header_path, 'JPEG')
            print(f"   ✅ Created default header image")
        except ImportError:
            # Create a simple text file as placeholder
            with open(default_header_path.replace('.jpg', '.txt'), 'w') as f:
                f.write("Placeholder for header image")
            print(f"   ⚠️  PIL not available, created text placeholder")
    
    # Create favicon (simple text file for now)
    favicon_path = os.path.join(STATIC_DIR, "favicon.ico")
    if not os.path.exists(favicon_path):
        with open(favicon_path, 'w') as f:
            f.write("")  # Empty file
        print(f"   ✅ Created favicon placeholder")

def run_database_initialization():
    """Run the database initialization script."""
    print("🗄️  Initializing database with test data...")
    
    try:
        # Import and run the database initialization
        from database_init import main as init_main
        init_main()
        print("   ✅ Database initialized successfully")
        return True
    except Exception as e:
        print(f"   ❌ Database initialization failed: {e}")
        return False

def create_run_script():
    """Create a script to run the portal."""
    print("🚀 Creating run script...")
    
    run_script_content = '''#!/usr/bin/env python3
"""
EDGI Cloud Portal - Start Script
"""

import os
import sys
import subprocess

# Set environment variables
os.environ['PORTAL_DB_PATH'] = "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db"

def main():
    print("🌱 Starting EDGI Datasette Cloud Portal...")
    print("=" * 50)
    
    try:
        # Start Datasette with the portal plugin
        cmd = [
            sys.executable, "-m", "datasette",
            "--metadata", "metadata.json",
            "--plugins-dir", ".",
            "--static", "static:static",
            "--template-dir", "templates",
            "--port", "8001",
            "--host", "localhost",
            "portal.db"
        ]
        
        print("🔗 Portal will be available at: http://localhost:8001")
        print("📊 Upload CSVs at: http://localhost:8001/{database_name}/-/upload-csvs")
        print("🔐 Login with: admin / password123")
        print("=" * 50)
        
        subprocess.run(cmd, cwd="C:/MS Data Science - WMU/EDGI/edgi-cloud")
        
    except KeyboardInterrupt:
        print("\\n👋 Portal stopped")
    except Exception as e:
        print(f"❌ Error starting portal: {e}")

if __name__ == "__main__":
    main()
'''
    
    run_script_path = os.path.join(PROJECT_DIR, "run_portal.py")
    with open(run_script_path, 'w') as f:
        f.write(run_script_content)
    
    print(f"   ✅ Created {run_script_path}")

def create_metadata_json():
    """Create Datasette metadata configuration."""
    print("⚙️  Creating Datasette configuration...")
    
    metadata = {
        "title": "EDGI Datasette Cloud Portal",
        "description": "Environmental data sharing platform powered by Datasette",
        "plugins": {
            "datasette-upload-csvs": {
                "permissions": ["upload-csvs"]
            }
        },
        "databases": {
            "portal": {
                "title": "Portal Database"
            }
        }
    }
    
    import json
    metadata_path = os.path.join(PROJECT_DIR, "metadata.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"   ✅ Created {metadata_path}")

def main():
    """Main setup function."""
    print("🌱 EDGI Cloud Portal - Complete Setup")
    print("=" * 50)
    
    # Step 1: Check Python version
    check_python_version()
    
    # Step 2: Create directories
    create_directories()
    
    # Step 3: Install dependencies
    if not install_dependencies():
        print("❌ Setup failed: Could not install dependencies")
        sys.exit(1)
    
    # Step 4: Create static files
    create_static_files()
    
    # Step 5: Create configuration
    create_metadata_json()
    
    # Step 6: Initialize database
    if not run_database_initialization():
        print("❌ Setup failed: Database initialization failed")
        sys.exit(1)
    
    # Step 7: Create run script
    create_run_script()
    
    print("\n" + "=" * 50)
    print("✅ Setup Complete!")
    print("\n🚀 Next Steps:")
    print("1. Copy datasette_admin_panel.py to the project directory")
    print("2. Copy HTML templates to the templates/ directory")
    print("3. Run: python run_portal.py")
    print("\n📝 File Structure:")
    print(f"{PROJECT_DIR}/")
    print("├── datasette_admin_panel.py")
    print("├── portal.db")
    print("├── metadata.json")
    print("├── run_portal.py")
    print("├── templates/")
    print("│   ├── index.html")
    print("│   ├── manage_databases.html")
    print("│   ├── create_database.html")
    print("│   └── ...")
    print("├── static/")
    print("│   ├── styles.css")
    print("│   ├── js/tailwind.config.js")
    print("│   └── default_header.jpg")
    print("└── data/")
    print("    └── {user_id}/")
    print("        └── {database_name}.db")

if __name__ == "__main__":
    main()