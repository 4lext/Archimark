# Archimark

A powerful web content archiving solution with advanced features for content extraction, organization, and RSS feed management.
REQUIRES PYTHON 3.9

## Installation

### Prerequisites
- Python 3.9
- NVIDIA GPU with CUDA (optional, for Text To Speech (TTS) acceleration)
### Create Virtual Environment
```bash
conda create --name nameofenvironment python=3.9
```

### Install Dependencies
After you have created the environment install the required packages. 
```bash
pip install -r requirements.txt
```
### Run 
```bash
python webpage2markdown3.py
```
### Basic Usage
1. Launch the Program
2. Enter a URL in the converter tab
3. Click "Extract" or press Ctrl+E
4. Preview the content
5. Add tags (Ctrl+T)
6. Save as markdown (Ctrl+S)

## Features

### Web Content Conversion
- Secure URL validation and content extraction
- Clean reader view conversion to markdown
- Real-time content preview
- Image downloading and management
- Browsing history with back/forward navigation
- Content caching for improved performance
- Support for favorite marking

### RSS Feed Reader
- Built-in RSS feed reader with categorization
- Multiple default feed categories (Technology, Wikipedia, AI)
- Custom feed category management
- Feed validation and testing
- Feed content caching
- Easy clipping from feeds to markdown converter

### Content Organization
- Tag-based organization system
- Hierarchical tag support
- YAML metadata format compatible with Obsidian
- Automatic metadata generation (title, source, date, tags)
- Custom save location management

### Text-to-Speech
- Built-in TTS support using VCTK model
- Multiple voice options
- GPU acceleration support
- Preview voice feature
- Read article functionality

### Security Features
- URL validation and attack pattern detection
- Secure HTTPS handling
- Input sanitization
- Domain validation
- Image content validation


## Usage


### RSS Reader
1. Switch to the News Reader tab
2. Select a category and feed
3. Click "Refresh" to load articles
4. Use "Clip" to send articles to converter
5. Manage feeds through the "Add Feed" button
6. Organize categories in Settings

### Settings
Access settings through:
- Menu bar → Settings → Preferences
- Keyboard shortcut: Ctrl+,

Configure:
- Save location
- TTS options
- Image handling
- RSS feed categories
- Feed display limits

## Keyboard Shortcuts
- Ctrl+E: Extract content
- Ctrl+S: Save as markdown
- Ctrl+T: Manage tags
- Ctrl+,: Open settings

## File Organization
Files are saved to `~/Documents/saved_articles/` by default, with:
- Markdown files in root directory
- Images in `images/` subdirectory
- Cache in `~/.webpage_converter/cache/`

## Metadata Format
Files are saved with YAML frontmatter:
```yaml
---
date: YYYY-MM-DD
time: HH:MM
source: URL
favorite: true/false
tags:
  - #tag1
  - #tag2
---
```

## Development

### Current Status
Version: 3.0.0
Last Updated: December 2024
Author: Alex Towery

### Recent Features
- RSS feed management
- Content caching system
- TTS integration
- History navigation
- Tag system improvements
- Obsidian-compatible metadata

### Planned Features
- Enhanced MIME-type validation
- Nested tag hierarchies
- Advanced feed filtering
- Offline reading mode
- Custom CSS support

## License
Copyright (c) 2024 Alex Towery
All rights reserved.

This software is provided "as is" without warranty. See LICENSE for full details.

## Third-Party Licenses
- PyQt6: GPL v3
- requests: Apache 2.0
- readability-lxml: Apache 2.0
- html2text: GPL v3
- PyQt6-WebEngine: GPL v3
- Beautiful Soup 4: MIT
- Pillow: HPND
- TTS: MIT

## Support
For issues and feature requests, please contact the author or submit through the project's issue tracker.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

Please ensure your contributions follow the existing code style and include appropriate tests.

## Version History

- 3.0.0 (December 2024)
  - Added RSS feed reader with category management
  - Implemented content caching system
  - Added TTS integration with GPU acceleration
  - Added browsing history with navigation
  - Enhanced tag system with Obsidian compatibility
  - Added favorite marking feature
  - Improved feed validation and management

- 2.0.0 (June 2024)
  - Added tag-based organization system
  - Implemented image handling and storage
  - Added YAML metadata support
  - Enhanced security features
  - Improved URL validation

- 1.0.0 (January 2024)
  - Initial release
  - Basic webpage to markdown conversion
  - Preview functionality
  - Simple save system

## Screenshots

### Main Converter Interface
![Main Interface](screenshots/main-interface.png)
- Modern, clean interface design
- URL input with navigation controls
- Live markdown preview
- Tag management system
- Favorite marking option
- TTS controls

### RSS Reader Tab
![News Reader](screenshots/news-reader.png)
- Category and feed management
- Article previews with clipping
- Feed validation tools
- Custom category organization

### Settings Dialog
![Settings](screenshots/settings.png)
- TTS configuration with voice selection
- Save location management
- Image handling options
- RSS feed category management
- Cache configuration

### Tag Management
![Tag Management](screenshots/tag-management.png)
- Enhanced tag organization
- Multiple tag selection
- Tag validation rules
- Obsidian-compatible format

### Feed Management
![Feed Management](screenshots/feed-management.png)
- Category creation and editing
- Feed validation tools
- Custom feed organization
- Easy feed addition

*Note: Screenshots are updated with each major release to reflect current functionality.*

## Acknowledgments

Special thanks to:
- The PyQt team for the robust GUI framework
- The TTS project for text-to-speech capabilities
- The Readability project for content extraction
- The Beautiful Soup team for HTML parsing
- The broader open-source community for their invaluable contributions
- All users who have provided feedback and suggestions

## Author

Alex Towery
- GitHub: [profile-link]
- Email: [contact-email]
- Website: [website-url]
