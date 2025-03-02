"""
Webpage to Markdown Converter (Version 3.0)
-----------------------------------------
A secure and organized web content archiving solution.

Copyright (c) 2024 Alex Towery
All rights reserved.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

DISCLAIMER OF WARRANTY AND LIMITATION OF LIABILITY:
------------------------------------------------
1. This software is provided "as is" without any guarantees or warranty.
2. The author makes no warranties, express or implied, about the software's 
   fitness for any particular purpose.
3. Users assume all risks associated with the use of this software.
4. The author shall not be liable for any damages or losses resulting from:
   - Use or inability to use the software
   - Data loss or corruption
   - System crashes or malfunctions
   - Any other damages related to software use
5. The author is not responsible for content accessed or saved through this software.
6. Users are responsible for complying with all applicable laws and website terms
   of service when using this software.

Third-Party Licenses:
--------------------
This software uses the following third-party libraries:
- PyQt6: GPL v3 License
- requests: Apache 2.0 License
- readability-lxml: Apache 2.0 License
- html2text: GPL v3 License
- PyQt6-WebEngine: GPL v3 License
- Beautiful Soup 4: MIT License
- Pillow: HPND License
- TTS: MIT License

For full license texts, please refer to the respective packages.

Program Evolution:
Initial Request: Simple program to save web pages to markdown
Current State: Secure content extraction tool with organization features
Security Focus: Added URL validation and attack pattern detection
Usability: Implemented tagging system and keyboard shortcuts

Core Features:
- Secure URL validation and content extraction
- Clean reader view conversion to markdown
- Content preview before saving
- Tag-based organization system
- Keyboard shortcuts (Ctrl+E: Extract, Ctrl+S: Save, Ctrl+T: Tags)
- Automatic metadata (title, source, date, tags)

Security Features:
- URL validation and attack pattern detection
- Secure HTTPS handling
- Input sanitization
- Domain validation

Usage:
1. Run: python webpage_to_markdown.py
2. Enter URL
3. Extract and preview content (Ctrl+E)
4. Manage tags if desired (Ctrl+T)
5. Save as markdown (Ctrl+S)
Files save to: ~/Documents/saved_articles/

Dependencies:
    pip install PyQt6 requests readability-lxml html2text PyQt6-WebEngine

Development Notes:
Next planned features:
- MIME-type validation enhancement
- Custom save location options
- Image handling improvements
- Hierarchical tag system

Author: Alex Towery
Version: 3.0.0
Last Updated: December 2024
"""

import sys
import os
from datetime import datetime
from urllib.parse import urlparse
import re
import logging
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QTextBrowser,
    QLabel,
    QMessageBox,
    QComboBox,
    QDialog,
    QListWidget,
    QTabWidget,
    QScrollArea,
    QFrame,
    QCheckBox,
    QGroupBox,
    QFileDialog,
    QListWidgetItem,
    QInputDialog,
)
from PyQt6.QtCore import Qt, QSettings, pyqtSignal, QMetaObject
from PyQt6.QtGui import QKeySequence, QShortcut
import requests
from urllib3.exceptions import InsecureRequestWarning
from readability import Document
import html2text
import markdown
import feedparser
import threading
import time
from TTS.api import TTS
from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
from PyQt6.QtCore import QUrl
import torch
import html
from bs4 import BeautifulSoup
import tempfile
import glob
import hashlib
from PIL import Image
from pathlib import Path
from urllib.parse import urljoin, urlparse
import io
import json
import sqlite3
from datetime import timedelta
import xml.etree.ElementTree

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class URLValidator:
    """
    Enhanced URL validator with content-type validation and security checks.
    """

    def __init__(self):
        self.patterns = {
            "protocol": re.compile(r"^https?://"),
            "domain": re.compile(
                r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$"
            ),
            "ip_address": re.compile(
                r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
            ),
            "unsafe_chars": re.compile(r"[<>{}|\\\^`]"),
        }

        self.attack_patterns = {
            "xss": re.compile(
                r"<script|javascript:|data:text/html|vbscript:", re.IGNORECASE
            ),
            "sqli": re.compile(
                r"(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\s+(?:ALL\s+)?(?:DISTINCT\s+)?(?:FROM|INTO|TABLE)",
                re.IGNORECASE,
            ),
            "path_traversal": re.compile(r"\.{2,}[/\\]"),
            "protocol_injection": re.compile(
                r"(?:file|data|ftp|ws|wss|jar):", re.IGNORECASE
            ),
        }

    def validate_url(self, url: str) -> tuple[bool, str, dict]:
        try:
            # Basic cleanup
            url = url.strip()
            if not url:
                return False, "URL cannot be empty", {}

            # Replace 'http://' with 'https://'
            if url.startswith("http://"):
                url = "https://" + url[len("http://") :]
            elif not url.startswith("https://"):
                # Force HTTPS if no protocol is specified
                url = f"https://{url}"

            # Parse URL
            parsed = urlparse(url)

            # Basic domain validation
            if not parsed.netloc:
                return False, "Invalid domain", {}

            # Check for attack patterns
            for attack_type, pattern in self.attack_patterns.items():
                if pattern.search(url):
                    return (
                        False,
                        f"Security check failed: {attack_type} pattern detected",
                        {},
                    )

            return True, url, {}

        except Exception as e:
            logger.error(f"URL validation error: {str(e)}")
            return False, f"Validation error: {str(e)}", {}


class TagDialog(QDialog):
    def __init__(self, parent=None, existing_tags=None):
        super().__init__(parent)
        self.existing_tags = existing_tags or []
        self.selected_tags = []
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Manage Tags")
        layout = QVBoxLayout(self)

        # Add help text explaining tag rules
        help_text = QLabel(
            "Tag Rules:\n"
            "• Only letters, numbers, hyphens and underscores allowed\n"
            "• Tags will be converted to lowercase\n"
            "• Maximum length: 50 characters\n"
            "• Spaces and special characters will be removed"
        )
        help_text.setStyleSheet("color: #c8aa6f; padding: 10px;")
        layout.addWidget(help_text)

        # Tag input
        self.tag_input = QLineEdit()
        self.tag_input.setPlaceholderText("Enter new tag...")
        layout.addWidget(self.tag_input)

        # Add tag button
        add_button = QPushButton("Add Tag")
        add_button.clicked.connect(self.add_tag)
        layout.addWidget(add_button)

        # Existing tags list
        self.tag_list = QListWidget()
        self.tag_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.refresh_tags()
        layout.addWidget(self.tag_list)

        # Done button
        done_button = QPushButton("Done")
        done_button.clicked.connect(self.accept)
        layout.addWidget(done_button)

    def add_tag(self):
        new_tag = self.tag_input.text().strip()
        if new_tag:
            # Sanitize the tag before adding
            sanitized_tag = sanitize_tag(new_tag)
            if sanitized_tag and sanitized_tag not in self.existing_tags:
                self.existing_tags.append(sanitized_tag)
                self.refresh_tags()
                self.tag_input.clear()

    def refresh_tags(self):
        self.tag_list.clear()
        for tag in sorted(self.existing_tags):
            self.tag_list.addItem(tag)

    def get_selected_tags(self):
        return [item.text() for item in self.tag_list.selectedItems()]


class MarkdownViewer(QTextBrowser):
    # Add signals
    tts_state_changed = pyqtSignal(bool)
    link_clicked = pyqtSignal(str)  # New signal for link clicks

    def __init__(self):
        super().__init__()
        self.setOpenExternalLinks(False)  # Disable automatic external link handling

        # Add base directory for images
        self.base_dir = os.path.expanduser(
            "~/Desktop/ObsidianKnowledgeVault/saved_articles"
        )
        # Set the search paths for resources
        self.setSearchPaths([self.base_dir])

        # Initialize TTS only if enabled in settings
        settings = QSettings("WebpageConverter", "Settings")
        if settings.value("enable_tts", False, type=bool):
            self.initialize_tts()

        # Setup context menu
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

        # Connect link clicks
        self.anchorClicked.connect(self.handle_link_click)

        # Set the widget's background color
        self.setStyleSheet(
            """
            QTextBrowser {
                background-color: #fcfcf7;
                border: none;
                color: #1a1a1a;  /* Dark gray, almost black */
            }
        """
        )

        # Set the document's styling
        self.document().setDefaultStyleSheet(
            """
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                line-height: 1.6;
                margin: 20px;
                background-color: #fcfcf7;  /* Warm off-white background */
                color: #1a1a1a;  /* Dark gray, almost black */
                box-shadow: 0 0 20px rgba(0,0,0,0.05);  /* Subtle paper-like shadow */
            }
            h1, h2, h3 { 
                color: #1a1a1a;
                border-bottom: 1px solid #eaeaea;
                padding-bottom: 0.3em;
            }
            pre { 
                background-color: #ffffff; 
                padding: 16px; 
                border-radius: 4px;
                border: 1px solid #e8e8e8;
            }
            code { 
                background-color: #ffffff; 
                padding: 2px 4px;
                border-radius: 3px;
                border: 1px solid #e8e8e8;
            }
            blockquote {
                border-left: 4px solid #b4b4b4;
                padding-left: 16px;
                color: #333333;  /* Darker gray for blockquotes */
                margin: 16px 0;
                background-color: #ffffff;
            }
            img { 
                max-width: min(800px, 90%);  /* Maximum of 800px or 90% of container width */
                min-width: 200px;            /* Minimum size to ensure readability */
                width: auto;                 /* Allow natural scaling */
                height: auto;                /* Maintain aspect ratio */
                display: block;
                margin: 1em auto;
                border-radius: 4px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                object-fit: contain;
            }
            /* Add media query for smaller screens */
            @media screen and (max-width: 768px) {
                img {
                    max-width: 95%;         /* Allow images to be wider on small screens */
                    min-width: 150px;       /* Smaller minimum on small screens */
                }
            }
            a { 
                color: #2173db;  /* Radiant blue for better contrast */
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
            p {
                margin: 1em;
                color: #1a1a1a;  /* Dark gray, almost black */
            }
        """
        )

        # Add stop button state
        self.is_playing = False

    def initialize_tts(self):
        # Check for CUDA availability
        self.use_cuda = torch.cuda.is_available()
        if self.use_cuda:
            print(f"CUDA is available. Using GPU: {torch.cuda.get_device_name(0)}")

        # Initialize TTS with GPU acceleration if available
        self.tts = TTS(model_name="tts_models/en/vctk/vits", gpu=self.use_cuda)

        # Get available speakers and set speaker from settings
        self.speakers = self.tts.speakers
        settings = QSettings("WebpageConverter", "Settings")
        default_speaker = settings.value("default_speaker", "")
        self.current_speaker = (
            default_speaker if default_speaker in self.speakers else self.speakers[0]
        )

        # Initialize audio player
        self.player = QMediaPlayer()
        self.audio_output = QAudioOutput()
        self.player.setAudioOutput(self.audio_output)

    def setMarkdown(self, text):
        # Convert relative image paths to absolute URLs for preview
        text = self._process_image_paths(text)

        html_content = markdown.markdown(
            text,
            extensions=[
                "markdown.extensions.fenced_code",
                "markdown.extensions.tables",
                "markdown.extensions.codehilite",
                "markdown.extensions.toc",
            ],
        )
        self.setHtml(html_content)

    def _process_image_paths(self, text):
        """Convert markdown image paths to proper URLs for preview"""
        # Regular expression to find markdown images
        image_pattern = r"!\[([^\]]*)\]\(([^)]+)\)"

        def replace_path(match):
            alt_text = match.group(1)
            image_path = match.group(2)

            # If it's already a URL, leave it unchanged
            if image_path.startswith(("http://", "https://")):
                return f"![{alt_text}]({image_path})"

            # Convert relative path to absolute file URL
            if image_path.startswith("images/"):
                abs_path = os.path.join(self.base_dir, image_path)
                return f"![{alt_text}](file:///{abs_path})"

            return match.group(0)

        return re.sub(image_pattern, replace_path, text)

    def show_context_menu(self, position):
        menu = self.createStandardContextMenu(position)

        # Add custom menu items for the current link if any
        cursor = self.cursorForPosition(position)
        if cursor.charFormat().anchorHref():
            current_link = cursor.charFormat().anchorHref()
            # Add option to open in converter
            open_action = menu.addAction("Open in Converter")
            open_action.triggered.connect(lambda: self.link_clicked.emit(current_link))
            # Add separator
            menu.addSeparator()

        # Only add TTS options if enabled in settings
        settings = QSettings("WebpageConverter", "Settings")
        if settings.value("enable_tts", False, type=bool):
            read_action = menu.addAction("Read Aloud")
            read_action.triggered.connect(self.read_selected_text)

        menu.exec(self.mapToGlobal(position))

    def set_speaker(self, speaker):
        self.current_speaker = speaker

    def read_selected_text(self):
        if self.is_playing:
            # Stop current playback
            self.stop_playback()
            return

        settings = QSettings("WebpageConverter", "Settings")
        if not settings.value("enable_tts", False, type=bool):
            return

        if not hasattr(self, "tts"):
            self.initialize_tts()

        text = self.textCursor().selectedText()
        if not text:
            return

        # Get the current default speaker from settings
        default_speaker = settings.value("default_speaker", "")

        # Ensure we have a speaker selected
        if not hasattr(self, "current_speaker") or not self.current_speaker:
            if default_speaker and default_speaker in self.speakers:
                self.current_speaker = default_speaker
                logger.info(
                    f"Using default speaker from settings: {self.current_speaker}"
                )
            elif self.speakers:
                self.current_speaker = self.speakers[0]
                logger.info(f"Using first available speaker: {self.current_speaker}")
            else:
                logger.error("No speakers available for TTS")
                QMessageBox.warning(self, "TTS Error", "No speakers available")
                return

        try:
            # Create a unique temporary file for each TTS request
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as temp_file:
                temp_path = temp_file.name

            # Generate audio with error checking
            try:
                self.tts.tts_to_file(
                    text=text,
                    file_path=temp_path,
                    speaker=self.current_speaker,
                    gpu=self.use_cuda,
                )
            except Exception as e:
                logger.error(f"TTS generation failed: {str(e)}")
                QMessageBox.warning(self, "TTS Error", "Failed to generate speech")
                return

            # Verify the file exists and has content
            if not os.path.exists(temp_path) or os.path.getsize(temp_path) == 0:
                logger.error("Generated audio file is empty or missing")
                QMessageBox.warning(
                    self, "TTS Error", "Generated audio file is invalid"
                )
                return

            # Set up media player with error handling
            try:
                self.player.setSource(QUrl.fromLocalFile(temp_path))
                self.audio_output.setVolume(50)

                # Connect error handling
                self.player.errorOccurred.connect(self.handle_player_error)

                # Start playback
                self.player.play()

                # Set playing state
                self.is_playing = True

                # Emit signal instead of trying to access parent
                self.tts_state_changed.emit(True)

                # Schedule cleanup after playback
                self.player.mediaStatusChanged.connect(
                    lambda status: (
                        self.cleanup_audio_file(temp_path)
                        if status == QMediaPlayer.MediaStatus.EndOfMedia
                        else None
                    )
                )

            except Exception as e:
                logger.error(f"Audio playback failed: {str(e)}")
                self.cleanup_audio_file(temp_path)
                QMessageBox.warning(self, "Playback Error", "Failed to play audio")

        except Exception as e:
            logger.error(f"TTS processing failed: {str(e)}")
            QMessageBox.warning(self, "Error", "Text-to-speech processing failed")
            self.stop_playback()

    def handle_player_error(self, error, error_string):
        logger.error(f"Media player error: {error_string}")
        QMessageBox.warning(
            self, "Playback Error", f"Audio playback error: {error_string}"
        )

    def cleanup_audio_file(self, filepath):
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            logger.error(f"Failed to cleanup temporary file {filepath}: {str(e)}")

    def stop_playback(self):
        """Stop current TTS playback"""
        if hasattr(self, "player"):
            self.player.stop()
        self.is_playing = False
        # Emit signal for state change
        self.tts_state_changed.emit(False)

    def cleanup(self):
        # Stop any ongoing playback
        if hasattr(self, "player"):
            self.player.stop()

        # Clean up temporary files
        temp_dir = tempfile.gettempdir()
        pattern = os.path.join(temp_dir, "*.wav")
        for temp_file in glob.glob(pattern):
            try:
                os.remove(temp_file)
            except Exception as e:
                logger.error(f"Failed to cleanup temp file {temp_file}: {str(e)}")

    def handle_link_click(self, url):
        """Handle clicked links by emitting the URL to the main window"""
        # Convert QUrl to string
        url_str = url.toString()
        # Emit the URL for the main window to handle
        self.link_clicked.emit(url_str)


class NewsReaderTab(QWidget):
    # Add signal for clip events
    clip_requested = pyqtSignal(str)
    # Add signal for thread-safe widget updates
    article_ready = pyqtSignal(dict)

    def __init__(self, parent=None, colors=None):
        super().__init__(parent)
        self.validator = URLValidator()
        self.colors = colors or {
            "primary": "#2c3e50",  # Dark blue-gray
            "secondary": "#34495e",  # Lighter blue-gray
            "accent": "#3498db",  # Bright blue
            "success": "#2ecc71",  # Green
            "warning": "#f1c40f",  # Yellow
            "error": "#e74c3c",  # Red
            "background": "#ecf0f1",  # Light gray
            "text": "#2c3e50",  # Dark blue-gray
            "button_hover": "#2980b9",  # Darker blue
        }

        # Load feeds from settings
        self.settings = QSettings("WebpageConverter", "RSSFeeds")
        self.feeds = self.load_feeds()
        self.initUI()

    def load_feeds(self):
        """Load feeds from settings or return defaults if none exist"""
        saved_feeds = self.settings.value("feeds")
        if saved_feeds:
            feeds = json.loads(saved_feeds)
            # Only return saved feeds if they're not empty
            if feeds and isinstance(feeds, dict) and any(feeds.values()):
                return feeds

        # Default feeds if no valid saved feeds exist
        return {
            "Technology": [
                ("TechCrunch", "https://techcrunch.com/feed/"),
                ("Wired", "https://www.wired.com/feed/rss"),
                ("The Verge", "https://www.theverge.com/rss/index.xml"),
            ],
            "Wikipedia": [
                (
                    "New Pages",
                    "https://en.wikipedia.org/w/index.php?title=Special:NewPages&feed=rss",
                ),
                (
                    "Featured Articles",
                    "https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=featured&feedformat=atom",
                ),
                (
                    "On This Day",
                    "https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=onthisday&feedformat=atom",
                ),
            ],
            "Artificial Intelligence": [
                (
                    "MIT AI News",
                    "http://news.mit.edu/rss/topic/artificial-intelligence2",
                ),
                ("NVIDIA Blog", "http://feeds.feedburner.com/nvidiablog"),
                ("AI Weirdness", "https://aiweirdness.com/rss"),
            ],
        }

    def save_feeds(self):
        """Save current feeds to settings"""
        # Only save if we have actual feeds
        if self.feeds and isinstance(self.feeds, dict) and any(self.feeds.values()):
            self.settings.setValue("feeds", json.dumps(self.feeds))
            self.settings.sync()  # Force sync to disk

    def initUI(self):
        layout = QVBoxLayout(self)

        # Feed selection with light theme styling
        feed_layout = QHBoxLayout()

        # Style labels
        category_label = QLabel("Category:")
        source_label = QLabel("Source:")
        for label in [category_label, source_label]:
            label.setStyleSheet(
                f"""
                QLabel {{
                    color: {self.colors['text']};
                    font-weight: bold;
                }}
            """
            )

        self.category_combo = QComboBox()
        self.category_combo.addItems(self.feeds.keys())
        self.feed_combo = QComboBox()
        self.refresh_button = QPushButton("Refresh")

        # Add new feed button
        self.add_feed_button = QPushButton("Add Feed")
        self.add_feed_button.clicked.connect(self.show_add_feed_dialog)
        self.add_feed_button.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {self.colors['success']};
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #27ae60;
            }}
        """
        )

        # Light theme combo box style
        combo_style = f"""
            QComboBox {{
                padding: 8px;
                border: 1px solid {self.colors['secondary']};
                border-radius: 4px;
                background-color: white;
                color: {self.colors['text']};
                min-width: 150px;
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox::down-arrow {{
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid {self.colors['secondary']};
                margin-right: 5px;
            }}
            QComboBox QAbstractItemView {{
                background-color: white;
                selection-background-color: {self.colors['accent']};
                selection-color: white;
            }}
        """

        self.category_combo.setStyleSheet(combo_style)
        self.feed_combo.setStyleSheet(combo_style)

        feed_layout.addWidget(category_label)
        feed_layout.addWidget(self.category_combo)
        feed_layout.addWidget(source_label)
        feed_layout.addWidget(self.feed_combo)
        feed_layout.addWidget(self.refresh_button)
        feed_layout.addWidget(self.add_feed_button)
        feed_layout.addStretch()

        layout.addLayout(feed_layout)

        # Light theme scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet(
            f"""
            QScrollArea {{
                border: 1px solid #ddd;
                background-color: white;
                border-radius: 4px;
            }}
            QScrollBar:vertical {{
                border: none;
                background: {self.colors['background']};
                width: 10px;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background: #b8b8b8;
                border-radius: 5px;
                min-height: 20px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: #a0a0a0;
            }}
        """
        )

        scroll_widget = QWidget()
        scroll_widget.setStyleSheet(
            """
            QWidget {
                background-color: white;
            }
        """
        )

        self.news_layout = QVBoxLayout(scroll_widget)
        self.news_layout.setSpacing(10)
        self.news_layout.setContentsMargins(10, 10, 10, 10)
        scroll_area.setWidget(scroll_widget)
        layout.addWidget(scroll_area)

        # Connect signals
        self.category_combo.currentTextChanged.connect(self.update_feeds)
        self.refresh_button.clicked.connect(self.fetch_news)

        # Initial setup
        self.update_feeds()

        # Connect signal to UI update method
        self.article_ready.connect(self.create_article_widget)

    def update_feeds(self):
        category = self.category_combo.currentText()
        self.feed_combo.clear()
        self.feed_combo.addItems([feed[0] for feed in self.feeds[category]])

    def fetch_news(self):
        try:
            # Clear previous news items
            for i in reversed(range(self.news_layout.count())):
                self.news_layout.itemAt(i).widget().setParent(None)

            category = self.category_combo.currentText()
            feed_name = self.feed_combo.currentText()
            feed_url = next(
                feed[1] for feed in self.feeds[category] if feed[0] == feed_name
            )

            # Show loading status
            loading_label = QLabel("Loading feed...")
            loading_label.setStyleSheet(
                f"""
                QLabel {{
                    color: {self.colors['text']};
                    padding: 10px;
                    font-style: italic;
                }}
            """
            )
            self.news_layout.addWidget(loading_label)

            # Start worker thread for feed processing
            worker = threading.Thread(target=self.process_feed, args=(feed_url,))
            worker.daemon = True  # Make thread daemon so it doesn't block program exit
            worker.start()
        except Exception as e:
            logger.error(f"Error starting feed fetch: {str(e)}")
            self.show_error(f"Failed to fetch news: {str(e)}")

    def process_feed(self, feed_url):
        """Process feed in worker thread with retry logic"""
        max_retries = 3
        retry_delay = 2  # seconds

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/rss+xml, application/xml, text/xml, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Connection": "keep-alive",
        }

        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    logger.debug(f"Retry attempt {attempt + 1} for {feed_url}")
                    time.sleep(retry_delay * attempt)  # Exponential backoff

                response = requests.get(feed_url, headers=headers, timeout=10)

                if response.status_code == 403:
                    logger.warning(f"Access denied (403) on attempt {attempt + 1}")
                    if attempt == max_retries - 1:
                        QMetaObject.invokeMethod(
                            self,
                            "show_error",
                            Qt.ConnectionType.QueuedConnection,
                            Q_ARG(
                                str,
                                "Feed access denied. The server might be rate-limiting requests. Please try again later.",
                            ),
                        )
                        return
                    continue

                response.raise_for_status()
                feed = feedparser.parse(response.text)

                if not feed.entries:
                    logger.warning("Feed contains no entries")
                    QMetaObject.invokeMethod(
                        self,
                        "show_error",
                        Qt.ConnectionType.QueuedConnection,
                        Q_ARG(
                            str,
                            "No entries found in feed. The feed might be empty or invalid.",
                        ),
                    )
                    return

                # Process each entry
                for entry in feed.entries:
                    # Prepare data for UI
                    article_data = {
                        "title": entry.title,
                        "date": datetime.fromtimestamp(
                            time.mktime(entry.published_parsed)
                        ),
                        "summary": BeautifulSoup(
                            entry.summary, "html.parser"
                        ).get_text(),
                        "link": entry.link,
                    }
                    # Emit signal to create widget in main thread
                    self.article_ready.emit(article_data)

                # Successfully processed feed, break the retry loop
                break

            except requests.exceptions.RequestException as e:
                logger.error(f"Request error on attempt {attempt + 1}: {str(e)}")
                if attempt == max_retries - 1:
                    QMetaObject.invokeMethod(
                        self,
                        "show_error",
                        Qt.ConnectionType.QueuedConnection,
                        Q_ARG(
                            str,
                            f"Failed to fetch feed after {max_retries} attempts: {str(e)}",
                        ),
                    )
            except Exception as e:
                logger.error(f"Feed processing error: {str(e)}")
                QMetaObject.invokeMethod(
                    self,
                    "show_error",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(str, f"Failed to process feed: {str(e)}"),
                )
                break  # Break on non-request errors

    def create_article_widget(self, data):
        """Create article widget in main thread"""
        try:
            article_widget = QWidget()
            article_widget.setStyleSheet(
                """
                QWidget {
                    background-color: white;
                    border: 1px solid #e0e0e0;
                    border-radius: 4px;
                }
            """
            )

            article_layout = QVBoxLayout(article_widget)
            article_layout.setContentsMargins(15, 15, 15, 15)

            # Title and date
            title_layout = QHBoxLayout()
            title_label = QLabel(f"<b>{data['title']}</b>")
            title_label.setWordWrap(True)
            title_label.setStyleSheet(
                """
                QLabel {
                    font-size: 14px;
                    color: #2c3e50;
                }
            """
            )

            date = QLabel(f"<i>{data['date'].strftime('%Y-%m-%d %H:%M')}</i>")
            date.setStyleSheet(
                """
                QLabel {
                    color: #7f8c8d;
                    font-size: 12px;
                }
            """
            )

            clip_button = QPushButton("Clip")
            clip_button.setStyleSheet(
                f"""
                QPushButton {{
                    background-color: {self.colors['accent']};
                    color: white;
                    border: none;
                    padding: 5px 15px;
                    border-radius: 3px;
                    font-size: 12px;
                }}
                QPushButton:hover {{
                    background-color: {self.colors['button_hover']};
                }}
            """
            )
            clip_button.clicked.connect(
                lambda checked, url=data["link"]: self.clip_article(url)
            )

            title_layout.addWidget(title_label)
            title_layout.addWidget(date)
            title_layout.addWidget(clip_button)

            article_layout.addLayout(title_layout)

            # Summary
            if "summary" in data:
                summary_label = QLabel(data["summary"])
                summary_label.setWordWrap(True)
                summary_label.setStyleSheet(
                    """
                    QLabel {
                        color: #34495e;
                        font-size: 13px;
                        margin-top: 5px;
                        line-height: 1.4;
                    }
                """
                )
                article_layout.addWidget(summary_label)

            # Add separator
            separator = QFrame()
            separator.setFrameShape(QFrame.Shape.HLine)
            separator.setFrameShadow(QFrame.Shadow.Sunken)
            separator.setStyleSheet(
                """
                background-color: #ecf0f1;
                margin: 5px 0px;
            """
            )

            article_layout.addWidget(separator)

            self.news_layout.addWidget(article_widget)
        except Exception as e:
            logger.error(f"Widget creation error: {str(e)}")
            self.show_error(f"Failed to create article widget: {str(e)}")

    def clip_article(self, url):
        # Emit signal instead of trying to access parent
        self.clip_requested.emit(url)

    def show_error(self, message):
        """Show error message to user"""
        QMessageBox.critical(self, "Error", message)

    def show_add_feed_dialog(self):
        """Show dialog to add a new RSS feed"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New RSS Feed")
        dialog.setMinimumWidth(400)

        layout = QVBoxLayout(dialog)

        # Feed name input
        name_layout = QHBoxLayout()
        name_label = QLabel("Feed Name:")
        name_input = QLineEdit()
        name_layout.addWidget(name_label)
        name_layout.addWidget(name_input)
        layout.addLayout(name_layout)

        # Feed URL input
        url_layout = QHBoxLayout()
        url_label = QLabel("Feed URL:")
        url_input = QLineEdit()
        url_layout.addWidget(url_label)
        url_layout.addWidget(url_input)
        layout.addLayout(url_layout)

        # Category selection
        category_layout = QHBoxLayout()
        category_label = QLabel("Category:")
        category_combo = QComboBox()
        category_combo.addItems(self.feeds.keys())
        category_layout.addWidget(category_label)
        category_layout.addWidget(category_combo)
        layout.addLayout(category_layout)

        # Note about adding new categories
        note_label = QLabel(
            "Note: To add a new category, please use the Settings dialog."
        )
        note_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(note_label)

        # Validate button
        validate_button = QPushButton("Validate Feed")
        validate_button.clicked.connect(lambda: self.validate_feed(url_input.text()))
        layout.addWidget(validate_button)

        # Buttons
        button_box = QHBoxLayout()
        add_button = QPushButton("Add Feed")
        cancel_button = QPushButton("Cancel")

        add_button.clicked.connect(
            lambda: self.add_feed(
                name_input.text(),
                url_input.text(),
                category_combo.currentText(),
                dialog,
            )
        )
        cancel_button.clicked.connect(dialog.reject)

        button_box.addWidget(add_button)
        button_box.addWidget(cancel_button)
        layout.addLayout(button_box)

        dialog.exec()

    def validate_feed(self, url):
        """
        Validate that the URL is a valid RSS feed with enhanced security and error handling.

        Returns:
            bool: True if valid feed, False otherwise
        """
        try:
            # Initial URL validation using the validator instance
            is_valid, validated_url, _ = self.validator.validate_url(url)
            if not is_valid:
                QMessageBox.warning(self, "Invalid URL", "Please enter a valid URL.")
                return False

            # Configure headers to mimic a browser request
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/rss+xml, application/xml, application/atom+xml, text/xml, */*",
                "Accept-Language": "en-US,en;q=0.5",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Connection": "keep-alive",
            }

            # Make initial request with redirect handling
            response = requests.get(
                validated_url,
                headers=headers,
                timeout=10,
                allow_redirects=False,
                stream=True,  # Enable streaming to check content size
            )

            # Handle redirects manually with validation
            redirect_count = 0
            max_redirects = 5
            while response.is_redirect and redirect_count < max_redirects:
                redirect_url = response.headers["Location"]
                # Validate redirect URL
                is_valid, validated_redirect, _ = self.validator.validate_url(
                    redirect_url
                )
                if not is_valid:
                    QMessageBox.warning(
                        self,
                        "Invalid Redirect",
                        "Feed redirects to an invalid URL. Please verify the feed URL.",
                    )
                    return False

                response = requests.get(
                    validated_redirect,
                    headers=headers,
                    timeout=10,
                    allow_redirects=False,
                    stream=True,
                )
                redirect_count += 1

            if redirect_count >= max_redirects:
                QMessageBox.warning(
                    self,
                    "Too Many Redirects",
                    "Feed URL has too many redirects. Please verify the URL.",
                )
                return False

            # Check status code after following redirects
            if response.status_code == 403:
                QMessageBox.warning(
                    self,
                    "Access Denied",
                    "The feed is protected or requires authentication. Please verify the URL or try an alternative feed URL.",
                )
                return False
            elif response.status_code != 200:
                QMessageBox.warning(
                    self,
                    "Invalid Feed",
                    f"Server returned status code {response.status_code}. Please verify the URL.",
                )
                return False

            # Validate content type
            content_type = response.headers.get("content-type", "").lower()
            valid_types = {
                "application/rss+xml",
                "application/xml",
                "application/atom+xml",
                "text/xml",
                "application/rdf+xml",
            }

            if not any(valid_type in content_type for valid_type in valid_types):
                QMessageBox.warning(
                    self,
                    "Invalid Content Type",
                    f"Expected RSS/XML feed but received {content_type}. Please verify the URL.",
                )
                return False

            # Check content size before downloading
            max_size = 10 * 1024 * 1024  # 10MB limit
            content_size = response.headers.get("content-length")
            if content_size and int(content_size) > max_size:
                QMessageBox.warning(
                    self,
                    "Feed Too Large",
                    "The feed is too large to process. Maximum size is 10MB.",
                )
                return False

            # Download content with size limit
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > max_size:
                    QMessageBox.warning(
                        self,
                        "Feed Too Large",
                        "The feed is too large to process. Maximum size is 10MB.",
                    )
                    return False

            # Try to parse the feed with enhanced error handling
            try:
                feed = feedparser.parse(content)

                # Check for feedparser-specific errors
                if hasattr(feed, "bozo") and feed.bozo:
                    error_msg = (
                        str(feed.bozo_exception)
                        if hasattr(feed, "bozo_exception")
                        else "Unknown parsing error"
                    )
                    QMessageBox.warning(
                        self,
                        "Feed Parsing Error",
                        f"The feed contains errors: {error_msg}\nPlease verify the feed URL.",
                    )
                    return False

                if not feed.version:
                    QMessageBox.warning(
                        self,
                        "Invalid Feed",
                        "The URL does not appear to be a valid RSS/Atom feed. Please verify the URL.",
                    )
                    return False

                if hasattr(feed, "status") and feed.status == 403:
                    QMessageBox.warning(
                        self,
                        "Access Denied",
                        "The feed is protected or requires authentication. Please verify the URL or try an alternative feed URL.",
                    )
                    return False

                # Additional feed validation
                if not feed.entries:
                    QMessageBox.warning(
                        self,
                        "Empty Feed",
                        "The feed appears to be valid but contains no entries. Please verify the URL.",
                    )
                    return False

                # Validate feed structure
                required_entry_fields = {"title", "link"}
                for entry in feed.entries[:1]:  # Check at least first entry
                    missing_fields = required_entry_fields - set(entry.keys())
                    if missing_fields:
                        QMessageBox.warning(
                            self,
                            "Invalid Feed Structure",
                            f"Feed entries are missing required fields: {', '.join(missing_fields)}",
                        )
                        return False

                QMessageBox.information(
                    self,
                    "Success",
                    f"Valid RSS feed detected with {len(feed.entries)} entries!",
                )
                return True

            except xml.etree.ElementTree.ParseError as e:
                QMessageBox.warning(
                    self,
                    "XML Parsing Error",
                    f"Failed to parse feed XML: {str(e)}\nPlease verify the feed URL.",
                )
                return False
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Feed Parsing Error",
                    f"Error parsing feed content: {str(e)}\nPlease verify the feed URL.",
                )
                return False

        except requests.exceptions.SSLError:
            QMessageBox.warning(
                self,
                "SSL Error",
                "Could not establish a secure connection. The site's security certificate might be invalid.",
            )
            return False
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(
                self,
                "Connection Error",
                "Could not connect to the server. Please check your internet connection and the URL.",
            )
            return False
        except requests.exceptions.Timeout:
            QMessageBox.warning(
                self,
                "Timeout Error",
                "The request timed out. Please try again or verify the URL.",
            )
            return False
        except requests.exceptions.TooManyRedirects:
            QMessageBox.warning(
                self,
                "Too Many Redirects",
                "The request exceeded the maximum number of redirects. Please verify the URL.",
            )
            return False
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Error validating feed: {str(e)}\nPlease verify the URL or try an alternative feed URL.",
            )
            return False

    def add_feed(self, name, url, category, dialog):
        """Add a new feed to the selected category"""
        if not name or not url:
            QMessageBox.warning(self, "Error", "Please fill in both name and URL.")
            return

        try:
            # Validate feed first
            if not self.validate_feed(url):
                return

            # Add feed to category
            self.feeds[category].append((name, url))

            # Save feeds
            self.save_feeds()

            # Update UI
            self.update_feeds()

            # Close dialog
            dialog.accept()

            # Show success message
            QMessageBox.information(
                self,
                "Success",
                f"Feed '{name}' added successfully to category '{category}'!",
            )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Error adding feed: {str(e)}\nPlease try again or use a different feed URL.",
            )


class ImageHandler:
    """Handles secure image downloading, validation, and storage"""

    ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
    MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB

    def __init__(self, base_dir):
        self.image_dir = Path(base_dir) / "images"
        self.image_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()

    def process_image(self, img_url, base_url):
        """Downloads, validates, and stores an image securely"""
        try:
            # Resolve relative URLs
            if not bool(urlparse(img_url).netloc):
                img_url = urljoin(base_url, img_url)

            logger.debug(f"Processing image from URL: {img_url}")

            # Download with timeout and size limit
            response = self.session.get(
                img_url, timeout=10, stream=True, headers={"User-Agent": "Mozilla/5.0"}
            )
            response.raise_for_status()

            # Validate content type
            content_type = response.headers.get("content-type", "").lower()
            logger.debug(f"Image content type: {content_type}")

            if content_type not in self.ALLOWED_MIME_TYPES:
                logger.warning(f"Unsupported content type: {content_type}")
                # Try to determine format from file extension
                ext = Path(img_url).suffix.lower()
                if ext in {".jpg", ".jpeg", ".png", ".gif", ".webp"}:
                    logger.debug(f"Using file extension: {ext}")
                else:
                    raise ValueError(f"Invalid image type: {content_type}")

            # Download and validate image data
            img_data = response.content
            if len(img_data) > self.MAX_IMAGE_SIZE:
                raise ValueError("Image too large")

            # Generate unique filename
            img_hash = hashlib.sha256(img_data).hexdigest()[:12]

            # Try to open image with PIL for validation
            try:
                with Image.open(io.BytesIO(img_data)) as img:
                    # Get actual image format
                    img_format = img.format.lower()
                    logger.debug(f"Detected image format: {img_format}")

                    # Save with proper extension
                    filename = f"{img_hash}.{img_format}"
                    img_path = self.image_dir / filename

                    # Save optimized image
                    img.save(img_path, optimize=True, quality=85)
                    logger.debug(f"Image saved successfully: {filename}")

                    return str(img_path.relative_to(self.image_dir))

            except Exception as e:
                logger.error(f"PIL processing error for {img_url}: {str(e)}")
                # Try alternative processing for problematic JPEGs
                if content_type == "image/jpeg" or img_url.lower().endswith(
                    (".jpg", ".jpeg")
                ):
                    return self._handle_problematic_jpeg(img_data, img_hash)
                raise

        except Exception as e:
            logger.error(f"Image processing failed for {img_url}: {str(e)}")
            return None

    def _handle_problematic_jpeg(self, img_data, img_hash):
        """Alternative handling for problematic JPEG images"""
        try:
            logger.debug("Attempting alternative JPEG processing")
            # Try to force JPEG processing with specific parameters
            with Image.open(io.BytesIO(img_data)) as img:
                img.load()  # Force decode
                filename = f"{img_hash}.jpg"
                img_path = self.image_dir / filename

                # Save with minimal processing
                img.save(img_path, "JPEG", quality=85, optimize=False)
                logger.debug(f"Alternative JPEG processing successful: {filename}")
                return str(img_path.relative_to(self.image_dir))
        except Exception as e:
            logger.error(f"Alternative JPEG processing failed: {str(e)}")
            return None


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        # Add color scheme
        self.colors = {
            "primary": "#2c3e50",  # Dark blue-gray
            "secondary": "#34495e",  # Lighter blue-gray
            "accent": "#3498db",  # Bright blue
            "success": "#2ecc71",  # Green
            "warning": "#f1c40f",  # Yellow
            "error": "#e74c3c",  # Red
            "background": "#ecf0f1",  # Light gray
            "text": "#2c3e50",  # Dark blue-gray
            "button_hover": "#2980b9",  # Darker blue
        }
        self.settings = QSettings("WebpageConverter", "Settings")
        self.feed_settings = QSettings("WebpageConverter", "RSSFeeds")
        self.preview_text = "This is a sample of how this voice will sound."
        self.temp_audio_file = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Settings")
        self.setMinimumWidth(400)
        layout = QVBoxLayout(self)

        # Add RSS Feed Categories Group
        feed_group = QGroupBox("RSS Feed Categories")
        feed_group.setStyleSheet(
            f"""
            QGroupBox {{
                font-size: 14px;
                font-weight: bold;
                color: {self.colors['text']};
                border: 2px solid {self.colors['accent']};
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 8px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: {self.colors['accent']};
            }}
        """
        )
        feed_layout = QVBoxLayout()

        # Category list
        self.category_list = QListWidget()
        self.category_list.setAlternatingRowColors(True)
        self.category_list.setStyleSheet(
            f"""
            QListWidget {{
                background-color: white;
                border: 1px solid {self.colors['accent']};
                border-radius: 4px;
                padding: 5px;
                color: {self.colors['text']};
                font-size: 13px;
            }}
            QListWidget::item {{
                padding: 8px;
                border-bottom: 1px solid #e0e0e0;
                border-radius: 4px;
            }}
            QListWidget::item:alternate {{
                background-color: #f8f9fa;
            }}
            QListWidget::item:selected {{
                background-color: {self.colors['accent']};
                color: white;
            }}
            QListWidget::item:hover {{
                background-color: #e3f2fd;
            }}
        """
        )

        # Load existing categories from NewsReaderTab's default feeds
        default_feeds = {
            "Technology": [
                ("TechCrunch", "https://techcrunch.com/feed/"),
                ("Wired", "https://www.wired.com/feed/rss"),
                ("The Verge", "https://www.theverge.com/rss/index.xml"),
            ],
            "Wikipedia": [
                (
                    "New Pages",
                    "https://en.wikipedia.org/w/index.php?title=Special:NewPages&feed=rss",
                ),
                (
                    "Featured Articles",
                    "https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=featured&feedformat=atom",
                ),
                (
                    "On This Day",
                    "https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=onthisday&feedformat=atom",
                ),
            ],
            "Artificial Intelligence": [
                (
                    "MIT AI News",
                    "http://news.mit.edu/rss/topic/artificial-intelligence2",
                ),
                ("NVIDIA Blog", "http://feeds.feedburner.com/nvidiablog"),
                ("AI Weirdness", "https://aiweirdness.com/rss"),
            ],
        }

        # Load feeds from settings or use defaults
        feeds = self.load_feeds() or default_feeds

        # Populate the category list
        for category in sorted(feeds.keys()):
            self.category_list.addItem(category)

        feed_layout.addWidget(self.category_list)

        # Category management buttons
        button_layout = QHBoxLayout()

        # Create and style buttons
        add_category_button = QPushButton("Add Category")
        remove_category_button = QPushButton("Remove Category")
        rename_category_button = QPushButton("Rename Category")

        for button in [
            add_category_button,
            remove_category_button,
            rename_category_button,
        ]:
            button.setStyleSheet(
                f"""
                QPushButton {{
                    background-color: {self.colors['accent']};
                    color: white;
                    border: none;
                    padding: 8px 15px;
                    border-radius: 4px;
                    font-weight: bold;
                    font-size: 12px;
                }}
                QPushButton:hover {{
                    background-color: {self.colors['button_hover']};
                }}
                QPushButton:disabled {{
                    background-color: #bdc3c7;
                }}
            """
            )

        add_category_button.clicked.connect(self.add_category)
        remove_category_button.clicked.connect(self.remove_category)
        rename_category_button.clicked.connect(self.rename_category)

        button_layout.addWidget(add_category_button)
        button_layout.addWidget(remove_category_button)
        button_layout.addWidget(rename_category_button)

        feed_layout.addLayout(button_layout)
        feed_group.setLayout(feed_layout)
        layout.addWidget(feed_group)

        # TTS Settings Group
        tts_group = QGroupBox("Text-to-Speech Settings")
        tts_layout = QVBoxLayout()

        self.enable_tts = QCheckBox("Enable Text-to-Speech")
        self.enable_tts.setChecked(self.settings.value("enable_tts", False, type=bool))
        self.enable_tts.toggled.connect(self.on_tts_toggled)
        tts_layout.addWidget(self.enable_tts)

        # Speaker selection
        speaker_layout = QHBoxLayout()
        speaker_label = QLabel("Default Speaker:")
        speaker_label.setStyleSheet("color: #ecf0f1; font-weight: bold;")
        self.speaker_combo = QComboBox()
        self.speaker_combo.setEnabled(self.enable_tts.isChecked())

        # Preview button
        self.preview_button = QPushButton("Preview Voice")
        self.preview_button.setEnabled(False)
        self.preview_button.clicked.connect(self.preview_voice)

        speaker_layout.addWidget(speaker_label)
        speaker_layout.addWidget(self.speaker_combo)
        speaker_layout.addWidget(self.preview_button)
        tts_layout.addLayout(speaker_layout)

        # Add note about TTS model download
        tts_note = QLabel(
            "Note: Enabling TTS will download a ~1GB model file on first use."
        )
        tts_note.setWordWrap(True)
        tts_note.setStyleSheet("color: #666; font-style: italic;")
        tts_layout.addWidget(tts_note)

        tts_group.setLayout(tts_layout)
        layout.addWidget(tts_group)

        # Initialize TTS and populate speakers if enabled
        if self.enable_tts.isChecked():
            self.initialize_tts()

        # Save Location Group
        save_group = QGroupBox("Save Location")
        save_layout = QHBoxLayout()

        self.save_location = QLineEdit()
        self.save_location.setText(
            self.settings.value(
                "save_location", os.path.expanduser("~/Documents/saved_articles")
            )
        )
        self.save_location.setStyleSheet(
            """
            QLineEdit {
                color: #2c3e50;  /* Dark blue-gray for better contrast */
                font-family: system-ui, -apple-system, sans-serif;
                font-size: 13px;
            }
        """
        )
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_save_location)

        save_layout.addWidget(self.save_location)
        save_layout.addWidget(browse_button)
        save_group.setLayout(save_layout)
        layout.addWidget(save_group)

        # Image Settings Group (new)
        image_group = QGroupBox("Image Settings")
        image_layout = QVBoxLayout()

        self.enable_images = QCheckBox("Extract and save images")
        self.enable_images.setChecked(
            self.settings.value("enable_images", True, type=bool)
        )
        self.enable_images.setToolTip(
            "When disabled, images will be excluded from both preview and saved files"
        )
        image_layout.addWidget(self.enable_images)

        image_group.setLayout(image_layout)
        layout.addWidget(image_group)

        # News Feed Settings Group (new)
        news_group = QGroupBox("News Feed Settings")
        news_layout = QHBoxLayout()

        feed_limit_label = QLabel("Number of news items to display:")
        self.feed_limit_combo = QComboBox()
        self.feed_limit_combo.addItems(["10", "25", "50", "100"])

        # Set current value from settings or default to 25
        current_limit = str(self.settings.value("news_feed_limit", 25, type=int))
        index = self.feed_limit_combo.findText(current_limit)
        if index >= 0:
            self.feed_limit_combo.setCurrentIndex(index)

        news_layout.addWidget(feed_limit_label)
        news_layout.addWidget(self.feed_limit_combo)
        news_group.setLayout(news_layout)
        layout.addWidget(news_group)

        # Buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        cancel_button = QPushButton("Cancel")

        save_button.clicked.connect(self.save_settings)
        cancel_button.clicked.connect(self.reject)

        button_layout.addStretch()
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

    def on_tts_toggled(self, checked):
        """Handle TTS enable/disable"""
        self.speaker_combo.setEnabled(checked)
        if checked and self.speaker_combo.count() == 0:
            self.initialize_tts()
        self.preview_button.setEnabled(checked and self.speaker_combo.count() > 0)

    def initialize_tts(self):
        """Initialize TTS and populate speaker list"""
        try:
            # Initialize TTS
            self.tts = TTS(
                model_name="tts_models/en/vctk/vits", gpu=torch.cuda.is_available()
            )

            # Populate speaker combo
            current_speaker = self.settings.value("default_speaker", "")
            self.speaker_combo.clear()
            self.speaker_combo.addItems(self.tts.speakers)

            # Set current speaker if previously selected
            if current_speaker and current_speaker in self.tts.speakers:
                index = self.speaker_combo.findText(current_speaker)
                self.speaker_combo.setCurrentIndex(index)

            self.preview_button.setEnabled(True)

        except Exception as e:
            logger.error(f"Failed to initialize TTS: {str(e)}")
            QMessageBox.warning(
                self,
                "TTS Error",
                "Failed to initialize Text-to-Speech. Please try again.",
            )
            self.enable_tts.setChecked(False)

    def preview_voice(self):
        """Preview the selected voice"""
        try:
            speaker = self.speaker_combo.currentText()
            if not speaker:
                return

            # Create temporary file for audio
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as temp_file:
                temp_path = temp_file.name
                self.temp_audio_file = temp_path

            # Generate preview audio
            self.tts.tts_to_file(
                text=self.preview_text,
                file_path=temp_path,
                speaker=speaker,
                gpu=torch.cuda.is_available(),
            )

            # Play the preview
            self.player = QMediaPlayer()
            self.audio_output = QAudioOutput()
            self.player.setAudioOutput(self.audio_output)
            self.player.setSource(QUrl.fromLocalFile(temp_path))
            self.audio_output.setVolume(50)
            self.player.play()

            # Disable preview button while playing
            self.preview_button.setEnabled(False)
            self.player.mediaStatusChanged.connect(self.on_preview_finished)

        except Exception as e:
            logger.error(f"Voice preview failed: {str(e)}")
            QMessageBox.warning(
                self, "Preview Error", "Failed to preview voice. Please try again."
            )

    def on_preview_finished(self, status):
        """Handle preview playback completion"""
        if status == QMediaPlayer.MediaStatus.EndOfMedia:
            self.preview_button.setEnabled(True)
            # Cleanup temp file
            if self.temp_audio_file and os.path.exists(self.temp_audio_file):
                try:
                    os.remove(self.temp_audio_file)
                    self.temp_audio_file = None
                except Exception as e:
                    logger.error(f"Failed to cleanup temp file: {str(e)}")

    def browse_save_location(self):
        directory = QFileDialog.getExistingDirectory(
            self, "Select Save Directory", self.save_location.text()
        )
        if directory:
            self.save_location.setText(directory)

    def save_settings(self):
        self.settings.setValue("enable_tts", self.enable_tts.isChecked())
        self.settings.setValue("save_location", self.save_location.text())
        if self.enable_tts.isChecked():
            self.settings.setValue("default_speaker", self.speaker_combo.currentText())
        self.settings.setValue("enable_images", self.enable_images.isChecked())
        self.settings.setValue(
            "news_feed_limit", int(self.feed_limit_combo.currentText())
        )
        self.accept()

    def cleanup(self):
        """Cleanup resources before closing"""
        if hasattr(self, "player"):
            self.player.stop()
        if self.temp_audio_file and os.path.exists(self.temp_audio_file):
            try:
                os.remove(self.temp_audio_file)
            except Exception as e:
                logger.error(f"Failed to cleanup temp file: {str(e)}")

    def closeEvent(self, event):
        """Handle dialog close"""
        self.cleanup()
        super().closeEvent(event)

    def load_feeds(self):
        """Load feeds from settings or return defaults if none exist"""
        saved_feeds = self.feed_settings.value("feeds")
        if saved_feeds:
            feeds = json.loads(saved_feeds)
            # Only return saved feeds if they're not empty
            if feeds and isinstance(feeds, dict) and any(feeds.values()):
                return feeds

        # Default feeds if no valid saved feeds exist
        return {
            "Technology": [
                ("TechCrunch", "https://techcrunch.com/feed/"),
                ("Wired", "https://www.wired.com/feed/rss"),
                ("The Verge", "https://www.theverge.com/rss/index.xml"),
            ],
            "Wikipedia": [
                (
                    "New Pages",
                    "https://en.wikipedia.org/w/index.php?title=Special:NewPages&feed=rss",
                ),
                (
                    "Featured Articles",
                    "https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=featured&feedformat=atom",
                ),
                (
                    "On This Day",
                    "https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=onthisday&feedformat=atom",
                ),
            ],
            "Artificial Intelligence": [
                (
                    "MIT AI News",
                    "http://news.mit.edu/rss/topic/artificial-intelligence2",
                ),
                ("NVIDIA Blog", "http://feeds.feedburner.com/nvidiablog"),
                ("AI Weirdness", "https://aiweirdness.com/rss"),
            ],
        }

    def save_feeds(self, feeds):
        """Save feeds to settings and ensure they persist"""
        if feeds and isinstance(feeds, dict) and any(feeds.values()):
            self.feed_settings.setValue("feeds", json.dumps(feeds))
            self.feed_settings.sync()  # Force sync to disk

    def add_category(self):
        """Add a new feed category"""
        category, ok = QInputDialog.getText(
            self, "Add Category", "Enter new category name:", QLineEdit.EchoMode.Normal
        )

        if ok and category:
            # Sanitize category name
            category = category.strip()

            # Check if category already exists
            existing_items = [
                self.category_list.item(i).text()
                for i in range(self.category_list.count())
            ]

            if category in existing_items:
                QMessageBox.warning(self, "Error", "Category already exists!")
                return

            # Add to list widget
            self.category_list.addItem(category)

            # Add to feeds
            feeds = self.load_feeds()
            if not feeds:
                # If no feeds exist, start with default feeds
                feeds = {
                    "Technology": [
                        ("TechCrunch", "https://techcrunch.com/feed/"),
                        ("Wired", "https://www.wired.com/feed/rss"),
                        ("The Verge", "https://www.theverge.com/rss/index.xml"),
                    ],
                    "Wikipedia": [
                        (
                            "New Pages",
                            "https://en.wikipedia.org/w/index.php?title=Special:NewPages&feed=rss",
                        ),
                        (
                            "Featured Articles",
                            "https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=featured&feedformat=atom",
                        ),
                        (
                            "On This Day",
                            "https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=onthisday&feedformat=atom",
                        ),
                    ],
                    "Artificial Intelligence": [
                        (
                            "MIT AI News",
                            "http://news.mit.edu/rss/topic/artificial-intelligence2",
                        ),
                        ("NVIDIA Blog", "http://feeds.feedburner.com/nvidiablog"),
                        ("AI Weirdness", "https://aiweirdness.com/rss"),
                    ],
                }
            feeds[category] = []  # Initialize with empty feed list
            self.save_feeds(feeds)

    def remove_category(self):
        """Remove selected feed category"""
        current_item = self.category_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Error", "Please select a category to remove.")
            return

        category = current_item.text()

        reply = QMessageBox.question(
            self,
            "Confirm Removal",
            f"Are you sure you want to remove the category '{category}' and all its feeds?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            # Remove from list widget
            self.category_list.takeItem(self.category_list.row(current_item))

            # Remove from feeds
            feeds = self.load_feeds()
            if feeds and category in feeds:
                del feeds[category]
                self.save_feeds(feeds)

    def rename_category(self):
        """Rename selected feed category"""
        current_item = self.category_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Error", "Please select a category to rename.")
            return

        old_name = current_item.text()
        new_name, ok = QInputDialog.getText(
            self,
            "Rename Category",
            "Enter new name for category:",
            QLineEdit.EchoMode.Normal,
            old_name,
        )

        if ok and new_name and new_name != old_name:
            # Check if new name already exists
            existing_items = [
                self.category_list.item(i).text()
                for i in range(self.category_list.count())
                if i != self.category_list.row(current_item)
            ]

            if new_name in existing_items:
                QMessageBox.warning(self, "Error", "Category name already exists!")
                return

            # Update list widget
            current_item.setText(new_name)

            # Update feeds
            feeds = self.load_feeds()
            if feeds and old_name in feeds:
                feeds[new_name] = feeds.pop(old_name)
                self.save_feeds(feeds)


class WebpageCache:
    """
    Handles caching of converted webpages with security features.

    The cache stores:
    - Converted markdown content
    - Page title
    - Metadata
    - Timestamp
    - Content hash for integrity verification

    Security features:
    - Content size limits
    - Content type validation
    - HTML/markdown sanitization
    - Metadata validation
    - URL validation
    - SQL injection prevention
    - Content integrity checks

    Cache entries expire after 7 days by default.
    """

    # Constants for validation
    MAX_CONTENT_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_TITLE_LENGTH = 500
    MAX_URL_LENGTH = 2048
    MAX_METADATA_SIZE = 100 * 1024  # 100KB
    ALLOWED_METADATA_KEYS = {"source", "date", "time", "tags", "favorite"}

    def __init__(self, cache_dir=None, expiry_days=7):
        self.cache_dir = cache_dir or Path.home() / ".webpage_converter" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.expiry_days = expiry_days
        self.db_path = self.cache_dir / "cache.db"
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database for cache storage with schema versioning"""
        with sqlite3.connect(self.db_path) as conn:
            # Create version tracking table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                )
            """
            )

            # Get current schema version
            cursor = conn.execute("SELECT version FROM schema_version")
            result = cursor.fetchone()
            current_version = result[0] if result else 0

            # Schema updates
            if current_version < 1:
                # Create initial cache table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cache (
                        url TEXT PRIMARY KEY,
                        content TEXT,
                        title TEXT,
                        metadata TEXT,
                        timestamp DATETIME
                    )
                """
                )
                # Update to version 1
                conn.execute(
                    "INSERT OR REPLACE INTO schema_version (version) VALUES (?)", (1,)
                )

            if current_version < 2:
                try:
                    # Check if columns exist before adding them
                    cursor = conn.execute("PRAGMA table_info(cache)")
                    existing_columns = [column[1] for column in cursor.fetchall()]

                    # Only add columns if they don't exist
                    if "content_hash" not in existing_columns:
                        conn.execute("ALTER TABLE cache ADD COLUMN content_hash TEXT")
                    if "content_size" not in existing_columns:
                        conn.execute(
                            "ALTER TABLE cache ADD COLUMN content_size INTEGER"
                        )

                    # Create new table with constraints
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS cache_new (
                            url TEXT PRIMARY KEY CHECK (length(url) <= 2048),
                            content TEXT NOT NULL,
                            title TEXT NOT NULL,
                            metadata TEXT NOT NULL,
                            timestamp DATETIME NOT NULL,
                            content_hash TEXT NOT NULL,
                            content_size INTEGER NOT NULL
                        )
                    """
                    )

                    # Copy data to new table, computing missing values
                    conn.execute(
                        """
                        INSERT INTO cache_new 
                        SELECT 
                            url,
                            COALESCE(content, ''),
                            COALESCE(title, ''),
                            COALESCE(metadata, '{}'),
                            COALESCE(timestamp, CURRENT_TIMESTAMP),
                            COALESCE(content_hash, ''),
                            COALESCE(content_size, 0)
                        FROM cache
                    """
                    )

                    # Drop old table and rename new one
                    conn.execute("DROP TABLE cache")
                    conn.execute("ALTER TABLE cache_new RENAME TO cache")

                    # Create index for faster timestamp-based cleanup
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_timestamp ON cache(timestamp)"
                    )

                    # Update schema version
                    conn.execute(
                        "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
                        (2,),
                    )

                    # Commit changes
                    conn.commit()

                except sqlite3.Error as e:
                    logger.error(f"Database migration error: {str(e)}")
                    # Rollback on error
                    conn.rollback()
                    raise

            # Future schema updates would go here with higher version numbers

    def _sanitize_html(self, content):
        """
        Sanitize HTML content to prevent XSS attacks.
        Removes potentially malicious tags and attributes.
        """
        if not content:
            return ""

        # Use BeautifulSoup for parsing and sanitization
        soup = BeautifulSoup(content, "html.parser")

        # Remove script tags and on* attributes
        for tag in soup.find_all():
            # Remove potentially dangerous tags
            if tag.name in ["script", "style", "iframe", "object", "embed", "form"]:
                tag.decompose()
                continue

            # Remove dangerous attributes
            for attr in list(tag.attrs):
                # Remove event handlers and javascript: URLs
                if attr.startswith("on") or (
                    attr in ["href", "src"] and "javascript:" in tag[attr].lower()
                ):
                    del tag[attr]

        return str(soup)

    def _sanitize_markdown(self, content):
        """
        Sanitize markdown content to prevent injection attacks.
        Removes potentially malicious markdown constructs.
        """
        if not content:
            return ""

        # Remove potentially dangerous markdown constructs
        sanitized = re.sub(
            r"[`]{3,}.*?[`]{3,}", "", content, flags=re.DOTALL
        )  # Remove code blocks
        sanitized = re.sub(
            r"^\s*[`]{1,2}.*?[`]{1,2}\s*$", "", sanitized, flags=re.MULTILINE
        )  # Remove inline code
        sanitized = re.sub(
            r"javascript:", "", sanitized, flags=re.IGNORECASE
        )  # Remove javascript: URLs
        sanitized = re.sub(
            r"data:", "", sanitized, flags=re.IGNORECASE
        )  # Remove data: URLs

        return sanitized

    def _validate_url(self, url):
        """
        Validate URL format and length.
        Returns (is_valid, error_message)
        """
        if not url:
            return False, "URL cannot be empty"

        if len(url) > self.MAX_URL_LENGTH:
            return (
                False,
                f"URL exceeds maximum length of {self.MAX_URL_LENGTH} characters",
            )

        try:
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                return False, "Invalid URL format"
            if parsed.scheme not in ["http", "https"]:
                return False, "URL must use HTTP or HTTPS protocol"
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"

        return True, None

    def _validate_metadata(self, metadata):
        """
        Validate metadata structure and content.
        Returns (is_valid, error_message)
        """
        if not isinstance(metadata, dict):
            return False, "Metadata must be a dictionary"

        # Check size
        metadata_size = len(json.dumps(metadata))
        if metadata_size > self.MAX_METADATA_SIZE:
            return (
                False,
                f"Metadata exceeds maximum size of {self.MAX_METADATA_SIZE} bytes",
            )

        # Validate keys and values
        for key, value in metadata.items():
            if key not in self.ALLOWED_METADATA_KEYS:
                return False, f"Invalid metadata key: {key}"
            if not isinstance(value, (str, bool, list)):
                return False, f"Invalid metadata value type for key {key}"
            if isinstance(value, str) and len(value) > 1000:
                return False, f"Metadata value too long for key {key}"
            if isinstance(value, list) and len(value) > 100:
                return False, f"Too many items in metadata list for key {key}"

        return True, None

    def _compute_content_hash(self, content):
        """Compute SHA-256 hash of content for integrity verification"""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def get(self, url):
        """
        Retrieve a page from cache if it exists and is not expired.
        Includes integrity verification.
        """
        # Validate URL
        is_valid, error = self._validate_url(url)
        if not is_valid:
            logger.error(f"Cache get failed: {error}")
            return None

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT content, title, metadata, timestamp, content_hash FROM cache WHERE url = ?",
                    (url,),
                )
                result = cursor.fetchone()

                if not result:
                    return None

                content, title, metadata_json, timestamp, stored_hash = result
                timestamp = datetime.fromisoformat(timestamp)

                # Check if cache is expired
                if datetime.now() - timestamp > timedelta(days=self.expiry_days):
                    self.remove(url)
                    return None

                # Verify content integrity
                current_hash = self._compute_content_hash(content)
                if current_hash != stored_hash:
                    logger.error(f"Cache integrity check failed for URL: {url}")
                    self.remove(url)
                    return None

                # Parse and validate metadata
                try:
                    metadata = json.loads(metadata_json)
                    is_valid, error = self._validate_metadata(metadata)
                    if not is_valid:
                        logger.error(f"Invalid cached metadata: {error}")
                        self.remove(url)
                        return None
                except json.JSONDecodeError:
                    logger.error("Failed to decode cached metadata")
                    self.remove(url)
                    return None

                return {
                    "content": content,
                    "title": title,
                    "metadata": metadata,
                    "timestamp": timestamp,
                }

        except sqlite3.Error as e:
            logger.error(f"Database error in cache get: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in cache get: {str(e)}")
            return None

    def set(self, url, content, title, metadata):
        """
        Store a page in the cache with validation and sanitization.
        Returns True if successful, False otherwise.
        """
        try:
            # Validate URL
            is_valid, error = self._validate_url(url)
            if not is_valid:
                logger.error(f"Cache set failed: {error}")
                return False

            # Validate title
            if not title or len(title) > self.MAX_TITLE_LENGTH:
                logger.error("Invalid title length")
                return False

            # Validate content size
            if len(content.encode("utf-8")) > self.MAX_CONTENT_SIZE:
                logger.error("Content exceeds maximum size")
                return False

            # Validate metadata
            is_valid, error = self._validate_metadata(metadata)
            if not is_valid:
                logger.error(f"Invalid metadata: {error}")
                return False

            # Sanitize content
            content = self._sanitize_markdown(self._sanitize_html(content))
            title = html.escape(title)

            # Compute content hash
            content_hash = self._compute_content_hash(content)

            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cache 
                    (url, content, title, metadata, timestamp, content_hash, content_size) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        url,
                        content,
                        title,
                        json.dumps(metadata),
                        datetime.now().isoformat(),
                        content_hash,
                        len(content.encode("utf-8")),
                    ),
                )
            return True

        except sqlite3.Error as e:
            logger.error(f"Database error in cache set: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error in cache set: {str(e)}")
            return False

    def remove(self, url):
        """Remove a page from cache with URL validation"""
        try:
            # Validate URL
            is_valid, error = self._validate_url(url)
            if not is_valid:
                logger.error(f"Cache remove failed: {error}")
                return False

            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM cache WHERE url = ?", (url,))
            return True

        except sqlite3.Error as e:
            logger.error(f"Database error in cache remove: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error in cache remove: {str(e)}")
            return False

    def clear(self):
        """Clear all cached pages"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM cache")
            return True
        except sqlite3.Error as e:
            logger.error(f"Database error in cache clear: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error in cache clear: {str(e)}")
            return False

    def cleanup_expired(self):
        """Remove expired cache entries"""
        try:
            expiry_date = (
                datetime.now() - timedelta(days=self.expiry_days)
            ).isoformat()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM cache WHERE timestamp < ?", (expiry_date,))
            return True
        except sqlite3.Error as e:
            logger.error(f"Database error in cleanup_expired: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error in cleanup_expired: {str(e)}")
            return False


class WebpageConverter(QMainWindow):
    def __init__(self):
        super().__init__()
        # Color scheme constants
        self.COLORS = {
            "primary": "#2173db",  # Radiant blue
            "secondary": "#2c3e50",  # Dark slate
            "accent": "#2173db",  # Radiant blue
            "success": "#2ecc71",  # Emerald green
            "warning": "#f1c40f",  # Sunflower yellow
            "error": "#e74c3c",  # Alizarin red
            "background": "#fcfcf7",  # Warm white
            "text": "#1a1a1a",  # Almost black
            "button_hover": "#1557b0",  # Darker blue
        }

        # Initialize history
        self.history = []  # List of visited URLs
        self.current_history_index = -1  # Current position in history
        self.max_history_size = 100  # Maximum number of URLs to store

        self.settings = QSettings("WebpageConverter", "Settings")
        self.save_directory = self.settings.value(
            "save_location", os.path.expanduser("~/Documents/saved_articles")
        )
        self.session = requests.Session()
        self.tag_settings = QSettings("WebpageConverter", "Tags")
        self.tags = self.load_tags()
        self.validator = URLValidator()
        self.initUI()
        self.setup_shortcuts()
        self.image_handler = ImageHandler(self.save_directory)

        # Create save directory if it doesn't exist
        if not os.path.exists(self.save_directory):
            os.makedirs(self.save_directory)

        # Initialize cache
        self.cache = WebpageCache()

    def setup_shortcuts(self):
        # Extract shortcut (Ctrl+E)
        self.extract_shortcut = QShortcut(QKeySequence("Ctrl+E"), self)
        self.extract_shortcut.activated.connect(self.extract_content)

        # Save shortcut (Ctrl+S)
        self.save_shortcut = QShortcut(QKeySequence("Ctrl+S"), self)
        self.save_shortcut.activated.connect(self.save_markdown)

        # Tag management shortcut (Ctrl+T)
        self.tag_shortcut = QShortcut(QKeySequence("Ctrl+T"), self)
        self.tag_shortcut.activated.connect(self.manage_tags)

        # Settings shortcut (Ctrl+,)
        self.settings_shortcut = QShortcut(QKeySequence("Ctrl+,"), self)
        self.settings_shortcut.activated.connect(self.show_settings)

    def load_tags(self):
        tags = self.tag_settings.value("tags", [])
        return tags if tags else []

    def save_tags(self):
        self.tag_settings.setValue("tags", self.tags)

    def manage_tags(self):
        dialog = TagDialog(self, self.tags)
        if dialog.exec():
            self.tags = sorted(set(dialog.existing_tags))
            self.save_tags()

    def initUI(self):
        self.setWindowTitle("Webpage to Markdown Converter")
        self.setGeometry(100, 100, 1000, 800)

        # Create tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Create and add converter tab
        self.converter_tab = QWidget()
        self.setup_converter_tab()
        self.tabs.addTab(self.converter_tab, "Web Converter")

        # Create and add news reader tab with color scheme
        self.news_tab = NewsReaderTab(colors=self.COLORS)
        self.tabs.addTab(self.news_tab, "News Reader")

        # Connect the clip_requested signal
        self.news_tab.clip_requested.connect(self.clip_to_converter)

        # Add Settings to menu bar
        menubar = self.menuBar()
        settings_menu = menubar.addMenu("Settings")
        settings_action = settings_menu.addAction("Preferences")
        settings_action.setShortcut("Ctrl+,")
        settings_action.triggered.connect(self.show_settings)

    def setup_converter_tab(self):
        layout = QVBoxLayout(self.converter_tab)

        # URL and Navigation section
        nav_layout = QHBoxLayout()

        # Back/Forward navigation buttons
        self.back_button = QPushButton("←")
        self.back_button.setToolTip("Go Back")
        self.back_button.clicked.connect(self.navigate_back)
        self.back_button.setEnabled(False)

        self.forward_button = QPushButton("→")
        self.forward_button.setToolTip("Go Forward")
        self.forward_button.clicked.connect(self.navigate_forward)
        self.forward_button.setEnabled(False)

        # Style navigation buttons
        for button in [self.back_button, self.forward_button]:
            button.setStyleSheet(
                f"""
                QPushButton {{
                    background-color: {self.COLORS['primary']};
                    color: white;
                    border: none;
                    padding: 8px 12px;
                    border-radius: 4px;
                    font-weight: bold;
                    font-size: 16px;
                    min-width: 40px;
                }}
                QPushButton:hover {{
                    background-color: {self.COLORS['button_hover']};
                }}
                QPushButton:disabled {{
                    background-color: #bdc3c7;
                }}
            """
            )
            nav_layout.addWidget(button)

        # History button
        self.history_button = QPushButton("📋 History")
        self.history_button.clicked.connect(self.show_history)
        self.history_button.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {self.COLORS['primary']};
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {self.COLORS['button_hover']};
            }}
            QPushButton:disabled {{
                background-color: #bdc3c7;
            }}
        """
        )
        nav_layout.addWidget(self.history_button)

        # URL input
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL...")
        self.url_input.setStyleSheet(
            """
            QLineEdit {
                color: #2c3e50;
                background-color: white;
                border: 2px solid #3498db;
                border-radius: 4px;
                padding: 8px;
                font-size: 13px;
                font-family: system-ui, -apple-system, sans-serif;
            }
            QLineEdit:focus {
                border-color: #2980b9;
                background-color: #f8f9fa;
            }
            QLineEdit::placeholder {
                color: #95a5a6;
            }
        """
        )
        nav_layout.addWidget(self.url_input)

        # Extract button
        self.extract_button = QPushButton("Extract")
        self.extract_button.clicked.connect(self.extract_content)
        nav_layout.addWidget(self.extract_button)

        layout.addLayout(nav_layout)

        # Preview section
        preview_layout = QHBoxLayout()
        preview_label = QLabel("Preview:")
        self.read_article_button = QPushButton("Read Article")
        self.read_article_button.setEnabled(False)  # Disabled until content is loaded
        self.read_article_button.clicked.connect(self.read_article)
        # Set initial visibility based on TTS settings
        self.read_article_button.setVisible(
            self.settings.value("enable_tts", False, type=bool)
        )
        preview_layout.addWidget(preview_label)
        preview_layout.addStretch()
        preview_layout.addWidget(self.read_article_button)
        layout.addLayout(preview_layout)

        self.preview_view = MarkdownViewer()
        # Connect the TTS state signal to our update method
        self.preview_view.tts_state_changed.connect(self.update_tts_button_state)
        # Connect the link clicked signal
        self.preview_view.link_clicked.connect(self.handle_link_click)
        self.preview_view.setMarkdown("Enter a URL above and click Extract to begin...")
        layout.addWidget(self.preview_view)

        # Tag management button
        tag_button = QPushButton("Manage Tags (Ctrl+T)")
        tag_button.clicked.connect(self.manage_tags)
        layout.addWidget(tag_button)

        # Add tag display
        self.tag_label = QLabel("Selected Tags: None")
        layout.addWidget(self.tag_label)

        # Save section with favorite checkbox
        save_layout = QHBoxLayout()

        # Add favorite checkbox with icon
        self.favorite_checkbox = QCheckBox("Mark as Favorite")
        self.favorite_checkbox.setStyleSheet(
            f"""
            QCheckBox {{
                color: {self.COLORS['text']};
                font-weight: bold;
                padding: 5px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
            }}
            QCheckBox::indicator:unchecked {{
                border: 2px solid {self.COLORS['secondary']};
                border-radius: 3px;
                background-color: white;
            }}
            QCheckBox::indicator:checked {{
                border: 2px solid {self.COLORS['accent']};
                border-radius: 3px;
                background-color: {self.COLORS['accent']};
            }}
        """
        )
        save_layout.addWidget(self.favorite_checkbox)

        # Save button
        self.save_button = QPushButton("Save as Markdown")
        self.save_button.clicked.connect(self.save_markdown)
        self.save_button.setEnabled(False)
        save_layout.addWidget(self.save_button)
        layout.addLayout(save_layout)

        # Status label
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

        # Update status label styling
        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
            }}
        """
        )

        # Update tag label styling
        self.tag_label.setStyleSheet(
            f"""
            QLabel {{
                color: {self.COLORS['secondary']};
                padding: 5px;
                background-color: white;
                border-radius: 4px;
                border: 1px solid {self.COLORS['secondary']};
            }}
        """
        )

    def read_article(self):
        """Read the entire article using TTS"""
        if not hasattr(self, "current_content"):
            return

        # If currently playing, stop playback
        if self.preview_view.is_playing:
            self.preview_view.stop_playback()
            return

        try:
            # Extract plain text from markdown content
            # Skip metadata section
            content_parts = self.current_content.split("---\n\n", 1)
            if len(content_parts) > 1:
                text_to_read = content_parts[1]
            else:
                text_to_read = self.current_content

            # Remove markdown formatting
            text_to_read = re.sub(
                r"\[([^\]]+)\]\([^)]+\)", r"\1", text_to_read
            )  # Remove links
            text_to_read = re.sub(
                r"[#*`_]", "", text_to_read
            )  # Remove markdown symbols
            text_to_read = re.sub(
                r"\n\n+", "\n", text_to_read
            )  # Reduce multiple newlines

            # Create a custom selection of text for the TTS
            self.preview_view.textCursor().clearSelection()  # Clear any existing selection
            self.preview_view.setPlainText(text_to_read)  # Temporarily set plain text
            cursor = self.preview_view.textCursor()
            cursor.select(cursor.SelectionType.Document)  # Select all text
            self.preview_view.setTextCursor(cursor)

            # Use the preview_view's TTS functionality with speaker handling
            if (
                not hasattr(self.preview_view, "current_speaker")
                or not self.preview_view.current_speaker
            ):
                # Initialize TTS if needed
                if not hasattr(self.preview_view, "tts"):
                    self.preview_view.initialize_tts()
                # Set default speaker if none selected
                if self.preview_view.speakers:
                    self.preview_view.current_speaker = self.preview_view.speakers[0]
                    logger.info(
                        f"Using default speaker: {self.preview_view.current_speaker}"
                    )

            self.preview_view.read_selected_text()

            # Restore the markdown content after TTS processing
            self.preview_view.setMarkdown(self.current_content)

        except Exception as e:
            error_msg = f"Error reading article: {str(e)}"
            logger.error(error_msg)
            self.show_error(error_msg)

    def extract_content(self):
        url = self.url_input.text().strip()

        # Validate URL
        is_valid, result, metadata = self.validator.validate_url(url)
        if not is_valid:
            self.show_error(result)
            logger.error(f"URL validation failed: {result}")
            return

        url = result  # Use the validated URL

        try:
            # Check cache first
            cached_data = self.cache.get(url)
            if cached_data:
                logger.debug(f"Loading {url} from cache")
                self.current_content = cached_data["content"]
                self.current_title = cached_data["title"]
                self.preview_view.setMarkdown(self.current_content)
                self.save_button.setEnabled(True)
                if self.settings.value("enable_tts", False, type=bool):
                    self.read_article_button.setEnabled(True)

                # Update status
                self.status_label.setText("✓ Content loaded from cache")
                self.status_label.setStyleSheet(
                    f"""
                    QLabel {{
                        color: white;
                        background-color: {self.COLORS['success']};
                        padding: 10px;
                        border-radius: 4px;
                        font-weight: bold;
                    }}
                """
                )
                return

            # Add URL to history before extraction
            self.add_to_history(url)

            # Configure headers
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Referer": url,
                "Connection": "keep-alive",
            }

            # Fetch webpage content
            logger.debug(f"Fetching content from URL: {url}")
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            # Extract main content using readability
            logger.debug("Extracting content with readability")
            doc = Document(response.text)
            title = doc.title()
            content = doc.summary()

            # Check if images are enabled before any image processing
            images_enabled = self.settings.value("enable_images", True, type=bool)
            logger.debug(
                f"Image processing is {'enabled' if images_enabled else 'disabled'}"
            )

            # Convert to markdown
            logger.debug("Converting content to markdown")
            converter = html2text.HTML2Text()
            converter.ignore_links = False
            converter.ignore_images = not images_enabled
            converter.body_width = 0

            # Process content
            soup = BeautifulSoup(content, "html.parser")

            if images_enabled:
                logger.debug("Processing and downloading images")
                for img in soup.find_all("img"):
                    src = img.get("src")
                    if src:
                        logger.debug(f"Processing image: {src}")
                        new_path = self.image_handler.process_image(src, url)
                        if new_path:
                            logger.debug(
                                f"Image processed successfully, new path: {new_path}"
                            )
                            img["src"] = f"images/{new_path}"
                        else:
                            logger.warning(f"Failed to process image: {src}")
            else:
                logger.debug(
                    "Images disabled - removing image tags without downloading"
                )
                for img in soup.find_all("img"):
                    img.decompose()

            markdown_content = converter.handle(str(soup))
            logger.debug("Content converted to markdown successfully")

            # Add metadata
            metadata = f"# {title}\n\nSource: {url}\nSaved: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n---\n\n"
            full_content = metadata + markdown_content

            # Show preview
            self.preview_view.setMarkdown(full_content)
            self.save_button.setEnabled(True)
            # Only enable read button if TTS is enabled
            if self.settings.value("enable_tts", False, type=bool):
                self.read_article_button.setEnabled(True)
            self.current_content = full_content
            self.current_title = title

            # Update status with success styling
            self.status_label.setText("✓ Content extracted and ready for saving")
            self.status_label.setStyleSheet(
                f"""
                QLabel {{
                    color: white;
                    background-color: {self.COLORS['success']};
                    padding: 10px;
                    border-radius: 4px;
                    font-weight: bold;
                }}
            """
            )
            logger.debug("Content extraction successful")

            # Cache the processed content
            self.cache.set(
                url,
                self.current_content,
                self.current_title,
                {
                    "source": url,
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "time": datetime.now().strftime("%H:%M"),
                },
            )

        except Exception as e:
            error_msg = f"Error processing content: {str(e)}"
            logger.error(error_msg)
            self.show_error(error_msg)

    def save_markdown(self):
        if not hasattr(self, "current_content") or not hasattr(self, "current_title"):
            return

        # Get tags
        dialog = TagDialog(self, self.tags)
        if dialog.exec():
            selected_tags = dialog.get_selected_tags()

            # Warn if no tags selected
            if not selected_tags:
                reply = QMessageBox.warning(
                    self,
                    "No Tags Selected",
                    "You haven't selected any tags for this document. Would you like to go back and add tags?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    return self.save_markdown()  # Recursive call to try again
        else:
            return

        # Create safe filename from title
        safe_title = "".join(
            x for x in self.current_title if x.isalnum() or x in (" ", "-", "_")
        ).strip()
        safe_title = safe_title.replace(" ", "-")
        filename = f"{safe_title}-{datetime.now().strftime('%Y%m%d')}.md"
        filepath = os.path.join(self.save_directory, filename)

        try:
            # Get current date and time
            current_datetime = datetime.now()

            # Create YAML metadata block
            metadata_parts = ["---"]

            # Add date and time
            metadata_parts.append(f"date: {current_datetime.strftime('%Y-%m-%d')}")
            metadata_parts.append(f"time: {current_datetime.strftime('%H:%M')}")

            # Add source URL
            metadata_parts.append(f"source: {self.url_input.text().strip()}")

            # Add favorite status
            metadata_parts.append(
                f"favorite: {str(self.favorite_checkbox.isChecked()).lower()}"
            )

            # Add tags
            metadata_parts.append("tags:")
            if selected_tags:
                for tag in selected_tags:
                    # Ensure tag has '#' prefix
                    if not tag.startswith("#"):
                        tag = f"#{tag}"
                    metadata_parts.append(f"  - {tag}")

            metadata_parts.append("---\n")

            # Join all metadata parts
            yaml_metadata = "\n".join(metadata_parts)

            # Replace the existing metadata section and add title
            content_parts = self.current_content.split("\n\n---\n", 1)
            if len(content_parts) > 1:
                # Keep the title from the original content
                title_line = content_parts[0].split("\n")[
                    0
                ]  # Get the first line (title)
                new_content = f"{title_line}\n\n{yaml_metadata}\n{content_parts[1]}"
            else:
                new_content = (
                    f"# {self.current_title}\n\n{yaml_metadata}\n{self.current_content}"
                )

            # Write the file
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(new_content)

            # Update tag label (show tags without '#' prefix in the UI)
            display_tags = (
                [tag.lstrip("#") for tag in selected_tags] if selected_tags else []
            )
            self.tag_label.setText(
                f"Selected Tags: {', '.join(display_tags) if display_tags else 'None'}"
            )

            # Show save success with updated styling
            self.status_label.setText(f"💾 File saved successfully to: {filepath}")
            self.status_label.setStyleSheet(
                f"""
                QLabel {{
                    color: white;
                    background-color: {self.COLORS['success']};
                    padding: 10px;
                    border-radius: 4px;
                    font-weight: bold;
                }}
            """
            )
            logger.info(f"File saved successfully: {filepath}")
        except Exception as e:
            error_msg = f"Error saving file: {str(e)}"
            logger.error(error_msg)
            self.show_error(error_msg)

    def show_error(self, message):
        self.status_label.setText(f"⚠️ {message}")
        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: white;
                background-color: {self.COLORS['error']};
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
            }}
        """
        )
        QMessageBox.critical(self, "Error", message)
        logger.error(message)

    def clip_to_converter(self, url):
        """Handle clipping a URL from the news reader to the converter tab"""
        self.tabs.setCurrentIndex(0)  # Switch to converter tab
        self.url_input.setText(url)
        self.extract_content()  # Automatically start extraction

    def show_settings(self):
        dialog = SettingsDialog(self)
        if dialog.exec():
            # Update save directory if changed
            new_save_dir = self.settings.value("save_location")
            if new_save_dir != self.save_directory:
                self.save_directory = new_save_dir
                self.image_handler = ImageHandler(self.save_directory)
                if not os.path.exists(self.save_directory):
                    os.makedirs(self.save_directory)

            # Update TTS visibility based on settings
            tts_enabled = self.settings.value("enable_tts", False, type=bool)
            self.read_article_button.setVisible(tts_enabled)

            # If TTS is disabled, cleanup any TTS resources
            if not tts_enabled and hasattr(self.preview_view, "cleanup"):
                self.preview_view.cleanup()
            # If TTS is enabled, update the speaker
            elif tts_enabled:
                if not hasattr(self.preview_view, "tts"):
                    self.preview_view.initialize_tts()
                else:
                    # Update current speaker from settings
                    default_speaker = self.settings.value("default_speaker", "")
                    if default_speaker in self.preview_view.speakers:
                        self.preview_view.current_speaker = default_speaker

    def update_tts_button_state(self, is_playing):
        """Update the TTS button state based on playback"""
        if is_playing:
            self.read_article_button.setText("Stop Reading")
        else:
            self.read_article_button.setText("Read Article")

    def handle_link_click(self, url):
        """Handle clicked links by loading them into the converter"""
        # Update URL input
        self.url_input.setText(url)
        # Extract content from the new URL
        self.extract_content()

    def show_history(self):
        """Display the history of visited URLs in a dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Browsing History")
        dialog.setMinimumWidth(600)

        layout = QVBoxLayout(dialog)

        # Add help text
        help_text = QLabel(
            "Double-click a URL to load it, or select and use the buttons below."
        )
        help_text.setStyleSheet(f"color: {self.COLORS['text']}; padding: 10px;")
        layout.addWidget(help_text)

        # Create list widget for history
        history_list = QListWidget()
        history_list.setAlternatingRowColors(True)
        history_list.setStyleSheet(
            f"""
            QListWidget {{
                background-color: {self.COLORS['background']};
                border: 1px solid {self.COLORS['primary']};
                border-radius: 4px;
                color: {self.COLORS['text']};
            }}
            QListWidget::item {{
                padding: 8px;
                border-bottom: 1px solid #e0e0e0;
            }}
            QListWidget::item:alternate {{
                background-color: white;
            }}
            QListWidget::item:hover {{
                background-color: #f0f7ff;
            }}
            QListWidget::item:selected {{
                background-color: {self.COLORS['primary']};
                color: white;
            }}
        """
        )

        # Add history items in reverse chronological order
        for url in reversed(self.history):
            item = QListWidgetItem(url)
            item.setToolTip(url)
            history_list.addItem(item)

        layout.addWidget(history_list)

        # Add buttons
        button_layout = QHBoxLayout()

        load_button = QPushButton("Load Selected")
        load_button.clicked.connect(
            lambda: self.load_from_history(history_list.currentItem())
        )

        clear_button = QPushButton("Clear History")
        clear_button.clicked.connect(lambda: self.clear_history(history_list))

        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)

        for button in [load_button, clear_button, close_button]:
            button.setStyleSheet(
                f"""
                QPushButton {{
                    background-color: {self.COLORS['primary']};
                    color: white;
                    border: none;
                    padding: 8px 15px;
                    border-radius: 4px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: {self.COLORS['button_hover']};
                }}
            """
            )
            button_layout.addWidget(button)

        layout.addLayout(button_layout)

        # Set dialog styling
        dialog.setStyleSheet(
            f"""
            QDialog {{
                background-color: {self.COLORS['background']};
            }}
        """
        )

        # Connect double-click
        history_list.itemDoubleClicked.connect(self.load_from_history)

        dialog.exec()

    def load_from_history(self, item):
        """Load a URL from the history list"""
        if item:
            url = item.text()
            self.url_input.setText(url)
            self.extract_content()

    def clear_history(self, list_widget):
        """Clear the browsing history and cache"""
        reply = QMessageBox.question(
            self,
            "Clear History",
            "Would you like to clear the cache as well as the browsing history?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No
            | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Cancel:
            return

        if reply == QMessageBox.StandardButton.Yes:
            self.cache.clear()

        self.history.clear()
        self.current_history_index = -1
        if list_widget:
            list_widget.clear()

    def add_to_history(self, url):
        """Add a URL to the browsing history"""
        # Don't add if it's the same as the current URL
        if (
            self.history
            and self.current_history_index >= 0
            and url == self.history[self.current_history_index]
        ):
            return

        # Remove any forward history
        if self.current_history_index < len(self.history) - 1:
            self.history = self.history[: self.current_history_index + 1]

        # Add new URL
        self.history.append(url)
        self.current_history_index = len(self.history) - 1

        # Limit history size
        if len(self.history) > self.max_history_size:
            self.history = self.history[-self.max_history_size :]
            self.current_history_index = len(self.history) - 1

        # Update navigation buttons
        self.update_navigation_buttons()

    def navigate_back(self):
        """Navigate to the previous URL in history"""
        if self.current_history_index > 0:
            self.current_history_index -= 1
            url = self.history[self.current_history_index]
            self.url_input.setText(url)
            self.extract_content_without_history()
            self.update_navigation_buttons()

    def navigate_forward(self):
        """Navigate to the next URL in history"""
        if self.current_history_index < len(self.history) - 1:
            self.current_history_index += 1
            url = self.history[self.current_history_index]
            self.url_input.setText(url)
            self.extract_content_without_history()
            self.update_navigation_buttons()

    def update_navigation_buttons(self):
        """Update the enabled state of navigation buttons"""
        self.back_button.setEnabled(self.current_history_index > 0)
        self.forward_button.setEnabled(
            self.current_history_index < len(self.history) - 1
        )

    def extract_content_without_history(self):
        """Extract content without modifying history"""
        url = self.url_input.text().strip()

        # Validate URL
        is_valid, result, metadata = self.validator.validate_url(url)
        if not is_valid:
            self.show_error(result)
            logger.error(f"URL validation failed: {result}")
            return

        url = result  # Use the validated URL

        try:
            # Check cache first
            cached_data = self.cache.get(url)
            if cached_data:
                logger.debug(f"Loading {url} from cache")
                self.current_content = cached_data["content"]
                self.current_title = cached_data["title"]
                self.preview_view.setMarkdown(self.current_content)
                self.save_button.setEnabled(True)
                if self.settings.value("enable_tts", False, type=bool):
                    self.read_article_button.setEnabled(True)

                # Update status
                self.status_label.setText("✓ Content loaded from cache")
                self.status_label.setStyleSheet(
                    f"""
                    QLabel {{
                        color: white;
                        background-color: {self.COLORS['success']};
                        padding: 10px;
                        border-radius: 4px;
                        font-weight: bold;
                    }}
                """
                )
                return

            # Configure headers
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Referer": url,
                "Connection": "keep-alive",
            }

            # Fetch webpage content
            logger.debug(f"Fetching content from URL: {url}")
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            # Extract main content using readability
            logger.debug("Extracting content with readability")
            doc = Document(response.text)
            title = doc.title()
            content = doc.summary()

            # Check if images are enabled before any image processing
            images_enabled = self.settings.value("enable_images", True, type=bool)
            logger.debug(
                f"Image processing is {'enabled' if images_enabled else 'disabled'}"
            )

            # Convert to markdown
            logger.debug("Converting content to markdown")
            converter = html2text.HTML2Text()
            converter.ignore_links = False
            converter.ignore_images = not images_enabled
            converter.body_width = 0

            # Process content
            soup = BeautifulSoup(content, "html.parser")

            if images_enabled:
                logger.debug("Processing and downloading images")
                for img in soup.find_all("img"):
                    src = img.get("src")
                    if src:
                        logger.debug(f"Processing image: {src}")
                        new_path = self.image_handler.process_image(src, url)
                        if new_path:
                            logger.debug(
                                f"Image processed successfully, new path: {new_path}"
                            )
                            img["src"] = f"images/{new_path}"
                        else:
                            logger.warning(f"Failed to process image: {src}")
            else:
                logger.debug(
                    "Images disabled - removing image tags without downloading"
                )
                for img in soup.find_all("img"):
                    img.decompose()

            markdown_content = converter.handle(str(soup))
            logger.debug("Content converted to markdown successfully")

            # Add metadata
            metadata = f"# {title}\n\nSource: {url}\nSaved: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n---\n\n"
            full_content = metadata + markdown_content

            # Show preview
            self.preview_view.setMarkdown(full_content)
            self.save_button.setEnabled(True)
            # Only enable read button if TTS is enabled
            if self.settings.value("enable_tts", False, type=bool):
                self.read_article_button.setEnabled(True)
            self.current_content = full_content
            self.current_title = title

            # Update status with success styling
            self.status_label.setText("✓ Content extracted and ready for saving")
            self.status_label.setStyleSheet(
                f"""
                QLabel {{
                    color: white;
                    background-color: {self.COLORS['success']};
                    padding: 10px;
                    border-radius: 4px;
                    font-weight: bold;
                }}
            """
            )
            logger.debug("Content extraction successful")

            # Cache the processed content
            self.cache.set(
                url,
                self.current_content,
                self.current_title,
                {
                    "source": url,
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "time": datetime.now().strftime("%H:%M"),
                },
            )

        except Exception as e:
            error_msg = f"Error processing content: {str(e)}"
            logger.error(error_msg)
            self.show_error(error_msg)


def sanitize_tag(tag):
    """
    Sanitizes a tag by:
    - Removing special characters
    - Converting to lowercase
    - Limiting length
    - Removing whitespace
    - Adding '#' prefix if not present
    """
    # Remove special chars, keep alphanumeric, hyphen, underscore
    sanitized = re.sub(r"[^a-zA-Z0-9\-_]", "", tag.lower().strip())
    # Add '#' prefix if not present
    if not sanitized.startswith("#"):
        sanitized = f"#{sanitized}"
    # Limit length to 50 characters (including '#' prefix)
    return sanitized[:50]


def main():
    app = QApplication(sys.argv)
    converter = WebpageConverter()
    converter.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
