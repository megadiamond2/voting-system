# ============================================================================
# PART 1: IMPORTS, CONFIGURATION, TIMEZONE HELPERS, APP INIT
# ============================================================================

import os
import json
import base64
import hashlib
import secrets
import csv
import io
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
import re
import time

# Third-party packages
import pytz
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session, send_file, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate                     # <-- Added for schema migrations
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, SelectField, TextAreaField, FileField, IntegerField, DateTimeField, HiddenField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp, ValidationError, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from jinja2 import BaseLoader, TemplateNotFound, Environment

# Optional email support
try:
    from flask_mail import Mail, Message
    mail_enabled = True
except ImportError:
    mail_enabled = False

# ----------------------------------------------------------------------------
# Load environment variables
# ----------------------------------------------------------------------------
load_dotenv()

# ----------------------------------------------------------------------------
# Configuration classes
# ----------------------------------------------------------------------------
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///smart_voting.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
    }
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', None)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    APP_NAME = 'Smart Encrypted Voting System'
    APP_TAGLINE = 'Secure. Transparent. Verified.'
    # Email settings (optional)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@voting.com')
    # Security
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 15 * 60  # 15 minutes

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_ECHO = True

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

# ----------------------------------------------------------------------------
# Timezone helpers (Nigeria / West Africa Time)
# ----------------------------------------------------------------------------
NIGERIA_TZ = pytz.timezone('Africa/Lagos')

def get_ng_time():
    """Get current Nigeria time (WAT - UTC+1)"""
    now_utc = datetime.utcnow().replace(tzinfo=timezone.utc)
    return now_utc.astimezone(NIGERIA_TZ).replace(tzinfo=None)

def utc_to_ng(utc_dt):
    """Convert UTC datetime to Nigeria time"""
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    return utc_dt.astimezone(NIGERIA_TZ).replace(tzinfo=None)

def ng_to_utc(ng_dt):
    """Convert Nigeria time to UTC"""
    if ng_dt.tzinfo is not None:
        ng_dt = ng_dt.replace(tzinfo=None)
    # Nigeria is UTC+1
    return ng_dt - timedelta(hours=1)

# ----------------------------------------------------------------------------
# App initialization
# ----------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(config[os.environ.get('FLASK_ENV', 'development')])
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

db = SQLAlchemy(app)
migrate = Migrate(app, db, render_as_batch=True)                  # <-- Enables schema migrations

login_manager = LoginManager(app)
csrf = CSRFProtect(app)

login_manager.login_view = 'auth_login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Optional email setup
if mail_enabled:
    mail = Mail(app)

# ----------------------------------------------------------------------------
# Context processor – makes timezone helpers available in all templates
# ----------------------------------------------------------------------------
@app.context_processor
def inject_timezone_helpers():
    return {
        'get_ng_time': get_ng_time,
        'utc_to_ng': utc_to_ng,
        'ng_to_utc': ng_to_utc,
        'now_ng': get_ng_time(),
    }

# ============================================================================
# END OF PART 1
# ============================================================================
# Your models, forms, routes, and templates follow below...

# ============================================================================
# PART 3: MODELS – User & VoterProfile
# ============================================================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='voter')
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)
    locked_until = db.Column(db.DateTime)

    voter_profile = db.relationship('VoterProfile', backref='user', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_locked_out(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False

    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.locked_until = None
        db.session.commit()

    def increment_failed_attempts(self):
        self.failed_login_attempts += 1
        self.last_failed_login = datetime.utcnow()
        if self.failed_login_attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
            self.locked_until = datetime.utcnow() + timedelta(seconds=app.config['LOCKOUT_DURATION'])
        db.session.commit()

    def __repr__(self):
        return f'<User {self.username}>'


class VoterProfile(db.Model):
    __tablename__ = 'voter_profiles'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    registration_number = db.Column(db.String(50), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    department = db.Column(db.String(100))
    faculty = db.Column(db.String(100))
    level = db.Column(db.String(20))
    photo = db.Column(db.String(200))
    has_voted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<VoterProfile {self.full_name}>'
# ============================================================================
# PART: ELECTION MODEL (complete, with all methods)
# ============================================================================

class Election(db.Model):
    __tablename__ = 'elections'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    election_type = db.Column(db.String(50), default='general')
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='draft')
    is_active = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ---- RELATIONSHIPS ----
    positions = db.relationship(
        'ElectionPosition',
        back_populates='election',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )

    # ----------------------------------------------------------------------
    # STATUS METHODS
    # ----------------------------------------------------------------------
    def get_status(self):
        """Get the current status based on dates and the stored status field."""
        now = datetime.utcnow()

        if self.status == 'archived':
            return 'archived'
        if self.status == 'draft':
            return 'draft'
        if self.status == 'results_published':
            return 'results_published'

        if now < self.start_date:
            return 'scheduled'
        elif self.start_date <= now <= self.end_date:
            return 'active'
        elif now > self.end_date:
            return 'closed'

        # Fallback
        return self.status or 'draft'

    def is_voting_open(self):
        """Check if voting is currently open."""
        return self.get_status() == 'active'

    def is_upcoming(self):
        """Check if the election is upcoming (scheduled)."""
        return self.get_status() == 'scheduled'

    def is_completed(self):
        """Check if the election is completed."""
        return self.get_status() in ['closed', 'results_published']

    def is_results_published(self):
        """Check if the results have been published."""
        return self.status == 'results_published'

    # ----------------------------------------------------------------------
    # TIMEZONE HELPERS
    # ----------------------------------------------------------------------
    def get_local_start(self):
        """Return start date in Nigeria time (WAT - UTC+1)."""
        utc_time = self.start_date.replace(tzinfo=timezone.utc)
        return utc_time.astimezone(NIGERIA_TZ).replace(tzinfo=None)

    def get_local_end(self):
        """Return end date in Nigeria time (WAT - UTC+1)."""
        utc_time = self.end_date.replace(tzinfo=timezone.utc)
        return utc_time.astimezone(NIGERIA_TZ).replace(tzinfo=None)

    # ----------------------------------------------------------------------
    # STATISTICS
    # ----------------------------------------------------------------------
    def get_vote_count(self):
        """Total votes cast in this election."""
        return Vote.query.filter_by(election_id=self.id).count()

    def get_progress(self):
        """Progress as a percentage of eligible voters who voted."""
        total_voters = VoterProfile.query.count()
        if total_voters == 0:
            return 0
        votes = self.get_vote_count()
        return (votes / total_voters) * 100

    def get_eligible_voters(self):
        """List of eligible voters for this election."""
        evs = ElectionVoter.query.filter_by(election_id=self.id, eligible=True).all()
        return [ev.voter for ev in evs]

    # ----------------------------------------------------------------------
    # ELIGIBILITY CHECK (updated – lenient by default)
    # ----------------------------------------------------------------------
    def is_voter_eligible(self, user_id):
        """
        Check if a voter is eligible for this election.

        Rules:
        - If no eligibility records exist for this election, everyone is eligible
          (this also covers candidates, admins, etc.).
        - If eligibility records exist, only voters marked as 'eligible' can vote.
        """
        # If there are no eligibility records at all, everyone is eligible
        any_records = ElectionVoter.query.filter_by(election_id=self.id).first()
        if not any_records:
            return True

        # Otherwise, check the specific voter's eligibility
        ev = ElectionVoter.query.filter_by(
            election_id=self.id,
            voter_id=user_id
        ).first()
        return ev is not None and ev.eligible

    # ----------------------------------------------------------------------
    # DEFAULT POSITIONS BY ELECTION TYPE
    # ----------------------------------------------------------------------
    @staticmethod
    def get_default_positions(election_type):
        """Return the list of default positions based on election type."""
        positions_map = {
            'student': [
                'President', 'Vice President', 'Secretary General',
                'Assistant Secretary', 'Treasurer', 'Financial Secretary',
                'Public Relations Officer', 'Assistant PRO',
                'Director of Socials', 'Director of Sports',
                'Director of Welfare', 'Director of Academics',
                'Faculty Representative', 'Departmental Representative',
                'Hall Representative', 'Class Representative'
            ],
            'faculty': [
                'Faculty President', 'Faculty Vice President',
                'Faculty Secretary', 'Faculty Treasurer',
                'Faculty PRO', 'Faculty Social Director',
                'Faculty Sports Director', 'Faculty Academic Director',
                'Faculty Representative'
            ],
            'department': [
                'Departmental President', 'Departmental Vice President',
                'Departmental Secretary', 'Departmental Treasurer',
                'Departmental PRO', 'Departmental Social Director',
                'Departmental Sports Director', 'Academic Representative'
            ],
            'general': [
                'Chairperson', 'Vice Chairperson', 'Secretary',
                'Treasurer', 'Public Relations Officer',
                'Member', 'Member', 'Member'
            ],
            'other': [
                'President', 'Vice President', 'Secretary',
                'Treasurer', 'Public Relations Officer'
            ]
        }
        return positions_map.get(election_type, positions_map['other'])

    # ----------------------------------------------------------------------
    def __repr__(self):
        return f'<Election {self.title}>'


# ============================================================================
# PART: ELECTION POSITION MODEL
# ============================================================================

class ElectionPosition(db.Model):
    __tablename__ = 'election_positions'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    max_selections = db.Column(db.Integer, default=1)
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ---- RELATIONSHIPS ----
    election = db.relationship('Election', back_populates='positions')
    candidates = db.relationship(
        'Candidate',
        back_populates='position',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )

    def get_candidates(self):
        """Return all active candidates for this position."""
        return Candidate.query.filter_by(position_id=self.id, is_active=True).all()

    def get_candidate_count(self):
        """Return count of active candidates."""
        return Candidate.query.filter_by(position_id=self.id, is_active=True).count()

    def __repr__(self):
        return f'<ElectionPosition {self.title}>'


# ============================================================================
# PART: CANDIDATE MODEL
# ============================================================================

class Candidate(db.Model):
    __tablename__ = 'candidates'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id', ondelete='CASCADE'), nullable=False)
    position_id = db.Column(db.Integer, db.ForeignKey('election_positions.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=True)
    full_name = db.Column(db.String(200), nullable=False)
    photo = db.Column(db.String(200))
    department = db.Column(db.String(100))
    faculty = db.Column(db.String(100))
    level = db.Column(db.String(20))
    manifesto = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ---- RELATIONSHIPS ----
    position = db.relationship('ElectionPosition', back_populates='candidates')
    user = db.relationship('User', backref=db.backref('candidates', lazy='dynamic'))

    def get_vote_count(self):
        """Total votes received by this candidate."""
        return Vote.query.filter_by(candidate_id=self.id).count()

    def get_profile(self):
        """Return the linked user profile if any."""
        return self.user.voter_profile if self.user else None

    def __repr__(self):
        return f'<Candidate {self.full_name}>'
# ============================================================================
# PART 5: VOTING AND RESULTS MODELS
# ============================================================================

class Vote(db.Model):
    __tablename__ = 'votes'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id', ondelete='CASCADE'), nullable=False)
    position_id = db.Column(db.Integer, db.ForeignKey('election_positions.id', ondelete='CASCADE'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidates.id', ondelete='CASCADE'), nullable=False)
    voter_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    encrypted_ballot = db.Column(db.Text, nullable=False)
    ballot_hash = db.Column(db.String(128), nullable=False)
    integrity_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))

    __table_args__ = (
        db.UniqueConstraint('election_id', 'voter_id', 'position_id', name='unique_vote_per_position'),
        db.Index('idx_vote_election_voter', 'election_id', 'voter_id'),
        db.Index('idx_vote_voter', 'voter_id'),
        db.Index('idx_vote_election', 'election_id'),
    )

    def __repr__(self):
        return f'<Vote election={self.election_id} voter={self.voter_id}>'


class ElectionResult(db.Model):
    __tablename__ = 'election_results'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id', ondelete='CASCADE'), unique=True, nullable=False)
    results_data = db.Column(db.JSON, nullable=False)
    total_votes = db.Column(db.Integer, default=0)
    registered_voters = db.Column(db.Integer, default=0)
    participation_rate = db.Column(db.Float, default=0.0)
    published_at = db.Column(db.DateTime, default=datetime.utcnow)
    published_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def get_winner_for_position(self, position_title):
        for position in self.results_data:
            if position.get('position_title') == position_title:
                if position.get('candidates'):
                    return position['candidates'][0]
        return None

    def get_position_results(self, position_title):
        for position in self.results_data:
            if position.get('position_title') == position_title:
                return position.get('candidates', [])
        return []

    def __repr__(self):
        return f'<ElectionResult election={self.election_id}>'


class Notification(db.Model):
    __tablename__ = 'notifications'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), default='info')
    is_read = db.Column(db.Boolean, default=False)
    link = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def mark_as_read(self):
        self.is_read = True
        db.session.commit()

    def get_icon(self):
        icons = {
            'success': 'bi-check-circle-fill',
            'danger': 'bi-exclamation-circle-fill',
            'warning': 'bi-exclamation-triangle-fill',
            'info': 'bi-info-circle-fill'
        }
        return icons.get(self.notification_type, 'bi-bell-fill')

    def __repr__(self):
        return f'<Notification {self.title}>'


# ============================================================================
# PART 6: AUDIT, SETTINGS, ELIGIBILITY, PASSWORD RESET
# ============================================================================

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    affected_model = db.Column(db.String(50))
    affected_id = db.Column(db.Integer)
    success = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_user(self):
        if self.user_id:
            return User.query.get(self.user_id)
        return None

    def get_action_color(self):
        colors = {
            'LOGIN': 'success',
            'LOGOUT': 'info',
            'LOGIN_FAILED': 'danger',
            'USER_CREATED': 'success',
            'USER_UPDATED': 'info',
            'USER_DELETED': 'danger',
            'ELECTION_CREATED': 'success',
            'ELECTION_UPDATED': 'info',
            'ELECTION_STATUS_CHANGED': 'warning',
            'CANDIDATE_CREATED': 'success',
            'CANDIDATE_UPDATED': 'info',
            'CANDIDATE_DELETED': 'danger',
            'VOTE_CAST': 'success',
            'RESULT_PUBLISHED': 'success',
            'ADMIN_ACTION': 'info',
            'SECURITY_EVENT': 'danger',
            'PASSWORD_RESET_REQUEST': 'info',
            'PASSWORD_RESET': 'info',
            'ACCOUNT_LOCKED': 'danger',
            'ACCOUNT_UNLOCKED': 'success',
        }
        return colors.get(self.action, 'secondary')

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.user_id}>'


class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    description = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod
    def get_setting(key, default=None):
        setting = SystemSetting.query.filter_by(key=key).first()
        if setting:
            return setting.value
        return default

    @staticmethod
    def set_setting(key, value, description=None):
        setting = SystemSetting.query.filter_by(key=key).first()
        if setting:
            setting.value = value
            setting.description = description or setting.description
        else:
            setting = SystemSetting(key=key, value=value, description=description)
            db.session.add(setting)
        db.session.commit()
        return setting

    def __repr__(self):
        return f'<SystemSetting {self.key}={self.value}>'


class ElectionVoter(db.Model):
    __tablename__ = 'election_voters'
    __table_args__ = (
        db.UniqueConstraint('election_id', 'voter_id', name='unique_election_voter'),
    )

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id', ondelete='CASCADE'), nullable=False)
    voter_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    eligible = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    election = db.relationship('Election', backref=db.backref('election_voters', lazy='dynamic'))
    voter = db.relationship('User', backref=db.backref('election_voters', lazy='dynamic'))


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token = db.Column(db.String(128), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('reset_tokens', lazy='dynamic'))

    def is_valid(self):
        return not self.used and datetime.utcnow() < self.expires_at
# ============================================================================
# PART7: SERVICES
# ============================================================================

class EncryptionService:
    """Secure encryption service for vote encryption and integrity verification."""

    @staticmethod
    def get_encryption_key():
        key = current_app.config.get('ENCRYPTION_KEY')
        if not key:
            salt = b'fixed_salt_for_voting_system'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.b64encode(kdf.derive(b'default-encryption-key-change-in-production')).decode('utf-8')
        return base64.b64decode(key)

    @staticmethod
    def encrypt_vote(data):
        try:
            key = EncryptionService.get_encryption_key()
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            if isinstance(data, dict):
                data = json.dumps(data)
            elif not isinstance(data, str):
                data = str(data)
            encrypted = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
            result = {
                'iv': base64.b64encode(iv).decode('utf-8'),
                'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
                'ciphertext': base64.b64encode(encrypted).decode('utf-8')
            }
            return base64.b64encode(json.dumps(result).encode('utf-8')).decode('utf-8')
        except Exception as e:
            current_app.logger.error(f"Encryption error: {str(e)}")
            raise ValueError("Failed to encrypt vote data")

    @staticmethod
    def decrypt_vote(encrypted_data):
        try:
            key = EncryptionService.get_encryption_key()
            decoded = json.loads(base64.b64decode(encrypted_data).decode('utf-8'))
            iv = base64.b64decode(decoded['iv'])
            tag = base64.b64decode(decoded['tag'])
            ciphertext = base64.b64decode(decoded['ciphertext'])
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            current_app.logger.error(f"Decryption error: {str(e)}")
            raise ValueError("Failed to decrypt vote data")

    @staticmethod
    def generate_integrity_hash(data):
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        elif not isinstance(data, str):
            data = str(data)
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def verify_integrity(data, hash_value):
        computed_hash = EncryptionService.generate_integrity_hash(data)
        return computed_hash == hash_value

    @staticmethod
    def generate_ballot_hash(election_id, voter_id, position_id, candidate_id):
        data = f"{election_id}:{voter_id}:{position_id}:{candidate_id}:{secrets.token_hex(16)}"
        return hashlib.sha512(data.encode('utf-8')).hexdigest()
# ============================================================================
# PART 8: AUDIT SERVICE
# ============================================================================

class AuditService:
    @staticmethod
    def log_action(user_id=None, action=None, description=None,
                   affected_model=None, affected_id=None, success=True, ip_address=None):
        try:
            if ip_address is None:
                ip_address = request.remote_addr if request else 'unknown'
            user_agent = request.headers.get('User-Agent', 'unknown') if request else 'unknown'
            audit = AuditLog(
                user_id=user_id,
                action=action,
                description=description,
                ip_address=ip_address,
                user_agent=user_agent,
                affected_model=affected_model,
                affected_id=affected_id,
                success=success,
                created_at=datetime.utcnow()
            )
            db.session.add(audit)
            db.session.commit()
            return audit
        except Exception as e:
            db.session.rollback()
            print(f"Error logging audit: {str(e)}")
            return None

    @staticmethod
    def get_logs(filters=None, limit=100, offset=0):
        query = AuditLog.query
        if filters:
            if 'user_id' in filters:
                query = query.filter_by(user_id=filters['user_id'])
            if 'action' in filters:
                query = query.filter_by(action=filters['action'])
            if 'success' in filters:
                query = query.filter_by(success=filters['success'])
            if 'start_date' in filters:
                query = query.filter(AuditLog.created_at >= filters['start_date'])
            if 'end_date' in filters:
                query = query.filter(AuditLog.created_at <= filters['end_date'])
        return query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset).all()

    @staticmethod
    def get_actions():
        return [
            'LOGIN', 'LOGOUT', 'LOGIN_FAILED',
            'USER_CREATED', 'USER_UPDATED', 'USER_DELETED',
            'ELECTION_CREATED', 'ELECTION_UPDATED', 'ELECTION_DELETED',
            'ELECTION_OPENED', 'ELECTION_CLOSED', 'ELECTION_STATUS_CHANGED',
            'CANDIDATE_CREATED', 'CANDIDATE_UPDATED', 'CANDIDATE_DELETED',
            'VOTE_CAST', 'VOTE_VERIFIED',
            'RESULT_PUBLISHED',
            'ADMIN_ACTION',
            'SECURITY_EVENT',
            'SYSTEM_CONFIGURED',
            'PASSWORD_RESET_REQUEST',
            'PASSWORD_RESET',
            'ACCOUNT_LOCKED',
            'ACCOUNT_UNLOCKED',
        ]

# ============================================================================
# VOTING SERVICE
# ============================================================================

class VotingService:
    @staticmethod
    def cast_vote(election_id, position_id, candidate_id, voter_id):
        try:
            # Check if voter already voted for this position
            existing = Vote.query.filter_by(
                election_id=election_id,
                voter_id=voter_id,
                position_id=position_id
            ).first()
            if existing:
                raise ValueError("You have already voted for this position")

            # Verify election is open
            election = Election.query.get(election_id)
            if not election or not election.is_voting_open():
                raise ValueError("Election is not open for voting")

            # Verify candidate belongs to position
            candidate = Candidate.query.get(candidate_id)
            if not candidate or candidate.position_id != position_id:
                raise ValueError("Invalid candidate for this position")

            # Check eligibility
            if not election.is_voter_eligible(voter_id):
                raise ValueError("You are not eligible to vote in this election")

            # Create vote data
            vote_data = {
                'election_id': election_id,
                'position_id': position_id,
                'candidate_id': candidate_id,
                'voter_id': voter_id,
                'timestamp': datetime.utcnow().isoformat()
            }

            # Encrypt vote
            encrypted_ballot = EncryptionService.encrypt_vote(vote_data)
            ballot_hash = EncryptionService.generate_ballot_hash(
                election_id, voter_id, position_id, candidate_id
            )
            integrity_hash = EncryptionService.generate_integrity_hash(vote_data)

            # Create vote record
            vote = Vote(
                election_id=election_id,
                position_id=position_id,
                candidate_id=candidate_id,
                voter_id=voter_id,
                encrypted_ballot=encrypted_ballot,
                ballot_hash=ballot_hash,
                integrity_hash=integrity_hash,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            db.session.add(vote)

            # Update voter profile
            profile = VoterProfile.query.filter_by(user_id=voter_id).first()
            if profile:
                profile.has_voted = True

            # Create audit log
            AuditService.log_action(
                user_id=voter_id,
                action='VOTE_CAST',
                description=f"Vote cast for position {position_id} in election {election_id}",
                affected_model='Vote',
                affected_id=vote.id
            )
            db.session.commit()
            return vote
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error casting vote: {str(e)}")
            raise

# ============================================================================
# ELIGIBILITY SERVICE
# ============================================================================

class EligibilityService:
    @staticmethod
    def add_eligible_voter(election_id, voter_id):
        ev = ElectionVoter.query.filter_by(election_id=election_id, voter_id=voter_id).first()
        if not ev:
            ev = ElectionVoter(election_id=election_id, voter_id=voter_id, eligible=True)
            db.session.add(ev)
        else:
            ev.eligible = True
        db.session.commit()
        return ev

    @staticmethod
    def remove_eligible_voter(election_id, voter_id):
        ev = ElectionVoter.query.filter_by(election_id=election_id, voter_id=voter_id).first()
        if ev:
            ev.eligible = False
            db.session.commit()
        return ev

    @staticmethod
    def is_eligible(election_id, voter_id):
        ev = ElectionVoter.query.filter_by(election_id=election_id, voter_id=voter_id).first()
        return ev is not None and ev.eligible

    @staticmethod
    def get_eligible_voters(election_id):
        evs = ElectionVoter.query.filter_by(election_id=election_id, eligible=True).all()
        return [ev.voter for ev in evs]

    @staticmethod
    def get_ineligible_voters(election_id):
        evs = ElectionVoter.query.filter_by(election_id=election_id, eligible=False).all()
        return [ev.voter for ev in evs]

# ============================================================================
# SECURITY SERVICE
# ============================================================================

class SecurityService:
    @staticmethod
    def check_login_attempt(user):
        if user.is_locked_out():
            return False, "Account is locked due to too many failed attempts. Please try again later."
        return True, None

    @staticmethod
    def record_failed_attempt(user):
        user.increment_failed_attempts()
        if user.is_locked_out():
            AuditService.log_action(
                user_id=user.id,
                action='ACCOUNT_LOCKED',
                description=f"Account locked for user {user.username} due to failed attempts",
                affected_model='User',
                affected_id=user.id,
                success=False
            )
            NotificationService.send_notification(
                user.id,
                "Account Locked",
                "Your account has been locked due to multiple failed login attempts. Please try again later.",
                'danger'
            )

    @staticmethod
    def unlock_account(user):
        user.reset_failed_attempts()
        AuditService.log_action(
            user_id=user.id,
            action='ACCOUNT_UNLOCKED',
            description=f"Account unlocked for user {user.username}",
            affected_model='User',
            affected_id=user.id
        )

# ============================================================================
# EMAIL SERVICE (optional)
# ============================================================================

class EmailService:
    @staticmethod
    def send_email(to, subject, body):
        if mail_enabled:
            try:
                msg = Message(subject, recipients=[to], body=body)
                mail.send(msg)
                return True
            except Exception as e:
                current_app.logger.error(f"Email send error: {str(e)}")
                return False
        else:
            current_app.logger.info(f"Email to {to}: {subject}\n{body}")
            return True

# ============================================================================
# NOTIFICATION SERVICE
# ============================================================================

class NotificationService:
    @staticmethod
    def send_notification(user_id, title, message, notification_type='info', link=None):
        notif = Notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notification_type,
            link=link
        )
        db.session.add(notif)
        db.session.commit()
        return notif

# ============================================================================
# SMART-CARD / BIOMETRIC ARCHITECTURE (Simulation)
# ============================================================================

class SmartCardService:
    """Interface for smart-card authentication."""
    @staticmethod
    def authenticate(card_id, pin):
        # Simulation: accept any card_id with pin "1234"
        if pin == "1234":
            user = User.query.filter_by(username='admin').first()
            return user
        return None

class BiometricService:
    """Interface for fingerprint verification."""
    @staticmethod
    def verify_fingerprint(user_id, fingerprint_data):
        # Simulation: always return True for demo
        return True

# ============================================================================
# VISUAL CRYPTOGRAPHY SERVICE (Demo)
# ============================================================================

class VisualCryptographyService:
    """Simple visual cryptography demo: split an image into two shares."""
    @staticmethod
    def generate_shares(image_data):
        import random
        share1 = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))
        share2 = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))
        return share1, share2

    @staticmethod
    def reconstruct(share1, share2):
        return "Reconstructed secret (simulated)"
# ============================================================================
# PART: FORMS (Complete with all form definitions)
# ============================================================================

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80),
        Regexp(r'^[a-zA-Z0-9_]+$', message='Username can only contain letters, numbers, and underscores')
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=200)])
    registration_number = StringField('Registration Number', validators=[DataRequired(), Length(max=50)])
    phone = StringField('Phone Number', validators=[DataRequired(), Length(max=20)])
    department = StringField('Department', validators=[DataRequired(), Length(max=100)])
    faculty = StringField('Faculty', validators=[DataRequired(), Length(max=100)])
    level = SelectField('Level', choices=[
        ('100', '100 Level'),
        ('200', '200 Level'),
        ('300', '300 Level'),
        ('400', '400 Level'),
        ('500', '500 Level'),
        ('600', '600 Level')
    ], validators=[DataRequired()])
    photo = FileField('Profile Photo')   # <-- NEW
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long'),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$',
            message='Password must contain at least one uppercase, one lowercase, one number, and one special character (@$!%*?&)'
        )
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already exists.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_registration_number(self, field):
        if VoterProfile.query.filter_by(registration_number=field.data).first():
            raise ValidationError('Registration number already exists.')

    def validate_photo(self, field):
        if field.data:
            if not allowed_file(field.data.filename):
                raise ValidationError('File type not allowed. Use PNG, JPG, JPEG, or GIF.')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long'),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$',
            message='Password must contain at least one uppercase, one lowercase, one number, and one special character (@$!%*?&)'
        )
    ])
    confirm_new_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])


# ============================================================================
# PART: ELECTION FORM (with position dropdown support)
# ============================================================================

class ElectionForm(FlaskForm):
    title = StringField('Election Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description')
    election_type = SelectField('Election Type', choices=[
        ('general', 'General Election'),
        ('student', 'Student Election'),
        ('faculty', 'Faculty Election'),
        ('department', 'Department Election'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    start_date = DateTimeField('Start Date', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    end_date = DateTimeField('End Date', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])

    def validate_end_date(self, field):
        if field.data and self.start_date.data:
            if field.data <= self.start_date.data:
                raise ValidationError('End date must be after start date.')

    def validate_start_date(self, field):
        if field.data:
            # Get current Nigeria time
            now_ng = get_ng_time()
            if field.data < now_ng:
                raise ValidationError('Start date cannot be in the past.')
                
class PositionForm(FlaskForm):
    title = StringField('Position Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    max_selections = IntegerField('Max Selections', default=1, validators=[DataRequired()])
    order = IntegerField('Display Order', default=0)

    def validate_max_selections(self, field):
        if field.data < 1:
            raise ValidationError('Max selections must be at least 1.')


class CandidateForm(FlaskForm):
    position_id = SelectField('Position', validators=[DataRequired()], coerce=int)
    # We'll handle voter selection in the route, not as a WTForms field
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=200)])
    photo = FileField('Photo')
    department = StringField('Department', validators=[Length(max=100)])
    faculty = StringField('Faculty', validators=[Length(max=100)])
    level = StringField('Level', validators=[Length(max=20)])
    manifesto = TextAreaField('Manifesto')
    is_active = BooleanField('Active', default=True)

    def validate_photo(self, field):
        if field.data:
            if not allowed_file(field.data.filename):
                raise ValidationError('File type not allowed. Use PNG, JPG, JPEG, or GIF.')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long'),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$',
            message='Password must contain at least one uppercase, one lowercase, one number, and one special character (@$!%*?&)'
        )
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    
# ============================================================================
# AUTO UPDATE ELECTION STATUS
# ============================================================================

def update_election_statuses():
    """Update election statuses based on current UTC time"""
    now = datetime.utcnow()
    elections = Election.query.filter(Election.status != 'archived').all()
    updated = 0
    for election in elections:
        if election.status == 'draft':
            continue
        if now < election.start_date and election.status != 'scheduled':
            election.status = 'scheduled'
            updated += 1
        elif election.start_date <= now <= election.end_date and election.status != 'active':
            election.status = 'active'
            updated += 1
        elif now > election.end_date and election.status not in ['closed', 'results_published', 'archived']:
            election.status = 'closed'
            updated += 1
    if updated:
        db.session.commit()
    return updated

@app.before_request
def before_request():
    try:
        update_election_statuses()
    except Exception:
        pass  # Don't break the app
# ============================================================================
# PART9: DECORATORS AND HELPERS
# ============================================================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('voter_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def voter_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('auth_login'))
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ============================================================================
# USER LOADER
# ============================================================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============================================================================
# CONTEXT PROCESSOR
# ============================================================================

@app.context_processor
def inject_globals():
    return {
        'app_name': app.config.get('APP_NAME', 'Smart Encrypted Voting System'),
        'app_tagline': app.config.get('APP_TAGLINE', 'Secure. Transparent. Verified.'),
        'css_styles': STYLES_CSS
    }
# ============================================================================
# AUTH ROUTES
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def auth_login():
    """Voter login only – separate from admin login (Chapter 4 design)."""
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('voter_dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            # Reject admin accounts on voter login page
            if user.role == 'admin':
                flash('Administrators must use the Admin Login page.', 'warning')
                return redirect(url_for('admin_login'))

            if user.is_locked_out():
                flash('Account is locked due to too many failed attempts. Please try again later.', 'danger')
                return render_template('auth/login.html', form=form)

            if not user.is_active:
                flash('Your account has been deactivated. Please contact support.', 'danger')
                return render_template('auth/login.html', form=form)

            user.reset_failed_attempts()
            login_user(user, remember=form.remember_me.data)
            user.last_login = datetime.utcnow()
            db.session.commit()

            AuditService.log_action(
                user_id=user.id,
                action='LOGIN',
                description=f"Voter {user.username} logged in"
            )

            next_page = request.args.get('next')
            return redirect(next_page or url_for('voter_dashboard'))
        else:
            if user:
                SecurityService.record_failed_attempt(user)
            AuditService.log_action(
                action='LOGIN_FAILED',
                description=f"Failed voter login attempt for username: {form.username.data}"
            )
            flash('Invalid username or password.', 'danger')

    return render_template('auth/login.html', form=form)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Dedicated Administrator login (Chapter 4 – separate Admin module)."""
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('voter_dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            if user.role != 'admin':
                flash('This portal is for administrators only. Voters please use the Voter Login.', 'danger')
                return redirect(url_for('auth_login'))

            if user.is_locked_out():
                flash('Account is locked due to too many failed attempts. Please try again later.', 'danger')
                return render_template('auth/admin_login.html', form=form)

            if not user.is_active:
                flash('Your account has been deactivated.', 'danger')
                return render_template('auth/admin_login.html', form=form)

            user.reset_failed_attempts()
            login_user(user, remember=form.remember_me.data)
            user.last_login = datetime.utcnow()
            db.session.commit()

            AuditService.log_action(
                user_id=user.id,
                action='LOGIN',
                description=f"Admin {user.username} logged in via admin portal"
            )

            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin_dashboard'))
        else:
            if user:
                SecurityService.record_failed_attempt(user)
            AuditService.log_action(
                action='LOGIN_FAILED',
                description=f"Failed admin login attempt for username: {form.username.data}"
            )
            flash('Invalid administrator credentials.', 'danger')

    return render_template('auth/admin_login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def auth_register():
    if current_user.is_authenticated:
        return redirect(url_for('voter_dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Save photo if uploaded
        photo_filename = None
        if form.photo.data:
            file = form.photo.data
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(upload_path)
                photo_filename = filename

        user = User(
            username=form.username.data,
            email=form.email.data,
            role='voter'
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()

        profile = VoterProfile(
            user_id=user.id,
            full_name=form.full_name.data,
            registration_number=form.registration_number.data,
            phone=form.phone.data,
            department=form.department.data,
            faculty=form.faculty.data,
            level=form.level.data,
            photo=photo_filename   # <-- Save photo
        )
        db.session.add(profile)
        db.session.commit()

        AuditService.log_action(
            user_id=user.id,
            action='USER_CREATED',
            description=f"User {user.username} registered",
            affected_model='User',
            affected_id=user.id
        )

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth_login'))

    return render_template('auth/register.html', form=form)
    
@app.route('/voter/settings', methods=['GET', 'POST'])
@login_required
def voter_settings():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return render_template('voter/settings.html', form=form)

        current_user.set_password(form.new_password.data)
        db.session.commit()

        AuditService.log_action(
            user_id=current_user.id,
            action='PASSWORD_RESET',
            description=f"User {current_user.username} changed their password"
        )

        flash('Password changed successfully.', 'success')
        return redirect(url_for('voter_settings'))

    return render_template('voter/settings.html', form=form)
    
@app.route('/logout')
@login_required
def auth_logout():
    AuditService.log_action(
        user_id=current_user.id,
        action='LOGOUT',
        description=f"User {current_user.username} logged out"
    )
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# ============================================================================
# PASSWORD RESET ROUTES
# ============================================================================

@app.route('/forgot-password', methods=['GET', 'POST'])
def auth_forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('voter_dashboard'))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = secrets.token_urlsafe(32)
            expires = datetime.utcnow() + timedelta(hours=24)
            reset_token = PasswordResetToken(user_id=user.id, token=token, expires_at=expires)
            db.session.add(reset_token)
            db.session.commit()

            reset_url = url_for('auth_reset_password', token=token, _external=True)
            body = f"""Hello {user.username},

You requested a password reset for your account at {app.config['APP_NAME']}.

Click the link below to reset your password:
{reset_url}

This link will expire in 24 hours.

If you did not request this, please ignore this email.

Thanks,
{app.config['APP_NAME']} Team
"""
            EmailService.send_email(user.email, "Password Reset Request", body)

            AuditService.log_action(
                user_id=user.id,
                action='PASSWORD_RESET_REQUEST',
                description=f"Password reset requested for {user.username}",
                affected_model='User',
                affected_id=user.id
            )
            flash('Password reset instructions have been sent to your email.', 'info')
            return redirect(url_for('auth_login'))
        else:
            flash('No account found with that email address.', 'danger')
    return render_template('auth/forgot_password.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def auth_reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    if not reset_token or not reset_token.is_valid():
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth_forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = reset_token.user
        user.set_password(form.password.data)
        reset_token.used = True
        db.session.commit()

        AuditService.log_action(
            user_id=user.id,
            action='PASSWORD_RESET',
            description=f"Password reset for user {user.username}",
            affected_model='User',
            affected_id=user.id
        )
        flash('Your password has been reset successfully. Please log in.', 'success')
        return redirect(url_for('auth_login'))

    return render_template('auth/reset_password.html', form=form)
# ============================================================================
# PART10: PUBLIC ROUTES
# ============================================================================

@app.route('/')
def index():
    total_elections = Election.query.count()
    now = datetime.utcnow()
    active_elections = Election.query.filter(
        Election.start_date <= now,
        Election.end_date >= now,
        Election.status != 'closed'
    ).count()
    completed_elections = Election.query.filter_by(status='results_published').count()
    recent_elections = Election.query.order_by(Election.created_at.desc()).limit(6).all()

    active_el = Election.query.filter(
        Election.start_date <= now,
        Election.end_date >= now,
        Election.status.in_(['scheduled', 'active'])
    ).limit(3).all()

    total_voter_profiles = VoterProfile.query.count()
    total_votes = Vote.query.count()
    participation_rate = (total_votes / total_voter_profiles * 100) if total_voter_profiles > 0 else 0

    return render_template('main/index.html',
                         total_elections=total_elections,
                         active_elections=active_elections,
                         completed_elections=completed_elections,
                         recent_elections=recent_elections,
                         active_el=active_el,
                         total_voter_profiles=total_voter_profiles,
                         total_votes=total_votes,
                         participation_rate=participation_rate)

@app.route('/about')
def about():
    return render_template('main/about.html')

@app.route('/how-it-works')
def how_it_works():
    return render_template('main/how_it_works.html')

@app.route('/features')
def features():
    return render_template('main/features.html')

@app.route('/visual-cryptography')
def visual_cryptography():
    return render_template('main/visual_cryptography.html')
# ============================================================================
# PART: VOTER DASHBOARD ROUTE (Nigeria time)
# ============================================================================

@app.route('/voter/dashboard')
@login_required
def voter_dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    profile = current_user.voter_profile
    if not profile:
        flash('Your voter profile is incomplete. Please contact support.', 'warning')
        return redirect(url_for('voter_profile'))

    now_ng = get_ng_time()
    now_utc = datetime.utcnow()

    # Active elections
    active_elections = Election.query.filter(
        Election.start_date <= now_utc,
        Election.end_date >= now_utc,
        Election.status.in_(['scheduled', 'active'])
    ).all()

    # Upcoming elections
    upcoming_elections = Election.query.filter(
        Election.start_date > now_utc,
        Election.status != 'archived'
    ).order_by(Election.start_date).limit(10).all()

    # Completed elections
    completed_elections = Election.query.filter(
        Election.status == 'results_published'
    ).order_by(Election.end_date.desc()).limit(5).all()

    # Voted election IDs
    voted_election_ids = {v.election_id for v in Vote.query.filter_by(voter_id=current_user.id).all()}

    # Unread notifications
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()

    # Voting history – with defensive filtering
    raw_votes = Vote.query.filter_by(voter_id=current_user.id).all()
    voting_history = []
    for v in raw_votes:
        election = Election.query.get(v.election_id)
        if election:
            voting_history.append({
                'election': election,
                'created_at': v.created_at
            })
    voting_history.sort(key=lambda x: x['created_at'], reverse=True)

    # Recent notifications
    recent_notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc()).limit(5).all()

    return render_template('voter/dashboard.html',
                         profile=profile,
                         active_elections=active_elections,
                         upcoming_elections=upcoming_elections,
                         completed_elections=completed_elections,
                         voted_election_ids=voted_election_ids,
                         unread_count=unread_count,
                         voting_history=voting_history,
                         recent_notifications=recent_notifications,
                         now_ng=now_ng)
                         
@app.route('/voter/profile', methods=['GET', 'POST'])
@login_required
def voter_profile():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    profile = current_user.voter_profile

    if request.method == 'POST':
        profile.full_name = request.form.get('full_name', profile.full_name)
        profile.phone = request.form.get('phone', profile.phone)
        profile.department = request.form.get('department', profile.department)
        profile.faculty = request.form.get('faculty', profile.faculty)
        profile.level = request.form.get('level', profile.level)

        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(upload_path)
                if profile.photo:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], profile.photo)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                profile.photo = filename

        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('voter_profile'))

    return render_template('voter/profile.html', profile=profile)

@app.route('/voter/notifications')
@login_required
def voter_notifications():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc()).all()

    return render_template('voter/notifications.html', notifications=notifications)

@app.route('/voter/notification/<int:notification_id>/read')
@login_required
def voter_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        flash('Unauthorized.', 'danger')
        return redirect(url_for('voter_notifications'))

    notification.is_read = True
    db.session.commit()
    flash('Notification marked as read.', 'success')
    return redirect(url_for('voter_notifications'))

@app.route('/voter/notifications/mark-all-read')
@login_required
def voter_mark_all_read():
    notifications = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).all()

    for notification in notifications:
        notification.is_read = True

    db.session.commit()
    flash('All notifications marked as read.', 'success')
    return redirect(url_for('voter_notifications'))
# ============================================================================
# PART: VOTING VIEW ELECTION (with Nigeria time display)
# ============================================================================

@app.route('/voting/election/<int:election_id>')
@login_required
def voting_view_election(election_id):
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    election = Election.query.get_or_404(election_id)
    is_open = election.is_voting_open()
    has_voted = Vote.query.filter_by(election_id=election_id, voter_id=current_user.id).first() is not None

    positions = election.positions.order_by(ElectionPosition.order).all()
    candidates_by_position = {}
    for position in positions:
        candidates = position.candidates.filter_by(is_active=True).all()
        for candidate in candidates:
            candidate.vote_count = Vote.query.filter_by(candidate_id=candidate.id, election_id=election_id).count()
        candidates_by_position[position.id] = candidates

    return render_template('voting/election.html',
                         election=election,
                         is_open=is_open,
                         has_voted=has_voted,
                         positions=positions,
                         candidates_by_position=candidates_by_position,
                         utc_to_ng=utc_to_ng)  # Pass helper for template
                         
# ============================================================================
# PART: VOTING ROUTES (skip positions with no candidates)
# ============================================================================

@app.route('/voting/election/<int:election_id>/vote', methods=['GET', 'POST'])
@login_required
def voting_cast_vote(election_id):
    if current_user.role == 'admin':
        flash('Administrators cannot vote.', 'warning')
        return redirect(url_for('admin_dashboard'))

    election = Election.query.get_or_404(election_id)

    if not election.is_voting_open():
        flash('Voting is not open for this election.', 'warning')
        return redirect(url_for('voter_dashboard'))

    if Vote.query.filter_by(election_id=election_id, voter_id=current_user.id).first():
        flash('You have already voted in this election.', 'info')
        return redirect(url_for('voter_dashboard'))

    if not election.is_voter_eligible(current_user.id):
        flash('You are not eligible to vote in this election.', 'danger')
        return redirect(url_for('voter_dashboard'))

    # Only include positions that HAVE candidates
    all_positions = election.positions.order_by(ElectionPosition.order).all()
    votable_positions = []
    candidates_by_position = {}

    for position in all_positions:
        cands = position.candidates.filter_by(is_active=True).all()
        if cands:
            votable_positions.append(position)
            candidates_by_position[position.id] = cands

    if not votable_positions:
        flash('No positions with candidates are available for voting yet.', 'warning')
        return redirect(url_for('voter_dashboard'))

    if request.method == 'POST':
        selected_candidates = {}
        for position in votable_positions:
            field_name = f'position_{position.id}'
            candidate_id = request.form.get(field_name)
            if not candidate_id:
                flash(f'Please select a candidate for {position.title}.', 'danger')
                return render_template('voting/vote.html',
                                     election=election,
                                     positions=votable_positions,
                                     candidates_by_position=candidates_by_position)
            selected_candidates[position.id] = int(candidate_id)

        session['vote_selections'] = selected_candidates
        session['vote_election_id'] = election_id
        return redirect(url_for('voting_review_vote', election_id=election_id))

    return render_template('voting/vote.html',
                         election=election,
                         positions=votable_positions,
                         candidates_by_position=candidates_by_position)
                         
@app.route('/voting/election/<int:election_id>/review')
@login_required
def voting_review_vote(election_id):
    if current_user.role == 'admin':
        flash('Administrators cannot vote.', 'warning')
        return redirect(url_for('admin_dashboard'))

    if 'vote_selections' not in session or session.get('vote_election_id') != election_id:
        flash('No vote selections found. Please cast your vote again.', 'warning')
        return redirect(url_for('voting_cast_vote', election_id=election_id))

    election = Election.query.get_or_404(election_id)
    selected_candidates = session['vote_selections']

    # Convert string keys/values to integers
    selections_int = {int(pid): int(cid) for pid, cid in selected_candidates.items()}

    review_data = []
    for position_id, candidate_id in selections_int.items():
        position = ElectionPosition.query.get(position_id)
        candidate = Candidate.query.get(candidate_id)
        if position and candidate:
            review_data.append({
                'position': position,
                'candidate': candidate
            })

    return render_template('voting/review.html',
                         election=election,
                         review_data=review_data)
                         
# ============================================================================
# PART: VOTING CONFIRM ROUTE (FIXED - converts session keys to int)
# ============================================================================

@app.route('/voting/election/<int:election_id>/confirm', methods=['POST'])
@login_required
def voting_confirm_vote(election_id):
    if current_user.role == 'admin':
        flash('Administrators cannot vote.', 'warning')
        return redirect(url_for('admin_dashboard'))

    if 'vote_selections' not in session or session.get('vote_election_id') != election_id:
        flash('No vote selections found. Please cast your vote again.', 'warning')
        return redirect(url_for('voting_cast_vote', election_id=election_id))

    election = Election.query.get_or_404(election_id)

    if not election.is_voting_open():
        session.pop('vote_selections', None)
        session.pop('vote_election_id', None)
        flash('Voting has closed for this election.', 'warning')
        return redirect(url_for('voter_dashboard'))

    if Vote.query.filter_by(election_id=election_id, voter_id=current_user.id).first():
        session.pop('vote_selections', None)
        session.pop('vote_election_id', None)
        flash('You have already voted in this election.', 'info')
        return redirect(url_for('voter_dashboard'))

    if not election.is_voter_eligible(current_user.id):
        flash('You are not eligible to vote in this election.', 'danger')
        return redirect(url_for('voter_dashboard'))

    selected_candidates = session['vote_selections']

    try:
        # Convert session keys (strings) to integers
        selections_int = {int(pid): int(cid) for pid, cid in selected_candidates.items()}

        for position_id, candidate_id in selections_int.items():
            candidate = Candidate.query.get(candidate_id)
            if not candidate or candidate.position_id != position_id:
                raise ValueError(f'Invalid candidate for position {position_id}')

            vote = VotingService.cast_vote(
                election_id=election_id,
                position_id=position_id,
                candidate_id=candidate_id,
                voter_id=current_user.id
            )

        session.pop('vote_selections', None)
        session.pop('vote_election_id', None)

        notification = Notification(
            user_id=current_user.id,
            title='Vote Submitted',
            message=f'Your vote for {election.title} has been submitted successfully.',
            notification_type='success',
            link=url_for('voter_dashboard')
        )
        db.session.add(notification)
        db.session.commit()

        flash('Your vote has been submitted successfully!', 'success')
        return redirect(url_for('voting_confirmation', election_id=election_id))

    except Exception as e:
        db.session.rollback()
        flash(f'Error casting vote: {str(e)}', 'danger')
        return redirect(url_for('voting_cast_vote', election_id=election_id))
        
@app.route('/voting/election/<int:election_id>/confirmation')
@login_required
def voting_confirmation(election_id):
    election = Election.query.get_or_404(election_id)

    has_voted = Vote.query.filter_by(
        election_id=election_id,
        voter_id=current_user.id
    ).first() is not None

    if not has_voted:
        flash('You have not voted in this election.', 'warning')
        return redirect(url_for('voter_dashboard'))

    votes = Vote.query.filter_by(
        election_id=election_id,
        voter_id=current_user.id
    ).all()

    vote_details = []
    for vote in votes:
        position = ElectionPosition.query.get(vote.position_id)
        candidate = Candidate.query.get(vote.candidate_id)
        if position and candidate:
            vote_details.append({
                'position': position,
                'candidate': candidate
            })

    return render_template('voting/confirmation.html',
                         election=election,
                         vote_details=vote_details)
# ============================================================================
# PART12: RESULTS ROUTES (Public)
# ============================================================================

@app.route('/results')
def results_index():
    elections = Election.query.filter_by(
        status='results_published'
    ).order_by(Election.end_date.desc()).all()

    election_results = []
    for election in elections:
        result = ElectionResult.query.filter_by(election_id=election.id).first()
        if result:
            election_results.append({
                'election': election,
                'result': result
            })

    return render_template('results/index.html',
                         election_results=election_results)

# ============================================================================
# PART: RESULTS VIEW ROUTE (with Nigeria time)
# ============================================================================

@app.route('/results/<int:election_id>')
def results_view(election_id):
    election = Election.query.get_or_404(election_id)

    if not election.is_results_published() and election.get_status() != 'closed':
        flash('Results are not yet available for this election.', 'info')
        return redirect(url_for('results_index'))

    result = ElectionResult.query.filter_by(election_id=election_id).first()
    if not result:
        flash('No results available for this election.', 'info')
        return redirect(url_for('results_index'))

    total_votes = Vote.query.filter_by(election_id=election_id).count()

    positions = election.positions.order_by(ElectionPosition.order).all()
    position_data = []
    for position in positions:
        candidates = position.candidates.filter_by(is_active=True).all()
        candidate_data = []
        for candidate in candidates:
            vote_count = Vote.query.filter_by(candidate_id=candidate.id, election_id=election_id).count()
            candidate_data.append({
                'candidate': candidate,
                'vote_count': vote_count,
                'percentage': (vote_count / total_votes * 100) if total_votes > 0 else 0
            })
        candidate_data.sort(key=lambda x: x['vote_count'], reverse=True)
        position_data.append({'position': position, 'candidates': candidate_data})

    return render_template('results/view.html',
                         election=election,
                         result=result,
                         position_data=position_data,
                         total_votes=total_votes,
                         utc_to_ng=utc_to_ng)
                         
@app.route('/results/<int:election_id>/export')
def results_export(election_id):
    election = Election.query.get_or_404(election_id)

    if not election.is_results_published():
        flash('Results are not yet published.', 'warning')
        return redirect(url_for('results_view', election_id=election_id))

    result = ElectionResult.query.filter_by(election_id=election_id).first()
    if not result:
        flash('No results available.', 'warning')
        return redirect(url_for('results_view', election_id=election_id))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Election', 'Position', 'Candidate', 'Votes', 'Percentage'])

    for position_data in result.results_data:
        position_title = position_data.get('position_title', '')
        for candidate in position_data.get('candidates', []):
            writer.writerow([
                election.title,
                position_title,
                candidate.get('candidate_name', ''),
                candidate.get('vote_count', 0),
                f"{candidate.get('percentage', 0):.1f}%"
            ])

    output.seek(0)
    return send_file(
        BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'{election.title}_results.csv'
    )
# ============================================================================
# PART: ADMIN DASHBOARD ROUTE (FIXED)
# ============================================================================

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_voters = User.query.filter_by(role='voter', is_active=True).count()
    total_voter_profiles = VoterProfile.query.count()
    total_admins = User.query.filter_by(role='admin', is_active=True).count()

    now_utc = datetime.utcnow()

    total_elections = Election.query.count()
    active_elections = Election.query.filter(
        Election.start_date <= now_utc,
        Election.end_date >= now_utc,
        Election.status != 'closed'
    ).count()
    upcoming_elections = Election.query.filter(
        Election.start_date > now_utc,
        Election.status != 'archived'
    ).count()
    completed_elections = Election.query.filter_by(status='results_published').count()
    draft_elections = Election.query.filter_by(status='draft').count()

    total_votes = Vote.query.count()
    participation_rate = (total_votes / total_voter_profiles * 100) if total_voter_profiles > 0 else 0

    recent_activity = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()

    election_activity = []
    elections = Election.query.order_by(Election.created_at.desc()).limit(5).all()
    for election in elections:
        vote_count = Vote.query.filter_by(election_id=election.id).count()
        election_activity.append({
            'title': election.title,
            'votes': vote_count,
            'status': election.get_status(),
            'id': election.id
        })

    recent_elections = Election.query.order_by(Election.created_at.desc()).limit(5).all()

    system_name = SystemSetting.get_setting('system_name', app.config['APP_NAME'])

    # Nigeria time for display
    now_ng = get_ng_time()

    return render_template('admin/dashboard.html',
                         total_voters=total_voters,
                         total_voter_profiles=total_voter_profiles,
                         total_admins=total_admins,
                         total_elections=total_elections,
                         active_elections=active_elections,
                         upcoming_elections=upcoming_elections,
                         completed_elections=completed_elections,
                         draft_elections=draft_elections,
                         total_votes=total_votes,
                         participation_rate=participation_rate,
                         recent_activity=recent_activity,
                         election_activity=election_activity,
                         recent_elections=recent_elections,
                         system_name=system_name,
                         now=now_ng,      # For backwards compatibility
                         now_ng=now_ng)   # For Nigeria time
# ============================================================================
# PART13: ADMIN VOTERS MANAGEMENT
# ============================================================================

@app.route('/admin/voters')
@login_required
@admin_required
def admin_voters():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    filter_status = request.args.get('status', '')

    query = User.query.filter_by(role='voter')

    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )

    if filter_status == 'active':
        query = query.filter_by(is_active=True)
    elif filter_status == 'inactive':
        query = query.filter_by(is_active=False)
    elif filter_status == 'verified':
        query = query.filter_by(is_verified=True)
    elif filter_status == 'unverified':
        query = query.filter_by(is_verified=False)

    voters = query.order_by(
        User.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    voter_data = []
    for user in voters.items:
        profile = VoterProfile.query.filter_by(user_id=user.id).first()
        if profile:
            voted = Vote.query.filter_by(voter_id=user.id).count()
            voter_data.append({
                'user': user,
                'profile': profile,
                'voted_count': voted
            })

    return render_template('admin/voters.html',
                         voters=voters,
                         voter_data=voter_data,
                         search=search,
                         filter_status=filter_status)

@app.route('/admin/voters/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_voter(user_id):
    user = User.query.get_or_404(user_id)
    if user.role != 'voter':
        flash('User is not a voter.', 'warning')
        return redirect(url_for('admin_voters'))

    profile = VoterProfile.query.filter_by(user_id=user.id).first()
    if not profile:
        flash('Voter profile not found.', 'danger')
        return redirect(url_for('admin_voters'))

    if request.method == 'POST':
        user.is_active = request.form.get('is_active') == 'on'
        user.is_verified = request.form.get('is_verified') == 'on'

        profile.full_name = request.form.get('full_name', profile.full_name)
        profile.phone = request.form.get('phone', profile.phone)
        profile.department = request.form.get('department', profile.department)
        profile.faculty = request.form.get('faculty', profile.faculty)
        profile.level = request.form.get('level', profile.level)

        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(upload_path)
                if profile.photo:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], profile.photo)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                profile.photo = filename

        db.session.commit()

        AuditService.log_action(
            user_id=current_user.id,
            action='USER_UPDATED',
            description=f"Updated voter {user.username}",
            affected_model='User',
            affected_id=user.id
        )

        flash('Voter updated successfully.', 'success')
        return redirect(url_for('admin_voters'))

    voting_history = Vote.query.filter_by(voter_id=user.id).join(
        Election
    ).order_by(Election.end_date.desc()).all()

    return render_template('admin/edit_voter.html',
                         user=user,
                         profile=profile,
                         voting_history=voting_history)

@app.route('/admin/voters/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_voter(user_id):
    user = User.query.get_or_404(user_id)
    if user.role != 'voter':
        flash('User is not a voter.', 'warning')
        return redirect(url_for('admin_voters'))

    votes = Vote.query.filter_by(voter_id=user.id).count()
    if votes > 0:
        flash('Cannot delete voter who has cast votes.', 'danger')
        return redirect(url_for('admin_voters'))

    profile = VoterProfile.query.filter_by(user_id=user.id).first()
    if profile:
        db.session.delete(profile)

    db.session.delete(user)
    db.session.commit()

    AuditService.log_action(
        user_id=current_user.id,
        action='USER_DELETED',
        description=f"Deleted voter {user.username}",
        affected_model='User',
        affected_id=user.id
    )

    flash('Voter deleted successfully.', 'success')
    return redirect(url_for('admin_voters'))
# ============================================================================
# ADMIN ELIGIBILITY MANAGEMENT
# ============================================================================

@app.route('/admin/elections/<int:election_id>/eligibility', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_eligibility(election_id):
    election = Election.query.get_or_404(election_id)

    if request.method == 'POST':
        action = request.form.get('action')
        voter_id = request.form.get('voter_id', type=int)
        if action == 'add':
            EligibilityService.add_eligible_voter(election_id, voter_id)
            flash('Voter added to eligibility list.', 'success')
        elif action == 'remove':
            EligibilityService.remove_eligible_voter(election_id, voter_id)
            flash('Voter removed from eligibility list.', 'success')

        return redirect(url_for('admin_eligibility', election_id=election_id))

    all_voters = User.query.filter_by(role='voter', is_active=True).all()
    eligible_ids = set(ev.voter_id for ev in ElectionVoter.query.filter_by(election_id=election_id, eligible=True).all())
    ineligible_ids = set(ev.voter_id for ev in ElectionVoter.query.filter_by(election_id=election_id, eligible=False).all())

    voters_status = []
    for voter in all_voters:
        if voter.id in eligible_ids:
            status = 'eligible'
        elif voter.id in ineligible_ids:
            status = 'ineligible'
        else:
            status = 'not_set'
        voters_status.append({
            'voter': voter,
            'status': status
        })

    return render_template('admin/eligibility.html',
                         election=election,
                         voters_status=voters_status)

# ============================================================================
# PART: ADMIN ELECTIONS LIST ROUTE (with Nigeria time)
# ============================================================================

@app.route('/admin/elections')
@login_required
@admin_required
def admin_elections():
    filter_status = request.args.get('status', '').strip()
    
    query = Election.query.order_by(Election.created_at.desc())
    
    if filter_status:
        query = query.filter_by(status=filter_status)
    
    elections = query.all()
    
    election_stats = []
    for election in elections:
        vote_count = Vote.query.filter_by(election_id=election.id).count()
        candidate_count = Candidate.query.filter_by(election_id=election.id).count()
        
        # Convert UTC to Nigeria time
        utc_start = election.start_date.replace(tzinfo=timezone.utc)
        utc_end = election.end_date.replace(tzinfo=timezone.utc)
        local_start = utc_start.astimezone(NIGERIA_TZ).replace(tzinfo=None)
        local_end = utc_end.astimezone(NIGERIA_TZ).replace(tzinfo=None)
        
        election_stats.append({
            'election': election,
            'vote_count': vote_count,
            'candidate_count': candidate_count,
            'local_start': local_start,
            'local_end': local_end,
        })
    
    return render_template('admin/elections.html', 
                         elections=election_stats, 
                         filter_status=filter_status)

# ============================================================================
# PART: ADMIN CREATE ELECTION ROUTE (with auto-positions by type)
# ============================================================================

@app.route('/admin/elections/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_election():
    form = ElectionForm()

    # Pre-fill date fields with Nigeria time
    if request.method == 'GET':
        now_ng = get_ng_time()
        form.start_date.data = now_ng + timedelta(days=1)
        form.end_date.data = now_ng + timedelta(days=8)

    if form.validate_on_submit():
        try:
            # Convert Nigeria time to UTC
            start_utc = ng_to_utc(form.start_date.data)
            end_utc = ng_to_utc(form.end_date.data)
            
            election = Election(
                title=form.title.data,
                description=form.description.data,
                election_type=form.election_type.data,
                start_date=start_utc,
                end_date=end_utc,
                status='scheduled',
                created_by=current_user.id
            )

            db.session.add(election)
            db.session.flush()  # Get election ID
            
            # Auto-create positions based on election type
            default_positions = Election.get_default_positions(form.election_type.data)
            for i, position_title in enumerate(default_positions):
                position = ElectionPosition(
                    election_id=election.id,
                    title=position_title,
                    description=f'Position for {position_title}',
                    order=i,
                    max_selections=1
                )
                db.session.add(position)
            
            db.session.commit()

            AuditService.log_action(
                user_id=current_user.id,
                action='ELECTION_CREATED',
                description=f"Created election: {election.title} with {len(default_positions)} positions",
                affected_model='Election',
                affected_id=election.id
            )

            flash(f'Election created successfully with {len(default_positions)} positions. You can now add candidates.', 'success')
            return redirect(url_for('admin_edit_election', election_id=election.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating election: {str(e)}', 'danger')
            return render_template('admin/create_election.html', form=form)

    return render_template('admin/create_election.html', form=form)    
# ============================================================================
# PART: ADMIN EDIT ELECTION ROUTE (with Nigeria time)
# ============================================================================

@app.route('/admin/elections/<int:election_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_election(election_id):
    election = Election.query.get_or_404(election_id)
    form = ElectionForm(obj=election)

    # Check if editing is allowed
    vote_count = Vote.query.filter_by(election_id=election.id).count()
    if vote_count > 0:
        flash('This election cannot be edited because it already has votes.', 'danger')
        return redirect(url_for('admin_elections'))

    if request.method == 'GET':
        form.start_date.data = utc_to_ng(election.start_date)
        form.end_date.data = utc_to_ng(election.end_date)

    if form.validate_on_submit():
        election.title = form.title.data
        election.description = form.description.data
        election.election_type = form.election_type.data
        election.start_date = ng_to_utc(form.start_date.data)
        election.end_date = ng_to_utc(form.end_date.data)
        db.session.commit()

        AuditService.log_action(
            user_id=current_user.id,
            action='ELECTION_UPDATED',
            description=f"Updated election: {election.title}",
            affected_model='Election',
            affected_id=election.id
        )
        flash('Election updated successfully.', 'success')
        return redirect(url_for('admin_edit_election', election_id=election.id))

    positions = election.positions.order_by(ElectionPosition.order).all()

    # Build candidate summary per position
    candidate_summary = []
    total_candidates = 0
    for pos in positions:
        count = Candidate.query.filter_by(position_id=pos.id, is_active=True).count()
        total_candidates += count
        candidate_summary.append({'position': pos, 'count': count})

    return render_template('admin/edit_election.html',
                         form=form,
                         election=election,
                         positions=positions,
                         candidate_summary=candidate_summary,
                         total_candidates=total_candidates)
                         
@app.route('/admin/elections/<int:election_id>/status', methods=['POST'])
@login_required
@admin_required
def admin_update_election_status(election_id):
    election = Election.query.get_or_404(election_id)
    status = request.form.get('status')

    if status not in ['draft', 'scheduled', 'active', 'closed', 'archived']:
        flash('Invalid status.', 'danger')
        return redirect(url_for('admin_elections'))

    current_status = election.status
    if current_status == 'archived' and status != 'archived':
        flash('Cannot un-archive an election.', 'danger')
        return redirect(url_for('admin_elections'))

    if current_status == 'results_published' and status != 'archived':
        flash('Cannot change status of a published election.', 'danger')
        return redirect(url_for('admin_elections'))

    election.status = status

    if status == 'active':
        positions = election.positions.all()
        if not positions:
            flash('Cannot activate election with no positions.', 'danger')
            return redirect(url_for('admin_elections'))

        for position in positions:
            if position.candidates.filter_by(is_active=True).count() == 0:
                flash(f'Position "{position.title}" has no candidates.', 'danger')
                return redirect(url_for('admin_elections'))

    db.session.commit()

    AuditService.log_action(
        user_id=current_user.id,
        action='ELECTION_STATUS_CHANGED',
        description=f"Changed election '{election.title}' status to {status}",
        affected_model='Election',
        affected_id=election.id
    )

    flash(f'Election status updated to {status}.', 'success')
    return redirect(url_for('admin_elections'))

# ============================================================================
# PART: ADMIN DELETE ELECTION ROUTE (allows deletion with candidates)
# ============================================================================

@app.route('/admin/elections/<int:election_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_election(election_id):
    election = Election.query.get_or_404(election_id)

    # Only prevent deletion if there are votes (candidates can be cascade-deleted)
    votes = Vote.query.filter_by(election_id=election_id).count()
    if votes > 0:
        flash('Cannot delete an election that already has votes.', 'danger')
        return redirect(url_for('admin_elections'))

    # Cascade delete will remove positions and candidates automatically
    db.session.delete(election)
    db.session.commit()

    AuditService.log_action(
        user_id=current_user.id,
        action='ELECTION_DELETED',
        description=f"Deleted election: {election.title} (ID: {election.id})",
        affected_model='Election',
        affected_id=election.id
    )

    flash('Election deleted successfully.', 'success')
    return redirect(url_for('admin_elections'))
# ============================================================================
# PART14: ADMIN POSITIONS MANAGEMENT
# ============================================================================

@app.route('/admin/elections/<int:election_id>/positions/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_position(election_id):
    election = Election.query.get_or_404(election_id)
    form = PositionForm()

    if form.validate_on_submit():
        existing = ElectionPosition.query.filter_by(
            election_id=election.id,
            title=form.title.data
        ).first()

        if existing:
            flash('A position with this title already exists.', 'danger')
            return render_template('admin/create_position.html', form=form, election=election)

        position = ElectionPosition(
            election_id=election.id,
            title=form.title.data,
            description=form.description.data,
            max_selections=form.max_selections.data,
            order=form.order.data
        )

        db.session.add(position)
        db.session.commit()

        AuditService.log_action(
            user_id=current_user.id,
            action='ADMIN_ACTION',
            description=f"Added position '{position.title}' to election {election.title}",
            affected_model='ElectionPosition',
            affected_id=position.id
        )

        flash('Position added successfully.', 'success')
        return redirect(url_for('admin_edit_election', election_id=election.id))

    return render_template('admin/create_position.html', form=form, election=election)

@app.route('/admin/elections/<int:election_id>/positions/<int:position_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_position(election_id, position_id):
    election = Election.query.get_or_404(election_id)
    position = ElectionPosition.query.get_or_404(position_id)
    form = PositionForm(obj=position)

    if form.validate_on_submit():
        existing = ElectionPosition.query.filter(
            ElectionPosition.election_id == election.id,
            ElectionPosition.title == form.title.data,
            ElectionPosition.id != position.id
        ).first()

        if existing:
            flash('A position with this title already exists.', 'danger')
            return render_template('admin/edit_position.html', form=form, election=election, position=position)

        position.title = form.title.data
        position.description = form.description.data
        position.max_selections = form.max_selections.data
        position.order = form.order.data
        db.session.commit()

        AuditService.log_action(
            user_id=current_user.id,
            action='ADMIN_ACTION',
            description=f"Updated position '{position.title}' in election {election.title}",
            affected_model='ElectionPosition',
            affected_id=position.id
        )

        flash('Position updated successfully.', 'success')
        return redirect(url_for('admin_edit_election', election_id=election.id))

    return render_template('admin/edit_position.html', form=form, election=election, position=position)

@app.route('/admin/elections/<int:election_id>/positions/<int:position_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_position(election_id, position_id):
    position = ElectionPosition.query.get_or_404(position_id)
    title = position.title

    votes = Vote.query.filter_by(position_id=position_id).count()
    if votes > 0:
        flash('Cannot delete position with existing votes.', 'danger')
        return redirect(url_for('admin_edit_election', election_id=election_id))

    candidates = position.candidates.all()
    for candidate in candidates:
        db.session.delete(candidate)

    db.session.delete(position)
    db.session.commit()

    AuditService.log_action(
        user_id=current_user.id,
        action='ADMIN_ACTION',
        description=f"Deleted position '{title}' from election {election_id}",
        affected_model='ElectionPosition',
        affected_id=position_id
    )

    flash('Position deleted successfully.', 'success')
    return redirect(url_for('admin_edit_election', election_id=election_id))
# ============================================================================
# PART: ADMIN CREATE CANDIDATE ROUTE (with voter selection)
# ============================================================================

@app.route('/admin/elections/<int:election_id>/candidates/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_candidate(election_id):
    election = Election.query.get_or_404(election_id)
    form = CandidateForm()
    form.position_id.choices = [(p.id, p.title) for p in election.positions.order_by(ElectionPosition.order).all()]

    # Pre-select position if passed in query string
    preselect_position = request.args.get('position_id', type=int)
    if preselect_position and request.method == 'GET':
        form.position_id.data = preselect_position

    # Fetch all voters (excluding admins)
    voters = User.query.filter_by(role='voter', is_active=True).all()
    voter_list = []
    for v in voters:
        profile = v.voter_profile
        if profile:
            voter_list.append({
                'id': v.id,
                'username': v.username,
                'full_name': profile.full_name,
                'registration_number': profile.registration_number,
                'department': profile.department or '',
                'faculty': profile.faculty or '',
                'level': profile.level or '',
                'phone': profile.phone or '',
                'photo': profile.photo or '',
            })

    if form.validate_on_submit():
        voter_id = request.form.get('voter_id', type=int)
        if not voter_id:
            flash('Please select a voter.', 'danger')
            return render_template('admin/create_candidate.html',
                                 form=form, election=election, voter_list=voter_list)

        # Prevent duplicates for same election
        existing = Candidate.query.filter_by(election_id=election.id, user_id=voter_id).first()
        if existing:
            flash('This voter is already a candidate in this election.', 'warning')
            return redirect(url_for('admin_create_candidate', election_id=election.id))

        # Optional custom photo upload (fallback to profile photo)
        photo_filename = None
        if form.photo.data and form.photo.data.filename:
            file = form.photo.data
            if allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                photo_filename = filename

        voter = User.query.get(voter_id)
        profile = voter.voter_profile
        if not photo_filename and profile and profile.photo:
            photo_filename = profile.photo

        candidate = Candidate(
            election_id=election.id,
            position_id=form.position_id.data,
            user_id=voter_id,
            full_name=profile.full_name if profile else form.full_name.data,
            photo=photo_filename,
            department=profile.department if profile else form.department.data,
            faculty=profile.faculty if profile else form.faculty.data,
            level=profile.level if profile else form.level.data,
            manifesto=form.manifesto.data,
            is_active=True
        )
        db.session.add(candidate)
        db.session.commit()

        # Auto-enroll candidate as eligible voter for this election
        EligibilityService.add_eligible_voter(election.id, voter_id)

        AuditService.log_action(
            user_id=current_user.id,
            action='CANDIDATE_CREATED',
            description=f"Added candidate '{candidate.full_name}' to election {election.title}",
            affected_model='Candidate',
            affected_id=candidate.id
        )

        flash(f'✅ {candidate.full_name} was added as candidate successfully. You can add another candidate below.', 'success')
        return redirect(url_for('admin_create_candidate', election_id=election.id) + f'?position_id={form.position_id.data}')

    return render_template('admin/create_candidate.html',
                         form=form, election=election, voter_list=voter_list)


@app.route('/admin/elections/<int:election_id>/candidates/<int:candidate_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_candidate(election_id, candidate_id):
    election = Election.query.get_or_404(election_id)
    candidate = Candidate.query.get_or_404(candidate_id)
    form = CandidateForm(obj=candidate)
    form.position_id.choices = [(p.id, p.title) for p in election.positions.all()]

    if form.validate_on_submit():
        if form.photo.data and allowed_file(form.photo.data.filename):
            file = form.photo.data
            filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(upload_path)
            if candidate.photo:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], candidate.photo)
                if os.path.exists(old_path):
                    os.remove(old_path)
            candidate.photo = filename

        candidate.position_id = form.position_id.data
        candidate.full_name = form.full_name.data
        candidate.department = form.department.data
        candidate.faculty = form.faculty.data
        candidate.level = form.level.data
        candidate.manifesto = form.manifesto.data
        candidate.is_active = form.is_active.data

        db.session.commit()

        AuditService.log_action(
            user_id=current_user.id,
            action='CANDIDATE_UPDATED',
            description=f"Updated candidate '{candidate.full_name}'",
            affected_model='Candidate',
            affected_id=candidate.id
        )

        flash('Candidate updated successfully.', 'success')
        return redirect(url_for('admin_edit_election', election_id=election.id))

    return render_template('admin/edit_candidate.html',
                         form=form,
                         election=election,
                         candidate=candidate)

@app.route('/admin/elections/<int:election_id>/candidates/<int:candidate_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_candidate(election_id, candidate_id):
    candidate = Candidate.query.get_or_404(candidate_id)
    name = candidate.full_name

    votes = Vote.query.filter_by(candidate_id=candidate_id).count()
    if votes > 0:
        flash('Cannot delete candidate with existing votes.', 'danger')
        return redirect(url_for('admin_edit_election', election_id=election_id))

    if candidate.photo:
        old_path = os.path.join(app.config['UPLOAD_FOLDER'], candidate.photo)
        if os.path.exists(old_path):
            os.remove(old_path)

    db.session.delete(candidate)
    db.session.commit()

    AuditService.log_action(
        user_id=current_user.id,
        action='CANDIDATE_DELETED',
        description=f"Deleted candidate '{name}'",
        affected_model='Candidate',
        affected_id=candidate_id
    )

    flash('Candidate deleted successfully.', 'success')
    return redirect(url_for('admin_edit_election', election_id=election.id))
# ============================================================================
# PART15: ADMIN RESULTS MANAGEMENT
# ============================================================================

@app.route('/admin/elections/<int:election_id>/results')
@login_required
@admin_required
def admin_view_results(election_id):
    election = Election.query.get_or_404(election_id)

    result = ElectionResult.query.filter_by(election_id=election_id).first()

    if not result:
        votes = Vote.query.filter_by(election_id=election_id).all()

        if votes:
            results_data = []
            positions = election.positions.all()

            for position in positions:
                position_votes = [v for v in votes if v.position_id == position.id]
                candidate_votes = {}

                for v in position_votes:
                    candidate = Candidate.query.get(v.candidate_id)
                    if candidate:
                        if candidate.id not in candidate_votes:
                            candidate_votes[candidate.id] = {
                                'candidate': candidate,
                                'count': 0
                            }
                        candidate_votes[candidate.id]['count'] += 1

                position_data = {
                    'position_title': position.title,
                    'candidates': []
                }

                for cand_id, data in candidate_votes.items():
                    position_data['candidates'].append({
                        'candidate_name': data['candidate'].full_name,
                        'vote_count': data['count']
                    })

                position_data['candidates'].sort(key=lambda x: x['vote_count'], reverse=True)
                results_data.append(position_data)

            total_votes = len(votes)
            registered_voters = VoterProfile.query.count()
            participation_rate = (total_votes / registered_voters * 100) if registered_voters > 0 else 0

            result = ElectionResult(
                election_id=election.id,
                results_data=results_data,
                total_votes=total_votes,
                registered_voters=registered_voters,
                participation_rate=participation_rate,
                published_at=datetime.utcnow()
            )
            db.session.add(result)
            db.session.commit()
        else:
            flash('No votes have been cast in this election yet.', 'info')
            return redirect(url_for('admin_elections'))

    return render_template('admin/results.html', election=election, result=result)

@app.route('/admin/results/<int:election_id>/publish', methods=['POST'])
@login_required
@admin_required
def admin_publish_results(election_id):
    election = Election.query.get_or_404(election_id)

    result = ElectionResult.query.filter_by(election_id=election_id).first()
    if not result:
        flash('Please generate results first.', 'warning')
        return redirect(url_for('admin_view_results', election_id=election_id))

    election.status = 'results_published'
    db.session.commit()

    AuditService.log_action(
        user_id=current_user.id,
        action='RESULT_PUBLISHED',
        description=f"Published results for election: {election.title}",
        affected_model='Election',
        affected_id=election.id
    )

    voters = User.query.filter_by(role='voter', is_active=True).all()
    for voter in voters:
        notification = Notification(
            user_id=voter.id,
            title=f"Results Published: {election.title}",
            message=f"The results for {election.title} have been published. View them now.",
            notification_type='info',
            link=url_for('results_view', election_id=election.id)
        )
        db.session.add(notification)

    db.session.commit()

    flash('Results published successfully. Notifications sent to all voters.', 'success')
    return redirect(url_for('admin_view_results', election_id=election_id))
# ============================================================================
# ADMIN AUDIT LOG
# ============================================================================

@app.route('/admin/audit')
@login_required
@admin_required
def admin_audit():
    page = request.args.get('page', 1, type=int)
    per_page = 50

    action = request.args.get('action', '')
    user_id = request.args.get('user_id', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    query = AuditLog.query

    if action:
        query = query.filter_by(action=action)
    if user_id:
        query = query.filter_by(user_id=int(user_id))
    if date_from:
        query = query.filter(AuditLog.created_at >= datetime.strptime(date_from, '%Y-%m-%d'))
    if date_to:
        query = query.filter(AuditLog.created_at <= datetime.strptime(date_to, '%Y-%m-%d'))

    logs = query.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    actions = AuditService.get_actions()

    return render_template('admin/audit.html',
                         logs=logs,
                         actions=actions,
                         action=action,
                         user_id=user_id,
                         date_from=date_from,
                         date_to=date_to)

# ============================================================================
# ADMIN SECURITY DASHBOARD
# ============================================================================

@app.route('/admin/security')
@login_required
@admin_required
def admin_security():
    security_actions = ['LOGIN_FAILED', 'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'SECURITY_EVENT']
    security_logs = AuditLog.query.filter(AuditLog.action.in_(security_actions)).order_by(
        AuditLog.created_at.desc()
    ).limit(50).all()

    locked_users = User.query.filter(User.locked_until > datetime.utcnow()).all()

    yesterday = datetime.utcnow() - timedelta(days=1)
    failed_count = AuditLog.query.filter(
        AuditLog.action == 'LOGIN_FAILED',
        AuditLog.created_at >= yesterday
    ).count()

    return render_template('admin/security.html',
                         security_logs=security_logs,
                         locked_users=locked_users,
                         failed_count=failed_count)

# ============================================================================
# ADMIN REPORTS
# ============================================================================

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    report_type = request.args.get('type', 'participation')
    election_id = request.args.get('election_id', type=int)

    if report_type == 'participation':
        departments = db.session.query(VoterProfile.department, db.func.count(VoterProfile.id)).group_by(VoterProfile.department).all()
        data = [{'department': d, 'count': c} for d, c in departments]
        return render_template('admin/reports.html', report_type='participation', data=data)

    elif report_type == 'turnout':
        elections = Election.query.all()
        data = []
        for e in elections:
            total_voters = VoterProfile.query.count()
            votes = e.get_vote_count()
            turnout = (votes / total_voters * 100) if total_voters > 0 else 0
            data.append({'election': e.title, 'votes': votes, 'turnout': turnout})
        return render_template('admin/reports.html', report_type='turnout', data=data)

    elif report_type == 'candidates':
        if election_id:
            election = Election.query.get(election_id)
            positions = election.positions.all()
            data = []
            for pos in positions:
                candidates = pos.candidates.filter_by(is_active=True).all()
                for cand in candidates:
                    votes = cand.get_vote_count()
                    data.append({
                        'position': pos.title,
                        'candidate': cand.full_name,
                        'votes': votes
                    })
            return render_template('admin/reports.html', report_type='candidates', data=data, election=election)
        else:
            flash('Please select an election for candidate report.', 'warning')
            return redirect(url_for('admin_elections'))

    else:
        flash('Invalid report type.', 'danger')
        return redirect(url_for('admin_dashboard'))

# ============================================================================
# ADMIN SETTINGS
# ============================================================================

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_settings():
    if request.method == 'POST':
        settings = {
            'system_name': request.form.get('system_name', ''),
            'system_tagline': request.form.get('system_tagline', ''),
            'maintenance_mode': request.form.get('maintenance_mode') == 'on',
            'voter_registration_open': request.form.get('voter_registration_open') == 'on'
        }

        for key, value in settings.items():
            SystemSetting.set_setting(key, str(value) if not isinstance(value, bool) else 'on' if value else 'off')

        flash('System settings updated successfully.', 'success')

        AuditService.log_action(
            user_id=current_user.id,
            action='SYSTEM_CONFIGURED',
            description="Updated system settings"
        )

        return redirect(url_for('admin_settings'))

    settings = {
        'system_name': SystemSetting.get_setting('system_name', app.config['APP_NAME']),
        'system_tagline': SystemSetting.get_setting('system_tagline', app.config['APP_TAGLINE']),
        'maintenance_mode': SystemSetting.get_setting('maintenance_mode', 'off') == 'on',
        'voter_registration_open': SystemSetting.get_setting('voter_registration_open', 'on') == 'on'
    }

    return render_template('admin/settings.html', settings=settings)

# ============================================================================
# API FOR REAL-TIME STATS
# ============================================================================

@app.route('/api/stats')
@login_required
@admin_required
def api_stats():
    now = datetime.utcnow()
    total_votes = Vote.query.count()
    total_voters = VoterProfile.query.count()
    active_elections = Election.query.filter(
        Election.start_date <= now,
        Election.end_date >= now,
        Election.status != 'closed'
    ).count()
    participation_rate = (total_votes / total_voters * 100) if total_voters > 0 else 0

    recent_votes = Vote.query.filter(Vote.created_at >= (now - timedelta(minutes=10))).count()

    return jsonify({
        'total_votes': total_votes,
        'total_voters': total_voters,
        'active_elections': active_elections,
        'participation_rate': round(participation_rate, 1),
        'recent_votes': recent_votes,
        'timestamp': now.isoformat()
    })
# ============================================================================
# PART16: COMPLETE CSS STYLES (inline, no external files)
# ============================================================================
STYLES_CSS = """
/* ============================================================
   SMART ENCRYPTED VOTING SYSTEM – Complete Styles
   ============================================================ */
* { margin:0; padding:0; box-sizing:border-box; }
html { scroll-behavior:smooth; }
body {
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    background:var(--page-bg);
    color:var(--text-primary);
    line-height:1.6;
    min-height:100vh;
    display:flex;
    flex-direction:column;
    transition:background 0.3s ease,color 0.3s ease;
}
a { color:var(--blue); text-decoration:none; }
a:hover { color:var(--navy); text-decoration:underline; }
img { max-width:100%; height:auto; }

:root {
    --navy:#0A2A4A; --navy-dark:#051B33;
    --blue:#1A5BBF; --blue-light:#3b82f6;
    --gold:#FAAF32; --gold-light:#FFD464;
    --teal:#00B894; --red:#E53E3E; --orange:#f59e0b;
    --page-bg:#F1F5F9; --card-bg:#FFFFFF;
    --secondary-bg:#F8FAFC; --border-color:#E2E8F0;
    --text-primary:#1E293B; --text-secondary:#334155; --text-muted:#64748B;
    --shadow-sm:0 1px 2px rgba(0,0,0,0.05);
    --shadow-md:0 4px 6px rgba(0,0,0,0.07);
    --shadow-lg:0 10px 25px rgba(0,0,0,0.1);
    --radius:12px; --radius-sm:8px;
    --transition:all 0.3s ease;
}
[data-theme="dark"] {
    --page-bg:#0F172A; --card-bg:#1E293B; --secondary-bg:#0F172A;
    --border-color:#334155; --text-primary:#F1F5F9;
    --text-secondary:#CBD5E1; --text-muted:#94A3B8;
}
[data-theme="dark"] .navbar { background:var(--navy-dark); }
[data-theme="dark"] .sidebar { background:var(--navy-dark); }
[data-theme="dark"] .card { border-color:rgba(255,255,255,0.06); }
[data-theme="dark"] .form-control { background:var(--secondary-bg); color:var(--text-primary); border-color:var(--border-color); }

.container { max-width:1200px; margin:0 auto; padding:0 20px; }
.container-fluid { width:100%; padding:0 24px; }

/* Utility */
.text-center{text-align:center}.text-muted{color:var(--text-muted)}.text-white{color:#fff}
.text-primary{color:var(--blue)}.text-success{color:var(--teal)}.text-danger{color:var(--red)}.text-warning{color:var(--orange)}
.mt-1{margin-top:10px}.mt-2{margin-top:20px}.mt-3{margin-top:30px}.mt-4{margin-top:40px}
.mb-1{margin-bottom:10px}.mb-2{margin-bottom:20px}.mb-3{margin-bottom:30px}.mb-4{margin-bottom:40px}
.me-1{margin-right:5px}.me-2{margin-right:10px}.me-3{margin-right:15px}.ms-2{margin-left:10px}
.p-3{padding:15px}.p-4{padding:25px}.py-4{padding:25px 0}.py-5{padding:35px 0}
.w-100{width:100%}.h-100{height:100%}.d-flex{display:flex}.d-none{display:none}
.justify-content-between{justify-content:space-between}.justify-content-center{justify-content:center}
.align-items-center{align-items:center}.flex-wrap{flex-wrap:wrap}.text-end{text-align:right}
.gap-3{gap:15px}.gap-4{gap:25px}.small{font-size:0.85rem}.fw-bold{font-weight:700}
.bg-light{background:var(--secondary-bg)!important}.bg-primary{background:var(--blue)!important;color:#fff}
.bg-success{background:var(--teal)!important;color:#fff}.bg-warning{background:var(--gold)!important;color:#000}
.bg-info{background:#17a2b8!important;color:#fff}.bg-secondary{background:#6c757d!important;color:#fff}
@media(max-width:768px){.d-md-block{display:none!important}}

/* Grid */
.row { display:flex; flex-wrap:wrap; margin:0 -12px; }
.row > * { padding:0 12px; }
.col-md-3{flex:0 0 25%;max-width:25%}.col-md-4{flex:0 0 33.333%;max-width:33.333%}
.col-md-6{flex:0 0 50%;max-width:50%}.col-md-8{flex:0 0 66.666%;max-width:66.666%}
.col-lg-4{flex:0 0 33.333%;max-width:33.333%}.col-lg-5{flex:0 0 41.666%;max-width:41.666%}
.col-lg-6{flex:0 0 50%;max-width:50%}.col-lg-7{flex:0 0 58.333%;max-width:58.333%}
.col-lg-8{flex:0 0 66.666%;max-width:66.666%}.col-xl-3{flex:0 0 25%;max-width:25%}
.g-4{margin:0 -12px}.g-4 > *{padding:0 12px;margin-bottom:24px}
@media(max-width:992px){.col-lg-4,.col-lg-5,.col-lg-6,.col-lg-7,.col-lg-8{flex:0 0 100%;max-width:100%}}
@media(max-width:768px){.row{flex-direction:column}.row > *{padding:0}.col-md-3,.col-md-4,.col-md-6,.col-md-8,.col-xl-3{flex:0 0 100%;max-width:100%}}

/* Navbar */
.navbar { background:linear-gradient(135deg,var(--navy),var(--navy-dark)); padding:12px 0; box-shadow:0 2px 12px rgba(0,0,0,0.15); position:sticky; top:0; z-index:1100; }
.navbar .container-fluid{display:flex;justify-content:space-between;align-items:center}
.navbar-left,.navbar-right{display:flex;align-items:center;gap:10px}
.navbar-brand{color:#fff!important;font-size:1.15rem;font-weight:700;display:flex;align-items:center;gap:10px}
.navbar-brand:hover{text-decoration:none;color:#fff}
.navbar-brand .logo-icon{background:var(--gold);color:var(--navy);width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:900;flex-shrink:0}
.navbar-user{color:rgba(255,255,255,0.9);font-size:0.9rem;display:flex;align-items:center;gap:6px}
.navbar-nav-desktop{display:flex;list-style:none;gap:4px;align-items:center;margin:0;padding:0}
.navbar-nav-desktop a{color:rgba(255,255,255,0.85);padding:8px 14px;border-radius:8px;font-size:0.9rem;display:inline-block;transition:all 0.2s}
.navbar-nav-desktop a:hover,.navbar-nav-desktop a.active{color:#fff;background:rgba(255,255,255,0.12);text-decoration:none}
.navbar-nav-desktop .btn-gold{background:var(--gold);color:var(--navy)!important;font-weight:600;padding:8px 20px;margin-left:6px}
.navbar-nav-desktop .btn-gold:hover{background:var(--gold-light)}
.theme-toggle,.nav-toggle{background:transparent;border:none;color:rgba(255,255,255,0.9);font-size:1.4rem;cursor:pointer;padding:6px 10px;border-radius:8px;display:flex;align-items:center;justify-content:center;transition:all 0.2s}
.theme-toggle:hover,.nav-toggle:hover{background:rgba(255,255,255,0.12);color:#fff}
.theme-toggle{font-size:1.15rem}
.nav-toggle{display:none}

/* Mobile Menu */
.mobile-menu-overlay,.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:1200;opacity:0;transition:opacity 0.3s}
.mobile-menu-overlay.active,.sidebar-overlay.active{display:block;opacity:1}
.mobile-menu{position:fixed;top:0;right:-340px;width:320px;max-width:86vw;height:100vh;background:var(--card-bg);z-index:1300;display:flex;flex-direction:column;transition:right 0.35s cubic-bezier(0.4,0,0.2,1);box-shadow:-4px 0 24px rgba(0,0,0,0.15);overflow-y:auto}
.mobile-menu.open{right:0}
.mobile-menu-header{display:flex;align-items:center;justify-content:space-between;padding:18px 20px;background:linear-gradient(135deg,var(--navy),var(--navy-dark));color:#fff}
.mobile-menu-brand{display:flex;align-items:center;gap:10px;font-weight:700}
.mobile-menu-brand .logo-icon{background:var(--gold);color:var(--navy);width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:900}
.mobile-menu-close{background:rgba(255,255,255,0.15);border:none;color:#fff;width:34px;height:34px;border-radius:50%;cursor:pointer}
.mobile-menu-list{list-style:none;padding:12px 0;margin:0;flex:1}
.mobile-menu-list a{display:flex;align-items:center;padding:14px 22px;color:var(--text-primary);font-weight:500;border-left:3px solid transparent;transition:all 0.2s}
.mobile-menu-list a i:first-child{font-size:1.15rem;width:26px;color:var(--blue);margin-right:12px;text-align:center}
.mobile-menu-list a .arrow{margin-left:auto;color:var(--text-muted);font-size:0.85rem}
.mobile-menu-list a:hover,.mobile-menu-list a.active{background:var(--secondary-bg);color:var(--blue);border-left-color:var(--blue);text-decoration:none}
.mobile-menu-footer{padding:18px 20px 24px;border-top:1px solid var(--border-color);background:var(--page-bg)}

/* App Layout + Sidebar */
.app-layout{display:flex;flex:1;min-height:calc(100vh - 130px)}
.sidebar{width:260px;background:linear-gradient(180deg,var(--navy) 0%,var(--navy-dark) 100%);color:#fff;padding:20px 0;flex-shrink:0;position:sticky;top:64px;height:calc(100vh - 64px);overflow-y:auto}
.sidebar-profile{display:flex;align-items:center;gap:12px;padding:0 20px 20px;border-bottom:1px solid rgba(255,255,255,0.08);margin-bottom:12px}
.sidebar-avatar{width:44px;height:44px;border-radius:50%;background:var(--gold);color:var(--navy);display:flex;align-items:center;justify-content:center;font-size:20px;overflow:hidden;flex-shrink:0}
.sidebar-avatar img{width:100%;height:100%;object-fit:cover}
.sidebar-user-info strong{display:block;font-size:0.9rem}
.sidebar-user-info small{color:rgba(255,255,255,0.6);font-size:0.75rem}
.sidebar-nav{list-style:none;padding:0;margin:0}
.sidebar-nav li a{display:flex;align-items:center;padding:12px 22px;color:rgba(255,255,255,0.8);font-size:0.92rem;border-left:3px solid transparent;transition:all 0.2s}
.sidebar-nav li a i{margin-right:12px;font-size:1.1rem;width:22px;text-align:center}
.sidebar-nav li a:hover,.sidebar-nav li a.active{background:rgba(255,255,255,0.1);color:#fff;border-left-color:var(--gold);text-decoration:none}
.logout-link{color:rgba(255,150,150,0.8)!important}
.sidebar-ad{padding:16px 20px;margin-top:auto;border-top:1px solid rgba(255,255,255,0.08)}
.sidebar-ad small{display:block;font-size:0.7rem;color:rgba(255,255,255,0.4);margin-bottom:8px;text-transform:uppercase;letter-spacing:1px}
.ad-box-sm{background:rgba(255,255,255,0.06);border:1px dashed rgba(255,255,255,0.2);border-radius:8px;padding:16px;text-align:center;font-size:0.8rem;color:rgba(255,255,255,0.6)}
.ad-box-sm i{font-size:1.5rem;display:block;margin-bottom:6px}

.main-content{flex:1;padding:24px 30px;background:var(--page-bg);min-width:0;display:flex;flex-direction:column;gap:20px}
.main-content.full-width{padding:0}
.flash-wrapper{margin:0}

/* Ads */
.ad-banner-top,.ad-banner-bottom{margin:0 auto 20px;max-width:970px;width:100%}
.ad-banner-bottom{margin-top:auto;margin-bottom:0}
.ad-banner-top small,.ad-banner-bottom small{display:block;text-align:center;font-size:0.7rem;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:1px}
.ad-content{background:linear-gradient(135deg,rgba(26,91,191,0.06),rgba(250,175,50,0.06));border:1px dashed var(--border-color);border-radius:12px;padding:24px;text-align:center;color:var(--text-muted);font-size:0.95rem;display:flex;align-items:center;justify-content:center;gap:12px}
.ad-content i{font-size:1.8rem;color:var(--blue)}

/* Cards */
.card{background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow-md);padding:24px;border:1px solid var(--border-color);transition:var(--transition);margin-bottom:20px}
.card:hover{box-shadow:var(--shadow-lg)}
.card-header{font-size:1.05rem;font-weight:700;margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid var(--border-color)}
.card-body{padding:5px 0}
.card-title{font-size:1.15rem;font-weight:700;margin-bottom:12px}

/* Buttons */
.btn{display:inline-block;padding:10px 22px;border:none;border-radius:var(--radius-sm);font-weight:600;font-size:0.95rem;cursor:pointer;transition:var(--transition);text-align:center;line-height:1.5}
.btn:hover{text-decoration:none;transform:translateY(-1px)}
.btn-primary{background:var(--blue);color:#fff}.btn-primary:hover{background:var(--navy);color:#fff}
.btn-gold{background:var(--gold);color:var(--navy)}.btn-gold:hover{background:var(--gold-light);color:var(--navy)}
.btn-outline{background:transparent;border:2px solid var(--blue);color:var(--blue)}.btn-outline:hover{background:var(--blue);color:#fff}
.btn-outline-secondary{background:transparent;border:2px solid var(--text-muted);color:var(--text-muted)}.btn-outline-secondary:hover{background:var(--text-muted);color:#fff}
.btn-danger{background:var(--red);color:#fff}.btn-danger:hover{background:#c0392b;color:#fff}
.btn-success{background:var(--teal);color:#fff}.btn-success:hover{background:#00a381;color:#fff}
.btn-secondary{background:#6c757d;color:#fff}.btn-secondary:hover{background:#5a6268;color:#fff}
.btn-info{background:#17a2b8;color:#fff}.btn-info:hover{background:#138496;color:#fff}
.btn-sm{padding:6px 14px;font-size:0.85rem}.btn-lg{padding:14px 36px;font-size:1.1rem}

/* Alerts */
.alert{padding:14px 20px;border-radius:var(--radius-sm);margin-bottom:16px;font-weight:500}
.alert-success{background:#D4EDDA;color:#155724;border:1px solid #C3E6CB}
.alert-danger{background:#F8D7DA;color:#721C24;border:1px solid #F5C6CB}
.alert-warning{background:#FFF3CD;color:#856404;border:1px solid #FFEEBA}
.alert-info{background:#D1ECF1;color:#0C5460;border:1px solid #BEE5EB}
[data-theme="dark"] .alert-success{background:#1A3A2A;color:#8BDFB0;border-color:#2A5A3A}
[data-theme="dark"] .alert-danger{background:#3A1A1A;color:#DF8B8B;border-color:#5A2A2A}
[data-theme="dark"] .alert-warning{background:#3A3A1A;color:#DFDF8B;border-color:#5A5A2A}
[data-theme="dark"] .alert-info{background:#1A2A3A;color:#8BB5DF;border-color:#2A4A5A}

/* Badges */
.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;text-transform:capitalize}
.badge-success,.badge-active{background:#28a745;color:#fff}
.badge-danger,.badge-closed{background:#dc3545;color:#fff}
.badge-warning,.badge-scheduled{background:#ffc107;color:#212529}
.badge-info,.badge-results_published{background:#17a2b8;color:#fff}
.badge-secondary,.badge-draft,.badge-archived{background:#6c757d;color:#fff}
.badge-primary{background:var(--blue);color:#fff}

/* Forms */
.form-group{margin-bottom:18px}
.form-label,.form-group label{display:block;font-weight:600;margin-bottom:6px;color:var(--text-secondary);font-size:0.9rem}
.form-control{width:100%;padding:12px 16px;border:2px solid var(--border-color);border-radius:var(--radius-sm);font-size:1rem;background:var(--card-bg);color:var(--text-primary);transition:var(--transition);font-family:inherit}
.form-control:focus{border-color:var(--blue);outline:none;box-shadow:0 0 0 3px rgba(26,91,191,0.15)}
.form-control-lg{padding:14px 18px;font-size:1.05rem}
.form-select{width:100%;padding:12px 16px;border:2px solid var(--border-color);border-radius:var(--radius-sm);background:var(--card-bg);color:var(--text-primary)}
.form-select-sm{padding:6px 10px;font-size:0.85rem}
.form-check{display:flex;align-items:center;margin-bottom:10px}
.form-check-input{margin-right:10px;width:16px;height:16px;cursor:pointer}
.form-check-label{font-weight:normal;cursor:pointer}
.form-error,.text-danger{color:var(--red);font-size:0.85rem;margin-top:4px}

/* Tables */
.table{width:100%;border-collapse:collapse;background:var(--card-bg);border-radius:var(--radius-sm);overflow:hidden}
.table th{background:var(--secondary-bg);color:var(--text-secondary);padding:14px 12px;text-align:left;font-weight:600;font-size:0.88rem}
.table td{padding:14px 12px;border-bottom:1px solid var(--border-color);font-size:0.93rem}
.table tbody tr:last-child td{border-bottom:none}
.table-striped tbody tr:nth-of-type(odd){background:var(--secondary-bg)}
.table-hover tbody tr:hover{background:var(--secondary-bg)}
.table-responsive{overflow-x:auto;width:100%}

/* Lists */
.list-group{list-style:none;padding:0;margin:0}
.list-group-item{padding:14px 18px;border-bottom:1px solid var(--border-color);background:var(--card-bg);color:var(--text-primary)}
.list-group-item:last-child{border-bottom:none}
.list-group-item.active{background:var(--blue);color:#fff}

/* Progress */
.progress{height:8px;border-radius:4px;background:var(--secondary-bg);overflow:hidden}
.progress-bar{height:100%;border-radius:4px;transition:width 0.6s ease}
.progress-bar.bg-success{background:var(--teal)}
.progress-bar.bg-primary{background:var(--blue)}

/* Hero */
.hero{padding:90px 20px 70px;background:linear-gradient(135deg,var(--navy) 0%,var(--navy-dark) 100%);color:#fff;text-align:center;border-bottom:4px solid var(--gold)}
.hero h1{font-size:3rem;font-weight:800;margin-bottom:18px;line-height:1.2}
.hero .highlight{color:var(--gold)}
.hero p{font-size:1.15rem;opacity:0.9;max-width:650px;margin:0 auto 30px}
.hero .btn-gold{background:var(--gold);color:var(--navy);padding:14px 44px;border-radius:var(--radius-sm);font-weight:700;font-size:1.05rem;display:inline-block;transition:var(--transition)}
.hero .btn-gold:hover{background:var(--gold-light);transform:translateY(-2px);color:var(--navy);text-decoration:none}

/* Sections */
.stats-section{padding:50px 0;background:var(--secondary-bg)}
.feature-section{padding:50px 0}
.elections-preview{padding:50px 0;background:var(--secondary-bg)}
.section-badge{display:inline-block;background:var(--gold);color:var(--navy);padding:5px 18px;border-radius:20px;font-weight:600;font-size:0.78rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px}
.section-title{font-size:2rem;font-weight:700;margin-bottom:10px}
.section-title .highlight{color:var(--blue)}
.section-subtitle{color:var(--text-muted);max-width:650px;margin:0 auto}

/* Stat Cards */
.stat-card{text-align:center;padding:25px 20px;border-radius:12px;background:var(--card-bg)}
.stat-card .number{font-size:2.5rem;font-weight:800;color:var(--navy);line-height:1.1}
.stat-card .label{color:var(--text-muted);font-size:0.9rem;margin-top:6px}
[data-theme="dark"] .stat-card .number{color:var(--gold)}

/* Gradient Stat Cards */
.stat-gradient{padding:22px;border-radius:14px;color:#fff;box-shadow:0 6px 15px rgba(0,0,0,0.1);display:flex;align-items:center;justify-content:space-between;transition:transform 0.2s}
.stat-gradient:hover{transform:translateY(-4px)}
.stat-gradient .stat-icon-lg{width:52px;height:52px;border-radius:12px;background:rgba(255,255,255,0.2);display:flex;align-items:center;justify-content:center;font-size:1.6rem}
.stat-gradient .stat-num{font-size:2rem;font-weight:800;line-height:1}
.stat-gradient .stat-lbl{font-size:0.85rem;opacity:0.9;margin-top:4px}
.grad-blue{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%)}
.grad-green{background:linear-gradient(135deg,#11998e 0%,#38ef7d 100%)}
.grad-orange{background:linear-gradient(135deg,#f093fb 0%,#f5576c 100%)}
.grad-cyan{background:linear-gradient(135deg,#4facfe 0%,#00f2fe 100%)}
.grad-purple{background:linear-gradient(135deg,#8e2de2 0%,#4a00e0 100%)}
.grad-gold{background:linear-gradient(135deg,#f6d365 0%,#fda085 100%)}

/* Footer */
.footer{background:linear-gradient(135deg,var(--navy),var(--navy-dark));color:#fff;padding:40px 0 20px;margin-top:auto}
.footer-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:30px;margin-bottom:24px}
.footer h6{font-size:0.95rem;font-weight:700;margin-bottom:12px;color:var(--gold)}
.footer .text-muted{color:rgba(255,255,255,0.6)!important;font-size:0.9rem}
.footer a{display:block;color:rgba(255,255,255,0.7);font-size:0.88rem;padding:4px 0;text-decoration:none}
.footer a:hover{color:var(--gold)}
.footer-bottom{border-top:1px solid rgba(255,255,255,0.1);padding-top:16px;text-align:center;font-size:0.85rem;color:rgba(255,255,255,0.5)}

/* Voting */
.candidate-photo{width:80px;height:80px;border-radius:50%;object-fit:cover;margin:10px auto;display:block}
.candidate-photo-sm{width:40px;height:40px;border-radius:50%;object-fit:cover;margin-right:10px}
.candidate-option{display:flex;align-items:center;padding:12px;border:1px solid var(--border-color);border-radius:var(--radius-sm);margin-bottom:8px;transition:var(--transition)}
.candidate-option:hover{border-color:var(--blue);background:var(--secondary-bg)}
.candidate-option input[type="radio"]{margin-right:12px}

/* Profile */
.profile-photo{width:120px;height:120px;border-radius:50%;object-fit:cover;border:3px solid var(--gold)}

/* Error pages */
.error-page .display-1{font-size:6rem;font-weight:300;line-height:1.2;color:var(--text-muted)}

/* Auth */
.auth-container{max-width:500px;margin:40px auto;padding:0 20px}

/* Responsive */
@media(max-width:768px){
    .nav-toggle{display:flex}
    .navbar-nav-desktop{display:none}
    .sidebar{position:fixed;top:0;left:-300px;height:100vh;width:270px;max-width:82vw;z-index:1300;padding-top:20px;transition:left 0.35s cubic-bezier(0.4,0,0.2,1);box-shadow:4px 0 20px rgba(0,0,0,0.2)}
    .sidebar.open{left:0}
    .main-content{padding:18px 15px}
    .app-layout{flex-direction:column}
    .navbar-brand .brand-text{font-size:0.9rem}
    .navbar-user{display:none!important}
    .hero{padding:60px 15px 45px}.hero h1{font-size:2rem}.hero p{font-size:1rem}
    .section-title{font-size:1.6rem}.stat-card .number{font-size:1.9rem}
    .card{padding:18px}.btn{padding:9px 16px;font-size:0.88rem}
    .table th,.table td{padding:10px 8px;font-size:0.85rem}
}
@media(max-width:480px){
    .mobile-menu{width:290px}.hero h1{font-size:1.6rem}.section-title{font-size:1.35rem}
    .card{padding:15px}.container-fluid{padding:0 12px}.main-content{padding:15px 12px}
}
"""
# ============================================================================
# PART17: TEMPLATE STRINGS
# ============================================================================

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en" data-theme="{{ session.get('theme', 'light') }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}{{ app_name }}{% endblock %}</title>
    <meta name="description" content="Secure, transparent and verified electronic voting platform">
    <link rel="icon" href="{{ url_for('static', filename='images/favicon.ico') }}">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>{{ css_styles }}</style>
    {% block extra_css %}{% endblock %}
</head>
<body>
    <!-- ================= TOP NAVBAR ================= -->
    <nav class="navbar">
        <div class="container-fluid">
            <div class="navbar-left">
                {% if current_user.is_authenticated %}
                    <button class="nav-toggle" onclick="toggleSidebar()" aria-label="Toggle sidebar">
                        <i class="bi bi-list"></i>
                    </button>
                {% endif %}
                <a href="{{ url_for('index') }}" class="navbar-brand">
                    <span class="logo-icon">🗳</span>
                    <span class="brand-text">{{ app_name }}</span>
                </a>
            </div>

            {% if not current_user.is_authenticated %}
                <ul class="navbar-nav-desktop">
                    <li><a href="{{ url_for('index') }}" class="{% if request.endpoint == 'index' %}active{% endif %}">Home</a></li>
                    <li><a href="{{ url_for('results_index') }}" class="{% if request.endpoint in ['results_index','results_view'] %}active{% endif %}">Results</a></li>
                    <li><a href="{{ url_for('how_it_works') }}" class="{% if request.endpoint == 'how_it_works' %}active{% endif %}">How It Works</a></li>
                    <li><a href="{{ url_for('features') }}" class="{% if request.endpoint == 'features' %}active{% endif %}">Features</a></li>
                    <li><a href="{{ url_for('about') }}" class="{% if request.endpoint == 'about' %}active{% endif %}">About Us</a></li>
                    <li><a href="{{ url_for('auth_login') }}">Voter Login</a></li>
                    <li><a href="{{ url_for('admin_login') }}">Admin Login</a></li>
                    <li><a href="{{ url_for('auth_register') }}" class="btn-gold">Register</a></li>
                </ul>
            {% endif %}

            <div class="navbar-right">
                {% if current_user.is_authenticated %}
                    <span class="navbar-user d-none d-md-block">
                        <i class="bi bi-person-circle"></i> {{ current_user.username }}
                    </span>
                {% endif %}
                <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
                    <i class="bi bi-moon-fill" id="themeIcon"></i>
                </button>
                {% if not current_user.is_authenticated %}
                    <button class="nav-toggle" onclick="toggleMobileMenu()" aria-label="Menu">
                        <i class="bi bi-list"></i>
                    </button>
                {% endif %}
            </div>
        </div>
    </nav>

    <!-- Mobile Menu (public) -->
    {% if not current_user.is_authenticated %}
        <div class="mobile-menu-overlay" id="mobileMenuOverlay" onclick="toggleMobileMenu()"></div>
        <aside class="mobile-menu" id="mobileMenu">
            <div class="mobile-menu-header">
                <div class="mobile-menu-brand">
                    <span class="logo-icon">🗳</span>
                    <span>{{ app_name }}</span>
                </div>
                <button class="mobile-menu-close" onclick="toggleMobileMenu()"><i class="bi bi-x-lg"></i></button>
            </div>
            <ul class="mobile-menu-list">
                <li><a href="{{ url_for('index') }}"><i class="bi bi-house-door"></i><span>Home</span><i class="bi bi-chevron-right arrow"></i></a></li>
                <li><a href="{{ url_for('results_index') }}"><i class="bi bi-graph-up-arrow"></i><span>Results</span><i class="bi bi-chevron-right arrow"></i></a></li>
                <li><a href="{{ url_for('how_it_works') }}"><i class="bi bi-question-circle"></i><span>How It Works</span><i class="bi bi-chevron-right arrow"></i></a></li>
                <li><a href="{{ url_for('features') }}"><i class="bi bi-stars"></i><span>Features</span><i class="bi bi-chevron-right arrow"></i></a></li>
                <li><a href="{{ url_for('about') }}"><i class="bi bi-info-circle"></i><span>About Us</span><i class="bi bi-chevron-right arrow"></i></a></li>
            </ul>
            <div class="mobile-menu-footer">
                <a href="{{ url_for('auth_login') }}" class="btn btn-primary w-100 mb-2"><i class="bi bi-box-arrow-in-right me-2"></i>Voter Login</a>
                <a href="{{ url_for('auth_register') }}" class="btn btn-outline w-100 mb-2"><i class="bi bi-person-plus me-2"></i>Register</a>
                <a href="{{ url_for('admin_login') }}" class="btn btn-outline-danger w-100"><i class="bi bi-shield-lock me-2"></i>Admin Login</a>
            </div>
        </aside>
    {% endif %}

    <!-- ================= MAIN LAYOUT ================= -->
    <div class="app-layout">
        {% if current_user.is_authenticated %}
            <aside class="sidebar" id="sidebar">
                <div class="sidebar-profile">
                    <div class="sidebar-avatar">
                        {% if current_user.voter_profile and current_user.voter_profile.photo %}
                            <img src="{{ url_for('static', filename='uploads/' ~ current_user.voter_profile.photo) }}" alt="Avatar">
                        {% else %}
                            <i class="bi bi-person-fill"></i>
                        {% endif %}
                    </div>
                    <div class="sidebar-user-info">
                        <strong>{{ current_user.username }}</strong>
                        <small>{{ current_user.role|capitalize }}</small>
                    </div>
                </div>
                <ul class="sidebar-nav">
                    {% if current_user.role == 'admin' %}
                        <li><a href="{{ url_for('admin_dashboard') }}" class="{% if request.endpoint == 'admin_dashboard' %}active{% endif %}"><i class="bi bi-speedometer2"></i> Dashboard</a></li>
                        <li><a href="{{ url_for('admin_elections') }}" class="{% if request.endpoint in ['admin_elections','admin_create_election','admin_edit_election'] %}active{% endif %}"><i class="bi bi-calendar-event"></i> Manage Elections</a></li>
                        <li><a href="{{ url_for('admin_voters') }}" class="{% if request.endpoint in ['admin_voters','admin_edit_voter'] %}active{% endif %}"><i class="bi bi-people"></i> Voters</a></li>
                        <li><a href="{{ url_for('admin_audit') }}" class="{% if request.endpoint == 'admin_audit' %}active{% endif %}"><i class="bi bi-clipboard-data"></i> Audit</a></li>
                        <li><a href="{{ url_for('admin_security') }}" class="{% if request.endpoint == 'admin_security' %}active{% endif %}"><i class="bi bi-shield-lock"></i> Security</a></li>
                        <li><a href="{{ url_for('admin_reports') }}" class="{% if request.endpoint == 'admin_reports' %}active{% endif %}"><i class="bi bi-file-earmark-bar-graph"></i> Reports</a></li>
                        <li><a href="{{ url_for('admin_settings') }}" class="{% if request.endpoint == 'admin_settings' %}active{% endif %}"><i class="bi bi-gear"></i> Settings</a></li>
                    {% else %}
                        <li><a href="{{ url_for('voter_dashboard') }}" class="{% if request.endpoint == 'voter_dashboard' %}active{% endif %}"><i class="bi bi-house"></i> Dashboard</a></li>
                        <li><a href="{{ url_for('voter_profile') }}" class="{% if request.endpoint == 'voter_profile' %}active{% endif %}"><i class="bi bi-person"></i> Profile</a></li>
                        <li><a href="{{ url_for('voter_notifications') }}" class="{% if request.endpoint == 'voter_notifications' %}active{% endif %}"><i class="bi bi-bell"></i> Notifications</a></li>
                        <li><a href="{{ url_for('voter_settings') }}" class="{% if request.endpoint == 'voter_settings' %}active{% endif %}"><i class="bi bi-gear"></i> Settings</a></li>
                    {% endif %}
                    <li><a href="{{ url_for('auth_logout') }}" class="logout-link"><i class="bi bi-box-arrow-right"></i> Logout</a></li>
                </ul>
                <!-- Sidebar Ad -->
                <div class="sidebar-ad">
                    <small>Advertisement</small>
                    <div class="ad-box-sm">
                        <i class="bi bi-megaphone"></i>
                        <span>Your Ad Here</span>
                    </div>
                </div>
            </aside>
            <div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>
        {% endif %}

        <main class="main-content {% if not current_user.is_authenticated %}full-width{% endif %}">
            <!-- Top Banner Ad (public only) -->
            {% if not current_user.is_authenticated and request.endpoint not in ['auth_login', 'auth_register'] %}
                <div class="ad-banner-top">
                    <small>Advertisement</small>
                    <div class="ad-content">
                        <i class="bi bi-megaphone-fill"></i>
                        <span>Google AdSense Banner Space — 728x90</span>
                    </div>
                </div>
            {% endif %}

            <div class="container-fluid flash-wrapper">
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
            </div>

            {% block content %}{% endblock %}

            <!-- Bottom Ad -->
            <div class="ad-banner-bottom">
                <small>Advertisement</small>
                <div class="ad-content">
                    <i class="bi bi-megaphone-fill"></i>
                    <span>Google AdSense Banner Space — 728x90</span>
                </div>
            </div>
        </main>
    </div>

    <footer class="footer">
        <div class="container">
            <div class="footer-grid">
                <div>
                    <h6>{{ app_name }}</h6>
                    <p class="text-muted">{{ app_tagline }}</p>
                </div>
                <div>
                    <h6>Quick Links</h6>
                    <a href="{{ url_for('index') }}">Home</a>
                    <a href="{{ url_for('results_index') }}">Results</a>
                    <a href="{{ url_for('how_it_works') }}">How It Works</a>
                </div>
                <div>
                    <h6>Company</h6>
                    <a href="{{ url_for('about') }}">About Us</a>
                    <a href="{{ url_for('features') }}">Features</a>
                    <a href="{{ url_for('visual_cryptography') }}">Visual Crypto</a>
                </div>
            </div>
            <div class="footer-bottom">
                <p>© {{ app_name }}. All Rights Reserved.</p>
            </div>
        </div>
    </footer>

    <script>
        function toggleTheme() {
            const html = document.documentElement;
            const newTheme = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeIcon(newTheme);
        }
        function updateThemeIcon(theme) {
            const icon = document.getElementById('themeIcon');
            if (icon) icon.className = theme === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
        }
        (function() {
            const saved = localStorage.getItem('theme');
            if (saved) {
                document.documentElement.setAttribute('data-theme', saved);
                updateThemeIcon(saved);
            }
        })();

        function toggleSidebar() {
            const sb = document.getElementById('sidebar');
            const ov = document.getElementById('sidebarOverlay');
            if (!sb) return;
            const open = sb.classList.toggle('open');
            if (ov) ov.classList.toggle('active', open);
            document.body.style.overflow = open ? 'hidden' : '';
        }
        function toggleMobileMenu() {
            const m = document.getElementById('mobileMenu');
            const ov = document.getElementById('mobileMenuOverlay');
            if (!m) return;
            const open = m.classList.toggle('open');
            if (ov) ov.classList.toggle('active', open);
            document.body.style.overflow = open ? 'hidden' : '';
        }
        window.addEventListener('resize', function() {
            if (window.innerWidth >= 768) {
                ['sidebar','mobileMenu'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) el.classList.remove('open');
                });
                ['sidebarOverlay','mobileMenuOverlay'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) el.classList.remove('active');
                });
                document.body.style.overflow = '';
            }
        });
    </script>
    {% block extra_js %}{% endblock %}
</body>
</html>
'''
# ============================================================================
# PART: AUTH TEMPLATES (Login, Register, Forgot Password, Reset Password)
# ============================================================================

LOGIN_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Login - {{ app_name }}{% endblock %}
{% block content %}
<div class="auth-page">
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <div class="auth-logo">
                    <i class="bi bi-shield-lock"></i>
                </div>
                <h1>Voter Login</h1>
                <p class="auth-subtitle">Sign in to cast your encrypted vote securely</p>
            </div>
            
            <form method="POST" action="{{ url_for('auth_login') }}" class="auth-form">
                {{ form.hidden_tag() }}
                
                <div class="form-group">
                    {{ form.username.label(class="form-label") }}
                    <div class="input-group">
                        <span class="input-group-icon"><i class="bi bi-person"></i></span>
                        {{ form.username(class="form-control", placeholder="Enter your username", autofocus=true) }}
                    </div>
                    {% if form.username.errors %}
                        <div class="form-error">{{ form.username.errors[0] }}</div>
                    {% endif %}
                </div>
                
                <div class="form-group">
                    {{ form.password.label(class="form-label") }}
                    <div class="input-group">
                        <span class="input-group-icon"><i class="bi bi-lock"></i></span>
                        {{ form.password(class="form-control", id="password", placeholder="Enter your password") }}
                        <button type="button" class="toggle-password-btn" onclick="togglePassword('password')">
                            <i class="bi bi-eye" id="passwordIcon"></i>
                        </button>
                    </div>
                    {% if form.password.errors %}
                        <div class="form-error">{{ form.password.errors[0] }}</div>
                    {% endif %}
                </div>
                
                <div class="form-options">
                    <label class="checkbox-label">
                        {{ form.remember_me(class="checkbox-input") }}
                        <span class="checkbox-text">Remember Me</span>
                    </label>
                    <a href="{{ url_for('auth_forgot_password') }}" class="forgot-link">Forgot Password?</a>
                </div>
                
                <button type="submit" class="btn-auth">
                    <i class="bi bi-box-arrow-in-right"></i>
                    Sign In
                </button>
            </form>
            
            <div class="auth-footer">
                <p>Don't have an account? <a href="{{ url_for('auth_register') }}">Create Account</a></p>
                <p class="mt-2"><a href="{{ url_for('admin_login') }}"><i class="bi bi-shield-lock me-1"></i>Administrator Login</a></p>
            </div>
        </div>
    </div>
</div>

<style>
.auth-page {
    min-height: calc(100vh - 200px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 40px 20px;
    background: var(--page-bg);
}
.auth-container {
    width: 100%;
    max-width: 480px;
}
.auth-card {
    background: var(--card-bg);
    border-radius: 20px;
    padding: 48px 40px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.08);
    border: 1px solid rgba(0,0,0,0.04);
}
.auth-header {
    text-align: center;
    margin-bottom: 36px;
}
.auth-logo {
    width: 72px;
    height: 72px;
    background: linear-gradient(135deg, var(--blue), var(--navy));
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 16px;
}
.auth-logo i {
    font-size: 32px;
    color: #fff;
}
.auth-header h1 {
    font-size: 28px;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0 0 8px;
}
.auth-subtitle {
    color: var(--text-muted);
    font-size: 15px;
    margin: 0;
}
.auth-form .form-group {
    margin-bottom: 20px;
}
.form-label {
    display: block;
    font-weight: 600;
    font-size: 14px;
    color: var(--text-secondary);
    margin-bottom: 6px;
}
.input-group {
    display: flex;
    align-items: center;
    background: var(--page-bg);
    border: 2px solid var(--secondary-bg);
    border-radius: 10px;
    transition: border-color 0.2s;
}
.input-group:focus-within {
    border-color: var(--blue);
    box-shadow: 0 0 0 4px rgba(26, 91, 191, 0.1);
}
.input-group-icon {
    padding: 0 14px;
    color: var(--text-muted);
    font-size: 18px;
}
.input-group .form-control {
    border: none;
    background: transparent;
    padding: 14px 14px 14px 0;
    font-size: 15px;
    color: var(--text-primary);
    flex: 1;
}
.input-group .form-control:focus {
    outline: none;
    box-shadow: none;
}
.toggle-password-btn {
    background: none;
    border: none;
    padding: 0 14px;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 18px;
}
.toggle-password-btn:hover {
    color: var(--text-primary);
}
.form-error {
    color: var(--red);
    font-size: 13px;
    margin-top: 4px;
}
.form-options {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
}
.checkbox-label {
    display: flex;
    align-items: center;
    cursor: pointer;
    font-size: 14px;
    color: var(--text-secondary);
}
.checkbox-input {
    width: 18px;
    height: 18px;
    margin-right: 8px;
    accent-color: var(--blue);
    cursor: pointer;
}
.checkbox-text {
    user-select: none;
}
.forgot-link {
    font-size: 14px;
    color: var(--blue);
    text-decoration: none;
}
.forgot-link:hover {
    text-decoration: underline;
}
.btn-auth {
    width: 100%;
    padding: 16px;
    background: linear-gradient(135deg, var(--blue), var(--navy));
    color: #fff;
    border: none;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
}
.btn-auth:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(26, 91, 191, 0.3);
}
.auth-footer {
    text-align: center;
    margin-top: 28px;
    padding-top: 20px;
    border-top: 1px solid var(--secondary-bg);
    font-size: 15px;
    color: var(--text-muted);
}
.auth-footer a {
    color: var(--blue);
    font-weight: 600;
    text-decoration: none;
}
.auth-footer a:hover {
    text-decoration: underline;
}

/* Dark mode */
[data-theme="dark"] .auth-card {
    border-color: rgba(255,255,255,0.05);
}
[data-theme="dark"] .input-group {
    background: var(--card-bg);
    border-color: var(--secondary-bg);
}
[data-theme="dark"] .btn-auth {
    background: linear-gradient(135deg, var(--blue), var(--navy-dark));
}
</style>

<script>
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    const icon = document.getElementById(fieldId + 'Icon');
    if (field.type === 'password') {
        field.type = 'text';
        icon.className = 'bi bi-eye-slash';
    } else {
        field.type = 'password';
        icon.className = 'bi bi-eye';
    }
}
</script>
{% endblock %}
'''

REGISTER_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Create Account - {{ app_name }}{% endblock %}
{% block content %}
<div class="auth-page">
    <div class="auth-container register-container">
        <div class="auth-card">
            <div class="auth-header">
                <div class="auth-logo">
                    <i class="bi bi-person-plus"></i>
                </div>
                <h1>Create Account</h1>
                <p class="auth-subtitle">Join the secure voting platform</p>
            </div>

            <form method="POST" action="{{ url_for('auth_register') }}" class="auth-form" enctype="multipart/form-data">
                {{ form.hidden_tag() }}

                <!-- Profile Photo Upload -->
                <div class="photo-upload-section">
                    <div class="photo-preview-wrap">
                        <div class="photo-preview" id="photoPreviewBox">
                            <i class="bi bi-person" id="photoPlaceholderIcon"></i>
                            <img id="previewImg" src="" alt="Preview" style="display:none;">
                        </div>
                        <label for="photoInput" class="photo-upload-btn" title="Upload photo">
                            <i class="bi bi-camera"></i>
                        </label>
                    </div>
                    <div class="photo-upload-info">
                        <h6>Profile Photo</h6>
                        <p>Upload a clear photo of yourself (PNG, JPG, JPEG — max 16MB)</p>
                        <div style="display:none;">
                            {{ form.photo(id="photoInput", accept="image/*") }}
                        </div>
                        {% if form.photo.errors %}
                            <div class="form-error">{{ form.photo.errors[0] }}</div>
                        {% endif %}
                    </div>
                </div>

                <hr class="form-divider">

                <!-- Account Information -->
                <h6 class="form-section-title"><i class="bi bi-shield-lock me-2"></i>Account Information</h6>

                <div class="form-row">
                    <div class="form-group half">
                        {{ form.username.label(class="form-label") }}
                        <div class="input-group">
                            <span class="input-group-icon"><i class="bi bi-person"></i></span>
                            {{ form.username(class="form-control", placeholder="Username") }}
                        </div>
                        {% if form.username.errors %}
                            <div class="form-error">{{ form.username.errors[0] }}</div>
                        {% endif %}
                    </div>

                    <div class="form-group half">
                        {{ form.email.label(class="form-label") }}
                        <div class="input-group">
                            <span class="input-group-icon"><i class="bi bi-envelope"></i></span>
                            {{ form.email(class="form-control", placeholder="Email address") }}
                        </div>
                        {% if form.email.errors %}
                            <div class="form-error">{{ form.email.errors[0] }}</div>
                        {% endif %}
                    </div>
                </div>

                <!-- Personal Information -->
                <h6 class="form-section-title"><i class="bi bi-person-badge me-2"></i>Personal Information</h6>

                <div class="form-group">
                    {{ form.full_name.label(class="form-label") }}
                    <div class="input-group">
                        <span class="input-group-icon"><i class="bi bi-person-badge"></i></span>
                        {{ form.full_name(class="form-control", placeholder="Enter your full name") }}
                    </div>
                    {% if form.full_name.errors %}
                        <div class="form-error">{{ form.full_name.errors[0] }}</div>
                    {% endif %}
                </div>

                <div class="form-row">
                    <div class="form-group half">
                        {{ form.registration_number.label(class="form-label") }}
                        <div class="input-group">
                            <span class="input-group-icon"><i class="bi bi-card-text"></i></span>
                            {{ form.registration_number(class="form-control", placeholder="Registration number") }}
                        </div>
                        {% if form.registration_number.errors %}
                            <div class="form-error">{{ form.registration_number.errors[0] }}</div>
                        {% endif %}
                    </div>

                    <div class="form-group half">
                        {{ form.phone.label(class="form-label") }}
                        <div class="input-group">
                            <span class="input-group-icon"><i class="bi bi-telephone"></i></span>
                            {{ form.phone(class="form-control", placeholder="Phone number") }}
                        </div>
                        {% if form.phone.errors %}
                            <div class="form-error">{{ form.phone.errors[0] }}</div>
                        {% endif %}
                    </div>
                </div>

                <!-- Academic Information -->
                <h6 class="form-section-title"><i class="bi bi-mortarboard me-2"></i>Academic Information</h6>

                <div class="form-row">
                    <div class="form-group half">
                        {{ form.department.label(class="form-label") }}
                        <div class="input-group">
                            <span class="input-group-icon"><i class="bi bi-building"></i></span>
                            {{ form.department(class="form-control", placeholder="Department") }}
                        </div>
                        {% if form.department.errors %}
                            <div class="form-error">{{ form.department.errors[0] }}</div>
                        {% endif %}
                    </div>

                    <div class="form-group half">
                        {{ form.faculty.label(class="form-label") }}
                        <div class="input-group">
                            <span class="input-group-icon"><i class="bi bi-bank"></i></span>
                            {{ form.faculty(class="form-control", placeholder="Faculty") }}
                        </div>
                        {% if form.faculty.errors %}
                            <div class="form-error">{{ form.faculty.errors[0] }}</div>
                        {% endif %}
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group half">
                        {{ form.level.label(class="form-label") }}
                        <div class="input-group">
                            <span class="input-group-icon"><i class="bi bi-bar-chart"></i></span>
                            {{ form.level(class="form-control") }}
                        </div>
                        {% if form.level.errors %}
                            <div class="form-error">{{ form.level.errors[0] }}</div>
                        {% endif %}
                    </div>
                    <div class="form-group half"></div>
                </div>

                <!-- Security -->
                <h6 class="form-section-title"><i class="bi bi-lock me-2"></i>Security</h6>

                <div class="form-row">
                    <div class="form-group half">
                        {{ form.password.label(class="form-label") }}
                        <div class="input-group">
                            <span class="input-group-icon"><i class="bi bi-lock"></i></span>
                            {{ form.password(class="form-control", id="password", placeholder="Password") }}
                            <button type="button" class="toggle-password-btn" onclick="togglePassword('password')">
                                <i class="bi bi-eye" id="passwordIcon"></i>
                            </button>
                        </div>
                        {% if form.password.errors %}
                            <div class="form-error">{{ form.password.errors[0] }}</div>
                        {% endif %}
                        <small class="password-hint">Min 6 chars with uppercase, lowercase, number & special character</small>
                    </div>

                    <div class="form-group half">
                        {{ form.confirm_password.label(class="form-label") }}
                        <div class="input-group">
                            <span class="input-group-icon"><i class="bi bi-lock-fill"></i></span>
                            {{ form.confirm_password(class="form-control", id="confirm_password", placeholder="Confirm password") }}
                            <button type="button" class="toggle-password-btn" onclick="togglePassword('confirm_password')">
                                <i class="bi bi-eye" id="confirm_passwordIcon"></i>
                            </button>
                        </div>
                        {% if form.confirm_password.errors %}
                            <div class="form-error">{{ form.confirm_password.errors[0] }}</div>
                        {% endif %}
                    </div>
                </div>

                <button type="submit" class="btn-auth">
                    <i class="bi bi-person-plus"></i>
                    Create Account
                </button>
            </form>

            <div class="auth-footer">
                <p>Already have an account? <a href="{{ url_for('auth_login') }}">Sign In</a></p>
            </div>
        </div>
    </div>
</div>

<style>
.auth-page {
    min-height: calc(100vh - 200px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 40px 20px;
    background: var(--page-bg);
}
.auth-container {
    width: 100%;
    max-width: 620px;
}
.auth-card {
    background: var(--card-bg);
    border-radius: 20px;
    padding: 40px 36px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.08);
    border: 1px solid var(--border-color);
}
.auth-header {
    text-align: center;
    margin-bottom: 30px;
}
.auth-logo {
    width: 72px;
    height: 72px;
    background: linear-gradient(135deg, var(--blue), var(--navy));
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 16px;
}
.auth-logo i { font-size: 32px; color: #fff; }
.auth-header h1 {
    font-size: 26px;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0 0 6px;
}
.auth-subtitle { color: var(--text-muted); font-size: 14px; margin: 0; }

/* Photo Upload */
.photo-upload-section {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 18px;
    background: var(--secondary-bg);
    border-radius: 12px;
    margin-bottom: 20px;
}
.photo-preview-wrap {
    position: relative;
    flex-shrink: 0;
}
.photo-preview {
    width: 90px;
    height: 90px;
    border-radius: 50%;
    background: var(--card-bg);
    border: 3px dashed var(--border-color);
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    transition: border-color 0.2s;
}
.photo-preview:hover { border-color: var(--blue); }
.photo-preview i { font-size: 32px; color: var(--text-muted); }
.photo-preview img { width: 100%; height: 100%; object-fit: cover; }
.photo-upload-btn {
    position: absolute;
    bottom: 0;
    right: 0;
    width: 30px;
    height: 30px;
    background: var(--blue);
    color: #fff;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    font-size: 14px;
    border: 2px solid var(--card-bg);
    transition: all 0.2s;
}
.photo-upload-btn:hover { background: var(--navy); transform: scale(1.1); }
.photo-upload-info h6 { margin: 0 0 4px; font-size: 15px; font-weight: 600; }
.photo-upload-info p { margin: 0; font-size: 13px; color: var(--text-muted); }

.form-divider {
    border: none;
    border-top: 1px solid var(--border-color);
    margin: 24px 0;
}

.form-section-title {
    font-size: 14px;
    font-weight: 700;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin: 20px 0 14px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border-color);
}

.auth-form .form-group { margin-bottom: 16px; }
.form-row { display: flex; gap: 16px; }
.form-group.half { flex: 1; }
.form-label {
    display: block;
    font-weight: 600;
    font-size: 13.5px;
    color: var(--text-secondary);
    margin-bottom: 6px;
}
.input-group {
    display: flex;
    align-items: center;
    background: var(--page-bg);
    border: 2px solid var(--border-color);
    border-radius: 10px;
    transition: border-color 0.2s;
}
.input-group:focus-within {
    border-color: var(--blue);
    box-shadow: 0 0 0 4px rgba(26, 91, 191, 0.1);
}
.input-group-icon {
    padding: 0 12px;
    color: var(--text-muted);
    font-size: 16px;
}
.input-group .form-control {
    border: none;
    background: transparent;
    padding: 12px 12px 12px 0;
    font-size: 14.5px;
    color: var(--text-primary);
    flex: 1;
}
.input-group .form-control:focus { outline: none; box-shadow: none; }
.toggle-password-btn {
    background: none;
    border: none;
    padding: 0 12px;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 16px;
}
.toggle-password-btn:hover { color: var(--text-primary); }
.form-error { color: var(--red); font-size: 12.5px; margin-top: 4px; }
.password-hint { display: block; color: var(--text-muted); font-size: 11.5px; margin-top: 4px; line-height: 1.4; }

.btn-auth {
    width: 100%;
    padding: 15px;
    background: linear-gradient(135deg, var(--blue), var(--navy));
    color: #fff;
    border: none;
    border-radius: 10px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    margin-top: 10px;
}
.btn-auth:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(26, 91, 191, 0.3);
}
.auth-footer {
    text-align: center;
    margin-top: 24px;
    padding-top: 20px;
    border-top: 1px solid var(--border-color);
    font-size: 14.5px;
    color: var(--text-muted);
}
.auth-footer a { color: var(--blue); font-weight: 600; text-decoration: none; }
.auth-footer a:hover { text-decoration: underline; }

@media (max-width: 640px) {
    .auth-card { padding: 28px 20px; }
    .form-row { flex-direction: column; gap: 0; }
    .photo-upload-section { flex-direction: column; text-align: center; }
    .auth-header h1 { font-size: 22px; }
}

[data-theme="dark"] .auth-card { border-color: rgba(255,255,255,0.05); }
[data-theme="dark"] .input-group { background: var(--card-bg); border-color: var(--secondary-bg); }
[data-theme="dark"] .photo-preview { background: var(--card-bg); }
</style>

<script>
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    const icon = document.getElementById(fieldId + 'Icon');
    if (field.type === 'password') {
        field.type = 'text';
        icon.className = 'bi bi-eye-slash';
    } else {
        field.type = 'password';
        icon.className = 'bi bi-eye';
    }
}

// Photo preview
document.addEventListener('DOMContentLoaded', function() {
    const photoInput = document.getElementById('photoInput');
    const previewImg = document.getElementById('previewImg');
    const placeholderIcon = document.getElementById('photoPlaceholderIcon');

    if (photoInput) {
        photoInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(ev) {
                    previewImg.src = ev.target.result;
                    previewImg.style.display = 'block';
                    placeholderIcon.style.display = 'none';
                };
                reader.readAsDataURL(file);
            } else {
                previewImg.style.display = 'none';
                placeholderIcon.style.display = 'block';
            }
        });
    }
});
</script>
{% endblock %}
'''

FORGOT_PASSWORD_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Forgot Password{% endblock %}
{% block content %}
<div class="container auth-container">
    <div class="card">
        <div class="card-body">
            <h2>Forgot Password</h2>
            <p>Enter your email address and we'll send you a link to reset your password.</p>
            <form method="POST">
                {{ form.hidden_tag() }}
                <div class="form-group">
                    {{ form.email.label }}
                    {{ form.email(class="form-control") }}
                    {% if form.email.errors %}
                        <div class="text-danger">{{ form.email.errors[0] }}</div>
                    {% endif %}
                </div>
                <button type="submit" class="btn btn-primary w-100">Send Reset Link</button>
            </form>
            <p class="text-center mt-3"><a href="{{ url_for('auth_login') }}">Back to Login</a></p>
        </div>
    </div>
</div>
{% endblock %}
'''

RESET_PASSWORD_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Reset Password{% endblock %}
{% block content %}
<div class="container auth-container">
    <div class="card">
        <div class="card-body">
            <h2>Reset Password</h2>
            <form method="POST">
                {{ form.hidden_tag() }}
                <div class="form-group">
                    {{ form.password.label }}
                    {{ form.password(class="form-control") }}
                    {% if form.password.errors %}
                        <div class="text-danger">{{ form.password.errors[0] }}</div>
                    {% endif %}
                </div>
                <div class="form-group">
                    {{ form.confirm_password.label }}
                    {{ form.confirm_password(class="form-control") }}
                    {% if form.confirm_password.errors %}
                        <div class="text-danger">{{ form.confirm_password.errors[0] }}</div>
                    {% endif %}
                </div>
                <button type="submit" class="btn btn-primary w-100">Reset Password</button>
            </form>
        </div>
    </div>
</div>
{% endblock %}
'''
# ============================================================================
# PART18: INDEX 
# ============================================================================

INDEX_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Home{% endblock %}
{% block content %}
<section class="hero">
    <div class="container">
        <span class="section-badge">Secure Online Voting</span>
        <h1>Secure. <span class="highlight">Transparent.</span> Verified.</h1>
        <p>A modern encrypted electronic voting platform built for trust, privacy, and accessibility.</p>
        <a href="{{ url_for('auth_register') }}" class="btn-gold">
            <i class="bi bi-person-plus me-2"></i>Get Started
        </a>
    </div>
</section>

<section class="stats-section">
    <div class="container">
        <div class="row">
            <div class="col-md-3"><div class="card stat-card"><div class="number">{{ total_elections }}</div><div class="label">Total Elections</div></div></div>
            <div class="col-md-3"><div class="card stat-card"><div class="number">{{ active_elections }}</div><div class="label">Active Elections</div></div></div>
            <div class="col-md-3"><div class="card stat-card"><div class="number">{{ completed_elections }}</div><div class="label">Completed</div></div></div>
            <div class="col-md-3"><div class="card stat-card"><div class="number">🔒</div><div class="label">Encrypted Votes</div></div></div>
        </div>
    </div>
</section>

<section class="feature-section">
    <div class="container">
        <div class="text-center mb-4">
            <span class="section-badge">How It Works</span>
            <h2 class="section-title">Three Simple <span class="highlight">Steps</span></h2>
        </div>
        <div class="row">
            <div class="col-md-4">
                <div class="card text-center">
                    <i class="bi bi-person-plus-fill" style="font-size:2.5rem;color:var(--blue);"></i>
                    <h4 class="mt-2">Register</h4>
                    <p class="text-muted">Create your voter account securely with your credentials.</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center">
                    <i class="bi bi-shield-lock-fill" style="font-size:2.5rem;color:var(--gold);"></i>
                    <h4 class="mt-2">Vote</h4>
                    <p class="text-muted">Cast your encrypted vote with confidence and privacy.</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center">
                    <i class="bi bi-bar-chart-fill" style="font-size:2.5rem;color:var(--teal);"></i>
                    <h4 class="mt-2">Results</h4>
                    <p class="text-muted">View transparent, verifiable election results.</p>
                </div>
            </div>
        </div>
    </div>
</section>

<section class="elections-preview">
    <div class="container">
        <div class="text-center mb-4">
            <span class="section-badge">Recent</span>
            <h2 class="section-title">Recent <span class="highlight">Elections</span></h2>
        </div>
        <div class="row">
            {% for election in recent_elections %}
                <div class="col-md-4">
                    <div class="card">
                        <h5>{{ election.title }}</h5>
                        <span class="badge badge-{{ election.get_status() }}">{{ election.get_status()|capitalize }}</span>
                        <p class="text-muted small mt-2">{{ utc_to_ng(election.start_date).strftime('%b %d, %Y') }} — {{ utc_to_ng(election.end_date).strftime('%b %d, %Y') }}</p>
                        <a href="{{ url_for('results_view', election_id=election.id) }}" class="btn btn-sm btn-outline">View</a>
                    </div>
                </div>
            {% else %}
                <p class="text-center text-muted">No recent elections.</p>
            {% endfor %}
        </div>
    </div>
</section>

<!-- Middle Ad -->
<div class="container" style="margin:30px auto;">
    <div class="ad-content">
        <i class="bi bi-megaphone-fill"></i>
        <span>Google AdSense In-Feed Ad Space</span>
    </div>
</div>

<section class="py-5" style="background:var(--secondary-bg);">
    <div class="container">
        <div class="text-center mb-4">
            <span class="section-badge">Live Progress</span>
            <h2 class="section-title">Real-Time <span class="highlight">Voting</span> Progress</h2>
        </div>
        <div class="row text-center">
            <div class="col-4"><div class="card stat-card"><div class="number">{{ total_voter_profiles|default(0) }}</div><div class="label">Registered Voters</div></div></div>
            <div class="col-4"><div class="card stat-card"><div class="number">{{ total_votes|default(0) }}</div><div class="label">Votes Cast</div></div></div>
            <div class="col-4"><div class="card stat-card"><div class="number">{{ participation_rate|default(0)|round(1) }}%</div><div class="label">Turnout</div></div></div>
        </div>
    </div>
</section>
{% endblock %}
'''

ABOUT_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}About {{ app_name }}{% endblock %}
{% block content %}
<div class="container py-4">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <div class="card">
                <div class="card-body p-4">
                    <h1 class="mb-4">About {{ app_name }}</h1>
                    
                    <div class="mb-4">
                        <h4><i class="bi bi-bullseye text-primary me-2"></i>Our Mission</h4>
                        <p>{{ app_name }} is a secure, transparent, and verified electronic voting platform built to modernize electoral processes. Our system uses advanced encryption to protect vote integrity and voter privacy.</p>
                    </div>
                    
                    <div class="mb-4">
                        <h4><i class="bi bi-eye text-primary me-2"></i>Our Vision</h4>
                        <p>To provide a trustworthy, accessible, and efficient voting platform that upholds democratic values and ensures every vote counts.</p>
                    </div>
                    
                    <div class="mb-4">
                        <h4><i class="bi bi-stars text-primary me-2"></i>Key Features</h4>
                        <div class="row mt-3">
                            <div class="col-md-6">
                                <ul class="list-unstyled">
                                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>🔐 Secure Authentication</li>
                                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>🔒 Encrypted Votes (AES-GCM)</li>
                                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>✅ One Voter – One Vote</li>
                                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>📋 Complete Audit Logging</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <ul class="list-unstyled">
                                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>📊 Protected Results</li>
                                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>👤 Role-Based Access Control</li>
                                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>🌓 Dark/Light Mode</li>
                                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>📱 Mobile Responsive</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <h4><i class="bi bi-shield-check text-primary me-2"></i>Security</h4>
                        <p>All votes are encrypted using AES-GCM with 256-bit keys. Each vote is hashed and verified for integrity. The system maintains a complete audit trail of all activities.</p>
                    </div>
                    
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle me-2"></i>
                        <strong>Version:</strong> 2.0 | Developed as a capstone project demonstrating secure online voting.
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'''

HOW_IT_WORKS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}How It Works - {{ app_name }}{% endblock %}
{% block content %}
<div class="container py-4">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <h1 class="text-center mb-4">How It Works</h1>
            <p class="text-center text-muted mb-4">A simple, secure, and transparent voting process in 5 steps</p>
            
            <div class="card">
                <div class="card-body p-4">
                    <div class="step mb-4">
                        <div class="d-flex align-items-start">
                            <div class="step-number me-3">1</div>
                            <div>
                                <h5>Create Account</h5>
                                <p class="text-muted">Register with your valid credentials. Your identity is verified through the system before you can participate.</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="step mb-4">
                        <div class="d-flex align-items-start">
                            <div class="step-number me-3">2</div>
                            <div>
                                <h5>Explore Elections</h5>
                                <p class="text-muted">Browse upcoming, active, and completed elections. View candidate information and election details.</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="step mb-4">
                        <div class="d-flex align-items-start">
                            <div class="step-number me-3">3</div>
                            <div>
                                <h5>Cast Your Vote</h5>
                                <p class="text-muted">Select your preferred candidates for each position. Your vote is encrypted and securely recorded.</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="step mb-4">
                        <div class="d-flex align-items-start">
                            <div class="step-number me-3">4</div>
                            <div>
                                <h5>Review & Confirm</h5>
                                <p class="text-muted">Review your selections before final submission. Once confirmed, your vote cannot be changed.</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="step">
                        <div class="d-flex align-items-start">
                            <div class="step-number me-3">5</div>
                            <div>
                                <h5>View Results</h5>
                                <p class="text-muted">After the election closes, view transparent, verifiable results published by the administrator.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="text-center mt-4">
                <a href="{{ url_for('auth_register') }}" class="btn btn-primary btn-lg">
                    <i class="bi bi-person-plus me-2"></i>Get Started Now
                </a>
            </div>
        </div>
    </div>
</div>

<style>
.step-number {
    width: 40px;
    height: 40px;
    background: linear-gradient(135deg, var(--blue), var(--navy));
    color: #fff;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 1.2rem;
    flex-shrink: 0;
}
[data-theme="dark"] .step-number {
    background: linear-gradient(135deg, var(--blue), var(--navy-dark));
}
</style>
{% endblock %}
'''

FEATURES_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Features - {{ app_name }}{% endblock %}
{% block content %}
<div class="container py-4">
    <h1 class="text-center mb-4">Features</h1>
    <p class="text-center text-muted mb-4">Discover what makes {{ app_name }} the secure choice for online voting</p>
    
    <div class="row g-4">
        <div class="col-md-4">
            <div class="card feature-card h-100">
                <div class="card-body text-center p-4">
                    <div class="feature-icon">
                        <i class="bi bi-lock-fill"></i>
                    </div>
                    <h4>Secure Authentication</h4>
                    <p class="text-muted">Multi-factor authentication ensures only authorized voters can access the system.</p>
                    <span class="badge bg-primary">Security</span>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="card feature-card h-100">
                <div class="card-body text-center p-4">
                    <div class="feature-icon" style="background: linear-gradient(135deg, var(--gold), #f39c12);">
                        <i class="bi bi-shield-shaded"></i>
                    </div>
                    <h4>Encrypted Votes</h4>
                    <p class="text-muted">All votes are encrypted using AES-GCM with 256-bit keys to ensure confidentiality and integrity.</p>
                    <span class="badge bg-warning text-dark">Encryption</span>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="card feature-card h-100">
                <div class="card-body text-center p-4">
                    <div class="feature-icon" style="background: linear-gradient(135deg, var(--teal), #00a381);">
                        <i class="bi bi-check-circle"></i>
                    </div>
                    <h4>One Voter – One Vote</h4>
                    <p class="text-muted">Prevents duplicate voting through database constraints and verification mechanisms.</p>
                    <span class="badge bg-success">Integrity</span>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="card feature-card h-100">
                <div class="card-body text-center p-4">
                    <div class="feature-icon" style="background: linear-gradient(135deg, var(--blue), #1a4a8a);">
                        <i class="bi bi-clipboard-data"></i>
                    </div>
                    <h4>Audit Logging</h4>
                    <p class="text-muted">Complete audit trail of all system activities for transparency and accountability.</p>
                    <span class="badge bg-info">Transparency</span>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="card feature-card h-100">
                <div class="card-body text-center p-4">
                    <div class="feature-icon" style="background: linear-gradient(135deg, #9b59b6, #8e44ad);">
                        <i class="bi bi-bar-chart-fill"></i>
                    </div>
                    <h4>Protected Results</h4>
                    <p class="text-muted">Results are automatically tallied and published securely with integrity verification.</p>
                    <span class="badge bg-secondary">Results</span>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="card feature-card h-100">
                <div class="card-body text-center p-4">
                    <div class="feature-icon" style="background: linear-gradient(135deg, #e67e22, #d35400);">
                        <i class="bi bi-person-badge"></i>
                    </div>
                    <h4>Role-Based Access</h4>
                    <p class="text-muted">Separate interfaces for voters and administrators with appropriate permissions.</p>
                    <span class="badge bg-warning text-dark">Access Control</span>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
.feature-card {
    border: none;
    transition: all 0.3s ease;
    box-shadow: 0 4px 6px rgba(0,0,0,0.07);
}
.feature-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 10px 20px rgba(0,0,0,0.12);
}
.feature-icon {
    width: 70px;
    height: 70px;
    background: linear-gradient(135deg, var(--blue), var(--navy));
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 15px;
}
.feature-icon i {
    font-size: 30px;
    color: #fff;
}
[data-theme="dark"] .feature-card {
    background: var(--card-bg);
}
</style>
{% endblock %}
'''

VISUAL_CRYPTOGRAPHY_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Visual Cryptography Demo - {{ app_name }}{% endblock %}
{% block content %}
<div class="container py-4">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <div class="card">
                <div class="card-body p-4">
                    <h2 class="text-center mb-4">Visual Cryptography Demo</h2>
                    <p class="text-center text-muted">A simulated demonstration of visual cryptography for secure vote verification</p>
                    
                    <div class="text-center mb-4">
                        <button id="genShares" class="btn btn-primary btn-lg">
                            <i class="bi bi-shield-shaded me-2"></i>Generate Shares
                        </button>
                    </div>
                    
                    <div class="row g-4">
                        <div class="col-md-4">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h5 class="mb-0"><i class="bi bi-1-circle me-2"></i>Share 1</h5>
                                </div>
                                <div class="card-body">
                                    <div id="share1" class="share-box p-3 bg-light border rounded" style="font-family: monospace; word-break: break-all; min-height: 100px;">
                                        <span class="text-muted">Click generate to create shares</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h5 class="mb-0"><i class="bi bi-2-circle me-2"></i>Share 2</h5>
                                </div>
                                <div class="card-body">
                                    <div id="share2" class="share-box p-3 bg-light border rounded" style="font-family: monospace; word-break: break-all; min-height: 100px;">
                                        <span class="text-muted">Click generate to create shares</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h5 class="mb-0"><i class="bi bi-check-circle me-2"></i>Reconstructed</h5>
                                </div>
                                <div class="card-body">
                                    <div id="reconstructed" class="share-box p-3 bg-success bg-opacity-10 border border-success rounded" style="font-family: monospace; word-break: break-all; min-height: 100px;">
                                        <span class="text-muted">Reconstruct to verify</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mt-4 text-center">
                        <p class="text-muted small">
                            <i class="bi bi-info-circle me-1"></i>
                            Visual cryptography splits a secret into two shares. Both shares are needed to reconstruct the original secret.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
document.getElementById('genShares').addEventListener('click', function() {
    function randHex(len) {
        let result = '';
        for (let i = 0; i < len; i++) {
            result += Math.floor(Math.random() * 16).toString(16).toUpperCase();
        }
        return result;
    }
    
    const s1 = randHex(64);
    const s2 = randHex(64);
    
    document.getElementById('share1').textContent = s1;
    document.getElementById('share2').textContent = s2;
    
    // Simulate reconstruction
    let rec = '';
    for (let i = 0; i < Math.min(s1.length, s2.length); i++) {
        const xor = parseInt(s1[i], 16) ^ parseInt(s2[i], 16);
        rec += xor.toString(16).toUpperCase();
    }
    
    document.getElementById('reconstructed').textContent = rec || 'Reconstructed secret (simulated)';
});
</script>

<style>
.share-box {
    min-height: 100px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.3s ease;
}
.share-box:hover {
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}
[data-theme="dark"] .share-box {
    background: var(--secondary-bg) !important;
}
</style>
{% endblock %}
'''

VOTER_DASHBOARD_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Voter Dashboard{% endblock %}
{% block content %}

<!-- ============ WELCOME HEADER ============ -->
<div class="dash-header">
    <div class="dash-welcome">
        <div class="dash-avatar">
            {% if profile and profile.photo %}
                <img src="{{ url_for('static', filename='uploads/' ~ profile.photo) }}"
                     alt="{{ profile.full_name or 'Voter' }}">
            {% else %}
                <span>{{ (profile.full_name[0] if profile and profile.full_name else 'U')|upper }}</span>
            {% endif %}
        </div>
        <div>
            <h1>Welcome, {{ (profile.full_name.split()[0] if profile and profile.full_name else current_user.username) }}!</h1>
            <p class="dash-sub">
                <i class="bi bi-card-text"></i>
                {{ profile.registration_number if profile and profile.registration_number else 'N/A' }}
            </p>
        </div>
    </div>
    <div class="dash-meta">
        <div class="dash-time">
            <i class="bi bi-clock-history"></i>
            {{ now_ng.strftime('%I:%M %p, %b %d') if now_ng else 'Now' }}
        </div>
        <a href="{{ url_for('voter_notifications') }}" class="dash-bell" title="Notifications">
            <i class="bi bi-bell-fill"></i>
            {% if unread_count and unread_count > 0 %}
                <span class="dash-bell-badge">{{ unread_count }}</span>
            {% endif %}
        </a>
        <a href="{{ url_for('voter_settings') }}" class="dash-settings" title="Settings">
            <i class="bi bi-gear-fill"></i>
        </a>
    </div>
</div>

<!-- ============ QUICK STATS ============ -->
<div class="row g-4">
    <div class="col-xl-3 col-md-6">
        <div class="stat-gradient grad-blue">
            <div>
                <div class="stat-num">{{ active_elections|length if active_elections else 0 }}</div>
                <div class="stat-lbl">Active Elections</div>
            </div>
            <div class="stat-icon-lg"><i class="bi bi-play-circle-fill"></i></div>
        </div>
    </div>
    <div class="col-xl-3 col-md-6">
        <div class="stat-gradient grad-orange">
            <div>
                <div class="stat-num">{{ upcoming_elections|length if upcoming_elections else 0 }}</div>
                <div class="stat-lbl">Upcoming</div>
            </div>
            <div class="stat-icon-lg"><i class="bi bi-clock-fill"></i></div>
        </div>
    </div>
    <div class="col-xl-3 col-md-6">
        <div class="stat-gradient grad-green">
            <div>
                <div class="stat-num">{{ voting_history|length if voting_history else 0 }}</div>
                <div class="stat-lbl">Votes Cast</div>
            </div>
            <div class="stat-icon-lg"><i class="bi bi-check-circle-fill"></i></div>
        </div>
    </div>
    <div class="col-xl-3 col-md-6">
        <div class="stat-gradient grad-purple">
            <div>
                <div class="stat-num">{{ unread_count if unread_count else 0 }}</div>
                <div class="stat-lbl">Notifications</div>
            </div>
            <div class="stat-icon-lg"><i class="bi bi-bell-fill"></i></div>
        </div>
    </div>
</div>

<!-- ============ ACTIVE ELECTIONS ============ -->
<h3 class="section-heading">
    <i class="bi bi-play-circle-fill text-success me-2"></i>Active Elections
    <span class="section-count">{{ active_elections|length if active_elections else 0 }}</span>
</h3>
<div class="row g-4">
    {% for election in active_elections %}
        <div class="col-lg-4 col-md-6">
            <div class="election-card">
                <div class="election-card-top">
                    <span class="badge badge-success">
                        <i class="bi bi-broadcast"></i> Live Now
                    </span>
                    <span class="election-type">{{ election.election_type|capitalize }}</span>
                </div>
                <h5 class="election-title">{{ election.title }}</h5>
                <p class="election-desc">{{ election.description or 'No description provided.' }}</p>

                <div class="election-meta">
                    <div><i class="bi bi-calendar-event"></i> Start: {{ utc_to_ng(election.start_date).strftime('%b %d, %I:%M %p') }}</div>
                    <div><i class="bi bi-calendar-x"></i> End: {{ utc_to_ng(election.end_date).strftime('%b %d, %I:%M %p') }}</div>
                </div>

                {% if election.id in voted_election_ids %}
                    <div class="election-voted">
                        <i class="bi bi-check-circle-fill"></i> You have voted
                    </div>
                {% else %}
                    <a href="{{ url_for('voting_view_election', election_id=election.id) }}"
                       class="btn btn-primary w-100 mt-3">
                        <i class="bi bi-check2-square me-1"></i> Vote Now
                    </a>
                {% endif %}
            </div>
        </div>
    {% else %}
        <div class="col-12">
            <div class="empty-state">
                <i class="bi bi-inbox"></i>
                <p>No active elections right now.</p>
            </div>
        </div>
    {% endfor %}
</div>

<!-- ============ UPCOMING ELECTIONS ============ -->
<h3 class="section-heading">
    <i class="bi bi-clock-fill text-warning me-2"></i>Upcoming Elections
    <span class="section-count">{{ upcoming_elections|length if upcoming_elections else 0 }}</span>
</h3>
<div class="row g-4">
    {% for election in upcoming_elections %}
        <div class="col-lg-4 col-md-6">
            <div class="election-card election-card-scheduled">
                <div class="election-card-top">
                    <span class="badge badge-warning">
                        <i class="bi bi-clock-history"></i> Scheduled
                    </span>
                    <span class="election-type">{{ election.election_type|capitalize }}</span>
                </div>
                <h5 class="election-title">{{ election.title }}</h5>
                <p class="election-desc">{{ election.description or '' }}</p>

                <div class="election-meta">
                    <div><i class="bi bi-calendar-event"></i> Starts: {{ utc_to_ng(election.start_date).strftime('%b %d, %I:%M %p') }}</div>
                    <div><i class="bi bi-hourglass-split"></i> Countdown: {{ election.start_date.strftime('%b %d') }}</div>
                </div>
            </div>
        </div>
    {% else %}
        <div class="col-12">
            <div class="empty-state">
                <i class="bi bi-calendar"></i>
                <p>No upcoming elections.</p>
            </div>
        </div>
    {% endfor %}
</div>

<!-- ============ COMPLETED ELECTIONS ============ -->
<h3 class="section-heading">
    <i class="bi bi-check-circle-fill text-muted me-2"></i>Completed Elections
    <span class="section-count">{{ completed_elections|length if completed_elections else 0 }}</span>
</h3>
<div class="row g-4">
    {% for election in completed_elections %}
        <div class="col-lg-4 col-md-6">
            <div class="election-card election-card-completed">
                <div class="election-card-top">
                    <span class="badge badge-secondary">
                        <i class="bi bi-check2-all"></i> Completed
                    </span>
                    <span class="election-type">{{ election.election_type|capitalize }}</span>
                </div>
                <h5 class="election-title">{{ election.title }}</h5>
                <div class="election-meta">
                    <div><i class="bi bi-calendar-check"></i> Ended: {{ utc_to_ng(election.end_date).strftime('%b %d, %Y') }}</div>
                </div>
                <a href="{{ url_for('results_view', election_id=election.id) }}"
                   class="btn btn-outline w-100 mt-3">
                    <i class="bi bi-bar-chart me-1"></i> View Results
                </a>
            </div>
        </div>
    {% else %}
        <div class="col-12">
            <div class="empty-state">
                <i class="bi bi-bar-chart"></i>
                <p>No completed elections yet.</p>
            </div>
        </div>
    {% endfor %}
</div>

<!-- ============ VOTING HISTORY ============ -->
<h3 class="section-heading">
    <i class="bi bi-clock-history me-2"></i>Voting History
    <span class="section-count">{{ voting_history|length if voting_history else 0 }}</span>
</h3>
<div class="card history-card">
    {% for item in voting_history %}
        <div class="history-item">
            <div class="history-left">
                <div class="history-icon"><i class="bi bi-check2-circle"></i></div>
                <div>
                    <div class="history-title">{{ item.election.title if item.election else 'Unknown Election' }}</div>
                    <div class="history-sub">
                        {{ item.election.election_type|capitalize if item.election and item.election.election_type else 'General' }}
                    </div>
                </div>
            </div>
            <div class="history-date">
                {{ utc_to_ng(item.created_at).strftime('%b %d, %Y') if item.created_at else 'N/A' }}
            </div>
        </div>
    {% else %}
        <div class="empty-state">
            <i class="bi bi-hourglass"></i>
            <p>You haven't voted in any election yet.</p>
        </div>
    {% endfor %}
</div>

<!-- ============ RECENT NOTIFICATIONS ============ -->
{% if recent_notifications %}
    <h3 class="section-heading">
        <i class="bi bi-bell-fill me-2"></i>Recent Notifications
    </h3>
    <div class="card history-card">
        {% for n in recent_notifications %}
            <div class="history-item">
                <div class="history-left">
                    <div class="history-icon history-icon-{{ n.notification_type }}">
                        <i class="bi {{ n.get_icon() }}"></i>
                    </div>
                    <div>
                        <div class="history-title">{{ n.title }}</div>
                        <div class="history-sub">{{ n.message|truncate(80) }}</div>
                    </div>
                </div>
                <div class="history-date">
                    {{ n.created_at.strftime('%b %d, %H:%M') if n.created_at else '' }}
                </div>
            </div>
        {% endfor %}
        <div class="text-center py-3">
            <a href="{{ url_for('voter_notifications') }}" class="btn btn-sm btn-outline">
                View All Notifications
            </a>
        </div>
    </div>
{% endif %}

<style>
/* ---------- Dashboard Header ---------- */
.dash-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 26px 28px;
    background: linear-gradient(135deg, var(--navy) 0%, var(--navy-dark) 100%);
    border-radius: 16px;
    color: #fff;
    margin-bottom: 28px;
    flex-wrap: wrap;
    gap: 16px;
    position: relative;
    overflow: hidden;
}
.dash-header::after {
    content: "";
    position: absolute;
    right: -40px;
    top: -40px;
    width: 180px;
    height: 180px;
    background: radial-gradient(circle, rgba(250,175,50,0.15), transparent 70%);
    border-radius: 50%;
}
.dash-welcome { display: flex; align-items: center; gap: 18px; position: relative; z-index: 2; }
.dash-avatar {
    width: 68px; height: 68px;
    border-radius: 50%;
    background: var(--gold);
    color: var(--navy);
    display: flex; align-items: center; justify-content: center;
    font-size: 1.7rem; font-weight: 800;
    overflow: hidden;
    flex-shrink: 0;
    border: 3px solid rgba(255,255,255,0.2);
}
.dash-avatar img { width: 100%; height: 100%; object-fit: cover; }
.dash-welcome h1 { font-size: 1.5rem; margin: 0 0 4px; font-weight: 700; color: #fff; }
.dash-sub { margin: 0; color: rgba(255,255,255,0.75); font-size: 0.88rem; display: flex; align-items: center; gap: 6px; }
.dash-meta { display: flex; align-items: center; gap: 10px; position: relative; z-index: 2; }
.dash-time {
    background: rgba(255,255,255,0.1);
    padding: 8px 14px;
    border-radius: 8px;
    font-size: 0.85rem;
    display: flex; align-items: center; gap: 6px;
}
.dash-bell, .dash-settings {
    width: 40px; height: 40px;
    border-radius: 50%;
    background: rgba(255,255,255,0.1);
    color: #fff;
    display: flex; align-items: center; justify-content: center;
    position: relative;
    transition: all 0.2s;
    text-decoration: none;
}
.dash-bell:hover, .dash-settings:hover { background: rgba(255,255,255,0.22); color: #fff; }
.dash-bell-badge {
    position: absolute;
    top: -4px; right: -4px;
    background: var(--red);
    color: #fff;
    font-size: 0.65rem;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 10px;
    min-width: 18px;
    text-align: center;
}

/* ---------- Section Headings ---------- */
.section-heading {
    font-size: 1.15rem;
    font-weight: 700;
    margin: 34px 0 16px;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 10px;
}
.section-count {
    background: var(--secondary-bg);
    color: var(--text-muted);
    font-size: 0.8rem;
    padding: 3px 12px;
    border-radius: 20px;
    font-weight: 600;
    margin-left: auto;
}

/* ---------- Election Cards ---------- */
.election-card {
    background: var(--card-bg);
    border-radius: 14px;
    padding: 22px;
    border: 1px solid var(--border-color);
    box-shadow: 0 2px 8px rgba(0,0,0,0.04);
    transition: transform 0.2s, box-shadow 0.2s;
    height: 100%;
    display: flex;
    flex-direction: column;
}
.election-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 12px 28px rgba(0,0,0,0.1);
}
.election-card-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 14px;
}
.election-type {
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 600;
}
.election-title {
    font-size: 1.05rem;
    font-weight: 700;
    margin: 0 0 8px;
    color: var(--text-primary);
    line-height: 1.4;
}
.election-desc {
    font-size: 0.88rem;
    color: var(--text-muted);
    margin: 0 0 14px;
    line-height: 1.5;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
}
.election-meta {
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: 0.82rem;
    color: var(--text-muted);
    padding-top: 14px;
    border-top: 1px solid var(--border-color);
    margin-top: auto;
}
.election-meta i { margin-right: 6px; color: var(--blue); }
.election-voted {
    text-align: center;
    padding: 10px;
    background: rgba(0,184,148,0.1);
    color: var(--teal);
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.9rem;
    margin-top: 12px;
}
.election-card-scheduled { border-left: 4px solid var(--gold); }
.election-card-completed { border-left: 4px solid var(--text-muted); opacity: 0.95; }

/* ---------- Empty State ---------- */
.empty-state {
    text-align: center;
    padding: 40px 20px;
    color: var(--text-muted);
    background: var(--card-bg);
    border-radius: 14px;
    border: 1px dashed var(--border-color);
}
.empty-state i { font-size: 2.5rem; opacity: 0.4; display: block; margin-bottom: 8px; }
.empty-state p { margin: 0; font-size: 0.9rem; }

/* ---------- History Card ---------- */
.history-card { padding: 8px 0; }
.history-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 22px;
    border-bottom: 1px solid var(--border-color);
    gap: 12px;
}
.history-item:last-child { border-bottom: none; }
.history-left { display: flex; align-items: center; gap: 14px; flex: 1; min-width: 0; }
.history-icon {
    width: 38px; height: 38px;
    border-radius: 10px;
    background: rgba(0,184,148,0.12);
    color: var(--teal);
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
    font-size: 1.1rem;
}
.history-icon-success { background: rgba(0,184,148,0.12); color: var(--teal); }
.history-icon-info { background: rgba(59,130,246,0.12); color: var(--blue); }
.history-icon-warning { background: rgba(245,158,11,0.12); color: var(--orange); }
.history-icon-danger { background: rgba(229,62,62,0.12); color: var(--red); }
.history-title { font-weight: 600; font-size: 0.93rem; color: var(--text-primary); }
.history-sub { font-size: 0.8rem; color: var(--text-muted); }
.history-date { font-size: 0.82rem; color: var(--text-muted); white-space: nowrap; }

/* ---------- Responsive ---------- */
@media (max-width: 768px) {
    .dash-header { padding: 20px; }
    .dash-welcome h1 { font-size: 1.2rem; }
    .dash-avatar { width: 54px; height: 54px; font-size: 1.4rem; }
    .dash-time { display: none; }
    .section-heading { font-size: 1rem; }
    .history-item { flex-direction: column; align-items: flex-start; gap: 6px; }
}

/* ---------- Dark mode ---------- */
[data-theme="dark"] .dash-header { background: linear-gradient(135deg, #0a1a3a 0%, #051b33 100%); }
[data-theme="dark"] .election-card { background: var(--card-bg); }
[data-theme="dark"] .empty-state { background: var(--secondary-bg); }
[data-theme="dark"] .history-card { background: var(--card-bg); }
</style>

{% endblock %}
'''

VOTER_NOTIFICATIONS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Notifications{% endblock %}
{% block content %}
<div class="container">
    <div class="page-header d-flex justify-content-between align-items-center">
        <div>
            <h1 class="page-title"><i class="bi bi-bell-fill me-2"></i>Notifications</h1>
            <p class="page-subtitle">{{ notifications|length }} total notifications</p>
        </div>
        <a href="{{ url_for('voter_mark_all_read') }}" class="btn btn-outline btn-sm">
            <i class="bi bi-check2-all me-1"></i>Mark All Read
        </a>
    </div>

    <div class="card notifications-card">
        {% for n in notifications %}
            <div class="notif-item {% if not n.is_read %}notif-unread{% endif %}">
                <div class="notif-icon notif-icon-{{ n.notification_type }}">
                    <i class="bi {{ n.get_icon() }}"></i>
                </div>
                <div class="notif-content">
                    <div class="notif-header">
                        <h6 class="mb-1">{{ n.title }}</h6>
                        <span class="notif-time">{{ n.created_at.strftime('%b %d, %Y at %I:%M %p') }}</span>
                    </div>
                    <p class="notif-message">{{ n.message }}</p>
                    {% if not n.is_read %}
                        <a href="{{ url_for('voter_notification_read', notification_id=n.id) }}"
                           class="btn btn-sm btn-outline mt-2">
                            <i class="bi bi-check2"></i> Mark as Read
                        </a>
                    {% endif %}
                </div>
            </div>
        {% else %}
            <div class="empty-state">
                <i class="bi bi-bell-slash"></i>
                <p>No notifications yet.</p>
            </div>
        {% endfor %}
    </div>
</div>

<style>
.page-header { margin-bottom: 22px; }
.page-title { font-size: 1.6rem; font-weight: 700; margin: 0; }
.page-subtitle { color: var(--text-muted); margin: 4px 0 0; font-size: 0.9rem; }
.notifications-card { padding: 0; }
.notif-item {
    display: flex; gap: 16px;
    padding: 20px 22px;
    border-bottom: 1px solid var(--border-color);
    transition: background 0.2s;
}
.notif-item:last-child { border-bottom: none; }
.notif-item:hover { background: var(--secondary-bg); }
.notif-unread { background: rgba(59,130,246,0.04); border-left: 3px solid var(--blue); }
.notif-icon {
    width: 44px; height: 44px;
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
    font-size: 1.3rem;
}
.notif-icon-success { background: rgba(0,184,148,0.12); color: var(--teal); }
.notif-icon-info { background: rgba(59,130,246,0.12); color: var(--blue); }
.notif-icon-warning { background: rgba(245,158,11,0.12); color: var(--orange); }
.notif-icon-danger { background: rgba(229,62,62,0.12); color: var(--red); }
.notif-content { flex: 1; min-width: 0; }
.notif-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
.notif-header h6 { font-size: 1rem; font-weight: 700; margin: 0; }
.notif-time { font-size: 0.78rem; color: var(--text-muted); white-space: nowrap; }
.notif-message { margin: 6px 0 0; font-size: 0.9rem; color: var(--text-secondary); line-height: 1.5; }
.empty-state { text-align: center; padding: 60px 20px; color: var(--text-muted); }
.empty-state i { font-size: 3rem; opacity: 0.4; display: block; margin-bottom: 10px; }
</style>
{% endblock %}
'''
VOTER_PROFILE_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}My Profile{% endblock %}
{% block content %}
<div class="container">
    <div class="page-header">
        <h1 class="page-title"><i class="bi bi-person-circle me-2"></i>My Profile</h1>
        <p class="page-subtitle">Manage your personal information and profile photo</p>
    </div>

    <div class="row g-4">
        <div class="col-lg-4">
            <div class="card profile-card">
                <div class="card-body text-center">
                    {% if profile.photo %}
                        <img src="{{ url_for('static', filename='uploads/' ~ profile.photo) }}"
                             alt="{{ profile.full_name }}" class="profile-photo-lg">
                    {% else %}
                        <div class="profile-photo-placeholder">
                            <i class="bi bi-person-fill"></i>
                        </div>
                    {% endif %}
                    <h4 class="mt-3 mb-1">{{ profile.full_name }}</h4>
                    <p class="text-muted small mb-2">{{ profile.registration_number }}</p>
                    <span class="badge badge-success">Verified Voter</span>

                    <hr>
                    <div class="profile-stats">
                        <div>
                            <strong>{{ profile.has_voted|default(false)|int if false else 0 }}</strong>
                            <small>Votes Cast</small>
                        </div>
                        <div>
                            <strong>{{ profile.created_at.strftime('%Y') if profile.created_at else 'N/A' }}</strong>
                            <small>Joined</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-lg-8">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="bi bi-pencil-square me-2"></i>Edit Profile</h5>
                </div>
                <div class="card-body">
                    <form method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Full Name</label>
                                    <input type="text" name="full_name" class="form-control"
                                           value="{{ profile.full_name or '' }}" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Registration Number</label>
                                    <input type="text" class="form-control"
                                           value="{{ profile.registration_number or '' }}" disabled>
                                    <small class="text-muted">Contact admin to change</small>
                                </div>
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Phone Number</label>
                                    <input type="text" name="phone" class="form-control"
                                           value="{{ profile.phone or '' }}">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Level</label>
                                    <select name="level" class="form-control">
                                        {% for lvl in ['100','200','300','400','500','600'] %}
                                            <option value="{{ lvl }}" {% if profile.level == lvl %}selected{% endif %}>
                                                {{ lvl }} Level
                                            </option>
                                        {% endfor %}
                                    </select>
                                </div>
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Department</label>
                                    <input type="text" name="department" class="form-control"
                                           value="{{ profile.department or '' }}">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Faculty</label>
                                    <input type="text" name="faculty" class="form-control"
                                           value="{{ profile.faculty or '' }}">
                                </div>
                            </div>
                        </div>

                        <div class="form-group">
                            <label>Profile Photo</label>
                            <input type="file" name="photo" class="form-control" accept="image/*">
                            <small class="text-muted">Upload a new photo (PNG, JPG, JPEG)</small>
                        </div>

                        <div class="d-flex gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="bi bi-check-circle me-1"></i>Save Changes
                            </button>
                            <a href="{{ url_for('voter_dashboard') }}" class="btn btn-outline-secondary">Cancel</a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
.page-header { margin-bottom: 24px; }
.page-title { font-size: 1.6rem; font-weight: 700; margin: 0; color: var(--text-primary); }
.page-subtitle { color: var(--text-muted); margin: 4px 0 0; font-size: 0.92rem; }
.profile-card { text-align: center; }
.profile-photo-lg {
    width: 140px; height: 140px;
    border-radius: 50%;
    object-fit: cover;
    border: 4px solid var(--gold);
}
.profile-photo-placeholder {
    width: 140px; height: 140px;
    border-radius: 50%;
    background: var(--secondary-bg);
    color: var(--text-muted);
    display: flex; align-items: center; justify-content: center;
    font-size: 4rem;
    margin: 0 auto;
    border: 4px solid var(--gold);
}
.profile-stats { display: flex; justify-content: space-around; }
.profile-stats strong { display: block; font-size: 1.3rem; color: var(--blue); }
.profile-stats small { font-size: 0.78rem; color: var(--text-muted); }
</style>
{% endblock %}
'''

# ============================================================================
# PART19: VOTING_ELECTION_TEMPLATE 
# ============================================================================

VOTING_ELECTION_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}{{ election.title }}{% endblock %}
{% block content %}
<div class="container">
    <h2>{{ election.title }}</h2>
    <p>{{ election.description }}</p>
    <div>
        <span class="badge badge-{{ election.get_status() }}">{{ election.get_status() }}</span>
        <span class="text-muted">
            <i class="bi bi-clock me-1"></i>
            {{ utc_to_ng(election.start_date).strftime('%I:%M %p, %b %d, %Y') }} -
            {{ utc_to_ng(election.end_date).strftime('%I:%M %p, %b %d, %Y') }}
        </span>
    </div>
    <hr>
    {% if is_open and not has_voted %}
        <a href="{{ url_for('voting_cast_vote', election_id=election.id) }}" class="btn btn-primary btn-lg">Cast Your Vote</a>
    {% elif has_voted %}
        <div class="alert alert-success">✅ You have already voted in this election.</div>
    {% else %}
        <div class="alert alert-warning">Voting is not open for this election.</div>
    {% endif %}

    <h4 class="mt-4">Candidates</h4>
    {% for position in positions %}
        <div class="card mb-3">
            <div class="card-header">
                <h5>{{ position.title }}</h5>
                <p class="text-muted">{{ position.description }}</p>
            </div>
            <div class="card-body">
                <div class="row">
                    {% for candidate in candidates_by_position[position.id] %}
                        <div class="col-md-3">
                            <div class="card candidate-card">
                                <div class="card-body text-center">
                                    {% if candidate.photo %}
                                        <img src="{{ url_for('static', filename='uploads/' ~ candidate.photo) }}" alt="{{ candidate.full_name }}" class="candidate-photo">
                                    {% else %}
                                        <i class="bi bi-person-circle" style="font-size:3rem;"></i>
                                    {% endif %}
                                    <h6>{{ candidate.full_name }}</h6>
                                    <p class="small text-muted">{{ candidate.department }}</p>
                                    {% if candidate.vote_count is defined %}
                                        <span class="badge badge-info">{{ candidate.vote_count }} votes</span>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    {% endfor %}
</div>
{% endblock %}
'''

VOTING_VOTE_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Cast Vote{% endblock %}
{% block content %}
<div class="container">
    <div class="vote-header">
        <h2><i class="bi bi-check2-square me-2"></i>{{ election.title }}</h2>
        <p class="text-muted">Please select your choice for each position below. Only positions with candidates are shown.</p>
    </div>

    <form method="POST" id="voteForm" action="{{ url_for('voting_cast_vote', election_id=election.id) }}">
        <!-- CSRF TOKEN – REQUIRED -->
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        {% for position in positions %}
            <div class="card mb-3">
                <div class="card-header">
                    <h5 class="mb-0">{{ position.title }}</h5>
                    {% if position.description %}
                        <p class="text-muted mb-0 small">{{ position.description }}</p>
                    {% endif %}
                </div>
                <div class="card-body">
                    <div class="row g-3">
                        {% for candidate in candidates_by_position[position.id] %}
                            <div class="col-md-4">
                                <label class="candidate-card-vote" for="cand_{{ candidate.id }}">
                                    <input type="radio"
                                           name="position_{{ position.id }}"
                                           value="{{ candidate.id }}"
                                           id="cand_{{ candidate.id }}"
                                           required>
                                    <div class="candidate-info">
                                        {% if candidate.photo %}
                                            <img src="{{ url_for('static', filename='uploads/' ~ candidate.photo) }}"
                                                 alt="{{ candidate.full_name }}"
                                                 class="candidate-photo">
                                        {% else %}
                                            <div class="candidate-photo-placeholder">
                                                <i class="bi bi-person-fill"></i>
                                            </div>
                                        {% endif %}
                                        <h6>{{ candidate.full_name }}</h6>
                                        <p class="small text-muted mb-0">{{ candidate.department or 'N/A' }}</p>
                                        {% if candidate.manifesto %}
                                            <button type="button" class="btn btn-sm btn-outline mt-2"
                                                    onclick="toggleManifesto({{ candidate.id }})">
                                                <i class="bi bi-file-text"></i> Manifesto
                                            </button>
                                            <div class="manifesto-box" id="manifesto_{{ candidate.id }}" style="display:none;">
                                                {{ candidate.manifesto }}
                                            </div>
                                        {% endif %}
                                    </div>
                                </label>
                            </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        {% endfor %}

        <div class="vote-actions">
            <button type="submit" class="btn btn-primary btn-lg">
                <i class="bi bi-check-circle me-2"></i>Review Your Vote
            </button>
            <a href="{{ url_for('voter_dashboard') }}" class="btn btn-outline-secondary btn-lg">Cancel</a>
        </div>
    </form>
</div>

<style>
.vote-header { margin-bottom: 24px; }
.vote-header h2 { font-weight: 700; }

.candidate-card-vote {
    display: block;
    position: relative;
    cursor: pointer;
    border: 2px solid var(--border-color);
    border-radius: 12px;
    padding: 16px;
    text-align: center;
    transition: all 0.2s;
    background: var(--card-bg);
    height: 100%;
}
.candidate-card-vote:hover {
    border-color: var(--blue);
    transform: translateY(-2px);
    box-shadow: 0 6px 16px rgba(0,0,0,0.08);
}
.candidate-card-vote input[type="radio"] {
    position: absolute;
    top: 12px;
    right: 12px;
    width: 20px;
    height: 20px;
    accent-color: var(--blue);
    cursor: pointer;
}
.candidate-card-vote:has(input:checked) {
    border-color: var(--blue);
    background: rgba(26, 91, 191, 0.06);
    box-shadow: 0 0 0 3px rgba(26, 91, 191, 0.15);
}
.candidate-photo {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    object-fit: cover;
    margin: 0 auto 10px;
    display: block;
    border: 3px solid var(--border-color);
}
.candidate-photo-placeholder {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    background: var(--secondary-bg);
    color: var(--text-muted);
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 10px;
    font-size: 2rem;
}
.candidate-info h6 { font-weight: 700; margin-bottom: 4px; font-size: 0.95rem; }
.manifesto-box {
    margin-top: 10px;
    padding: 10px;
    background: var(--secondary-bg);
    border-radius: 6px;
    font-size: 0.8rem;
    color: var(--text-secondary);
    text-align: left;
    max-height: 150px;
    overflow-y: auto;
}
.vote-actions { text-align: center; margin-top: 24px; display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
</style>

<script>
function toggleManifesto(id) {
    const box = document.getElementById('manifesto_' + id);
    if (box) {
        box.style.display = box.style.display === 'none' ? 'block' : 'none';
    }
}
</script>
{% endblock %}
'''

VOTING_REVIEW_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Review Your Vote{% endblock %}
{% block content %}
<div class="container">
    <h2>Review Your Vote</h2>
    <p class="text-muted">Please review your selections before submitting.</p>

    <div class="card">
        <div class="card-body">
            <h4>{{ election.title }}</h4>
            <hr>
            {% for item in review_data %}
                <div class="review-item d-flex justify-content-between align-items-center">
                    <strong>{{ item.position.title }}</strong>
                    <span>{{ item.candidate.full_name }}</span>
                </div>
            {% endfor %}
        </div>
    </div>

    <div class="text-center mt-3">
        <form method="POST" action="{{ url_for('voting_confirm_vote', election_id=election.id) }}" style="display:inline;">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">   <!-- CSRF TOKEN -->
            <button type="submit" class="btn btn-success btn-lg">
                <i class="bi bi-check-circle me-2"></i>Confirm and Submit Vote
            </button>
        </form>
        <a href="{{ url_for('voting_cast_vote', election_id=election.id) }}" class="btn btn-outline btn-lg">Back and Edit</a>
    </div>
</div>
{% endblock %}
'''

VOTING_CONFIRMATION_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Vote Confirmed{% endblock %}
{% block content %}
<div class="container">
    <div class="card confirmation-card">
        <div class="card-body text-center py-5">
            <div class="success-icon"><i class="bi bi-check-circle-fill"></i></div>
            <h2 class="mt-3">Vote Submitted Successfully!</h2>
            <p class="text-muted">Your vote for <strong>{{ election.title }}</strong> has been securely recorded.</p>

            {% if vote_details %}
                <div class="vote-details text-start mt-4">
                    <h5 class="mb-3"><i class="bi bi-list-check me-2"></i>Your Selections</h5>
                    {% for item in vote_details %}
                        <div class="vote-detail-item">
                            <span class="position-name">{{ item.position.title }}</span>
                            <span class="candidate-name">{{ item.candidate.full_name }}</span>
                        </div>
                    {% endfor %}
                </div>
            {% endif %}

            <div class="mt-4 d-flex gap-2 justify-content-center flex-wrap">
                <a href="{{ url_for('voter_dashboard') }}" class="btn btn-primary">
                    <i class="bi bi-house me-1"></i>Go to Dashboard
                </a>
                <a href="{{ url_for('results_view', election_id=election.id) }}" class="btn btn-outline">
                    <i class="bi bi-bar-chart me-1"></i>View Results
                </a>
            </div>
        </div>
    </div>
</div>

<style>
.confirmation-card { max-width: 720px; margin: 30px auto; }
.success-icon { font-size: 5rem; color: var(--teal); line-height: 1; }
.vote-details { background: var(--secondary-bg); border-radius: 12px; padding: 20px; }
.vote-detail-item { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid var(--border-color); }
.vote-detail-item:last-child { border-bottom: none; }
.position-name { font-weight: 600; }
.candidate-name { color: var(--blue); font-weight: 600; }
</style>
{% endblock %}
'''
VOTING_CONFIRMATION_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Vote Confirmed{% endblock %}
{% block content %}
<div class="container">
    <div class="card confirmation-card">
        <div class="card-body text-center py-5">
            <div class="success-icon"><i class="bi bi-check-circle-fill"></i></div>
            <h2 class="mt-3">Vote Submitted Successfully!</h2>
            <p class="text-muted">Your vote for <strong>{{ election.title }}</strong> has been securely recorded.</p>

            {% if vote_details %}
                <div class="vote-details text-start mt-4">
                    <h5 class="mb-3"><i class="bi bi-list-check me-2"></i>Your Selections</h5>
                    {% for item in vote_details %}
                        <div class="vote-detail-item">
                            <span class="position-name">{{ item.position.title }}</span>
                            <span class="candidate-name">{{ item.candidate.full_name }}</span>
                        </div>
                    {% endfor %}
                </div>
            {% endif %}

            <div class="mt-4 d-flex gap-2 justify-content-center flex-wrap">
                <a href="{{ url_for('voter_dashboard') }}" class="btn btn-primary">
                    <i class="bi bi-house me-1"></i>Go to Dashboard
                </a>
                <a href="{{ url_for('results_view', election_id=election.id) }}" class="btn btn-outline">
                    <i class="bi bi-bar-chart me-1"></i>View Results
                </a>
            </div>
        </div>
    </div>
</div>

<style>
.confirmation-card { max-width: 720px; margin: 30px auto; }
.success-icon { font-size: 5rem; color: var(--teal); line-height: 1; }
.vote-details { background: var(--secondary-bg); border-radius: 12px; padding: 20px; }
.vote-detail-item { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid var(--border-color); }
.vote-detail-item:last-child { border-bottom: none; }
.position-name { font-weight: 600; }
.candidate-name { color: var(--blue); font-weight: 600; }
</style>
{% endblock %}
'''

RESULTS_INDEX_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Election Results{% endblock %}
{% block content %}
<div class="container">
    <h2>Published Election Results</h2>
    <div class="row">
        {% for item in election_results %}
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5>{{ item.election.title }}</h5>
                        <span class="badge badge-success">Published</span>
                        <p class="small">{{ item.election.end_date.strftime('%b %d, %Y') }}</p>
                        <div class="text-muted small">
                            <span>{{ item.result.total_votes }} votes</span>
                            <span>{{ item.result.participation_rate|round(1) }}% turnout</span>
                        </div>
                        <a href="{{ url_for('results_view', election_id=item.election.id) }}" class="btn btn-outline btn-sm mt-2">View Results</a>
                    </div>
                </div>
            </div>
        {% else %}
            <div class="col-12 text-center py-5">
                <i class="bi bi-file-earmark-text" style="font-size:3rem;color:var(--text-muted);opacity:0.5;"></i>
                <p class="text-muted">No results published yet.</p>
            </div>
        {% endfor %}
    </div>
</div>
{% endblock %}
'''

RESULTS_VIEW_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Results - {{ election.title }}{% endblock %}
{% block content %}
<div class="container">
    <h2>{{ election.title }} - Results</h2>
    <p class="text-muted">
        <i class="bi bi-calendar3 me-1"></i>
        {{ utc_to_ng(election.end_date).strftime('%b %d, %Y at %I:%M %p') }}
    </p>
    <div class="row stats-row">
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="number">{{ total_votes }}</div>
                <div class="label">Total Votes</div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="number">{{ result.registered_voters }}</div>
                <div class="label">Registered Voters</div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="number">{{ result.participation_rate|round(1) }}%</div>
                <div class="label">Participation</div>
            </div>
        </div>
    </div>

    {% for data in position_data %}
        <div class="card mt-4">
            <div class="card-header">
                <h4>{{ data.position.title }}</h4>
            </div>
            <div class="card-body">
                <div class="list-group">
                    {% for candidate in data.candidates %}
                        <div class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>{{ candidate.candidate.full_name }}</strong>
                                <span class="text-muted">{{ candidate.candidate.department }}</span>
                            </div>
                            <div>
                                <span class="badge badge-primary">{{ candidate.vote_count }} votes</span>
                                <span class="badge badge-info">{{ candidate.percentage|round(1) }}%</span>
                            </div>
                        </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    {% endfor %}

    <div class="mt-4 text-center">
        <a href="{{ url_for('results_index') }}" class="btn btn-outline">Back to Results</a>
        <a href="{{ url_for('results_export', election_id=election.id) }}" class="btn btn-secondary">Export CSV</a>
    </div>
</div>
{% endblock %}
'''
# ============================================================================
# PART20: ADMIN_DASHBOARD_TEMPLATE  
# ============================================================================

ADMIN_DASHBOARD_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Admin Dashboard{% endblock %}
{% block content %}
<div class="admin-hero">
    <div>
        <h1><i class="bi bi-speedometer2 me-2"></i>Administrator Dashboard</h1>
        <p>{{ now.strftime('%A, %B %d, %Y — %I:%M %p') }}</p>
    </div>
    <div class="admin-hero-actions">
        <a href="{{ url_for('admin_create_election') }}" class="btn btn-gold"><i class="bi bi-plus-circle me-1"></i>New Election</a>
        <a href="{{ url_for('admin_elections') }}" class="btn btn-outline-light"><i class="bi bi-list-ul me-1"></i>All Elections</a>
    </div>
</div>

<!-- Gradient Stats -->
<div class="row g-4">
    <div class="col-xl-3 col-md-6">
        <div class="stat-gradient grad-blue">
            <div><div class="stat-num">{{ total_voters }}</div><div class="stat-lbl">Registered Voters</div></div>
            <div class="stat-icon-lg"><i class="bi bi-people-fill"></i></div>
        </div>
    </div>
    <div class="col-xl-3 col-md-6">
        <div class="stat-gradient grad-green">
            <div><div class="stat-num">{{ active_elections }}</div><div class="stat-lbl">Active Elections</div></div>
            <div class="stat-icon-lg"><i class="bi bi-play-circle-fill"></i></div>
        </div>
    </div>
    <div class="col-xl-3 col-md-6">
        <div class="stat-gradient grad-orange">
            <div><div class="stat-num">{{ total_votes }}</div><div class="stat-lbl">Total Votes Cast</div></div>
            <div class="stat-icon-lg"><i class="bi bi-check-circle-fill"></i></div>
        </div>
    </div>
    <div class="col-xl-3 col-md-6">
        <div class="stat-gradient grad-purple">
            <div><div class="stat-num">{{ participation_rate|round(1) }}%</div><div class="stat-lbl">Participation</div></div>
            <div class="stat-icon-lg"><i class="bi bi-graph-up-arrow"></i></div>
        </div>
    </div>
</div>

<!-- Secondary Stats -->
<div class="row g-4">
    <div class="col-md-4"><div class="card stat-card"><div class="number">{{ upcoming_elections }}</div><div class="label">Upcoming Elections</div></div></div>
    <div class="col-md-4"><div class="card stat-card"><div class="number">{{ draft_elections }}</div><div class="label">Draft Elections</div></div></div>
    <div class="col-md-4"><div class="card stat-card"><div class="number">{{ completed_elections }}</div><div class="label">Completed</div></div></div>
</div>

<!-- Quick Actions -->
<div class="card">
    <div class="card-header"><h5 class="mb-0"><i class="bi bi-lightning-charge-fill me-2"></i>Quick Actions</h5></div>
    <div class="card-body">
        <div class="action-grid">
            <a href="{{ url_for('admin_create_election') }}" class="qa-btn qa-primary"><i class="bi bi-plus-circle-fill"></i><span>Create Election</span></a>
            <a href="{{ url_for('admin_elections') }}" class="qa-btn qa-info"><i class="bi bi-calendar-event-fill"></i><span>Manage Elections</span></a>
            <a href="{{ url_for('admin_voters') }}" class="qa-btn qa-success"><i class="bi bi-people-fill"></i><span>Manage Voters</span></a>
            <a href="{{ url_for('admin_audit') }}" class="qa-btn qa-secondary"><i class="bi bi-clipboard-data-fill"></i><span>Audit Log</span></a>
            <a href="{{ url_for('admin_security') }}" class="qa-btn qa-danger"><i class="bi bi-shield-lock-fill"></i><span>Security</span></a>
            <a href="{{ url_for('admin_reports') }}" class="qa-btn qa-warning"><i class="bi bi-file-earmark-bar-graph-fill"></i><span>Reports</span></a>
        </div>
    </div>
</div>

<div class="row g-4">
    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0"><i class="bi bi-clock-history me-2"></i>Recent Activity</h5>
                <a href="{{ url_for('admin_audit') }}" class="small">View All</a>
            </div>
            <div class="card-body p-0">
                {% for log in recent_activity %}
                    <div class="activity-row">
                        <span class="badge badge-{{ log.get_action_color() }}">{{ log.action }}</span>
                        <span class="activity-text">{{ log.description }}</span>
                        <span class="activity-time">{{ log.created_at.strftime('%b %d, %H:%M') }}</span>
                    </div>
                {% endfor %}
            </div>
        </div>
    </div>
    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0"><i class="bi bi-bar-chart-fill me-2"></i>Election Activity</h5>
                <a href="{{ url_for('admin_elections') }}" class="small">View All</a>
            </div>
            <div class="card-body p-0">
                {% for e in election_activity %}
                    <div class="activity-row">
                        <span class="activity-text">{{ e.title }}</span>
                        <span class="badge badge-primary">{{ e.votes }} votes</span>
                        <span class="badge badge-{{ e.status }}">{{ e.status|capitalize }}</span>
                    </div>
                {% endfor %}
            </div>
        </div>
    </div>
</div>

<!-- Recent Elections Table -->
<div class="card">
    <div class="card-header d-flex justify-content-between align-items-center">
        <h5 class="mb-0"><i class="bi bi-table me-2"></i>Recent Elections</h5>
        <a href="{{ url_for('admin_elections') }}" class="small">View All</a>
    </div>
    <div class="card-body p-0">
        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr><th>Title</th><th>Type</th><th>Start</th><th>End</th><th>Status</th><th>Actions</th></tr>
                </thead>
                <tbody>
                    {% for e in recent_elections %}
                    <tr>
                        <td><strong>{{ e.title }}</strong></td>
                        <td><span class="badge bg-light text-dark">{{ e.election_type }}</span></td>
                        <td>{{ utc_to_ng(e.start_date).strftime('%d %b, %H:%M') }}</td>
                        <td>{{ utc_to_ng(e.end_date).strftime('%d %b, %H:%M') }}</td>
                        <td><span class="badge badge-{{ e.get_status() }}">{{ e.get_status()|capitalize }}</span></td>
                        <td>
                            <a href="{{ url_for('admin_edit_election', election_id=e.id) }}" class="btn btn-sm btn-primary"><i class="bi bi-pencil"></i></a>
                            <a href="{{ url_for('admin_view_results', election_id=e.id) }}" class="btn btn-sm btn-success"><i class="bi bi-bar-chart"></i></a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<style>
.admin-hero{background:linear-gradient(135deg,var(--navy),var(--navy-dark));color:#fff;padding:28px;border-radius:16px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;margin-bottom:24px}
.admin-hero h1{font-size:1.6rem;margin:0 0 4px;font-weight:700}
.admin-hero p{margin:0;color:rgba(255,255,255,0.75);font-size:0.9rem}
.admin-hero-actions{display:flex;gap:10px;flex-wrap:wrap}
.btn-outline-light{background:transparent;border:2px solid rgba(255,255,255,0.3);color:#fff}
.btn-outline-light:hover{background:rgba(255,255,255,0.1);color:#fff;border-color:#fff}
.action-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.qa-btn{display:flex;flex-direction:column;align-items:center;padding:18px;border-radius:12px;color:#fff;text-decoration:none;font-weight:600;transition:all 0.2s;font-size:0.9rem;gap:8px}
.qa-btn i{font-size:1.5rem}
.qa-btn:hover{transform:translateY(-3px);text-decoration:none;color:#fff;box-shadow:0 8px 20px rgba(0,0,0,0.15)}
.qa-primary{background:linear-gradient(135deg,#3b82f6,#1e40af)}
.qa-info{background:linear-gradient(135deg,#06b6d4,#0891b2)}
.qa-success{background:linear-gradient(135deg,#10b981,#059669)}
.qa-secondary{background:linear-gradient(135deg,#6b7280,#4b5563)}
.qa-danger{background:linear-gradient(135deg,#ef4444,#b91c1c)}
.qa-warning{background:linear-gradient(135deg,#f59e0b,#d97706)}
.activity-row{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--border-color);font-size:0.9rem}
.activity-row:last-child{border-bottom:none}
.activity-text{flex:1;color:var(--text-secondary)}
.activity-time{color:var(--text-muted);font-size:0.8rem;white-space:nowrap}
</style>
{% endblock %}
'''

ADMIN_VOTERS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Manage Voters{% endblock %}
{% block content %}
<div class="container">
    <h2>Voters</h2>
    <form method="GET" class="mb-3">
        <div class="row">
            <div class="col-md-4">
                <input type="text" name="search" placeholder="Search..." value="{{ search or '' }}" class="form-control">
            </div>
            <div class="col-md-3">
                <select name="status" class="form-control" onchange="this.form.submit()">
                    <option value="">All Status</option>
                    <option value="active" {% if filter_status == 'active' %}selected{% endif %}>Active</option>
                    <option value="inactive" {% if filter_status == 'inactive' %}selected{% endif %}>Inactive</option>
                    <option value="verified" {% if filter_status == 'verified' %}selected{% endif %}>Verified</option>
                    <option value="unverified" {% if filter_status == 'unverified' %}selected{% endif %}>Unverified</option>
                </select>
            </div>
            <div class="col-md-2">
                <button type="submit" class="btn btn-primary">Search</button>
            </div>
        </div>
    </form>

    <table class="table table-striped">
        <thead>
            <tr>
                <th>Username</th>
                <th>Full Name</th>
                <th>Registration</th>
                <th>Email</th>
                <th>Status</th>
                <th>Votes</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for data in voter_data %}
            <tr>
                <td>{{ data.user.username }}</td>
                <td>{{ data.profile.full_name }}</td>
                <td>{{ data.profile.registration_number }}</td>
                <td>{{ data.user.email }}</td>
                <td>
                    <span class="badge badge-{{ 'success' if data.user.is_active else 'danger' }}">
                        {{ 'Active' if data.user.is_active else 'Inactive' }}
                    </span>
                    {% if data.user.is_verified %}
                        <span class="badge badge-info">Verified</span>
                    {% endif %}
                </td>
                <td>{{ data.voted_count }}</td>
                <td>
                    <a href="{{ url_for('admin_edit_voter', user_id=data.user.id) }}" class="btn btn-sm btn-primary">Edit</a>
                    <form method="POST" action="{{ url_for('admin_delete_voter', user_id=data.user.id) }}" style="display:inline;" onsubmit="return confirm('Delete this voter?')">
                        <button type="submit" class="btn btn-sm btn-danger">Delete</button>
                    </form>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {{ voters.links }}
</div>
{% endblock %}
'''

ADMIN_EDIT_VOTER_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Edit Voter{% endblock %}
{% block content %}
<div class="container">
    <h2>Edit Voter: {{ user.username }}</h2>
    <form method="POST" enctype="multipart/form-data">
        <div class="row">
            <div class="col-md-4 text-center">
                {% if profile.photo %}
                    <img src="{{ url_for('static', filename='uploads/' ~ profile.photo) }}" alt="{{ profile.full_name }}" class="profile-photo">
                {% else %}
                    <i class="bi bi-person-circle" style="font-size:80px;color:var(--text-muted);"></i>
                {% endif %}
            </div>
            <div class="col-md-8">
                <div class="form-group">
                    <label>Full Name</label>
                    <input type="text" name="full_name" class="form-control" value="{{ profile.full_name }}" required>
                </div>
                <div class="form-group">
                    <label>Phone</label>
                    <input type="text" name="phone" class="form-control" value="{{ profile.phone or '' }}">
                </div>
                <div class="form-group">
                    <label>Department</label>
                    <input type="text" name="department" class="form-control" value="{{ profile.department or '' }}">
                </div>
                <div class="form-group">
                    <label>Faculty</label>
                    <input type="text" name="faculty" class="form-control" value="{{ profile.faculty or '' }}">
                </div>
                <div class="form-group">
                    <label>Level</label>
                    <select name="level" class="form-control">
                        <option value="100" {% if profile.level=='100' %}selected{% endif %}>100 Level</option>
                        <option value="200" {% if profile.level=='200' %}selected{% endif %}>200 Level</option>
                        <option value="300" {% if profile.level=='300' %}selected{% endif %}>300 Level</option>
                        <option value="400" {% if profile.level=='400' %}selected{% endif %}>400 Level</option>
                        <option value="500" {% if profile.level=='500' %}selected{% endif %}>500 Level</option>
                        <option value="600" {% if profile.level=='600' %}selected{% endif %}>600 Level</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Profile Photo</label>
                    <input type="file" name="photo" class="form-control" accept="image/*">
                </div>
                <div class="form-check">
                    <input type="checkbox" name="is_active" class="form-check-input" {% if user.is_active %}checked{% endif %}>
                    <label class="form-check-label">Active</label>
                </div>
                <div class="form-check">
                    <input type="checkbox" name="is_verified" class="form-check-input" {% if user.is_verified %}checked{% endif %}>
                    <label class="form-check-label">Verified</label>
                </div>
                <button type="submit" class="btn btn-primary mt-3">Update Voter</button>
            </div>
        </div>
    </form>

    <hr>
    <h4>Voting History</h4>
    <div class="list-group">
        {% for vote in voting_history %}
            <div class="list-group-item d-flex justify-content-between">
                <span>{{ vote.election.title }}</span>
                <span class="text-muted">{{ vote.created_at.strftime('%b %d, %Y') }}</span>
            </div>
        {% else %}
            <p class="text-muted">No voting history.</p>
        {% endfor %}
    </div>
</div>
{% endblock %}
'''

ADMIN_ELECTIONS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Manage Elections{% endblock %}
{% block content %}
<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2>Elections</h2>
        <a href="{{ url_for('admin_create_election') }}" class="btn btn-primary">
            <i class="bi bi-plus-circle me-1"></i>Create New Election
        </a>
    </div>

    <form method="GET" class="mb-3">
        <div class="row">
            <div class="col-md-3">
                <select name="status" class="form-control" onchange="this.form.submit()">
                    <option value="">All Status</option>
                    <option value="draft" {% if filter_status=='draft' %}selected{% endif %}>Draft</option>
                    <option value="scheduled" {% if filter_status=='scheduled' %}selected{% endif %}>Scheduled</option>
                    <option value="active" {% if filter_status=='active' %}selected{% endif %}>Active</option>
                    <option value="closed" {% if filter_status=='closed' %}selected{% endif %}>Closed</option>
                    <option value="results_published" {% if filter_status=='results_published' %}selected{% endif %}>Published</option>
                    <option value="archived" {% if filter_status=='archived' %}selected{% endif %}>Archived</option>
                </select>
            </div>
            <div class="col-md-1">
                <a href="{{ url_for('admin_elections') }}" class="btn btn-outline-secondary">Clear</a>
            </div>
        </div>
    </form>

    {% if elections %}
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Type</th>
                        <th>Start (Nigeria Time)</th>
                        <th>End (Nigeria Time)</th>
                        <th>Status</th>
                        <th>Votes</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in elections %}
                    <tr>
                        <td>{{ item.election.title }}</td>
                        <td>{{ item.election.election_type }}</td>
                        <td>{{ item.local_start.strftime('%Y-%m-%d %H:%M') }}</td>
                        <td>{{ item.local_end.strftime('%Y-%m-%d %H:%M') }}</td>
                        <td>
                            {% set status = item.election.get_status() %}
                            <span class="badge badge-{{ status }}">{{ status }}</span>
                        </td>
                        <td>{{ item.vote_count }}</td>
                        <td>
                            <a href="{{ url_for('admin_edit_election', election_id=item.election.id) }}" class="btn btn-sm btn-primary">Edit</a>
                            <form method="POST" action="{{ url_for('admin_update_election_status', election_id=item.election.id) }}" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <select name="status" onchange="this.form.submit()" class="form-select form-select-sm d-inline-block w-auto">
                                    <option value="draft" {% if item.election.status=='draft' %}selected{% endif %}>Draft</option>
                                    <option value="scheduled" {% if item.election.status=='scheduled' %}selected{% endif %}>Scheduled</option>
                                    <option value="active" {% if item.election.status=='active' %}selected{% endif %}>Active</option>
                                    <option value="closed" {% if item.election.status=='closed' %}selected{% endif %}>Closed</option>
                                    <option value="results_published" {% if item.election.status=='results_published' %}selected{% endif %}>Publish</option>
                                    <option value="archived" {% if item.election.status=='archived' %}selected{% endif %}>Archive</option>
                                </select>
                            </form>
                            <a href="{{ url_for('admin_view_results', election_id=item.election.id) }}" class="btn btn-sm btn-success">Results</a>
                            <a href="{{ url_for('admin_eligibility', election_id=item.election.id) }}" class="btn btn-sm btn-info">Eligibility</a>
                            {% if item.vote_count == 0 %}
                                <form method="POST" action="{{ url_for('admin_delete_election', election_id=item.election.id) }}" style="display:inline;" onsubmit="return confirm('Delete this election? All positions and candidates will also be deleted. This cannot be undone.')">
                                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                    <button type="submit" class="btn btn-sm btn-danger">Delete</button>
                                </form>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    {% else %}
        <div class="alert alert-info text-center py-4">
            <i class="bi bi-inbox" style="font-size:2rem;display:block;margin-bottom:10px;"></i>
            No elections found. <a href="{{ url_for('admin_create_election') }}">Create one now</a>.
        </div>
    {% endif %}
</div>
{% endblock %}
'''

# ============================================================================
# PART21: ADMIN_CREATE_ELECTION_TEMPLATE 
# ============================================================================

ADMIN_CREATE_ELECTION_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Create Election{% endblock %}
{% block content %}
<div class="container">
    <div class="create-election-header">
        <h2><i class="bi bi-plus-circle-fill me-2"></i>Create New Election</h2>
        <p class="text-muted">Fill in the details below to create a new election. Positions will be auto-created based on the election type.</p>
    </div>

    <div class="row">
        <div class="col-lg-8">
            <div class="card">
                <div class="card-body">
                    <form method="POST" id="createElectionForm">
                        {{ form.hidden_tag() }}
                        
                        <div class="form-group">
                            {{ form.title.label }}
                            {{ form.title(class="form-control form-control-lg", placeholder="Enter election title") }}
                            {% if form.title.errors %}
                                <div class="text-danger">{{ form.title.errors[0] }}</div>
                            {% endif %}
                        </div>
                        
                        <div class="form-group">
                            {{ form.description.label }}
                            {{ form.description(class="form-control", rows=4, placeholder="Describe the purpose of this election") }}
                            {% if form.description.errors %}
                                <div class="text-danger">{{ form.description.errors[0] }}</div>
                            {% endif %}
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    {{ form.election_type.label }}
                                    {{ form.election_type(class="form-control", id="election_type") }}
                                    {% if form.election_type.errors %}
                                        <div class="text-danger">{{ form.election_type.errors[0] }}</div>
                                    {% endif %}
                                    <small class="text-muted">Positions will be auto-generated based on this type.</small>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Position Preview</label>
                                    <div class="position-preview" id="positionPreview">
                                        <span class="text-muted">Select a type to see positions</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    {{ form.start_date.label }}
                                    {{ form.start_date(class="form-control", type="datetime-local", id="start_date") }}
                                    {% if form.start_date.errors %}
                                        <div class="text-danger">{{ form.start_date.errors[0] }}</div>
                                    {% endif %}
                                    <small class="text-muted">Nigeria time (WAT - UTC+1)</small>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    {{ form.end_date.label }}
                                    {{ form.end_date(class="form-control", type="datetime-local", id="end_date") }}
                                    {% if form.end_date.errors %}
                                        <div class="text-danger">{{ form.end_date.errors[0] }}</div>
                                    {% endif %}
                                    <small class="text-muted">Nigeria time (WAT - UTC+1)</small>
                                </div>
                            </div>
                        </div>
                        
                        <div class="form-actions">
                            <button type="submit" class="btn btn-primary btn-lg">
                                <i class="bi bi-check-circle me-2"></i>Create Election
                            </button>
                            <a href="{{ url_for('admin_elections') }}" class="btn btn-outline-secondary btn-lg">Cancel</a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <div class="col-lg-4">
            <div class="card bg-light">
                <div class="card-body">
                    <h5><i class="bi bi-info-circle me-2"></i>Information</h5>
                    <ul class="list-unstyled">
                        <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i> Positions auto-created based on election type</li>
                        <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i> You can add/remove positions later</li>
                        <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i> You can add candidates after creation</li>
                        <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i> Set status to 'active' when ready</li>
                    </ul>
                    <hr>
                    <h6>Position Types by Election Type:</h6>
                    <div id="positionTypeInfo">
                        <p><strong>Student:</strong> President, VP, Secretary, Treasurer, Directors, Representatives</p>
                        <p><strong>Faculty:</strong> Faculty President, VP, Secretary, Treasurer, Directors</p>
                        <p><strong>Department:</strong> Dept. President, VP, Secretary, Treasurer, PRO</p>
                        <p><strong>General:</strong> Chairperson, Vice, Secretary, Treasurer, PRO</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Date defaults
    const startInput = document.getElementById('start_date');
    const endInput = document.getElementById('end_date');
    
    if (startInput && !startInput.value) {
        const now = new Date();
        now.setDate(now.getDate() + 1);
        startInput.value = now.toISOString().slice(0, 16);
    }
    if (endInput && !endInput.value) {
        const now = new Date();
        now.setDate(now.getDate() + 8);
        endInput.value = now.toISOString().slice(0, 16);
    }
    
    // Position preview based on election type
    const typeSelect = document.getElementById('election_type');
    const previewDiv = document.getElementById('positionPreview');
    
    const positionsMap = {
        'student': ['President', 'Vice President', 'Secretary General', 'Assistant Secretary', 'Treasurer', 'Financial Secretary', 'Public Relations Officer', 'Assistant PRO', 'Director of Socials', 'Director of Sports', 'Director of Welfare', 'Director of Academics', 'Faculty Representative', 'Departmental Representative', 'Hall Representative', 'Class Representative'],
        'faculty': ['Faculty President', 'Faculty Vice President', 'Faculty Secretary', 'Faculty Treasurer', 'Faculty PRO', 'Faculty Social Director', 'Faculty Sports Director', 'Faculty Academic Director', 'Faculty Representative'],
        'department': ['Departmental President', 'Departmental Vice President', 'Departmental Secretary', 'Departmental Treasurer', 'Departmental PRO', 'Departmental Social Director', 'Departmental Sports Director', 'Academic Representative'],
        'general': ['Chairperson', 'Vice Chairperson', 'Secretary', 'Treasurer', 'Public Relations Officer', 'Member', 'Member', 'Member'],
        'other': ['President', 'Vice President', 'Secretary', 'Treasurer', 'Public Relations Officer']
    };
    
    typeSelect.addEventListener('change', function() {
        const type = this.value;
        const positions = positionsMap[type] || [];
        if (positions.length > 0) {
            previewDiv.innerHTML = '<span class="badge bg-success">' + positions.join('</span> <span class="badge bg-success">') + '</span>';
        } else {
            previewDiv.innerHTML = '<span class="text-muted">No positions defined for this type</span>';
        }
    });
    
    // Trigger change to show default
    typeSelect.dispatchEvent(new Event('change'));
});
</script>

<style>
.create-election-header {
    padding: 20px 0;
    margin-bottom: 25px;
}
.create-election-header h2 {
    font-weight: 700;
}
.position-preview {
    min-height: 40px;
    padding: 8px 12px;
    background: var(--secondary-bg);
    border-radius: 6px;
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
}
.position-preview .badge {
    font-size: 0.85rem;
    padding: 6px 12px;
}
.form-actions {
    margin-top: 25px;
    display: flex;
    gap: 15px;
}
[data-theme="dark"] .bg-light {
    background: var(--card-bg) !important;
}
</style>
{% endblock %}
'''

ADMIN_EDIT_ELECTION_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Edit Election{% endblock %}
{% block content %}
<div class="container-fluid">
    <div class="page-header">
        <div>
            <h1 class="page-title"><i class="bi bi-pencil-square me-2"></i>Edit Election</h1>
            <p class="page-subtitle">{{ election.title }}</p>
        </div>
        <a href="{{ url_for('admin_elections') }}" class="btn btn-outline-secondary">
            <i class="bi bi-arrow-left me-1"></i>Back
        </a>
    </div>

    <!-- Quick Actions -->
    <div class="action-bar">
        <a href="{{ url_for('admin_create_position', election_id=election.id) }}" class="action-btn action-btn-success">
            <i class="bi bi-plus-circle-fill"></i>
            <span>Add New Position</span>
            <small>{{ positions|length }} positions</small>
        </a>
        <a href="{{ url_for('admin_create_candidate', election_id=election.id) }}" class="action-btn action-btn-primary">
            <i class="bi bi-person-plus-fill"></i>
            <span>Add Candidate</span>
            <small>{{ total_candidates }} candidates</small>
        </a>
        <a href="{{ url_for('admin_eligibility', election_id=election.id) }}" class="action-btn action-btn-info">
            <i class="bi bi-people-fill"></i>
            <span>Eligibility</span>
            <small>Manage voters</small>
        </a>
        <a href="{{ url_for('admin_view_results', election_id=election.id) }}" class="action-btn action-btn-warning">
            <i class="bi bi-bar-chart-fill"></i>
            <span>Results</span>
            <small>View / Publish</small>
        </a>
    </div>

    <div class="row g-4">
        <div class="col-lg-7">
            <!-- Election Details Form -->
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="bi bi-info-circle me-2"></i>Election Details</h5>
                </div>
                <div class="card-body">
                    <form method="POST">
                        {{ form.hidden_tag() }}
                        <div class="form-group">
                            {{ form.title.label }}
                            {{ form.title(class="form-control") }}
                        </div>
                        <div class="form-group">
                            {{ form.description.label }}
                            {{ form.description(class="form-control", rows=3) }}
                        </div>
                        <div class="form-group">
                            {{ form.election_type.label }}
                            {{ form.election_type(class="form-control") }}
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    {{ form.start_date.label }}
                                    {{ form.start_date(class="form-control", type="datetime-local") }}
                                    <small class="text-muted">Nigeria time (WAT - UTC+1)</small>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    {{ form.end_date.label }}
                                    {{ form.end_date(class="form-control", type="datetime-local") }}
                                    <small class="text-muted">Nigeria time (WAT - UTC+1)</small>
                                </div>
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-check-circle me-1"></i>Save Changes
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-lg-5">
            <!-- Election Summary -->
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="bi bi-clipboard-data me-2"></i>Summary</h5>
                </div>
                <div class="card-body">
                    <div class="summary-item">
                        <span><i class="bi bi-flag-fill text-primary"></i> Status</span>
                        <span class="badge badge-{{ election.get_status() }}">{{ election.get_status()|capitalize }}</span>
                    </div>
                    <div class="summary-item">
                        <span><i class="bi bi-list-check text-success"></i> Positions</span>
                        <strong>{{ positions|length }}</strong>
                    </div>
                    <div class="summary-item">
                        <span><i class="bi bi-person-badge text-info"></i> Candidates</span>
                        <strong>{{ total_candidates }}</strong>
                    </div>
                    <div class="summary-item">
                        <span><i class="bi bi-check-circle text-warning"></i> Votes Cast</span>
                        <strong>{{ election.get_vote_count() }}</strong>
                    </div>
                    <div class="summary-item">
                        <span><i class="bi bi-calendar-event text-danger"></i> Starts</span>
                        <strong>{{ utc_to_ng(election.start_date).strftime('%b %d, %Y') }}</strong>
                    </div>
                    <div class="summary-item">
                        <span><i class="bi bi-calendar-x text-muted"></i> Ends</span>
                        <strong>{{ utc_to_ng(election.end_date).strftime('%b %d, %Y') }}</strong>
                    </div>
                </div>
            </div>

            <!-- Info Card -->
            <div class="card info-card">
                <div class="card-body">
                    <h6><i class="bi bi-lightbulb-fill me-2"></i>Good to Know</h6>
                    <ul class="info-list">
                        <li><i class="bi bi-check2"></i> Positions were auto-created based on the election type</li>
                        <li><i class="bi bi-check2"></i> You only need 1 candidate per position to open voting</li>
                        <li><i class="bi bi-check2"></i> Positions without candidates are skipped automatically</li>
                        <li><i class="bi bi-check2"></i> Candidates are automatically eligible to vote</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
.page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
    flex-wrap: wrap;
    gap: 12px;
}
.page-title {
    font-size: 1.75rem;
    font-weight: 700;
    margin: 0;
    color: var(--text-primary);
}
.page-subtitle { color: var(--text-muted); margin: 4px 0 0 0; font-size: 0.95rem; }

.action-bar {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}
.action-btn {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    padding: 20px;
    border-radius: 12px;
    text-decoration: none;
    color: #fff;
    transition: transform 0.2s, box-shadow 0.2s;
    box-shadow: 0 4px 6px rgba(0,0,0,0.08);
}
.action-btn:hover { transform: translateY(-4px); box-shadow: 0 12px 24px rgba(0,0,0,0.15); color: #fff; text-decoration: none; }
.action-btn i { font-size: 1.75rem; margin-bottom: 10px; opacity: 0.9; }
.action-btn span { font-size: 1rem; font-weight: 700; margin-bottom: 2px; }
.action-btn small { opacity: 0.85; font-size: 0.78rem; }
.action-btn-success { background: linear-gradient(135deg, #10b981 0%, #059669 100%); }
.action-btn-primary { background: linear-gradient(135deg, #3b82f6 0%, #1e40af 100%); }
.action-btn-info { background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%); }
.action-btn-warning { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }

.summary-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 0;
    border-bottom: 1px solid var(--border-color);
    font-size: 0.95rem;
}
.summary-item:last-child { border-bottom: none; }
.summary-item i { margin-right: 8px; }

.info-card {
    background: linear-gradient(135deg, rgba(59,130,246,0.08), rgba(168,85,247,0.08));
    border: 1px solid rgba(59,130,246,0.2);
}
.info-list { list-style: none; padding: 0; margin: 12px 0 0; }
.info-list li { padding: 6px 0; font-size: 0.9rem; display: flex; align-items: flex-start; gap: 8px; }
.info-list i { color: var(--teal); flex-shrink: 0; margin-top: 3px; }
</style>
{% endblock %}
'''

ADMIN_CREATE_POSITION_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Add Position{% endblock %}
{% block content %}
<div class="container">
    <h2>Add Position to {{ election.title }}</h2>
    <div class="card">
        <div class="card-body">
            <form method="POST">
                {{ form.hidden_tag() }}
                <div class="form-group">
                    {{ form.title.label }}
                    {{ form.title(class="form-control") }}
                    {% if form.title.errors %}
                        <div class="text-danger">{{ form.title.errors[0] }}</div>
                    {% endif %}
                </div>
                <div class="form-group">
                    {{ form.description.label }}
                    {{ form.description(class="form-control", rows=3) }}
                    {% if form.description.errors %}
                        <div class="text-danger">{{ form.description.errors[0] }}</div>
                    {% endif %}
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            {{ form.max_selections.label }}
                            {{ form.max_selections(class="form-control") }}
                            {% if form.max_selections.errors %}
                                <div class="text-danger">{{ form.max_selections.errors[0] }}</div>
                            {% endif %}
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            {{ form.order.label }}
                            {{ form.order(class="form-control") }}
                            {% if form.order.errors %}
                                <div class="text-danger">{{ form.order.errors[0] }}</div>
                            {% endif %}
                        </div>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">Add Position</button>
                <a href="{{ url_for('admin_edit_election', election_id=election.id) }}" class="btn btn-outline">Cancel</a>
            </form>
        </div>
    </div>
</div>
{% endblock %}
'''

ADMIN_EDIT_POSITION_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Edit Position{% endblock %}
{% block content %}
<div class="container">
    <h2>Edit Position: {{ position.title }}</h2>
    <div class="card">
        <div class="card-body">
            <form method="POST">
                {{ form.hidden_tag() }}
                <div class="form-group">
                    {{ form.title.label }}
                    {{ form.title(class="form-control") }}
                    {% if form.title.errors %}
                        <div class="text-danger">{{ form.title.errors[0] }}</div>
                    {% endif %}
                </div>
                <div class="form-group">
                    {{ form.description.label }}
                    {{ form.description(class="form-control", rows=3) }}
                    {% if form.description.errors %}
                        <div class="text-danger">{{ form.description.errors[0] }}</div>
                    {% endif %}
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            {{ form.max_selections.label }}
                            {{ form.max_selections(class="form-control") }}
                            {% if form.max_selections.errors %}
                                <div class="text-danger">{{ form.max_selections.errors[0] }}</div>
                            {% endif %}
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            {{ form.order.label }}
                            {{ form.order(class="form-control") }}
                            {% if form.order.errors %}
                                <div class="text-danger">{{ form.order.errors[0] }}</div>
                            {% endif %}
                        </div>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">Update Position</button>
                <a href="{{ url_for('admin_edit_election', election_id=election.id) }}" class="btn btn-outline">Cancel</a>
            </form>
        </div>
    </div>
</div>
{% endblock %}
'''

ADMIN_CREATE_CANDIDATE_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Add Candidate{% endblock %}
{% block content %}
<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2>Add Candidate to <strong>{{ election.title }}</strong></h2>
        <a href="{{ url_for('admin_edit_election', election_id=election.id) }}" class="btn btn-outline-secondary">
            <i class="bi bi-arrow-left me-1"></i>Back to Election
        </a>
    </div>

    <div class="card">
        <div class="card-body">
            <form method="POST" enctype="multipart/form-data" id="candidateForm">
                {{ form.hidden_tag() }}

                <!-- Voter Selection -->
                <div class="form-group">
                    <label>Select Registered Voter <span class="text-danger">*</span></label>
                    <select name="voter_id" id="voterSelect" class="form-control select2" required>
                        <option value="">-- Search by name or registration number --</option>
                        {% for v in voter_list %}
                            <option value="{{ v.id }}"
                                    data-name="{{ v.full_name }}"
                                    data-reg="{{ v.registration_number }}"
                                    data-dept="{{ v.department }}"
                                    data-faculty="{{ v.faculty }}"
                                    data-level="{{ v.level }}"
                                    data-photo="{{ v.photo }}">
                                {{ v.full_name }} — {{ v.registration_number }} ({{ v.username }})
                            </option>
                        {% endfor %}
                    </select>
                    <small class="text-muted">All fields below will auto-fill from the selected voter's profile.</small>
                </div>

                <!-- Auto-filled Preview Card -->
                <div id="voterPreview" class="voter-preview" style="display:none;">
                    <div class="preview-photo">
                        <img id="previewPhoto" src="" alt="Photo" style="width:90px;height:90px;border-radius:50%;object-fit:cover;border:3px solid var(--gold);">
                    </div>
                    <div class="preview-info">
                        <h5 id="previewName"></h5>
                        <p><i class="bi bi-card-text me-1"></i> <span id="previewReg"></span></p>
                        <p><i class="bi bi-building me-1"></i> <span id="previewDept"></span> | <span id="previewFaculty"></span></p>
                        <p><i class="bi bi-mortarboard me-1"></i> <span id="previewLevel"></span></p>
                    </div>
                </div>

                <!-- Position -->
                <div class="form-group mt-3">
                    {{ form.position_id.label }} <span class="text-danger">*</span>
                    {{ form.position_id(class="form-control") }}
                    {% if form.position_id.errors %}
                        <div class="form-error">{{ form.position_id.errors[0] }}</div>
                    {% endif %}
                </div>

                <!-- Hidden/auto-filled fields -->
                <input type="hidden" name="full_name" id="full_name" value="">
                <input type="hidden" name="department" id="department" value="">
                <input type="hidden" name="faculty" id="faculty" value="">
                <input type="hidden" name="level" id="level" value="">

                <!-- Optional custom photo override -->
                <div class="form-group">
                    <label>Override Photo (optional)</label>
                    {{ form.photo(class="form-control", accept="image/*") }}
                    <small class="text-muted">Leave empty to use the voter's profile photo.</small>
                </div>

                <!-- Manifesto -->
                <div class="form-group">
                    {{ form.manifesto.label }}
                    {{ form.manifesto(class="form-control", rows=4, placeholder="Candidate's manifesto / vision statement") }}
                </div>

                <div class="form-check mb-3">
                    {{ form.is_active(class="form-check-input") }}
                    {{ form.is_active.label(class="form-check-label") }}
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-check-circle me-1"></i>Add Candidate
                    </button>
                    <a href="{{ url_for('admin_edit_election', election_id=election.id) }}" class="btn btn-outline-secondary">Cancel</a>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Select2 for searchable dropdown -->
<link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>

<style>
.voter-preview {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 20px;
    background: var(--secondary-bg);
    border-radius: var(--radius);
    border-left: 4px solid var(--gold);
    margin-top: 15px;
}
.voter-preview h5 { margin: 0 0 8px 0; color: var(--text-primary); }
.voter-preview p { margin: 3px 0; color: var(--text-secondary); font-size: 0.9rem; }
.preview-info { flex: 1; }
.form-actions { display: flex; gap: 12px; margin-top: 20px; }
.select2-container { width: 100% !important; }
.select2-container .select2-selection--single { height: 46px !important; padding: 8px 12px; border: 2px solid var(--border-color); border-radius: var(--radius-sm); }
.select2-container--default .select2-selection--single .select2-selection__rendered { line-height: 28px; color: var(--text-primary); }
.select2-container--default .select2-selection--single .select2-selection__arrow { height: 44px; }
[data-theme="dark"] .select2-container--default .select2-selection--single { background: var(--card-bg); border-color: var(--border-color); }
[data-theme="dark"] .select2-dropdown { background: var(--card-bg); border-color: var(--border-color); color: var(--text-primary); }
[data-theme="dark"] .select2-results__option { color: var(--text-primary); }
[data-theme="dark"] .select2-search__field { background: var(--secondary-bg); color: var(--text-primary); border-color: var(--border-color); }
</style>

<script>
$(document).ready(function() {
    $('.select2').select2({
        placeholder: "-- Search by name or registration number --",
        allowClear: true
    });

    // Auto-fill when voter selected
    $('#voterSelect').on('change', function() {
        const opt = $(this).find(':selected');
        if (!opt.val()) {
            $('#voterPreview').hide();
            return;
        }
        const name = opt.data('name') || '';
        const reg = opt.data('reg') || '';
        const dept = opt.data('dept') || '';
        const faculty = opt.data('faculty') || '';
        const level = opt.data('level') || '';
        const photo = opt.data('photo') || '';

        $('#previewName').text(name);
        $('#previewReg').text(reg);
        $('#previewDept').text(dept);
        $('#previewFaculty').text(faculty);
        $('#previewLevel').text(level ? level + ' Level' : 'N/A');

        if (photo) {
            $('#previewPhoto').attr('src', '/static/uploads/' + photo).show();
        } else {
            $('#previewPhoto').attr('src', 'https://via.placeholder.com/90?text=No+Photo').show();
        }
        $('#voterPreview').show();

        // Populate hidden fields
        $('#full_name').val(name);
        $('#department').val(dept);
        $('#faculty').val(faculty);
        $('#level').val(level);
    });

    // Trigger on page load if preselected
    if ($('#voterSelect').val()) {
        $('#voterSelect').trigger('change');
    }
});
</script>
{% endblock %}
'''

ADMIN_EDIT_CANDIDATE_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Edit Candidate{% endblock %}
{% block content %}
<div class="container">
    <h2>Edit Candidate: {{ candidate.full_name }}</h2>
    <div class="card">
        <div class="card-body">
            <form method="POST" enctype="multipart/form-data">
                {{ form.hidden_tag() }}
                <div class="row">
                    <div class="col-md-3 text-center">
                        {% if candidate.photo %}
                            <img src="{{ url_for('static', filename='uploads/' ~ candidate.photo) }}" alt="{{ candidate.full_name }}" style="width:120px;height:120px;border-radius:50%;object-fit:cover;">
                        {% else %}
                            <i class="bi bi-person-circle" style="font-size:80px;color:var(--text-muted);"></i>
                        {% endif %}
                    </div>
                    <div class="col-md-9">
                        <div class="form-group">
                            {{ form.position_id.label }}
                            {{ form.position_id(class="form-control") }}
                            {% if form.position_id.errors %}
                                <div class="text-danger">{{ form.position_id.errors[0] }}</div>
                            {% endif %}
                        </div>
                        <div class="form-group">
                            {{ form.full_name.label }}
                            {{ form.full_name(class="form-control") }}
                            {% if form.full_name.errors %}
                                <div class="text-danger">{{ form.full_name.errors[0] }}</div>
                            {% endif %}
                        </div>
                        <div class="form-group">
                            {{ form.photo.label }}
                            {{ form.photo(class="form-control") }}
                            {% if form.photo.errors %}
                                <div class="text-danger">{{ form.photo.errors[0] }}</div>
                            {% endif %}
                        </div>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-4">
                        <div class="form-group">
                            {{ form.department.label }}
                            {{ form.department(class="form-control") }}
                            {% if form.department.errors %}
                                <div class="text-danger">{{ form.department.errors[0] }}</div>
                            {% endif %}
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="form-group">
                            {{ form.faculty.label }}
                            {{ form.faculty(class="form-control") }}
                            {% if form.faculty.errors %}
                                <div class="text-danger">{{ form.faculty.errors[0] }}</div>
                            {% endif %}
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="form-group">
                            {{ form.level.label }}
                            {{ form.level(class="form-control") }}
                            {% if form.level.errors %}
                                <div class="text-danger">{{ form.level.errors[0] }}</div>
                            {% endif %}
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    {{ form.manifesto.label }}
                    {{ form.manifesto(class="form-control", rows=4) }}
                    {% if form.manifesto.errors %}
                        <div class="text-danger">{{ form.manifesto.errors[0] }}</div>
                    {% endif %}
                </div>
                <div class="form-check">
                    {{ form.is_active(class="form-check-input") }}
                    {{ form.is_active.label(class="form-check-label") }}
                </div>
                <button type="submit" class="btn btn-primary mt-3">Update Candidate</button>
                <a href="{{ url_for('admin_edit_election', election_id=election.id) }}" class="btn btn-outline mt-3">Cancel</a>
            </form>
        </div>
    </div>
</div>
{% endblock %}
'''
# ============================================================================
# PART22: ADMIN_RESULTS_TEMPLATE  
# ============================================================================

ADMIN_RESULTS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Results - {{ election.title }}{% endblock %}
{% block content %}
<div class="container">
    <h2>Results: {{ election.title }}</h2>
    <div class="row stats-row">
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="number">{{ result.total_votes }}</div>
                <div class="label">Total Votes</div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="number">{{ result.registered_voters }}</div>
                <div class="label">Registered Voters</div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="number">{{ result.participation_rate|round(1) }}%</div>
                <div class="label">Participation</div>
            </div>
        </div>
    </div>

    {% if election.status != 'results_published' %}
        <div class="alert alert-info">
            Results are calculated but not published.
            <form method="POST" action="{{ url_for('admin_publish_results', election_id=election.id) }}" style="display:inline;">
                {{ csrf_token() }}
                <button type="submit" class="btn btn-success">Publish Results</button>
            </form>
        </div>
    {% else %}
        <div class="alert alert-success">✅ Results are published and visible to voters.</div>
    {% endif %}

    <hr>
    {% for position_data in result.results_data %}
        <div class="card mt-3">
            <div class="card-header">
                <h4>{{ position_data.position_title }}</h4>
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Candidate</th>
                            <th>Votes</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for candidate in position_data.candidates %}
                            <tr>
                                <td>{{ candidate.candidate_name }}</td>
                                <td>{{ candidate.vote_count }}</td>
                                <td>{{ (candidate.vote_count / result.total_votes * 100)|round(1) if result.total_votes > 0 else 0 }}%</td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    {% endfor %}

    <div class="mt-4">
        <a href="{{ url_for('admin_elections') }}" class="btn btn-outline">Back to Elections</a>
        <a href="{{ url_for('results_view', election_id=election.id) }}" class="btn btn-secondary">View Public Results</a>
    </div>
</div>
{% endblock %}
'''

ADMIN_AUDIT_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Audit Log{% endblock %}
{% block content %}
<div class="container">
    <h2>Audit Log</h2>
    <div class="card">
        <div class="card-body">
            <form method="GET" class="row mb-3">
                <div class="col-md-3">
                    <select name="action" class="form-control">
                        <option value="">All Actions</option>
                        {% for a in actions %}
                            <option value="{{ a }}" {% if action == a %}selected{% endif %}>{{ a }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="col-md-2">
                    <input type="text" name="user_id" placeholder="User ID" value="{{ user_id }}" class="form-control">
                </div>
                <div class="col-md-2">
                    <input type="date" name="date_from" value="{{ date_from }}" class="form-control">
                </div>
                <div class="col-md-2">
                    <input type="date" name="date_to" value="{{ date_to }}" class="form-control">
                </div>
                <div class="col-md-3">
                    <button type="submit" class="btn btn-primary">Filter</button>
                    <a href="{{ url_for('admin_audit') }}" class="btn btn-outline">Clear</a>
                </div>
            </form>

            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>User</th>
                        <th>Action</th>
                        <th>Description</th>
                        <th>IP</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs.items %}
                    <tr>
                        <td>{{ log.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                        <td>{{ log.user_id or 'System' }}</td>
                        <td><span class="badge badge-{{ log.get_action_color() }}">{{ log.action }}</span></td>
                        <td>{{ log.description }}</td>
                        <td>{{ log.ip_address }}</td>
                        <td>
                            {% if log.success %}
                                <span class="badge badge-success">Success</span>
                            {% else %}
                                <span class="badge badge-danger">Failed</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {{ logs.links }}
        </div>
    </div>
</div>
{% endblock %}
'''

ADMIN_SECURITY_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Security Dashboard{% endblock %}
{% block content %}
<div class="container">
    <h2>Security Dashboard</h2>
    <div class="row">
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="number">{{ failed_count }}</div>
                <div class="label">Failed Logins (24h)</div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="number">{{ locked_users|length }}</div>
                <div class="label">Locked Accounts</div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="number">{{ security_logs|length }}</div>
                <div class="label">Recent Security Events</div>
            </div>
        </div>
    </div>

    <div class="card mt-4">
        <div class="card-header">Locked Accounts</div>
        <div class="card-body">
            {% if locked_users %}
                <ul class="list-group">
                    {% for user in locked_users %}
                        <li class="list-group-item d-flex justify-content-between">
                            <span>{{ user.username }}</span>
                            <span class="text-muted">Locked until {{ user.locked_until.strftime('%Y-%m-%d %H:%M') }}</span>
                        </li>
                    {% endfor %}
                </ul>
            {% else %}
                <p class="text-muted">No locked accounts.</p>
            {% endif %}
        </div>
    </div>

    <div class="card mt-4">
        <div class="card-header">Recent Security Events</div>
        <div class="card-body">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Action</th>
                        <th>User</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in security_logs %}
                    <tr>
                        <td>{{ log.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                        <td><span class="badge badge-{{ log.get_action_color() }}">{{ log.action }}</span></td>
                        <td>{{ log.user_id or 'System' }}</td>
                        <td>{{ log.description }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endblock %}
'''

ADMIN_REPORTS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Reports{% endblock %}
{% block content %}
<div class="container">
    <h2>Reports</h2>
    <div class="card">
        <div class="card-body">
            <form method="GET" class="row mb-3">
                <div class="col-md-3">
                    <select name="type" class="form-control" onchange="this.form.submit()">
                        <option value="participation" {% if report_type == 'participation' %}selected{% endif %}>Participation</option>
                        <option value="turnout" {% if report_type == 'turnout' %}selected{% endif %}>Turnout</option>
                        <option value="candidates" {% if report_type == 'candidates' %}selected{% endif %}>Candidates</option>
                    </select>
                </div>
                {% if report_type == 'candidates' %}
                <div class="col-md-3">
                    <select name="election_id" class="form-control" onchange="this.form.submit()">
                        <option value="">Select Election</option>
                        {% for e in Election.query.all() %}
                            <option value="{{ e.id }}" {% if election and election.id == e.id %}selected{% endif %}>{{ e.title }}</option>
                        {% endfor %}
                    </select>
                </div>
                {% endif %}
            </form>

            {% if report_type == 'participation' %}
                <h4>Voter Participation by Department</h4>
                <table class="table">
                    <thead>
                        <tr><th>Department</th><th>Voters</th></tr>
                    </thead>
                    <tbody>
                        {% for item in data %}
                            <tr><td>{{ item.department }}</td><td>{{ item.count }}</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% elif report_type == 'turnout' %}
                <h4>Turnout per Election</h4>
                <table class="table">
                    <thead>
                        <tr><th>Election</th><th>Votes</th><th>Turnout %</th></tr>
                    </thead>
                    <tbody>
                        {% for item in data %}
                            <tr><td>{{ item.election }}</td><td>{{ item.votes }}</td><td>{{ item.turnout|round(1) }}%</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% elif report_type == 'candidates' %}
                <h4>Candidate Votes</h4>
                {% if data %}
                    <table class="table">
                        <thead>
                            <tr><th>Position</th><th>Candidate</th><th>Votes</th></tr>
                        </thead>
                        <tbody>
                            {% for item in data %}
                                <tr><td>{{ item.position }}</td><td>{{ item.candidate }}</td><td>{{ item.votes }}</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p class="text-muted">No data available. Please select an election.</p>
                {% endif %}
            {% endif %}
        </div>
    </div>
</div>
{% endblock %}
'''

ADMIN_SETTINGS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}System Settings{% endblock %}
{% block content %}
<div class="container">
    <h2>System Settings</h2>
    <div class="card">
        <div class="card-body">
            <form method="POST">
                <div class="form-group">
                    <label>System Name</label>
                    <input type="text" name="system_name" class="form-control" value="{{ settings.system_name }}">
                </div>
                <div class="form-group">
                    <label>System Tagline</label>
                    <input type="text" name="system_tagline" class="form-control" value="{{ settings.system_tagline }}">
                </div>
                <div class="form-check">
                    <input type="checkbox" name="maintenance_mode" class="form-check-input" {% if settings.maintenance_mode %}checked{% endif %}>
                    <label class="form-check-label">Maintenance Mode</label>
                </div>
                <div class="form-check">
                    <input type="checkbox" name="voter_registration_open" class="form-check-input" {% if settings.voter_registration_open %}checked{% endif %}>
                    <label class="form-check-label">Voter Registration Open</label>
                </div>
                <button type="submit" class="btn btn-primary mt-3">Save Settings</button>
            </form>
        </div>
    </div>
</div>
{% endblock %}
'''

# ============================================================================
# ERROR PAGES TEMPLATES
# ============================================================================

ERROR_404_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}404 - Page Not Found{% endblock %}
{% block content %}
<div class="container text-center error-page">
    <div class="card">
        <div class="card-body py-5">
            <h1 class="display-1 text-muted">404</h1>
            <h2>Page Not Found</h2>
            <p>The page you are looking for does not exist.</p>
            <a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
        </div>
    </div>
</div>
{% endblock %}
'''

ERROR_403_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}403 - Forbidden{% endblock %}
{% block content %}
<div class="container text-center error-page">
    <div class="card">
        <div class="card-body py-5">
            <h1 class="display-1 text-muted">403</h1>
            <h2>Access Denied</h2>
            <p>You do not have permission to access this page.</p>
            <a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
        </div>
    </div>
</div>
{% endblock %}
'''

ERROR_500_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}500 - Server Error{% endblock %}
{% block content %}
<div class="container text-center error-page">
    <div class="card">
        <div class="card-body py-5">
            <h1 class="display-1 text-muted">500</h1>
            <h2>Server Error</h2>
            <p>Something went wrong on our end. Please try again later.</p>
            <a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
        </div>
    </div>
</div>
{% endblock %}
'''

ERROR_400_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}400 - Bad Request{% endblock %}
{% block content %}
<div class="container text-center error-page">
    <div class="card">
        <div class="card-body py-5">
            <h1 class="display-1 text-muted">400</h1>
            <h2>Bad Request</h2>
            <p>The request could not be processed.</p>
            <a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
        </div>
    </div>
</div>
{% endblock %}
'''

ERROR_401_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}401 - Unauthorized{% endblock %}
{% block content %}
<div class="container text-center error-page">
    <div class="card">
        <div class="card-body py-5">
            <h1 class="display-1 text-muted">401</h1>
            <h2>Unauthorized</h2>
            <p>Please log in to access this page.</p>
            <a href="{{ url_for('auth_login') }}" class="btn btn-primary">Login</a>
        </div>
    </div>
</div>
{% endblock %}
'''

ERROR_405_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}405 - Method Not Allowed{% endblock %}
{% block content %}
<div class="container text-center error-page">
    <div class="card">
        <div class="card-body py-5">
            <h1 class="display-1 text-muted">405</h1>
            <h2>Method Not Allowed</h2>
            <p>The HTTP method used is not allowed for this endpoint.</p>
            <a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
        </div>
    </div>
</div>
{% endblock %}
'''

ERROR_429_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}429 - Too Many Requests{% endblock %}
{% block content %}
<div class="container text-center error-page">
    <div class="card">
        <div class="card-body py-5">
            <h1 class="display-1 text-muted">429</h1>
            <h2>Too Many Requests</h2>
            <p>You are making too many requests. Please slow down.</p>
            <a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
        </div>
    </div>
</div>
{% endblock %}
'''
# ============================================================================
#PART23: FORGOT_PASSWORD_TEMPLATE
# ============================================================================


VOTER_SETTINGS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Settings & Security{% endblock %}
{% block content %}
<div class="container">
    <div class="page-header">
        <h1 class="page-title"><i class="bi bi-shield-lock me-2"></i>Settings &amp; Security</h1>
        <p class="page-subtitle">Manage your account security and password</p>
    </div>

    <div class="row g-4">
        <div class="col-lg-8">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="bi bi-key-fill me-2"></i>Change Password</h5>
                </div>
                <div class="card-body">
                    <form method="POST">
                        {{ form.hidden_tag() }}

                        <div class="form-group">
                            {{ form.current_password.label }}
                            <div class="input-group">
                                <span class="input-group-icon"><i class="bi bi-lock"></i></span>
                                {{ form.current_password(class="form-control", id="current_password", placeholder="Enter current password") }}
                                <button type="button" class="toggle-password-btn" onclick="togglePassword('current_password')">
                                    <i class="bi bi-eye" id="current_passwordIcon"></i>
                                </button>
                            </div>
                            {% if form.current_password.errors %}
                                <div class="form-error">{{ form.current_password.errors[0] }}</div>
                            {% endif %}
                        </div>

                        <div class="form-group">
                            {{ form.new_password.label }}
                            <div class="input-group">
                                <span class="input-group-icon"><i class="bi bi-lock-fill"></i></span>
                                {{ form.new_password(class="form-control", id="new_password", placeholder="Enter new password") }}
                                <button type="button" class="toggle-password-btn" onclick="togglePassword('new_password')">
                                    <i class="bi bi-eye" id="new_passwordIcon"></i>
                                </button>
                            </div>
                            {% if form.new_password.errors %}
                                <div class="form-error">{{ form.new_password.errors[0] }}</div>
                            {% endif %}
                            <small class="text-muted">Min 6 chars with uppercase, lowercase, number &amp; special character</small>
                        </div>

                        <div class="form-group">
                            {{ form.confirm_new_password.label }}
                            <div class="input-group">
                                <span class="input-group-icon"><i class="bi bi-shield-lock-fill"></i></span>
                                {{ form.confirm_new_password(class="form-control", id="confirm_new_password", placeholder="Confirm new password") }}
                                <button type="button" class="toggle-password-btn" onclick="togglePassword('confirm_new_password')">
                                    <i class="bi bi-eye" id="confirm_new_passwordIcon"></i>
                                </button>
                            </div>
                            {% if form.confirm_new_password.errors %}
                                <div class="form-error">{{ form.confirm_new_password.errors[0] }}</div>
                            {% endif %}
                        </div>

                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-check-circle me-1"></i>Update Password
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-lg-4">
            <div class="card security-tips">
                <div class="card-header">
                    <h5 class="mb-0"><i class="bi bi-info-circle me-2"></i>Security Tips</h5>
                </div>
                <div class="card-body">
                    <ul class="tips-list">
                        <li><i class="bi bi-check-circle-fill text-success"></i> Use a unique password</li>
                        <li><i class="bi bi-check-circle-fill text-success"></i> Include numbers &amp; symbols</li>
                        <li><i class="bi bi-check-circle-fill text-success"></i> Never share your login</li>
                        <li><i class="bi bi-check-circle-fill text-success"></i> Logout on public devices</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
.page-header { margin-bottom: 24px; }
.page-title { font-size: 1.6rem; font-weight: 700; margin: 0; }
.page-subtitle { color: var(--text-muted); margin: 4px 0 0; font-size: 0.92rem; }
.input-group {
    display: flex; align-items: center;
    background: var(--page-bg);
    border: 2px solid var(--border-color);
    border-radius: 10px;
}
.input-group:focus-within { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(26,91,191,0.15); }
.input-group-icon { padding: 0 12px; color: var(--text-muted); font-size: 16px; }
.input-group .form-control { border: none; background: transparent; padding: 12px 12px 12px 0; flex: 1; }
.toggle-password-btn { background: none; border: none; padding: 0 12px; color: var(--text-muted); cursor: pointer; font-size: 16px; }
.toggle-password-btn:hover { color: var(--text-primary); }
.tips-list { list-style: none; padding: 0; margin: 0; }
.tips-list li { padding: 8px 0; font-size: 0.9rem; display: flex; align-items: center; gap: 8px; }
</style>

<script>
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    const icon = document.getElementById(fieldId + 'Icon');
    if (field.type === 'password') {
        field.type = 'text';
        icon.className = 'bi bi-eye-slash';
    } else {
        field.type = 'password';
        icon.className = 'bi bi-eye';
    }
}
</script>
{% endblock %}
'''

ADMIN_ELIGIBILITY_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Eligibility Management{% endblock %}
{% block content %}
<div class="container">
    <h2>Eligibility for: {{ election.title }}</h2>
    <div class="card">
        <div class="card-body">
            <table class="table">
                <thead>
                    <tr>
                        <th>Voter</th>
                        <th>Registration</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in voters_status %}
                    <tr>
                        <td>{{ item.voter.username }}</td>
                        <td>{{ item.voter.voter_profile.registration_number }}</td>
                        <td>
                            {% if item.status == 'eligible' %}
                                <span class="badge badge-success">Eligible</span>
                            {% elif item.status == 'ineligible' %}
                                <span class="badge badge-danger">Ineligible</span>
                            {% else %}
                                <span class="badge badge-secondary">Not Set</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if item.status != 'eligible' %}
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="add">
                                    <input type="hidden" name="voter_id" value="{{ item.voter.id }}">
                                    <button type="submit" class="btn btn-sm btn-success">Add</button>
                                </form>
                            {% endif %}
                            {% if item.status == 'eligible' %}
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="remove">
                                    <input type="hidden" name="voter_id" value="{{ item.voter.id }}">
                                    <button type="submit" class="btn btn-sm btn-danger">Remove</button>
                                </form>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endblock %}
'''

# ============================================================================
# DICTIONARY OF ALL TEMPLATES
# ============================================================================


ADMIN_LOGIN_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Admin Login - {{ app_name }}{% endblock %}
{% block content %}
<div class="auth-page">
    <div class="auth-container">
        <div class="auth-card admin-auth-card">
            <div class="auth-header">
                <div class="auth-logo admin-logo">
                    <i class="bi bi-shield-lock-fill"></i>
                </div>
                <h1>Administrator Login</h1>
                <p class="auth-subtitle">Secure access for election officials</p>
            </div>
            
            <form method="POST" action="{{ url_for('admin_login') }}" class="auth-form">
                {{ form.hidden_tag() }}
                
                <div class="form-group">
                    {{ form.username.label(class="form-label") }}
                    <div class="input-group">
                        <span class="input-group-icon"><i class="bi bi-person-badge"></i></span>
                        {{ form.username(class="form-control", placeholder="Admin username", autofocus=true) }}
                    </div>
                    {% if form.username.errors %}
                        <div class="form-error">{{ form.username.errors[0] }}</div>
                    {% endif %}
                </div>
                
                <div class="form-group">
                    {{ form.password.label(class="form-label") }}
                    <div class="input-group">
                        <span class="input-group-icon"><i class="bi bi-key"></i></span>
                        {{ form.password(class="form-control", id="password", placeholder="Admin password") }}
                        <button type="button" class="toggle-password-btn" onclick="togglePassword('password')">
                            <i class="bi bi-eye" id="passwordIcon"></i>
                        </button>
                    </div>
                    {% if form.password.errors %}
                        <div class="form-error">{{ form.password.errors[0] }}</div>
                    {% endif %}
                </div>
                
                <div class="form-options">
                    <label class="checkbox-label">
                        {{ form.remember_me(class="checkbox-input") }}
                        <span class="checkbox-text">Remember Me</span>
                    </label>
                </div>
                
                <button type="submit" class="btn-auth btn-admin">
                    <i class="bi bi-box-arrow-in-right"></i> Admin Sign In
                </button>
            </form>
            
            <div class="auth-footer">
                <p><a href="{{ url_for('auth_login') }}"><i class="bi bi-person me-1"></i>Voter Login</a></p>
                <p class="mt-2 text-muted" style="font-size:0.85rem;">Authorized personnel only. All login attempts are audited.</p>
            </div>
        </div>
    </div>
</div>

<style>
.admin-auth-card {
    border-top: 4px solid #dc2626;
}
.admin-logo {
    background: linear-gradient(135deg, #dc2626, #991b1b) !important;
}
.btn-admin {
    background: linear-gradient(135deg, #dc2626, #991b1b) !important;
}
.btn-admin:hover {
    box-shadow: 0 8px 25px rgba(220, 38, 38, 0.35) !important;
}
</style>

<script>
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    const icon = document.getElementById(fieldId + 'Icon');
    if (field.type === 'password') {
        field.type = 'text';
        icon.className = 'bi bi-eye-slash';
    } else {
        field.type = 'password';
        icon.className = 'bi bi-eye';
    }
}
</script>
{% endblock %}
'''


TEMPLATES = {
    'base.html': BASE_TEMPLATE,
    'auth/login.html': LOGIN_TEMPLATE,
    'auth/admin_login.html': ADMIN_LOGIN_TEMPLATE,
    'auth/register.html': REGISTER_TEMPLATE,
    'auth/forgot_password.html': FORGOT_PASSWORD_TEMPLATE,
    'auth/reset_password.html': RESET_PASSWORD_TEMPLATE,
    'main/index.html': INDEX_TEMPLATE,
    'main/about.html': ABOUT_TEMPLATE,
    'main/how_it_works.html': HOW_IT_WORKS_TEMPLATE,
    'main/features.html': FEATURES_TEMPLATE,
    'main/visual_cryptography.html': VISUAL_CRYPTOGRAPHY_TEMPLATE,
    'voter/dashboard.html': VOTER_DASHBOARD_TEMPLATE,
    'voter/profile.html': VOTER_PROFILE_TEMPLATE,
    'voter/notifications.html': VOTER_NOTIFICATIONS_TEMPLATE,
    'voter/settings.html': VOTER_SETTINGS_TEMPLATE,
    'voting/election.html': VOTING_ELECTION_TEMPLATE,
    'voting/vote.html': VOTING_VOTE_TEMPLATE,
    'voting/review.html': VOTING_REVIEW_TEMPLATE,
    'voting/confirmation.html': VOTING_CONFIRMATION_TEMPLATE,
    'results/index.html': RESULTS_INDEX_TEMPLATE,
    'results/view.html': RESULTS_VIEW_TEMPLATE,
    'admin/dashboard.html': ADMIN_DASHBOARD_TEMPLATE,
    'admin/voters.html': ADMIN_VOTERS_TEMPLATE,
    'admin/edit_voter.html': ADMIN_EDIT_VOTER_TEMPLATE,
    'admin/elections.html': ADMIN_ELECTIONS_TEMPLATE,
    'admin/create_election.html': ADMIN_CREATE_ELECTION_TEMPLATE,
    'admin/edit_election.html': ADMIN_EDIT_ELECTION_TEMPLATE,
    'admin/create_position.html': ADMIN_CREATE_POSITION_TEMPLATE,
    'admin/edit_position.html': ADMIN_EDIT_POSITION_TEMPLATE,
    'admin/create_candidate.html': ADMIN_CREATE_CANDIDATE_TEMPLATE,
    'admin/edit_candidate.html': ADMIN_EDIT_CANDIDATE_TEMPLATE,
    'admin/results.html': ADMIN_RESULTS_TEMPLATE,
    'admin/audit.html': ADMIN_AUDIT_TEMPLATE,
    'admin/security.html': ADMIN_SECURITY_TEMPLATE,
    'admin/reports.html': ADMIN_REPORTS_TEMPLATE,
    'admin/settings.html': ADMIN_SETTINGS_TEMPLATE,
    'admin/eligibility.html': ADMIN_ELIGIBILITY_TEMPLATE,
    'errors/404.html': ERROR_404_TEMPLATE,
    'errors/403.html': ERROR_403_TEMPLATE,
    'errors/500.html': ERROR_500_TEMPLATE,
    'errors/400.html': ERROR_400_TEMPLATE,
    'errors/401.html': ERROR_401_TEMPLATE,
    'errors/405.html': ERROR_405_TEMPLATE,
    'errors/429.html': ERROR_429_TEMPLATE,
}


# ============================================================================
# CUSTOM JINJA2 LOADER
# ============================================================================

class StringTemplateLoader(BaseLoader):
    def __init__(self, templates):
        self.templates = templates

    def get_source(self, environment, template):
        if template in self.templates:
            return self.templates[template], template, lambda: False
        raise TemplateNotFound(template)

app.jinja_loader = StringTemplateLoader(TEMPLATES)
print("[OK] Custom template loader enabled.")

# ============================================================================
# PART 24: ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500

@app.errorhandler(400)
def bad_request(e):
    return render_template('errors/400.html'), 400

@app.errorhandler(401)
def unauthorized(e):
    return render_template('errors/401.html'), 401

@app.errorhandler(405)
def method_not_allowed(e):
    return render_template('errors/405.html'), 405

@app.errorhandler(429)
def too_many_requests(e):
    return render_template('errors/429.html'), 429

# ============================================================================
# DATABASE INITIALIZATION FUNCTIONS
# ============================================================================

def create_admin_user():
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@system.com',
            role='admin',
            is_active=True,
            is_verified=True
        )
        admin.set_password('Admin@123')
        db.session.add(admin)
        db.session.commit()
        print("[OK] Admin user created: admin / Admin@123")
        return True
    return False

def create_default_settings():
    settings = [
        ('system_name', app.config['APP_NAME'], 'System display name'),
        ('system_tagline', app.config['APP_TAGLINE'], 'System tagline'),
        ('maintenance_mode', 'off', 'Enable maintenance mode'),
        ('voter_registration_open', 'on', 'Allow new voter registrations'),
    ]
    for key, value, description in settings:
        existing = SystemSetting.query.filter_by(key=key).first()
        if not existing:
            setting = SystemSetting(key=key, value=value, description=description)
            db.session.add(setting)
    db.session.commit()

def create_sample_data():
    if Election.query.count() > 0:
        return
    print("Creating sample data...")
    
    # Get current Nigeria time
    now_ng = get_ng_time()
    start_ng = now_ng + timedelta(days=1)
    end_ng = now_ng + timedelta(days=8)
    start_utc = ng_to_utc(start_ng)
    end_utc = ng_to_utc(end_ng)
    
    election = Election(
        title='Student Union Elections 2026',
        description='Election for Student Union positions',
        election_type='student',
        start_date=start_utc,
        end_date=end_utc,
        status='scheduled',
        is_active=False
    )
    db.session.add(election)
    db.session.flush()
    
    positions = ['President', 'Vice President', 'Secretary', 'Treasurer', 'Public Relations Officer']
    for i, title in enumerate(positions):
        position = ElectionPosition(
            election_id=election.id, 
            title=title, 
            description=f'Candidate for {title} position', 
            order=i
        )
        db.session.add(position)
        db.session.flush()
        for j in range(3):
            candidate = Candidate(
                election_id=election.id,
                position_id=position.id,
                user_id=None,  # Explicitly set to None for sample data
                full_name=f'Candidate {j+1} for {title}',
                department='Computer Science',
                faculty='Science',
                level='300',
                manifesto=f'My vision for {title} position.',
                is_active=True
            )
            db.session.add(candidate)
    db.session.commit()
    print(f"[OK] Sample data created with Nigeria time. Start: {start_ng.strftime('%Y-%m-%d %H:%M')}")
# ============================================================================
# DATABASE INITIALIZATION (must run after all models are defined)
# ============================================================================

with app.app_context():
    db.create_all()
    create_admin_user()
    create_default_settings()
    if app.config.get('DEBUG', False):
        create_sample_data()
# ============================================================================
# RUN APP (ENTRY POINT FOR DEVELOPMENT)
# ============================================================================

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)