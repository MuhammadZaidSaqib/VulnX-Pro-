"""
Enhanced configuration management with environment variable support.
"""
import os
from typing import Dict, Any

# ==================== ENVIRONMENT CONFIG ====================

class Config:
    """Base configuration"""
    # Flask
    DEBUG = False
    TESTING = False
    JSONIFY_PRETTYPRINT_REGULAR = False

    # Crawler settings
    MAX_DEPTH = int(os.getenv("MAX_DEPTH", "2"))
    REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "5"))
    USER_AGENT = os.getenv("USER_AGENT", "VulnX_Pro-Scanner/2.0")

    # Threading
    THREADS = int(os.getenv("THREADS", "5"))
    MAX_WORKERS = THREADS

    # Rate limiting
    RATE_LIMIT_DELAY = float(os.getenv("RATE_LIMIT_DELAY", "0.4"))

    # Database
    DATABASE_PATH = os.getenv("DATABASE_PATH", "database/vulnx.db")

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # Feature flags
    ENABLE_CRAWLING = os.getenv("ENABLE_CRAWLING", "true").lower() == "true"
    ENABLE_SQLI_DETECTION = os.getenv("ENABLE_SQLI_DETECTION", "true").lower() == "true"
    ENABLE_XSS_DETECTION = os.getenv("ENABLE_XSS_DETECTION", "true").lower() == "true"


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = "DEBUG"


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    LOG_LEVEL = "WARNING"
    RATE_LIMIT_DELAY = 1.0  # Stricter rate limiting


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    REQUEST_TIMEOUT = 2
    MAX_DEPTH = 1
    THREADS = 2
    RATE_LIMIT_DELAY = 0.0


# ==================== CONFIG SELECTION ====================

def get_config(env: str = None) -> Config:
    """
    Get configuration based on environment.

    Args:
        env: Environment name ('development', 'production', 'testing')

    Returns:
        Configuration object
    """
    if env is None:
        env = os.getenv("FLASK_ENV", "development")

    configs = {
        "development": DevelopmentConfig,
        "production": ProductionConfig,
        "testing": TestingConfig,
    }

    return configs.get(env, DevelopmentConfig)


# ==================== VALIDATION ====================

def validate_config(config: Config) -> bool:
    """
    Validate configuration values.

    Args:
        config: Configuration to validate

    Returns:
        True if valid, raises ValueError otherwise
    """
    errors = []

    if config.MAX_DEPTH < 0:
        errors.append("MAX_DEPTH must be >= 0")

    if config.REQUEST_TIMEOUT <= 0:
        errors.append("REQUEST_TIMEOUT must be > 0")

    if config.THREADS <= 0:
        errors.append("THREADS must be > 0")

    if config.RATE_LIMIT_DELAY < 0:
        errors.append("RATE_LIMIT_DELAY must be >= 0")

    if errors:
        raise ValueError("\n".join(errors))

    return True


# ==================== CONFIG EXPORT ====================

# Default config instance
_current_config = None


def init_config(env: str = None):
    """Initialize global config"""
    global _current_config
    _current_config = get_config(env)
    validate_config(_current_config)


def get_current_config() -> Config:
    """Get current config instance"""
    global _current_config
    if _current_config is None:
        init_config()
    return _current_config


def config_to_dict(config: Config = None) -> Dict[str, Any]:
    """
    Convert config to dictionary.

    Args:
        config: Configuration to convert

    Returns:
        Dictionary of config values
    """
    if config is None:
        config = get_current_config()

    return {
        "debug": config.DEBUG,
        "max_depth": config.MAX_DEPTH,
        "request_timeout": config.REQUEST_TIMEOUT,
        "threads": config.THREADS,
        "rate_limit": config.RATE_LIMIT_DELAY,
        "database": config.DATABASE_PATH,
        "log_level": config.LOG_LEVEL,
        "features": {
            "crawling": config.ENABLE_CRAWLING,
            "sqli_detection": config.ENABLE_SQLI_DETECTION,
            "xss_detection": config.ENABLE_XSS_DETECTION,
        }
    }


# Initialize on import
init_config()

