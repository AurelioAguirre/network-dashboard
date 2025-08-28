"""
Configuration Management Module

This module handles loading and accessing configuration settings from YAML files.
It demonstrates file I/O operations, YAML parsing, and safe nested dictionary access.

Educational Concepts:
- Class design and encapsulation
- File handling and parsing with context managers
- Exception handling patterns
- Nested dictionary traversal with safe fallbacks
"""

import yaml
from pathlib import Path


class Config:
    """
    Configuration Management Class

    This class handles loading and accessing configuration settings from a YAML file.
    It demonstrates:
    - File I/O operations with YAML
    - Error handling for missing files/keys
    - Nested dictionary access with safe fallbacks

    Educational Concepts:
    - Class design and encapsulation
    - File handling and parsing
    - Exception handling patterns
    """

    def __init__(self, config_path="config.yaml"):
        """
        Initialize the configuration manager.

        Args:
            config_path (str): Path to the YAML configuration file

        Educational Note:
            The __init__ method is called when creating a new instance of the class.
            It sets up the initial state of the object.
        """
        self.config_path = config_path
        self.reload()  # Load configuration immediately upon creation

    def reload(self):
        """
        Load or reload configuration from the YAML file.

        Educational Concepts:
        - File reading with context managers (with statement)
        - YAML parsing
        - Error handling for file operations

        Raises:
            FileNotFoundError: If the config file doesn't exist
            yaml.YAMLError: If the YAML syntax is invalid
        """
        with open(self.config_path, 'r') as f:
            # The 'with' statement ensures the file is properly closed
            # even if an error occurs during reading
            self.config = yaml.safe_load(f)

    def get(self, *keys, default=None):
        """
        Safely retrieve nested configuration values with fallback defaults.

        This method demonstrates advanced Python concepts:
        - *args parameter (variable number of arguments)
        - Nested dictionary traversal
        - Exception handling for missing keys
        - Default value patterns

        Args:
            *keys: Variable number of keys for nested dictionary access
            default: Value to return if the key path doesn't exist

        Returns:
            The configuration value or the default if not found

        Example:
            config.get('display', 'max_packets_per_ip', default=5)
            This would access config['display']['max_packets_per_ip']
        """
        value = self.config
        for key in keys:
            try:
                value = value[key]
            except (KeyError, TypeError):
                # KeyError: Key doesn't exist in dictionary
                # TypeError: Trying to access key on non-dict value
                return default
        return value