"""
NGSIEM Query Catalog Loader

Loads and provides access to NGSIEM functions, syntax, and templates
from YAML configuration files.

Security Notes:
- YAML files are loaded once at startup (immutable)
- No user input in YAML parsing (safe from injection)
- All data is read-only after loading
"""
import os
import logging
from pathlib import Path
from typing import Any, Optional
from functools import lru_cache

import yaml

logger = logging.getLogger(__name__)


class QueryCatalog:
    """
    Provides access to NGSIEM query functions, syntax, and templates.
    
    Thread-safe: Data is immutable after initialization.
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize catalog from YAML files.
        
        Args:
            config_dir: Path to config directory. Defaults to ./config/
        """
        if config_dir is None:
            config_dir = os.path.join(os.path.dirname(__file__), "config")
        
        self._config_dir = Path(config_dir)
        self._functions: dict = {}
        self._syntax: dict = {}
        self._templates: dict = {}
        self._best_practices: dict = {}
        
        self._load_catalogs()
    
    def _load_catalogs(self) -> None:
        """Load all YAML catalog files."""
        self._functions = self._load_yaml("ngsiem_functions.yaml")
        self._syntax = self._load_yaml("ngsiem_syntax.yaml")
        self._templates = self._load_yaml("ngsiem_templates.yaml")
        self._best_practices = self._load_yaml("ngsiem_best_practices.yaml")
        
        bp_steps = len(self._best_practices.get("query_pipeline", {}).get("steps", []))
        logger.info(
            f"Loaded query catalog: "
            f"{self._count_functions()} functions, "
            f"{self._count_templates()} templates, "
            f"{bp_steps} pipeline steps"
        )
    
    def _load_yaml(self, filename: str) -> dict:
        """
        Safely load a YAML file.
        
        Security: Uses safe_load to prevent code execution.
        """
        filepath = self._config_dir / filename
        
        if not filepath.exists():
            logger.warning(f"Catalog file not found: {filepath}")
            return {}
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                # safe_load prevents arbitrary code execution
                data = yaml.safe_load(f)
                return data if data else {}
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse {filename}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Failed to load {filename}: {e}")
            return {}
    
    def _count_functions(self) -> int:
        """Count total functions across all categories."""
        count = 0
        for category in self._functions.values():
            if isinstance(category, dict):
                count += len(category)
        return count
    
    def _count_templates(self) -> int:
        """Count total templates across all categories."""
        count = 0
        for category in self._templates.values():
            if isinstance(category, dict):
                count += len(category)
        return count
    
    # =========================================================================
    # FUNCTION CATALOG ACCESS
    # =========================================================================
    
    def get_function_categories(self) -> list[str]:
        """Get list of function categories."""
        # Skip metadata keys
        return [k for k in self._functions.keys() 
                if k not in ("version", "last_updated")]
    
    def get_functions_by_category(self, category: str) -> dict:
        """
        Get all functions in a category.
        
        Args:
            category: Category name (e.g., 'aggregate', 'filtering')
            
        Returns:
            Dictionary of functions in the category
        """
        return self._functions.get(category, {})
    
    def get_function(self, name: str) -> Optional[dict]:
        """
        Get function details by name.
        
        Args:
            name: Function name (e.g., 'count', 'groupBy')
            
        Returns:
            Function details or None if not found
        """
        for category in self.get_function_categories():
            functions = self._functions.get(category, {})
            if name in functions:
                result = functions[name].copy()
                result["category"] = category
                return result
        return None
    
    def search_functions(self, query: str) -> list[dict]:
        """
        Search functions by name or description.
        
        Args:
            query: Search term
            
        Returns:
            List of matching functions
        """
        query_lower = query.lower()
        results = []
        
        for category in self.get_function_categories():
            for name, details in self._functions.get(category, {}).items():
                if isinstance(details, dict):
                    # Search in name and description
                    name_match = query_lower in name.lower()
                    desc_match = query_lower in details.get("description", "").lower()
                    
                    if name_match or desc_match:
                        result = details.copy()
                        result["name"] = name
                        result["category"] = category
                        results.append(result)
        
        return results
    
    def list_all_functions(self) -> list[dict]:
        """
        List all available functions.
        
        Returns:
            List of function summaries
        """
        results = []
        
        for category in self.get_function_categories():
            for name, details in self._functions.get(category, {}).items():
                if isinstance(details, dict):
                    results.append({
                        "name": name,
                        "category": category,
                        "syntax": details.get("syntax", ""),
                        "description": details.get("description", "")
                    })
        
        return sorted(results, key=lambda x: x["name"])
    
    # =========================================================================
    # SYNTAX REFERENCE ACCESS
    # =========================================================================
    
    def get_syntax_topics(self) -> list[str]:
        """Get list of syntax topics."""
        return [k for k in self._syntax.keys() 
                if k not in ("version", "last_updated")]
    
    def get_syntax(self, topic: str) -> Optional[dict]:
        """
        Get syntax reference for a topic.
        
        Args:
            topic: Topic name (e.g., 'pipes', 'field_filters')
            
        Returns:
            Syntax details or None
        """
        return self._syntax.get(topic)
    
    def get_operators(self) -> dict:
        """Get all operators from field_filters topic."""
        return self._syntax.get("field_filters", {})
    
    def get_event_types(self) -> dict:
        """Get common CrowdStrike event types."""
        return self._syntax.get("event_types", {})
    
    def get_common_patterns(self) -> dict:
        """Get common query patterns."""
        return self._syntax.get("common_patterns", {})
    
    # =========================================================================
    # TEMPLATE ACCESS
    # =========================================================================
    
    def get_template_categories(self) -> list[str]:
        """Get list of template categories."""
        return [k for k in self._templates.keys() 
                if k not in ("version", "last_updated")]
    
    def get_templates_by_category(self, category: str) -> dict:
        """
        Get all templates in a category.
        
        Args:
            category: Category name (e.g., 'threat_hunting')
            
        Returns:
            Dictionary of templates
        """
        return self._templates.get(category, {})
    
    def get_template(self, name: str) -> Optional[dict]:
        """
        Get template by name.
        
        Args:
            name: Template name (e.g., 'powershell_execution')
            
        Returns:
            Template details or None
        """
        for category in self.get_template_categories():
            templates = self._templates.get(category, {})
            if name in templates:
                result = templates[name].copy()
                result["category"] = category
                result["id"] = name
                return result
        return None
    
    def search_templates(self, query: str) -> list[dict]:
        """
        Search templates by name or description.
        
        Args:
            query: Search term
            
        Returns:
            List of matching templates
        """
        query_lower = query.lower()
        results = []
        
        for category in self.get_template_categories():
            for name, details in self._templates.get(category, {}).items():
                if isinstance(details, dict):
                    name_match = query_lower in name.lower()
                    desc_match = query_lower in details.get("description", "").lower()
                    title_match = query_lower in details.get("name", "").lower()
                    
                    if name_match or desc_match or title_match:
                        result = details.copy()
                        result["id"] = name
                        result["category"] = category
                        results.append(result)
        
        return results
    
    def list_all_templates(self) -> list[dict]:
        """
        List all available templates.
        
        Returns:
            List of template summaries
        """
        results = []
        
        for category in self.get_template_categories():
            for template_id, details in self._templates.get(category, {}).items():
                if isinstance(details, dict):
                    results.append({
                        "id": template_id,
                        "name": details.get("name", template_id),
                        "category": category,
                        "severity": details.get("severity", "info"),
                        "description": details.get("description", ""),
                        "has_parameters": bool(details.get("parameters"))
                    })
        
        return results
    
    def render_template(self, name: str, **params) -> Optional[str]:
        """
        Render a template with parameters.
        
        Args:
            name: Template name
            **params: Parameter values for placeholders
            
        Returns:
            Rendered query string or None
            
        Security:
            Parameters are escaped to prevent query injection.
        """
        template = self.get_template(name)
        if not template:
            return None
        
        query = template.get("query", "")
        
        # Replace placeholders with escaped values
        for param, value in params.items():
            placeholder = "{{" + param + "}}"
            # Basic sanitization: escape quotes
            safe_value = str(value).replace('"', '\\"').replace("'", "\\'")
            query = query.replace(placeholder, safe_value)
        
        return query.strip()
    
    # =========================================================================
    # REPOSITORY CATALOG ACCESS
    # =========================================================================
    
    def get_repositories(self) -> list[dict]:
        """
        Load and return available repositories from config.
        
        Returns:
            List of repository dictionaries with name, description, etc.
            
        Security:
            File is loaded with safe_load to prevent code execution.
        """
        repos_file = self._config_dir / "repositories.yaml"
        
        if not repos_file.exists():
            logger.warning("No repositories.yaml found - using empty list")
            return []
        
        try:
            with open(repos_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data.get("repositories", []) if data else []
        except Exception as e:
            logger.error(f"Failed to load repositories: {e}")
            return []
    
    def get_default_repository(self) -> Optional[str]:
        """
        Get the name of the default repository.
        
        Returns:
            Name of default repository or None
        """
        repos = self.get_repositories()
        for repo in repos:
            if repo.get("default", False):
                return repo.get("name")
        return repos[0].get("name") if repos else None
    
    # =========================================================================
    # BEST PRACTICES ACCESS
    # =========================================================================
    
    def get_query_pipeline(self) -> list[dict]:
        """
        Get the query construction pipeline steps.
        
        Returns:
            List of pipeline steps in recommended order.
        """
        pipeline = self._best_practices.get("query_pipeline", {})
        return pipeline.get("steps", [])
    
    def get_optimization_tips(self) -> list[dict]:
        """
        Get query optimization tips.
        
        Returns:
            List of optimization tip objects.
        """
        return self._best_practices.get("optimization_tips", [])
    
    def get_anti_patterns(self) -> list[dict]:
        """
        Get common anti-patterns to avoid.
        
        Returns:
            List of anti-pattern objects with bad/good examples.
        """
        return self._best_practices.get("anti_patterns", [])
    
    def get_efficient_patterns(self) -> list[dict]:
        """
        Get efficient query patterns.
        
        Returns:
            List of efficient pattern objects.
        """
        return self._best_practices.get("efficient_patterns", [])
    
    def get_best_practices_summary(self) -> dict:
        """
        Get a complete summary of best practices for LLM context.
        
        Returns:
            Dictionary with pipeline, tips, patterns, and anti-patterns.
        """
        pipeline = self._best_practices.get("query_pipeline", {})
        return {
            "description": pipeline.get("description", ""),
            "template": pipeline.get("template", ""),
            "pipeline_steps": self.get_query_pipeline(),
            "optimization_tips": self.get_optimization_tips(),
            "efficient_patterns": self.get_efficient_patterns(),
            "anti_patterns": self.get_anti_patterns()
        }


# Singleton instance for shared access
_catalog_instance: Optional[QueryCatalog] = None


def get_catalog() -> QueryCatalog:
    """Get or create the singleton catalog instance."""
    global _catalog_instance
    if _catalog_instance is None:
        _catalog_instance = QueryCatalog()
    return _catalog_instance


def reload_catalog() -> QueryCatalog:
    """Force reload of catalog (for development/testing)."""
    global _catalog_instance
    _catalog_instance = QueryCatalog()
    return _catalog_instance
