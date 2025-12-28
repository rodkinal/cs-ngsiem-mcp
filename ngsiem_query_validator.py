"""
NGSIEM Query Validator

Validates NGSIEM query syntax before execution to prevent errors
and provide helpful feedback.

Security Notes:
- No external API calls during validation
- Input sanitization for injection prevention
- Read-only operations only
"""
import re
import logging
from dataclasses import dataclass
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class IssueSeverity(Enum):
    """Severity levels for validation issues."""
    ERROR = "error"      # Prevents execution
    WARNING = "warning"  # May cause issues
    INFO = "info"        # Suggestion only


@dataclass
class ValidationIssue:
    """Represents a validation issue found in query."""
    severity: IssueSeverity
    message: str
    position: Optional[int] = None
    suggestion: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of query validation."""
    valid: bool
    issues: list[ValidationIssue]
    sanitized_query: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "valid": self.valid,
            "issues": [
                {
                    "severity": issue.severity.value,
                    "message": issue.message,
                    "position": issue.position,
                    "suggestion": issue.suggestion
                }
                for issue in self.issues
            ],
            "sanitized_query": self.sanitized_query
        }


class QueryValidator:
    """
    Validates NGSIEM query syntax.
    
    Performs static analysis without API calls.
    """
    
    # Known function patterns (from catalog)
    KNOWN_FUNCTION_PREFIXES = {
        "count", "avg", "sum", "min", "max", "groupBy", "bucket",
        "collect", "percentile", "stdDev", "variance", "top", "stats",
        "in", "regex", "cidr", "ipLocation", "test", "exists", "empty",
        "select", "rename", "drop", "eval", "format", "lower", "upper",
        "replace", "split", "concat",
        "sort", "head", "tail", "sample", "dedup",
        "ioc:lookup", "hashMatch", "hashRewrite",
        "formatTime", "parseTimestamp", "now", "timechart",
        "kvParse", "parseJson", "parseXml", "parseCsv",
        "join", "selfJoin", "correlate",
        "table", "sankey", "worldMap", "piechart", "barchart",
        "array:append", "array:contains", "array:filter", "array:length",
        "array:eval", "array:exists", "array:intersection", "array:union"
    }
    
    # Dangerous patterns that could indicate injection
    DANGEROUS_PATTERNS = [
        r";\s*(?:drop|delete|truncate|insert|update)",  # SQL-like
        r"<script",  # XSS
        r"{{.*}}",  # Template injection (if not parameter)
        r"\$\{.*\}",  # Shell injection
    ]
    
    def __init__(self):
        """Initialize validator."""
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        self._dangerous_re = [
            re.compile(p, re.IGNORECASE) 
            for p in self.DANGEROUS_PATTERNS
        ]
        self._function_re = re.compile(r'(\w+(?::\w+)?)\s*\(')
        self._field_filter_re = re.compile(r'(\w+)\s*([=!<>]=?|/)')
    
    def validate(self, query: str, strict: bool = False) -> ValidationResult:
        """
        Validate NGSIEM query syntax.
        
        Args:
            query: Query string to validate
            strict: If True, warnings are treated as errors
            
        Returns:
            ValidationResult with issues found
        """
        issues: list[ValidationIssue] = []
        
        if not query or not query.strip():
            issues.append(ValidationIssue(
                severity=IssueSeverity.ERROR,
                message="Query cannot be empty"
            ))
            return ValidationResult(valid=False, issues=issues)
        
        query = query.strip()
        
        # Check for dangerous patterns
        danger_issues = self._check_dangerous_patterns(query)
        issues.extend(danger_issues)
        
        # Check balanced parentheses
        paren_issue = self._check_balanced_parens(query)
        if paren_issue:
            issues.append(paren_issue)
        
        # Check balanced brackets
        bracket_issue = self._check_balanced_brackets(query)
        if bracket_issue:
            issues.append(bracket_issue)
        
        # Check balanced quotes
        quote_issue = self._check_balanced_quotes(query)
        if quote_issue:
            issues.append(quote_issue)
        
        # Check function names
        unknown_funcs = self._check_function_names(query)
        issues.extend(unknown_funcs)
        
        # Check pipe syntax
        pipe_issues = self._check_pipe_syntax(query)
        issues.extend(pipe_issues)
        
        # Check for common mistakes
        mistake_issues = self._check_common_mistakes(query)
        issues.extend(mistake_issues)
        
        # Determine validity
        has_errors = any(
            i.severity == IssueSeverity.ERROR 
            for i in issues
        )
        has_warnings = any(
            i.severity == IssueSeverity.WARNING 
            for i in issues
        )
        
        valid = not has_errors and (not strict or not has_warnings)
        
        # Sanitize query if valid
        sanitized = self._sanitize_query(query) if valid else None
        
        return ValidationResult(
            valid=valid,
            issues=issues,
            sanitized_query=sanitized
        )
    
    def _check_dangerous_patterns(self, query: str) -> list[ValidationIssue]:
        """Check for potentially dangerous patterns."""
        issues = []
        
        for pattern_re in self._dangerous_re:
            if pattern_re.search(query):
                issues.append(ValidationIssue(
                    severity=IssueSeverity.ERROR,
                    message="Query contains potentially dangerous pattern",
                    suggestion="Remove suspicious content"
                ))
                break  # One is enough
        
        return issues
    
    def _check_balanced_parens(self, query: str) -> Optional[ValidationIssue]:
        """Check for balanced parentheses."""
        depth = 0
        in_string = False
        string_char = None
        
        for i, char in enumerate(query):
            # Handle strings
            if char in ('"', "'") and (i == 0 or query[i-1] != '\\'):
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
                    string_char = None
                continue
            
            if in_string:
                continue
            
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth < 0:
                    return ValidationIssue(
                        severity=IssueSeverity.ERROR,
                        message="Unmatched closing parenthesis",
                        position=i
                    )
        
        if depth != 0:
            return ValidationIssue(
                severity=IssueSeverity.ERROR,
                message=f"Unbalanced parentheses: {abs(depth)} unclosed",
                suggestion="Check opening and closing parentheses match"
            )
        
        return None
    
    def _check_balanced_brackets(self, query: str) -> Optional[ValidationIssue]:
        """Check for balanced square brackets."""
        depth = 0
        in_string = False
        string_char = None
        
        for i, char in enumerate(query):
            if char in ('"', "'") and (i == 0 or query[i-1] != '\\'):
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
            
            if in_string:
                continue
            
            if char == '[':
                depth += 1
            elif char == ']':
                depth -= 1
                if depth < 0:
                    return ValidationIssue(
                        severity=IssueSeverity.ERROR,
                        message="Unmatched closing bracket",
                        position=i
                    )
        
        if depth != 0:
            return ValidationIssue(
                severity=IssueSeverity.ERROR,
                message=f"Unbalanced brackets: {abs(depth)} unclosed",
                suggestion="Check opening and closing brackets match"
            )
        
        return None
    
    def _check_balanced_quotes(self, query: str) -> Optional[ValidationIssue]:
        """Check for balanced quotes."""
        double_count = 0
        single_count = 0
        
        i = 0
        while i < len(query):
            char = query[i]
            
            # Skip escaped quotes
            if i > 0 and query[i-1] == '\\':
                i += 1
                continue
            
            if char == '"':
                double_count += 1
            elif char == "'":
                single_count += 1
            
            i += 1
        
        issues = []
        if double_count % 2 != 0:
            return ValidationIssue(
                severity=IssueSeverity.ERROR,
                message="Unbalanced double quotes",
                suggestion="Check all double quotes are closed"
            )
        
        if single_count % 2 != 0:
            return ValidationIssue(
                severity=IssueSeverity.ERROR,
                message="Unbalanced single quotes",
                suggestion="Check all single quotes are closed"
            )
        
        return None
    
    def _check_function_names(self, query: str) -> list[ValidationIssue]:
        """Check for unknown function names."""
        issues = []
        
        # Find all function calls
        for match in self._function_re.finditer(query):
            func_name = match.group(1)
            
            # Check if known
            if func_name.lower() not in {f.lower() for f in self.KNOWN_FUNCTION_PREFIXES}:
                # Could be a field filter, not a function
                if not self._is_likely_field_filter(query, match.start()):
                    issues.append(ValidationIssue(
                        severity=IssueSeverity.WARNING,
                        message=f"Unknown function: {func_name}",
                        position=match.start(),
                        suggestion="Check function name spelling or refer to documentation"
                    ))
        
        return issues
    
    def _is_likely_field_filter(self, query: str, pos: int) -> bool:
        """Check if position is likely a field filter, not function call."""
        # Look for field=value pattern before the parenthesis
        before = query[:pos].strip()
        if before.endswith('=') or before.endswith('!'):
            return True
        return False
    
    def _check_pipe_syntax(self, query: str) -> list[ValidationIssue]:
        """Check pipe syntax for issues."""
        issues = []
        
        # Check for empty pipe segments
        if re.search(r'\|\s*\|', query):
            issues.append(ValidationIssue(
                severity=IssueSeverity.ERROR,
                message="Empty pipe segment (consecutive pipes)",
                suggestion="Remove duplicate pipe or add command between pipes"
            ))
        
        # Check for trailing pipe
        if query.strip().endswith('|'):
            issues.append(ValidationIssue(
                severity=IssueSeverity.ERROR,
                message="Query ends with pipe but no following command",
                suggestion="Add command after pipe or remove trailing pipe"
            ))
        
        # Check for leading pipe (usually wrong)
        if query.strip().startswith('|'):
            issues.append(ValidationIssue(
                severity=IssueSeverity.WARNING,
                message="Query starts with pipe",
                suggestion="Usually queries should start with a filter, not a pipe"
            ))
        
        return issues
    
    def _check_common_mistakes(self, query: str) -> list[ValidationIssue]:
        """Check for common query mistakes."""
        issues = []
        
        # Check for = vs == confusion
        if ' == ' in query:
            issues.append(ValidationIssue(
                severity=IssueSeverity.WARNING,
                message="Use single = for equality, not ==",
                suggestion="Replace == with ="
            ))
        
        # Check for AND/OR case
        if ' and ' in query or ' or ' in query:
            issues.append(ValidationIssue(
                severity=IssueSeverity.WARNING,
                message="Logical operators should be uppercase (AND, OR)",
                suggestion="Use AND/OR instead of and/or"
            ))
        
        # Check for missing quotes in string values with spaces
        space_value = re.search(r'=\s*([^"\'=\s]+\s+[^"\'=\s]+)\s*(?:\||$)', query)
        if space_value:
            issues.append(ValidationIssue(
                severity=IssueSeverity.WARNING,
                message="Value with spaces should be quoted",
                suggestion=f'Consider: ="{space_value.group(1)}"'
            ))
        
        return issues
    
    def _sanitize_query(self, query: str) -> str:
        """
        Sanitize query for safe execution.
        
        Security: Remove/escape potentially harmful content.
        """
        # Normalize whitespace
        sanitized = ' '.join(query.split())
        
        # Remove comments (prevent hiding malicious content)
        sanitized = re.sub(r'//[^\n]*', '', sanitized)
        sanitized = re.sub(r'/\*.*?\*/', '', sanitized, flags=re.DOTALL)
        
        return sanitized.strip()
    
    def suggest_completion(self, partial: str) -> list[str]:
        """
        Suggest completions for partial query.
        
        Args:
            partial: Partial query string
            
        Returns:
            List of suggested completions
        """
        suggestions = []
        partial_lower = partial.lower().strip()
        
        # If ends with pipe, suggest functions
        if partial_lower.endswith('|'):
            for func in sorted(self.KNOWN_FUNCTION_PREFIXES):
                suggestions.append(f"{func}()")
                if len(suggestions) >= 10:
                    break
        
        # If typing a function name
        elif '|' in partial_lower:
            last_segment = partial_lower.split('|')[-1].strip()
            for func in sorted(self.KNOWN_FUNCTION_PREFIXES):
                if func.lower().startswith(last_segment):
                    suggestions.append(func)
                    if len(suggestions) >= 10:
                        break
        
        return suggestions


# Singleton instance
_validator_instance: Optional[QueryValidator] = None


def get_validator() -> QueryValidator:
    """Get or create singleton validator instance."""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = QueryValidator()
    return _validator_instance
