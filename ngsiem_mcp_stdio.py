#!/usr/bin/env python3
"""
CrowdStrike NGSIEM MCP Server
Exposes NGSIEM search capabilities via Model Context Protocol.
"""
import asyncio
import json
import logging
from typing import Any, Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, Resource
from pydantic import BaseModel, Field

from config import CONFIG, load_config
from ngsiem_tools import create_ngsiem_client, NGSIEMSearchTools
from ngsiem_query_catalog import get_catalog, QueryCatalog
from ngsiem_query_validator import get_validator, ValidationResult


# Configure logging
logging.basicConfig(
    level=getattr(logging, CONFIG.log_level if CONFIG else "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(CONFIG.log_file if CONFIG else "ngsiem_mcp.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Initialize MCP server
app = Server("ngsiem-server")


# Global NGSIEM client instance
ngsiem_client: NGSIEMSearchTools = None


# Tool argument schemas
class StartSearchArgs(BaseModel):
    """Arguments for starting a NGSIEM search."""
    repository: Optional[str] = Field(
        default=None,
        description="NGSIEM repository name (uses default from config if not specified)"
    )
    query_string: str = Field(
        description="NGSIEM search query (e.g., '#event_simpleName=ProcessRollup2')"
    )
    start: str = Field(
        default="1d",
        description="Time range start (e.g., '1d', '24h', '2025-01-01T00:00:00Z')"
    )
    is_live: bool = Field(
        default=False,
        description="Enable live/streaming search mode"
    )


class GetSearchStatusArgs(BaseModel):
    """Arguments for getting NGSIEM search status."""
    repository: Optional[str] = Field(
        default=None,
        description="NGSIEM repository name (uses default from config if not specified)"
    )
    search_id: str = Field(..., description="Search job ID from start_search")


class SearchAndWaitArgs(BaseModel):
    """Arguments for search_and_wait (blocking search with auto-polling)."""
    repository: Optional[str] = Field(
        default=None,
        description="NGSIEM repository name (uses default from config if not specified)"
    )
    query_string: str = Field(..., description="NGSIEM search query")
    start: str = Field(default="1d", description="Time range (e.g., '1d', '24h')")
    is_live: bool = Field(default=False, description="Live/streaming search mode")
    max_wait_seconds: int = Field(
        default=300,
        description="Maximum time to wait for results (1-3600 seconds)"
    )
    poll_interval: int = Field(
        default=2,
        description="Seconds between status checks (1-60 seconds)"
    )


class StopSearchArgs(BaseModel):
    """Arguments for stop_search tool."""
    repository: Optional[str] = Field(
        default=None,
        description="NGSIEM repository name (uses default from config if not specified)"
    )
    search_id: str = Field(
        description="Search job ID to cancel"
    )


class GetQueryReferenceArgs(BaseModel):
    """Arguments for query reference lookup."""
    category: Optional[str] = Field(
        default=None,
        description="Filter by category: aggregate, filtering, security, data_manipulation, sorting, time, parsing, correlation"
    )
    function_name: Optional[str] = Field(
        default=None,
        description="Get details for specific function (e.g., 'count', 'groupBy', 'ioc:lookup')"
    )
    search_term: Optional[str] = Field(
        default=None,
        description="Search functions by keyword in name/description"
    )


class ListTemplatesArgs(BaseModel):
    """Arguments for listing query templates."""
    category: Optional[str] = Field(
        default=None,
        description="Filter by category: threat_hunting, ioc_hunting, incident_response, baseline, compliance, statistics"
    )
    search_term: Optional[str] = Field(
        default=None,
        description="Search templates by keyword"
    )


class ValidateQueryArgs(BaseModel):
    """Arguments for query validation."""
    query: str = Field(..., description="NGSIEM query to validate")
    strict: bool = Field(
        default=False,
        description="If true, warnings are treated as errors"
    )


class BuildQueryArgs(BaseModel):
    """Arguments for assisted query building."""
    template: Optional[str] = Field(
        default=None,
        description="Template name to use as base (e.g., 'powershell_execution', 'check_ip')"
    )
    parameters: Optional[dict] = Field(
        default=None,
        description="Template parameter values (e.g., {'ip_address': '10.0.0.1'})"
    )


class GetRepoFieldsetArgs(BaseModel):
    """
    Arguments for repository field schema discovery.
    
    This tool is MANDATORY before constructing any search query.
    The LLM must only use fields returned by this tool.
    """
    repository: Optional[str] = Field(
        default=None,
        description=(
            "NGSIEM repository name. Uses default from config if not specified. "
            "Must contain only alphanumeric characters, underscores, and hyphens."
        )
    )
    timeout_seconds: int = Field(
        default=60,
        ge=1,
        le=120,
        description="Maximum wait time for schema retrieval (1-120 seconds)"
    )


# =============================================================================
# MCP RESOURCES
# =============================================================================

@app.list_resources()
async def list_resources() -> list[Resource]:
    """
    List available MCP resources.
    
    Exposes NGSIEM repository configuration to the LLM.
    """
    logger.info("[RESOURCE] LLM requested list of resources")
    return [
        Resource(
            uri="ngsiem://repositories",
            name="User's NGSIEM Repository Configuration",
            description=(
                "CRITICAL: Read this first before answering repository questions. "
                "Contains the complete list of NGSIEM repositories configured by the user, "
                "including names, descriptions, data types, use cases, and retention policies. "
                "Always consult this resource to provide accurate repository recommendations."
            ),
            mimeType="application/json"
        )
    ]


@app.read_resource()
async def read_resource(uri: str) -> str:
    """
    Read the content of a resource by URI.
    
    Args:
        uri: Resource URI (e.g., 'ngsiem://repositories')
        
    Returns:
        Resource content as JSON string
    """
    # Convert Pydantic AnyUrl to string for comparison
    uri_str = str(uri)
    logger.info(f"[RESOURCE] LLM reading resource: {uri_str}")
    
    if uri_str == "ngsiem://repositories":
        try:
            catalog = get_catalog()
            logger.info("[RESOURCE] Catalog loaded successfully")
            
            repos = catalog.get_repositories()
            logger.info(f"[RESOURCE] Retrieved {len(repos)} repositories from catalog")
            
            json_str = json.dumps(repos, indent=2, ensure_ascii=False)
            logger.info(f"[RESOURCE] JSON serialized, length: {len(json_str)} chars")
            logger.info(f"[RESOURCE] Returning {len(repos)} repositories to LLM")
            
            return json_str
            
        except Exception as e:
            logger.error(f"[RESOURCE] ERROR loading repositories: {type(e).__name__}: {e}", exc_info=True)
            raise
    
    raise ValueError(f"Unknown resource: {uri_str}")


# =============================================================================
# MCP TOOLS
# =============================================================================

@app.list_tools()
async def list_tools() -> list[Tool]:
    """
    List available NGSIEM tools.
    
    Returns:
        List of MCP Tool definitions
    """
    return [
        Tool(
            name="get_available_repositories",
            description=(
                "Get the list of NGSIEM repositories configured in this environment. "
                "IMPORTANT: Call this tool FIRST before answering questions about repositories "
                "or making search recommendations. Returns repository names, descriptions, "
                "data types, use cases, and retention policies for ALL configured repositories."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_search_status",
            description=(
                "Check the status of a running NGSIEM search and retrieve results if complete. "
                "Returns search status (RUNNING/DONE), event count, and events if the search has finished. "
                "Poll this endpoint periodically for long-running searches."
            ),
            inputSchema=GetSearchStatusArgs.model_json_schema()
        ),
        Tool(
            name="stop_search",
            description=(
                "Cancel a running NGSIEM search. "
                "Useful for stopping long-running or resource-intensive searches. "
                "Returns confirmation of cancellation."
            ),
            inputSchema=StopSearchArgs.model_json_schema()
        ),
        Tool(
            name="search_and_wait",
            description=(
                "Execute a NGSIEM search and automatically wait for results (blocking). "
                "This combines start_search and get_search_status into one operation. "
                "The server will poll the API until results are ready or timeout occurs. "
                "Default timeout: 5 minutes. Use this for quick searches where you want "
                "immediate results. For long-running searches, use start_search + get_search_status "
                "to allow progress monitoring and avoid timeouts."
            ),
            inputSchema=SearchAndWaitArgs.model_json_schema()
        ),
        Tool(
            name="get_query_reference",
            description=(
                "Get NGSIEM query language reference. "
                "Returns available functions, syntax, and operators. "
                "Use to discover available functions before building queries. "
                "Filter by category (aggregate, filtering, security, etc.) or search by keyword."
            ),
            inputSchema=GetQueryReferenceArgs.model_json_schema()
        ),
        Tool(
            name="list_templates",
            description=(
                "List available pre-built NGSIEM query templates for security operations. "
                "Templates cover threat hunting, IOC hunting, incident response, baselines, and compliance. "
                "Each template includes the query, description, MITRE ATT&CK mapping, and required parameters."
            ),
            inputSchema=ListTemplatesArgs.model_json_schema()
        ),
        Tool(
            name="validate_query",
            description=(
                "Validate NGSIEM query syntax before execution. "
                "Checks for balanced parentheses/brackets/quotes, unknown functions, "
                "common mistakes, and potentially dangerous patterns. "
                "Returns issues with suggestions for fixes."
            ),
            inputSchema=ValidateQueryArgs.model_json_schema()
        ),
        Tool(
            name="build_query",
            description=(
                "Build a NGSIEM query from a template with parameters. "
                "Use list_templates first to see available templates. "
                "Provide template name and parameters to generate a ready-to-execute query."
            ),
            inputSchema=BuildQueryArgs.model_json_schema()
        ),
        Tool(
            name="get_repo_fieldset",
            description=(
                "MANDATORY FIRST STEP: Discover ALL available fields in a NGSIEM repository. "
                "You MUST call this tool BEFORE constructing ANY search query. "
                "Returns the complete list of valid field names for the specified repository. "
                "\n\n"
                "CRITICAL RULES FOR LLM AGENTS:\n"
                "1. ONLY use field names returned by this tool in your queries\n"
                "2. NEVER invent, guess, or hallucinate field names\n"
                "3. If a user asks for a field not in this list, inform them it doesn't exist\n"
                "\n"
                "This prevents query failures from non-existent field references."
            ),
            inputSchema=GetRepoFieldsetArgs.model_json_schema()
        ),
        Tool(
            name="get_query_best_practices",
            description=(
                "Get NGSIEM query writing best practices for optimal performance. "
                "Returns the 8-step query construction pipeline (from Humio documentation), "
                "optimization tips, efficient patterns, and common anti-patterns to avoid. "
                "Use this to learn how to structure queries for maximum efficiency: "
                "tag filters first, then field filters, then transformations, then aggregations."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """
    Execute NGSIEM tool calls.
    
    Args:
        name: Tool name (start_search, get_search_status, stop_search)
        arguments: Tool-specific arguments
        
    Returns:
        List of TextContent with results
        
    Raises:
        ValueError: If tool name is unknown or arguments are invalid
        RuntimeError: If API call fails
    """
    global ngsiem_client
    
    # Ensure client is initialized
    if ngsiem_client is None:
        try:
            ngsiem_client = create_ngsiem_client()
        except Exception as e:
            logger.error(f"Failed to initialize NGSIEM client: {e}")
            return [TextContent(
                type="text",
                text=f"❌ Configuration error: {e}\n\n"
                     f"Please ensure .env file exists with valid CrowdStrike credentials."
            )]
    
    try:
        # Route to appropriate tool handler
        if name == "get_available_repositories":
            catalog = get_catalog()
            repos = catalog.get_repositories()
            logger.info(f"[TOOL] Returning {len(repos)} repositories to LLM")
            
            # Format response as detailed markdown
            response_text = "# NGSIEM Repositories Configuration\n\n"
            response_text += f"**Total Repositories**: {len(repos)}\n\n"
            
            for repo in repos:
                response_text += f"## {repo.get('name', 'Unnamed')}\n\n"
                response_text += f"**Description**: {repo.get('description', 'No description')}\n\n"
                
                if repo.get('default'):
                    response_text += "**⭐ Default Repository**\n\n"
                
                if repo.get('data_types'):
                    response_text += "**Data Types**:\n"
                    for dt in repo['data_types']:
                        response_text += f"- {dt}\n"
                    response_text += "\n"
                
                if repo.get('use_cases'):
                    response_text += "**Use Cases**:\n"
                    for uc in repo['use_cases']:
                        response_text += f"- {uc}\n"
                    response_text += "\n"
                
                if repo.get('retention'):
                    response_text += f"**Retention**: {repo['retention']}\n\n"
                
                response_text += "---\n\n"
            
            return [TextContent(type="text", text=response_text)]
        
        elif name == "start_search":
            args = StartSearchArgs(**arguments)
            
            # Use default repository if not specified
            repository = args.repository or CONFIG.default_repository
            
            result = ngsiem_client.start_search(
                repository=repository,
                query_string=args.query_string,
                start=args.start,
                is_live=args.is_live
            )
            
            return [TextContent(
                type="text",
                text=(
                    f"✅ Search started successfully!\n\n"
                    f"**Search ID:** `{result['id']}`\n"
                    f"**Repository:** {result['repository']}\n"
                    f"**Query:** {result['query']}\n"
                    f"**Time Range:** {result['start']}\n"
                    f"**Live Search:** {result['is_live']}\n\n"
                    f"Use `get_search_status` with this search ID to check progress and retrieve results."
                )
            )]
        
        elif name == "get_search_status":
            args = GetSearchStatusArgs(**arguments)
            
            # Use default repository if not specified
            repository = args.repository or CONFIG.default_repository
            
            result = ngsiem_client.get_search_status(
                repository=repository,
                search_id=args.search_id
            )
            
            status_emoji = "✅" if result['done'] else "⏳"
            
            response_text = (
                f"{status_emoji} **Search Status**\n\n"
                f"**Search ID:** `{result['id']}`\n"
                f"**Repository:** {result['repository']}\n"
                f"**Status:** {result['status']}\n"
                f"**Event Count:** {result['event_count']}\n"
            )
            
            if result['done'] and result['event_count'] > 0:
                response_text += f"\n**Results:**\n```json\n{result['events'][:5]}\n```\n"
                if result['event_count'] > 5:
                    response_text += f"\n_(Showing first 5 of {result['event_count']} events)_"
            elif result['done']:
                response_text += "\n_No events found matching the query._"
            else:
                response_text += "\n_Search still running. Check again in a few seconds._"
            
            return [TextContent(type="text", text=response_text)]
        
        elif name == "stop_search":
            args = StopSearchArgs(**arguments)
            
            # Use default repository if not specified
            repository = args.repository or CONFIG.default_repository
            
            result = ngsiem_client.stop_search(
                repository=repository,
                search_id=args.search_id
            )
            response_text = (
                f"✅ **Search Cancelled**\n\n"
                f"- **Search ID**: `{result['id']}`\n"
                f"- **Repository**: `{result['repository']}`\n"
                f"- **Status**: {result['status']}\n"
                f"- **Stopped at**: {result['stopped_at']}\n"
            )
        
        elif name == "search_and_wait":
            args = SearchAndWaitArgs(**arguments)
            
            # Use default repository if not specified
            repository = args.repository or CONFIG.default_repository
            
            response_text = (
                f"🔍 **Starting Search** (will wait for results)...\n\n"
                f"- **Repository**: `{repository}`\n"
                f"- **Query**: `{args.query_string}`\n"
                f"- **Time Range**: {args.start}\n"
                f"- **Max Wait**: {args.max_wait_seconds}s\n"
                f"- **Poll Interval**: {args.poll_interval}s\n\n"
                f"⏳ Waiting for results...\n\n"
            )
            
            try:
                result = ngsiem_client.search_and_wait(
                    repository=repository,
                    query_string=args.query_string,
                    start=args.start,
                    is_live=args.is_live,
                    max_wait_seconds=args.max_wait_seconds,
                    poll_interval=args.poll_interval
                )
                
                response_text += (
                    f"✅ **Search Complete**\n\n"
                    f"- **Search ID**: `{result['search_id']}`\n"
                    f"- **Status**: {result['status']}\n"
                    f"- **Events Found**: {result['event_count']}\n"
                    f"- **Time Taken**: {result['elapsed_time']:.1f}s\n"
                    f"- **Polls**: {result['poll_count']}\n\n"
                )
                
                if result['event_count'] > 0:
                    # Show sample results
                    sample_count = min(5, result['event_count'])
                    response_text += f"**First {sample_count} Results:**\n```json\n"
                    response_text += json.dumps(result['events'][:sample_count], indent=2)
                    response_text += "\n```\n\n"
                    
                    if result['event_count'] > sample_count:
                        response_text += f"*({result['event_count'] - sample_count} more events in full result)*\n"
                else:
                    response_text += "No events found matching the query.\n"
                    
            except TimeoutError as e:
                response_text += (
                    f"⏱️ **Search Timeout**\n\n"
                    f"{str(e)}\n\n"
                    f"The search is still running in the background. "
                    f"You can check results later using `get_search_status`.\n"
                )
        
        elif name == "get_query_reference":
            args = GetQueryReferenceArgs(**arguments)
            catalog = get_catalog()
            
            if args.function_name:
                # Get specific function details
                func = catalog.get_function(args.function_name)
                if func:
                    response_text = (
                        f"📖 **Function: {args.function_name}**\n\n"
                        f"**Category:** {func.get('category', 'N/A')}\n"
                        f"**Syntax:** `{func.get('syntax', 'N/A')}`\n"
                        f"**Description:** {func.get('description', 'N/A')}\n\n"
                    )
                    
                    if func.get('parameters'):
                        response_text += "**Parameters:**\n"
                        for param in func['parameters']:
                            req = "required" if param.get('required') else "optional"
                            response_text += f"- `{param['name']}` ({param.get('type', 'any')}, {req}): {param.get('description', '')}\n"
                        response_text += "\n"
                    
                    if func.get('examples'):
                        response_text += "**Examples:**\n```\n"
                        for ex in func['examples'][:3]:
                            if isinstance(ex, dict):
                                response_text += f"{ex.get('query', ex)}\n"
                            else:
                                response_text += f"{ex}\n"
                        response_text += "```\n"
                else:
                    response_text = f"❌ Function '{args.function_name}' not found.\n\nUse `get_query_reference` without parameters to see all available functions."
            
            elif args.search_term:
                # Search functions
                results = catalog.search_functions(args.search_term)
                if results:
                    response_text = f"🔍 **Functions matching '{args.search_term}':**\n\n"
                    for func in results[:10]:
                        response_text += f"- **{func['name']}** ({func['category']}): {func.get('description', '')[:80]}...\n"
                else:
                    response_text = f"No functions found matching '{args.search_term}'."
            
            elif args.category:
                # List functions in category
                funcs = catalog.get_functions_by_category(args.category)
                if funcs:
                    response_text = f"📚 **{args.category.title()} Functions:**\n\n"
                    for name, details in list(funcs.items())[:15]:
                        if isinstance(details, dict):
                            response_text += f"- **{name}**: `{details.get('syntax', name + '()')}` - {details.get('description', '')[:60]}...\n"
                else:
                    cats = catalog.get_function_categories()
                    response_text = f"❌ Category '{args.category}' not found.\n\nAvailable categories: {', '.join(cats)}"
            
            else:
                # List all categories with counts
                response_text = "📚 **NGSIEM Query Reference**\n\n**Function Categories:**\n"
                for cat in catalog.get_function_categories():
                    funcs = catalog.get_functions_by_category(cat)
                    count = len([f for f in funcs.values() if isinstance(f, dict)])
                    response_text += f"- **{cat}**: {count} functions\n"
                response_text += "\n**Syntax Topics:**\n"
                for topic in catalog.get_syntax_topics():
                    response_text += f"- {topic}\n"
                response_text += "\nUse `get_query_reference` with `category` or `function_name` for details."
        
        elif name == "list_templates":
            args = ListTemplatesArgs(**arguments)
            catalog = get_catalog()
            
            if args.search_term:
                results = catalog.search_templates(args.search_term)
                if results:
                    response_text = f"🔍 **Templates matching '{args.search_term}':**\n\n"
                    for tmpl in results[:10]:
                        response_text += f"- **{tmpl['id']}** ({tmpl['category']}): {tmpl.get('name', '')}\n"
                        response_text += f"  _{tmpl.get('description', '')[:80]}_\n"
                else:
                    response_text = f"No templates found matching '{args.search_term}'."
            
            elif args.category:
                templates = catalog.get_templates_by_category(args.category)
                if templates:
                    response_text = f"📋 **{args.category.replace('_', ' ').title()} Templates:**\n\n"
                    for tmpl_id, details in templates.items():
                        if isinstance(details, dict):
                            severity = details.get('severity', 'info')
                            severity_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢', 'info': 'ℹ️'}.get(severity, 'ℹ️')
                            response_text += f"- {severity_emoji} **{tmpl_id}**: {details.get('name', tmpl_id)}\n"
                            if details.get('mitre_techniques'):
                                response_text += f"  MITRE: {', '.join(details['mitre_techniques'][:3])}\n"
                else:
                    cats = catalog.get_template_categories()
                    response_text = f"❌ Category '{args.category}' not found.\n\nAvailable: {', '.join(cats)}"
            
            else:
                response_text = "📋 **Available Query Templates**\n\n"
                for cat in catalog.get_template_categories():
                    templates = catalog.get_templates_by_category(cat)
                    count = len([t for t in templates.values() if isinstance(t, dict)])
                    response_text += f"**{cat.replace('_', ' ').title()}** ({count} templates)\n"
                response_text += "\nUse `list_templates` with `category` to see templates in a category."
        
        elif name == "validate_query":
            args = ValidateQueryArgs(**arguments)
            validator = get_validator()
            result = validator.validate(args.query, strict=args.strict)
            
            if result.valid:
                response_text = "✅ **Query is valid**\n\n"
                response_text += f"**Sanitized Query:**\n```\n{result.sanitized_query}\n```\n"
            else:
                response_text = "❌ **Query has issues**\n\n"
            
            if result.issues:
                response_text += "**Issues Found:**\n"
                for issue in result.issues:
                    emoji = {'error': '🔴', 'warning': '🟡', 'info': 'ℹ️'}.get(issue.severity.value, '•')
                    response_text += f"- {emoji} **{issue.severity.value.upper()}**: {issue.message}\n"
                    if issue.suggestion:
                        response_text += f"  _Suggestion: {issue.suggestion}_\n"
        
        elif name == "build_query":
            args = BuildQueryArgs(**arguments)
            catalog = get_catalog()
            
            if not args.template:
                response_text = "❌ Please specify a template name.\n\nUse `list_templates` to see available templates."
            else:
                template = catalog.get_template(args.template)
                if not template:
                    response_text = f"❌ Template '{args.template}' not found.\n\nUse `list_templates` to see available templates."
                else:
                    params = args.parameters or {}
                    query = catalog.render_template(args.template, **params)
                    
                    response_text = f"🔨 **Built Query from '{args.template}'**\n\n"
                    response_text += f"**Template:** {template.get('name', args.template)}\n"
                    response_text += f"**Category:** {template.get('category', 'N/A')}\n"
                    response_text += f"**Time Range:** {template.get('time_range', '1d')}\n\n"
                    response_text += f"**Generated Query:**\n```\n{query}\n```\n\n"
                    
                    # Check for unfilled parameters
                    if '{{' in query:
                        response_text += "⚠️ **Warning:** Query has unfilled parameters. Required:\n"
                        for param in template.get('parameters', []):
                            if param.get('required', False):
                                response_text += f"- `{param['name']}`: {param.get('description', '')}\n"
                    else:
                        response_text += "✅ Query is ready to execute with `search_and_wait` or `start_search`."
        
        elif name == "get_repo_fieldset":
            args = GetRepoFieldsetArgs(**arguments)
            
            # Use default repository if not specified
            repository = args.repository or CONFIG.default_repository
            
            if not repository:
                return [TextContent(
                    type="text",
                    text=(
                        "❌ **Repository Required**\n\n"
                        "No repository specified and no default configured.\n"
                        "Use `get_available_repositories` to see valid options."
                    )
                )]
            
            logger.info(f"[TOOL] Fetching fieldset for repository: {repository}")
            
            try:
                result = ngsiem_client.get_repo_fieldset(
                    repository=repository,
                    timeout_seconds=args.timeout_seconds
                )
                
                # Format response for LLM consumption
                field_count = result.get('field_count', 0)
                fields = result.get('fields', [])
                
                response_text = (
                    f"🔍 **Repository Schema: {repository}**\n\n"
                    f"**Total Fields:** {field_count}\n"
                    f"**Retrieved At:** {result.get('retrieved_at', 'N/A')}\n\n"
                )
                
                if result.get('warning'):
                    response_text += f"⚠️ **Warning:** {result['warning']}\n\n"
                
                if fields:
                    response_text += "## Available Fields\n\n"
                    response_text += "```\n"
                    # Display in columns for readability
                    for i, field in enumerate(fields):
                        response_text += f"{field}\n"
                    response_text += "```\n\n"
                    
                    response_text += (
                        "---\n"
                        "⚠️ **IMPORTANT**: You MUST only use fields from this list in your queries.\n"
                        "Do NOT invent or guess field names that are not listed above."
                    )
                else:
                    response_text += (
                        "_No fields returned. Verify the repository name is correct._"
                    )
                
            except TimeoutError as e:
                response_text = f"⏱️ **Timeout**\n\n{str(e)}"
            except ValueError as e:
                response_text = f"❌ **Validation Error**\n\n{str(e)}"
            except RuntimeError as e:
                response_text = f"❌ **API Error**\n\n{str(e)}"
        
        elif name == "get_query_best_practices":
            catalog = get_catalog()
            summary = catalog.get_best_practices_summary()
            
            response_text = "📖 **NGSIEM Query Best Practices**\n\n"
            response_text += f"{summary.get('description', '')}\n\n"
            response_text += f"**Template:** `{summary.get('template', '')}`\n\n"
            
            # Pipeline steps
            response_text += "## Query Construction Pipeline\n\n"
            response_text += "Follow these steps IN ORDER for optimal query performance:\n\n"
            for step in summary.get('pipeline_steps', []):
                response_text += f"### {step.get('order')}. {step.get('name')}\n\n"
                response_text += f"{step.get('description', '')}\n\n"
                if step.get('rationale'):
                    response_text += f"*Why:* {step.get('rationale')}\n\n"
                if step.get('examples'):
                    response_text += "**Examples:**\n```\n"
                    for ex in step['examples'][:3]:
                        response_text += f"{ex}\n"
                    response_text += "```\n\n"
            
            # Optimization tips
            response_text += "## Optimization Tips\n\n"
            for tip in summary.get('optimization_tips', []):
                response_text += f"### {tip.get('title', '')}\n\n"
                response_text += f"{tip.get('description', '')}\n\n"
                if tip.get('impact'):
                    response_text += f"**Impact:** {tip.get('impact')}\n\n"
            
            # Anti-patterns
            if summary.get('anti_patterns'):
                response_text += "## Anti-Patterns to Avoid\n\n"
                for ap in summary['anti_patterns']:
                    response_text += f"**{ap.get('name', '')}**\n"
                    response_text += f"- ❌ Bad: `{ap.get('bad', '')}`\n"
                    response_text += f"- ✅ Good: `{ap.get('good', '')}`\n"
                    response_text += f"- Issue: {ap.get('issue', '')}\n\n"
        
        else:
            raise ValueError(f"Unknown tool: {name}")
        
        return [TextContent(type="text", text=response_text)] # Moved common return here
    
    except ValueError as e:
        logger.error(f"Validation error in {name}: {e}")
        return [TextContent(
            type="text",
            text=f"❌ **Validation Error**\n\n{str(e)}"
        )]
    
    except RuntimeError as e:
        logger.error(f"Runtime error in {name}: {e}")
        return [TextContent(
            type="text",
            text=f"❌ **API Error**\n\n{str(e)}"
        )]
    
    except Exception as e:
        logger.error(f"Unexpected error in {name}: {e}", exc_info=True)
        return [TextContent(
            type="text",
            text=f"❌ **Unexpected Error**\n\n{str(e)}\n\nCheck logs for details."
        )]


async def main():
    """Main entry point for the MCP server."""
    logger.info("Starting NGSIEM MCP Server...")
    
    # Validate configuration on startup
    try:
        config = load_config()
        logger.info(f"Configuration loaded successfully")
        logger.info(f"Base URL: {config.base_url}")
        logger.info(f"Default Repository: {config.default_repository or 'Not set'}")
    except Exception as e:
        logger.error(f"Configuration error: {e}")
        logger.error("Server will start but tools will fail until configuration is fixed")
    
    # Run MCP server
    async with stdio_server() as (read_stream, write_stream):
        logger.info("MCP Server running on stdio")
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
