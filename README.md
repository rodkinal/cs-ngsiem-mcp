# NGSIEM MCP Server

A Model Context Protocol (MCP) server that provides programmatic access to CrowdStrike NGSIEM search capabilities. This server enables MCP-compatible applications to execute security event searches through a standardized interface.

## Overview

This MCP server acts as an intelligent bridge between LLMs and CrowdStrike NGSIEM, designed to prevent hallucinations and enforce query integrity. It exposes NGSIEM functionality through **ten specialized tools** that prioritize validation and context awareness.

## Quick Start

### Prerequisites

- Python 3.13+
- CrowdStrike API credentials with NGSIEM scope
- MCP-compatible client application

### Installation

1. **Clone and setup environment**:
   ```bash
   cd /path/to/cs-ngsiem-mcp
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Configure Environment Variables**:
   
   Create a `.env` file in the root directory:
   ```bash
   cp .env.example .env
   ```

   Add your CrowdStrike API credentials (ensure `NGSIEM` and `Falcon Data Replicator` scopes are enabled):
   ```ini
   #.env
   CROWDSTRIKE_CLIENT_ID=your_client_id_here
   CROWDSTRIKE_CLIENT_SECRET=your_client_secret_here
   CROWDSTRIKE_BASE_URL=https://api.eu-1.crowdstrike.com
   NGSIEM_DEFAULT_REPOSITORY=base_sensor
   LOG_LEVEL=INFO
   ```

3. **Configure Repositories**:

   Create the repository catalog file `config/repositories.yaml`:

   ```bash
   cp config/repositories.example.yaml config/repositories.yaml
   ```

   The `repositories.yaml` format allows you to define schema and context for each repository:
   
   ```yaml
   repositories:
     - name: "base_sensor"
       description: "Telemetry events from Falcon sensors (process, network, file)"
       default: true
       data_types:
         - "ProcessRollup2"
         - "NetworkConnectIP4"
       use_cases:
         - "Threat hunting"
         - "Incident investigation"
         
     - name: "audit_logs"
       description: "Falcon platform audit logs"
       default: false
   ```

   > **Tip**: You can use the `get_repo_fieldset` tool to discover available fields in any configured repository.

## Key Capabilities

1. **Intelligent Query Validation**:
   Before any search is executed, the **Query Validator** analyzes the syntax to catch common errors. It checks for balanced parentheses, valid operators, and correct function usage, ensuring that only syntactically correct queries are sent to the API.

2. **Dynamic Schema Discovery (Field Validation)**:
   To prevent the LLM from hallucinating non-existent fields, the server provides the `get_repo_fieldset` tool. This tool dynamically downloads the **live schema** (all valid fields) for a specific repository from your environment. The LLM is instructed to *always* consult this schema before constructing a query.

3. **Context-Aware Repository Management**:
   The server does not guess where logs are securely stored. You explicitly define your log sources in `config/repositories.yaml`. This configuration file tells the LLM exactly **which repository** contains what data (e.g., "base_sensor" repository for process events, "squid" repository for proxy logs), allowing it to intelligently select the right data source for each question.

```mermaid
graph TD
    A[LLM Query] --> B{Schema Check}
    B -->|get_repo_fieldset| C[Download Live Fields]
    C --> D[Construct Query]
    D --> E{Syntax Check}
    E -->|validate_query| F[Execute Search]
    
    style A fill:#e1f5ff
    style B fill:#fff3e0
    style E fill:#fff3e0
    style F fill:#e8f5e9
```

## HTTP Server Mode (FastAPI + SSE)

For production deployments or remote access, the server supports the **MCP 2025-11-25 Streamable HTTP** transport.

📄 **[Read the Full Architecture & Feature Guide](Documentation/SERVER_ARCHITECTURE.md)** for detailed diagrams and flows.

📄 **[Read the Full Query Validation Architecture](Documentation/QUERY_VALIDATION_ARCHITECTURE.md)** for detailed diagrams and flows.

### Quick Start (HTTP)

1.  **Configure API Key**:
    Add `MCP_API_KEY` to your `.env` file (generated automatically if missing, but better to set it).

2.  **Start the Server**:
    Use the provided script which handles environment loading and logging:
    ```bash
    ./start_http_server.sh
    ```

3.  **Verify Connection**:
    Use the Inspector script to test the server:
    ```bash
    ./start_http_inspector.sh
    ```

### Claude Desktop Integration

To connect Claude Desktop to the HTTP server, you must use a proxy to inject the authentication headers.

Update your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ngsiem-http": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://localhost:8080/mcp",
        "--header",
        "Authorization: Bearer <YOUR_MCP_API_KEY_LOCATED_IN_YOUR .env FILE>"
      ]
    }
  }
}
```

See [SERVER_ARCHITECTURE.md](Documentation/SERVER_ARCHITECTURE.md) for detailed configuration options.

### VS Code Integration

For VS Code users (using extensions like Cline or Roo Code), the configuration uses the native HTTP transport directly without the need for a proxy.

Update your MCP settings in VS Code:

```json
{
  "servers": {
    "cs-ngsiem-mcp": {
      "type": "http",
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer <YOUR_AUTH_TOKEN>"
      }
    }
  }
}
```

## Architecture

For a detailed breakdown of the system architecture, request flows, and component diagrams, please refer to:

👉 **[SERVER_ARCHITECTURE.md](Documentation/SERVER_ARCHITECTURE.md)**



## Available Tools

### Tool Workflow

This diagram illustrates the typical user journey from discovering repositories to executing searches.

```mermaid
graph TD
    Start[User Goal] --> KnowRepo{Know Config?}
    
    KnowRepo -->|No| ListRepos[get_available_repositories]
    ListRepos --> ChooseRepo[Select Repository]
    KnowRepo -->|Yes| ChooseRepo
    
    ChooseRepo --> NeedQuery{Need Query?}
    
    NeedQuery -->|Yes| BrowseTemplates[list_templates]
    BrowseTemplates --> BuildQuery[build_query]
    BuildQuery --> Validate[validate_query]
    
    NeedQuery -->|No| Validate
    
    Validate -->|Valid| Execution{Execution Mode}
    Validate -->|Invalid| BuildQuery
    
    Execution -->|Async| StartSearch[start_search]
    Execution -->|Blocking| SearchWait[search_and_wait]
    
    StartSearch --> Poll[get_search_status]
    Poll -->|Running| Poll
    Poll -->|Done| Results[Get Results]
    
    SearchWait --> Results
    
    style ListRepos fill:#fff3e0
    style BrowseTemplates fill:#fff3e0
    style BuildQuery fill:#fff3e0
    style Validate fill:#fff3e0
    style StartSearch fill:#e8f5e9
    style SearchWait fill:#e8f5e9
```

### 1. get_available_repositories

Get the list of configured NGSIEM repositories.

**Parameters**: None

**Returns**: List of repositories with descriptions, data types, and use cases.

**Use Case**: Discovery of available data sources before searching.

### 2. start_search

Initiates an asynchronous NGSIEM search.

**Parameters**:
- `repository` (string, optional): Repository name (defaults to `.env` config)
- `query_string` (string, required): NGSIEM query syntax
- `start` (string, optional): Time range (default: "1d")
- `is_live` (boolean, optional): Live search mode (default: false)

**Returns**: Search job ID for status polling

**Use Case**: Long-running searches where client wants progress control

**Example Query**:
```
#event_simpleName=ProcessRollup2 | FileName=powershell.exe
```

### 3. get_search_status

Retrieves status and results of a running search.

**Parameters**:
- `repository` (string, optional): Repository name
- `search_id` (string, required): ID from start_search

**Returns**: Status, event count, and results (if complete)

**Use Case**: Polling for search completion

### 4. search_and_wait

Executes search and waits for completion (blocking operation).

**Parameters**:
- `repository` (string, optional): Repository name
- `query_string` (string, required): NGSIEM query
- `start` (string, optional): Time range (default: "1d")
- `is_live` (boolean, optional): Live search mode (default: false)
- `max_wait_seconds` (integer, optional): Timeout (default: 300, max: 3600)
- `poll_interval` (integer, optional): Poll frequency (default: 2s)

**Returns**: Complete results or timeout error

**Use Case**: Quick searches with immediate results needed

**Internal Flow**:
```mermaid
graph LR
    A[search_and_wait] --> B[start_search]
    B --> C{Poll Loop}
    C -->|done=false| D[sleep poll_interval]
    D --> E[get_search_status]
    E --> C
    C -->|done=true| F[Return Results]
    C -->|timeout| G[Raise TimeoutError]
    
    style F fill:#e8f5e9
    style G fill:#ffebee
```

### 5. stop_search

Cancels a running search.

**Parameters**:
- `repository` (string, optional): Repository name
- `search_id` (string, required): ID to cancel

**Returns**: Cancellation confirmation

**Use Case**: Terminating long-running searches

### 6. get_query_reference

Access NGSIEM query language documentation.

**Parameters**:
- `category` (string, optional): Filter by category (aggregate, filtering, security, etc.)
- `function_name` (string, optional): Get details for specific function
- `search_term` (string, optional): Search functions by keyword

**Returns**: Function documentation with syntax and examples

**Use Case**: Discover available functions before building queries

### 7. list_templates

Browse pre-built security query templates.

**Parameters**:
- `category` (string, optional): Filter by category (threat_hunting, ioc_hunting, etc.)
- `search_term` (string, optional): Search templates by keyword

**Returns**: Available templates with descriptions and MITRE ATT&CK mapping

**Use Case**: Find ready-to-use queries for common security operations

### 8. validate_query

Validate query syntax before execution.

**Parameters**:
- `query` (string, required): NGSIEM query to validate
- `strict` (boolean, optional): Treat warnings as errors

**Returns**: Validation result with issues and suggestions

**Use Case**: Catch syntax errors before running searches

### 9. build_query

Build queries from templates with parameters.

**Parameters**:
- `template` (string, required): Template name to use
- `parameters` (object, optional): Values for template placeholders

**Returns**: Generated query ready for execution

**Use Case**: Create customized queries from templates

### 10. get_repo_fieldset

**MANDATORY FIRST STEP**: Discover all available fields in a NGSIEM repository.

> **Important**: Call this tool BEFORE constructing any search query. Only use field names returned by this tool in your queries.

**Parameters**:

- `repository` (string, optional): Repository name (uses default from config if not specified)
- `timeout_seconds` (integer, optional): Maximum wait time (1-120 seconds, default: 60)

**Returns**: Complete list of valid field names for the repository

**Use Case**: Schema discovery to prevent query failures from invalid field references

**Security**: Repository name is validated against injection attacks (alphanumeric, underscores, hyphens only)

### 11. get_query_best_practices

Get NGSIEM query writing best practices for optimal performance.

**Parameters**: None

**Returns**: 
- 8-step query construction pipeline (based on Humio/LogScale documentation)
- Optimization tips (tag specificity, limit placement, case sensitivity)
- Efficient patterns with examples
- Anti-patterns to avoid

**Use Case**: Learn how to structure queries for maximum efficiency

**Query Pipeline** (execute in order):
```
tag-filters | field-filters | transformations | aggregate | visualization
```

1. **Narrow Timeframe** - Reduce search scope
2. **Tag Filters First** - Use `#field` syntax for indexed fields (30x faster)
3. **Field Value Filters** - Filter by specific values
4. **Exclusion Filters** - Remove unwanted results
5. **Regex Filters** - Pattern matching (use sparingly)
6. **Transformations** - eval, format, parse functions
7. **Aggregations** - count, sum, groupBy, etc.
8. **Visualization** - sort, table, head for output

## Available Resources

### ngsiem://repositories

A JSON-formatted resource providing detailed metadata about all configured repositories.

**Content:**
```json
[
  {
    "name": "base_sensor",
    "description": "Main event stream",
    "data_types": ["ProcessRollup2", "DnsRequest"],
    "use_cases": ["General threat hunting", "Process analysis"]
  }
]
```

**Usage**:
- **Claude Desktop**: Automatically reads this on startup to understand the environment.
- **Manual**: Use `read_resource("ngsiem://repositories")` to inspect config.

## Project Structure

```
cs-ngsiem-mcp/
├── ngsiem_mcp_stdio.py      # MCP stdio server implementation
├── ngsiem_mcp_http.py       # MCP HTTP server implementation
├── ngsiem_tools.py           # NGSIEM API wrapper
├── ngsiem_query_catalog.py   # Query function/template catalog
├── ngsiem_query_validator.py # Query syntax validator
├── config.py                 # Configuration management
├── config/                   # Query catalogs
│   ├── ngsiem_functions.yaml # 54 NGSIEM functions
│   ├── ngsiem_syntax.yaml    # Query syntax reference
│   └── ngsiem_templates.yaml # 32 security templates
├── .env                      # Credentials (gitignored)
├── .env.example              # Configuration template
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

### Module Dependencies

```mermaid
graph TD
    A[ngsiem_mcp_http.py] --> B[ngsiem_tools.py]
    A --> C[config.py]
    B --> C
    C --> D[.env]
    B --> E[falconpy.APIHarnessV2]
    A --> F[mcp.server]
    
    A:::server
    B:::tools
    C:::config
    D:::env
    E:::external
    F:::external
    
    classDef server fill:#34a853,color:#fff
    classDef tools fill:#fbbc04
    classDef config fill:#4285f4,color:#fff
    classDef env fill:#ea4335,color:#fff
    classDef external fill:#9e9e9e,color:#fff
```

## Security Architecture

```mermaid
graph LR
    A[Client Input] -->|Pydantic| B[Validation Layer]
    B -->|Sanitization| C[Query Builder]
    C -->|OAuth2| D[API Request]
    D -->|TLS 1.2+| E[CrowdStrike API]
    
    B -.->|Invalid| F[Error Response]
    D -.->|Auth Fail| F
    
    style A fill:#e1f5ff
    style B fill:#e8f5e9
    style C fill:#fff4e1
    style E fill:#fce4ec
    style F fill:#ffebee
```

### Security Features

- **No hardcoded credentials**: All secrets in `.env`
- **Input validation**: Pydantic models with strict typing
- **Query sanitization**: Prevents injection attacks
- **OAuth2 authentication**: Automatic token management
- **Audit logging**: Detailed operation logs
- **Error handling**: No sensitive data in error messages

## Configuration

### Environment Variables

| Variable | Description | Example | Required |
|----------|-------------|---------|----------|
| `CROWDSTRIKE_CLIENT_ID` | API Client ID | `abc123...` | Yes |
| `CROWDSTRIKE_CLIENT_SECRET` | API Secret | `xyz789...` | Yes |
| `CROWDSTRIKE_BASE_URL` | API Endpoint | `https://api.eu-1.crowdstrike.com` | Yes |
| `NGSIEM_DEFAULT_REPOSITORY` | Default Repository | `base_sensor` | Yes |
| `LOG_LEVEL` | Logging Level | `INFO` | No |
| `LOG_FILE` | Log File Path (Stdio Mode) | `ngsiem_mcp.log` | No |
| **HTTP Server Config** | | | |
| `MCP_API_KEY` | Bearer Token for Auth | `secret-token-123` | Yes (HTTP) |
| `MCP_HTTP_HOST` | Server Host | `0.0.0.0` | No |
| `MCP_HTTP_PORT` | Server Port | `8080` | No |
| `MCP_HTTP_ACCESS_LOG` | Uvicorn Access Log Path | `ngsiem-mcp-http.log` | No |
| `MCP_HTTP_APP_LOG` | Application Log Path | `ngsiem-mcp-app.log` | No |
| `MCP_CORS_ORIGINS` | CORS Allowed Origins | `*` or `http://localhost:3000` | No |
| `NGSIEM_THREAD_POOL_SIZE` | Max threads for blocking API calls | `4` | No |
| `MCP_SKIP_AUTH` | Bypass auth for dev testing | `true` | No |

> **Note**: `MCP_SKIP_AUTH=true` disables authentication entirely. Only use for development with MCP Inspector (which has a known bug that prevents header forwarding).

### Regional Endpoints

| Region | Base URL |
|--------|----------|
| US-1 | `https://api.crowdstrike.com` |
| US-2 | `https://api.us-2.crowdstrike.com` |
| EU-1 | `https://api.eu-1.crowdstrike.com` |

### Default Repository

The `repository` parameter is **optional** in all tools. When omitted, the server uses `NGSIEM_DEFAULT_REPOSITORY` from `.env`.

**Benefits**:
- Fewer parameters required
- Reduced client complexity
- Consistent repository usage

**Override**: Specify `repository` parameter to use a different repository for specific searches.

### Repository Configuration

Define available repositories in `config/repositories.yaml`.

```yaml
repositories:
  - name: base_sensor
    default: true
    description: "Main event stream"
  - name: zscaler
    description: "Zscaler Web logs"
```

**Note**: `config/repositories.yaml` is in `.gitignore` to prevent leaking sensitive internal names.

## Logging

### Log Levels

```mermaid
graph TD
    A[Log Entry] --> B{Level}
    B -->|DEBUG| C[API Responses<br/>Request Details]
    B -->|INFO| D[Operations<br/>Status Changes]
    B -->|WARNING| E[Recoverable Issues<br/>Timeouts]
    B -->|ERROR| F[Failures<br/>Exceptions]
    
    C --> G[Development]
    D --> H[Production]
    E --> H
    F --> H
    
    style D fill:#e8f5e9
    style E fill:#fff4e1
    style F fill:#ffebee
```

### Log Location

- **Default**: `ngsiem_mcp.log` (current directory)
- **Custom**: Set `LOG_FILE` in `.env`

### Debug Mode

```bash
# In .env
LOG_LEVEL=DEBUG
```

View logs:
```bash
tail -f ngsiem-mcp-http.log
tail -f ngsiem-mcp-app.log
```

## Resources

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [CrowdStrike NGSIEM API Documentation](https://falcon.crowdstrike.com/documentation/page/ngsiem-api)
- [FalconPy SDK](https://github.com/CrowdStrike/falconpy)
- [NGSIEM Query Language Guide](https://falcon.crowdstrike.com/documentation/page/ngsiem-query-language)


## Contributing

For issues or enhancements:
1. Test changes locally
2. Update documentation
3. Follow existing code style
4. Ensure security best practices

---

**Built with**: Python 3.13 | MCP SDK 1.25.0 | FalconPy 1.5.5 | Pydantic 2.12.5 by **Rodkinal** and **GenIA**
