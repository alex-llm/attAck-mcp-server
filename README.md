# ATT&CK MCP Server

This project is an MCP (Model Context Protocol) server designed to provide comprehensive query capabilities for the MITRE ATT&CK framework. It allows users to access detailed information about attack techniques, tactics, associated mitigations, and detection methods.

## Features

*   Loads MITRE ATT&CK data (from `enterprise-attack.json`).
*   Provides tools to query techniques, mitigations, detections, and tactics.
*   Supports both precise ID lookups and fuzzy name searches for techniques.
*   Offers clear and structured JSON responses.

## Tools

The server exposes the following tools for interaction via an MCP client:

### 1. `query_technique`

**Description (from `main.py`):** 通过技术ID精确查询或技术名称模糊搜索ATT&CK攻击技术的详细信息。ID查询返回单个技术的完整数据，名称搜索返回匹配技术列表的摘要。
(Query detailed information of ATT&CK attack techniques through precise query by technique ID or fuzzy search by technique name. ID query returns complete data for a single technique, name search returns a summary of the list of matching techniques.)

**Arguments:**

*   `technique_id` (string, optional): The exact ID of the technique to query (e.g., "T1059.001").
*   `tech_name` (string, optional): A keyword or partial name for fuzzy searching techniques (e.g., "phishing"). 支持名称模糊搜索。

**Behavior & Response:**

*   **If `technique_id` is provided (Precise Query):**
    *   Returns a dictionary containing full details of the specified technique, including ID, name, description, platforms, kill chain phases, references, and sub-techniques (if any).
    *   **Example Request:**
        ```json
        {
          "technique_id": "T1059.001"
        }
        ```
    *   **Example Successful Response (Structure):**
        ```json
        {
          "id": "T1059.001",
          "name": "PowerShell",
          "description": "Adversaries may abuse PowerShell commands and scripts...",
          "platforms": ["Windows"],
          "kill_chain": ["execution"],
          "references": [{"source": "Mitre ATT&CK", "url": "https://attack.mitre.org/techniques/T1059/001"}],
          "subtechniques": [] // or list of sub-technique objects
        }
        ```
    *   **Error Response (Invalid ID):**
        ```json
        {
          "error": "未找到技术ID T1059.001" 
        }
        ```
*   **If `tech_name` is provided (Fuzzy Search):**
    *   Returns a dictionary containing a list of techniques that match the name, along with a count. Each item in the list provides a summary (ID, name, abridged description).
    *   **Example Request:**
        ```json
        {
          "tech_name": "phishing"
        }
        ```
    *   **Example Successful Response (Structure):**
        ```json
        {
          "results": [
            {
              "id": "T1566",
              "name": "Phishing",
              "description": "Adversaries may send phishing messages to elicit sensitive information..."
            },
            {
              "id": "T1598.003",
              "name": "Phishing for Information: Spearphishing Link",
              "description": "Adversaries may send spearphishing messages with a link..."
            }
          ],
          "count": 2 
        }
        ```
*   **If neither `technique_id` nor `tech_name` is provided:**
    *   Raises an `HTTPException` (typically resulting in a 500 error from the MCP server wrapper in `main.py` due to internal error handling catching the initial 400 error), with a detail message indicating that one parameter is required. Example: `{"detail":"查询失败: 400: 必须提供ID或名称参数"}`.

### 2. `query_mitigations`

**Description (from `main.py`):** 根据ATT&CK技术ID查询相关的缓解措施列表。为每个缓解措施提供ID、名称和描述。
(Query the list of related mitigation measures based on ATT&CK technique ID. Provide ID, name, and description for each mitigation measure.)

**Arguments:**

*   `technique_id` (string, required): The exact ID of the technique for which to find mitigations (e.g., "T1078").

**Behavior & Response:**

*   Returns a list of mitigation objects associated with the technique. Each object includes the mitigation's "id", "name", and "description".
*   If the technique ID is invalid or not found, returns an error dictionary: `{"error": "未找到技术ID TXXXX"}`.
*   **Example Request:**
    ```json
    {
      "technique_id": "T1078"
    }
    ```
*   **Example Successful Response (Structure):**
    ```json
    [
      {
        "id": "M1015",
        "name": "Application Isolation and Sandboxing",
        "description": "Application isolation and sandboxing may..."
      },
      {
        "id": "M1017",
        "name": "User Training",
        "description": "Train users to be aware of the risks of reusing credentials..."
      }
    ]
    ```
    (Note: An empty list `[]` is returned if a valid technique has no associated mitigations.)

### 3. `query_detections`

**Description (from `main.py`):** 根据ATT&CK技术ID查询相关的检测方法或数据组件。为每个检测方法提供其来源(数据组件名称)和描述。
(Query related detection methods or data components based on ATT&CK technique ID. Provide its source (data component name) and description for each detection method.)

**Arguments:**

*   `technique_id` (string, required): The exact ID of the technique for which to find detection methods/data components (e.g., "T1059.001").

**Behavior & Response:**

*   Returns a list of detection data component objects associated with the technique. Each object includes the "source" (data component name) and "description".
*   If the technique ID is invalid or not found, returns an error dictionary: `{"error": "未找到技术ID TXXXX"}`.
*   **Example Request:**
    ```json
    {
      "technique_id": "T1059.001"
    }
    ```
*   **Example Successful Response (Structure):**
    ```json
    [
      {
        "source": "Command: Command Execution",
        "description": "Monitor executed commands and arguments for PowerShell..."
      },
      {
        "source": "Process: Process Creation",
        "description": "Monitor for newly created processes that execute PowerShell..."
      }
    ]
    ```
    (Note: An empty list `[]` is returned if a valid technique has no associated detection data components.)

### 4. `list_tactics`

**Description (from `main.py`):** 获取并列出MITRE ATT&CK框架中定义的所有战术。为每个战术提供ID、名称和描述。
(Get and list all tactics defined in the MITRE ATT&CK framework. Provide ID, name, and description for each tactic.)

**Arguments:**

*   None.

**Behavior & Response:**

*   Returns a list of all ATT&CK tactics. Each tactic object in the list includes its "id", "name", and "description".
*   **Example Request:**
    ```json
    {}
    ```
*   **Example Successful Response (Structure - showing one tactic):**
    ```json
    [
      {
        "id": "TA0001",
        "name": "Initial Access",
        "description": "The adversary is trying to get into your network..."
      }
      // ... (typically 13 more tactics for Enterprise ATT&CK)
    ]
    ```

### 5. `health_check`

**Description (from `main.py`):** Checks the server status and confirms ATT&CK data is loaded. Returns basic statistics about the loaded data.

**Arguments:**

*   None.

**Behavior & Response:**

*   Attempts to load or verify that the ATT&CK data (`enterprise-attack.json`) is loaded into memory.
*   Returns a status object indicating success or failure, along with counts of loaded techniques and tactics.
*   **Example Request:**
    ```json
    {}
    ```
*   **Example Successful Response:**
    ```json
    {
      "status": "OK",
      "message": "ATT&CK data loaded successfully.",
      "loaded_techniques_count": 701, // Example count
      "loaded_tactics_count": 14
    }
    ```
*   **Example Error Response (if data loading fails):**
    ```json
    {
      "status": "ERROR",
      "message": "ATT&CK data could not be loaded." 
      // Or a more specific error: "ATT&CK data could not be loaded or processed. Error: <details>"
    }
    ```

## Setup and Usage

### Prerequisites
* Python 3.8+
* `pip` for installing dependencies.

### Installation
1.  Clone this repository:
    ```bash
    git clone <repository_url>
    cd attAck-mcp-server
    ```
2.  Install the required dependencies (preferably in a virtual environment):
    ```bash
    pip install -r requirements.txt
    ```
3.  Ensure the `enterprise-attack.json` file (MITRE ATT&CK STIX data) is present in the project root directory. This file is automatically downloaded by `mitreattack-python` if not found during the first run of `ensure_attack_data_loaded()` in `main.py`, but it's good practice to ensure it's managed appropriately.

### Running the Server

The server can be run in two modes:

**1. Local Stdio Mode (Recommended for Smithery/Local AI Agent Integration)**

*   This is the default mode when running `main.py` directly.
*   **Command:**
    ```bash
    python main.py
    ```
*   The MCP server communicates over standard input/output.
*   Configure your MCP client for "local/stdio" service type. No host/port needed.

**2. HTTP/SSE Mode (For Remote Access, Development, Debugging)**

*   To enable this mode, you need to modify `main.py`:
    1.  Comment out `mcp.run()` at the end of the file.
    2.  Uncomment the `uvicorn.run(...)` block.
*   **Command (after modifying `main.py`):**
    ```bash
    python main.py
    ```
    Alternatively, you can run directly with Uvicorn without modifying the file if `app = mcp.sse_app()` is accessible:
    ```bash
    uvicorn main:app --host 0.0.0.0 --port 8001 --log-level info
    ```
*   The MCP server will be available via HTTP SSE.
*   Configure your MCP client for "http" service type, using the appropriate URL (e.g., `http://127.0.0.1:8001/sse`).

## ATT&CK Framework

ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

---

For issues or contributions, please refer to the project's repository.
