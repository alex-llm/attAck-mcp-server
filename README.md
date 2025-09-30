# attAck-mcp-server

This project is an MCP (Model Context Protocol) server for querying ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) techniques and tactics. It provides a way to access and retrieve information about various attack techniques and tactics used by adversaries.

## Tools

The server provides the following tools:

*   **query\_technique:**  This tool allows you to query ATT&CK techniques by ID or name.
    *   **Arguments:**
        *   `technique_id` (string, optional): The ID of the technique to query.
        *   `tech_name` (string, optional): The name (or partial name) of the technique to query. 支持名称模糊搜索。
    *   **Example:**
        - 按ID查询：
        ```json
        {
          "technique_id": "T1059.001"
        }
        ```
        - 按名称模糊搜索：
        ```json
        {
          "tech_name": "phishing"
        }
        ```
*   **search\_technique\_full:**  通过技术 ID 或名称查询攻击技术的所有详细信息，返回的数据包含 ID、名称、描述、适用平台、Kill Chain 阶段、参考资料、子技术及缓解措施。名称搜索返回格式为 `{ "results": [...], "count": N }` 的字典，其中 `results` 为匹配技术完整数据列表。
    *   **Arguments:**
        *   `technique_id` (string, optional): 要查询的技术ID。
        *   `tech_name` (string, optional): 技术名称关键字，支持模糊匹配。
    *   **Example:**
        - 按ID查询：
        ```json
        {
          "technique_id": "T1059.001"
        }
        ```
        - 按名称模糊搜索：
        ```json
        {
          "tech_name": "phishing"
        }
        ```
*   **query\_mitigations:** 查询技术的缓解措施
    *   **Arguments:**
        *   `technique_id` (string, required): 要查询的技术ID
    *   **Example:**
        ```json
        {
          "technique_id": "T1059.001"
        }
        ```
*   **query\_detections:** 查询技术的检测方法
    *   **Arguments:**
        *   `technique_id` (string, required): 要查询的技术ID
    *   **Example:**
        ```json
        {
          "technique_id": "T1059.001"
        }
        ```
*   **list\_tactics:** This tool allows you to retrieve a list of all ATT&CK tactics.
    *   **Arguments:** None
*   **server_info:** 返回服务与数据集的版本、维护者和Git信息。
    *   **Arguments:** None
    *   **Example:**
        ```json
        {}
        ```

## Usage

To use this MCP server, you need to have an MCP client configured to connect to it. Once connected, you can use the provided tools to query ATT&CK techniques and tactics.

## MCP Client 配置说明

### 1. 本地 stdio 方式（推荐 Smithery/本地集成）

- 直接运行：
  ```bash
  python main.py
  ```
- 程序会自动选择 stdio 模式（默认或 `ATTACK_MCP_MODE=stdio`），适用于 Smithery、Cursor 等支持本地 MCP stdio 的客户端。
- MCP 客户端配置服务类型为"local/stdio"，无需指定端口。
- 适用场景：Smithery 自动化、CI/CD、本地 AI Agent 集成。

### 2. HTTP/Streamable 方式（远程/开发/调试）

- 使用 CLI 参数切换模式：
  ```bash
  python main.py --mode http --host 0.0.0.0 --port 8081 --log-level info
  ```
- 或通过环境变量控制：
  ```bash
  export ATTACK_MCP_MODE=http
  export ATTACK_MCP_HOST=0.0.0.0   # 可选，默认 0.0.0.0 或 $HOST
  export ATTACK_MCP_PORT=8081      # 可选，默认 8081 或 $PORT
  export ATTACK_MCP_LOG_LEVEL=info # 可选，默认 info
  python main.py
  ```
- 运行后服务以 streamable HTTP 方式暴露，可在客户端配置服务类型为 "http"，地址如 `http://127.0.0.1:8081/mcp`。
- 远程部署（如 Smithery Cloud）通常会提供 `PORT` 或 `MCP_TRANSPORT` 环境变量，可直接运行 `python main.py` 即使用 HTTP。对于值为 `streaming`、`streamable`、`streamable-http`、`streamable HTTP transport` 或 `stdioNotSupported` 等新枚举的运行环境，程序会自动回退到 HTTP 模式，无需额外配置。
- Smithery 等容器平台会通过 `PORT`（默认为 8081）告知监听端口；程序会自动读取该值并监听在 `0.0.0.0:$PORT`。
- **工具名称**：`query_technique`、`search_technique_full`、`query_mitigations`、`query_detections`、`list_tactics`、`server_info`
- **参数示例**：
  - 按ID查询技术：
    ```json
    {
      "technique_id": "T1059.001"
    }
    ```
  - 按名称模糊搜索技术：
    ```json
    {
      "tech_name": "phishing"
    }
    ```
  - 使用 `search_technique_full` 获取技术的完整详细信息：
    ```json
    {
      "tech_name": "phishing"
    }
    ```
  - 查询技术缓解措施：
    ```json
    {
      "technique_id": "T1059.001"
    }
    ```
  - 查询技术检测方法：
    ```json
    {
      "technique_id": "T1059.001"
    }
    ```
  - 查询战术列表：
    ```json
    {}
    ```
  - 查询服务与数据集信息：
    ```json
    {}
    ```

> 具体的客户端配置方式请参考您的 MCP 客户端文档，将上述服务地址和工具名称填入对应位置即可。

## Installation

1.  Clone this repository.
2.  Install the required dependencies using `pip install -r requirements.txt`.
3.  Configure the MCP server in your MCP client.

## ATT&CK

ATT&CK is a curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary's attack lifecycle and the platforms they are known to target. ATT&CK is useful for understanding security risks against any specific technology or organization.

## 快速启动

### 方式一：直接用 Python 脚本运行（开发/调试推荐）

1. 安装依赖（建议在虚拟环境中）：
   ```bash
   pip install -r requirements.txt
   ```
2. 确保 enterprise-attack.json 数据集在项目根目录。
3. 启动服务（默认 stdio 模式，适用于本地客户端集成）：
   ```bash
   python main.py
   ```
4. 如果需要以 HTTP 方式提供服务，请显式选择模式：
   ```bash
   python main.py --mode http --host 127.0.0.1 --port 8081
   ```

### 方式二：生产环境推荐（Docker 部署）

#### Docker
1. 构建镜像：
   ```bash
   docker build -t attack-mcp-server .
   ```
2. 运行容器：
   ```bash
   docker run -p 8081:8081 attack-mcp-server
   ```

---

## API 说明
- /query_technique 通过ID或名称查询攻击技术详情（支持名称模糊搜索）
- /search_technique_full 通过ID或名称查询攻击技术的完整详细信息（名称搜索返回匹配技术列表，包含子技术与缓解措施）
- /query_mitigations 查询指定技术的缓解措施
- /query_detections 查询指定技术的检测方法
- /list_tactics 获取所有ATT&CK战术分类
- /server_info 返回服务版本、数据集版本和Git信息

---

如有问题请联系维护者。
