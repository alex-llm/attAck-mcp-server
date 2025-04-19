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

## Usage

To use this MCP server, you need to have an MCP client configured to connect to it. Once connected, you can use the provided tools to query ATT&CK techniques and tactics.

## MCP Client 配置说明

### 1. 本地 stdio 方式（推荐 Smithery/本地集成）

- 直接运行：
  ```bash
  python main.py
  ```
- main.py 默认以 stdio (mcp.serve) 模式启动，适用于 Smithery、Cursor 等支持本地 MCP stdio 的客户端。
- MCP 客户端配置服务类型为"local/stdio"，无需指定端口。
- 适用场景：Smithery 自动化、CI/CD、本地 AI Agent 集成。

### 2. HTTP/SSE 方式（远程/开发/调试）

- 取消 main.py 末尾的 mcp.serve() 注释，启用 uvicorn 相关代码。
- 启动服务：
  ```bash
  python main.py
  # 或
  uvicorn main:app --host 0.0.0.0 --port 8001
  ```
- MCP 客户端配置服务类型为"http"，地址如 `http://127.0.0.1:8001/sse`。

- **工具名称**：`query_technique`、`query_mitigations`、`query_detections`、`list_tactics`
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
3. 启动服务：
   ```bash
   python main.py
   ```
4. 服务默认监听 http://127.0.0.1:8001

### 方式二：生产环境推荐（Docker 或 Uvicorn）

#### Docker
1. 构建镜像：
   ```bash
   docker build -t attack-mcp-server .
   ```
2. 运行容器：
   ```bash
   docker run -p 8001:8001 attack-mcp-server
   ```

#### Uvicorn 命令行
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8001
   ```

---

## API 说明
- /query_technique 通过ID或名称查询攻击技术详情（支持名称模糊搜索）
- /query_mitigations 查询指定技术的缓解措施
- /query_detections 查询指定技术的检测方法  
- /list_tactics 获取所有ATT&CK战术分类

---

如有问题请联系维护者。
