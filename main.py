# 导入核心库
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from mitreattack.stix20 import MitreAttackData
from fastapi import HTTPException
from starlette.middleware.cors import CORSMiddleware
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send
import uvicorn
import argparse
import sys
import json
from typing import Optional, List
import asyncio
import logging
import os
from urllib.parse import parse_qs, unquote

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 初始化MCP服务器
logger.info("正在初始化MCP服务器...")
PROJECT_VERSION = "2.1"
PROJECT_NAME = "ATT&CK_Query_Service"
PROJECT_DESCRIPTION = "提供MITRE ATT&CK技术、战术及缓解措施的查询服务"
MESSAGE_ENDPOINT_PATH = "/messages/"

mcp = FastMCP(
    name=PROJECT_NAME,
    description=PROJECT_DESCRIPTION,
    version=PROJECT_VERSION,
    message_path=MESSAGE_ENDPOINT_PATH,
)

attack_data = None
TECH_CACHE = None
TECH_NAME_CACHE = None
attack_data_lock = asyncio.Lock()


def read_commit_hash(repo_root: str) -> Optional[str]:
    """Read the current commit hash from the `.git` directory without invoking Git."""
    git_dir = os.path.join(repo_root, ".git")
    head_file = os.path.join(git_dir, "HEAD")
    if not os.path.exists(head_file):
        return None

    with open(head_file, "r") as f:
        ref_line = f.read().strip()

    if ref_line.startswith("ref:"):
        ref_path = os.path.join(git_dir, ref_line.split(":", 1)[1].strip())
        if os.path.exists(ref_path):
            with open(ref_path, "r") as f:
                return f.read().strip()
        return None
    else:
        return ref_line

async def ensure_attack_data_loaded():
    global attack_data, TECH_CACHE, TECH_NAME_CACHE
    if attack_data is None or TECH_CACHE is None or TECH_NAME_CACHE is None:
        async with attack_data_lock:
            if attack_data is None or TECH_CACHE is None or TECH_NAME_CACHE is None:
                logger.info("首次加载ATT&CK数据集，可能需要几秒...")
                data_path = os.path.join(os.path.dirname(__file__), "enterprise-attack.json")
                attack_data = MitreAttackData(data_path)
                TECH_CACHE = {t.external_references[0].external_id: t for t in attack_data.get_techniques()}
                TECH_NAME_CACHE = {tid: tech.name.lower() for tid, tech in TECH_CACHE.items()}
                logger.info(f"成功加载 {len(TECH_CACHE)} 个技术条目")

# 核心查询工具
@mcp.tool(
    name="query_technique",
    description="通过技术ID精确查询或技术名称模糊搜索ATT&CK攻击技术的详细信息。ID查询返回单个技术的完整数据，名称搜索返回匹配技术列表的摘要。"
)
async def query_attack_technique(
    technique_id: Optional[str] = None, 
    tech_name: Optional[str] = None
):
    """
    根据提供的技术ID或技术名称查询ATT&CK攻击技术。

    当提供 `technique_id` 时 (例如 "T1059.001")，执行精确匹配查询。
    成功时返回该技术的详细信息，包括：ID, 名称, 描述, 适用平台, Kill Chain阶段, 相关参考资料, 以及子技术列表 (如果存在)。
    如果ID无效或未找到，将返回一个包含错误信息的字典。

    当提供 `tech_name` 时 (例如 "phishing")，执行模糊匹配搜索。
    返回一个包含技术列表摘要的字典，其中每个条目包含技术的ID、名称和简短描述。
    同时返回匹配结果的数量。

    参数:
        technique_id (Optional[str]): 要查询的ATT&CK技术ID。如果提供此参数，则优先使用ID进行精确查询。
        tech_name (Optional[str]): 用于模糊搜索的ATT&CK技术名称中的关键词。如果未提供 `technique_id`，则使用此参数进行搜索。

    返回:
        dict: 
            - 如果是ID查询且成功，返回包含技术完整详情的字典。
            - 如果是名称搜索，返回一个格式为 {"results": [...], "count": N} 的字典，其中 "results" 是技术摘要列表，"count" 是结果数量。
            - 如果参数无效 (例如两者都未提供) 或查询过程中发生内部错误，可能返回包含 "error" 键的字典或引发HTTPException。
    """
    await ensure_attack_data_loaded()
    logger.info(f"收到查询请求 - ID: {technique_id}, 名称: {tech_name}")
    try:
        if technique_id:
            # ID精确查询逻辑
            if technique_id.upper() not in TECH_CACHE:
                logger.warning(f"未找到技术ID: {technique_id}")
                return {"error": f"未找到技术ID {technique_id}"}
            
            tech = TECH_CACHE[technique_id.upper()]
            logger.info(f"成功查询到技术: {tech.name}")
            return format_technique_data(tech)
            
        elif tech_name:
            # 名称模糊搜索逻辑
            results = []
            search_term = tech_name.lower()
            for tid, name_lower in TECH_NAME_CACHE.items():
                if search_term in name_lower:
                    tech = TECH_CACHE[tid]
                    results.append({
                        "id": tid,
                        "name": tech.name,
                        "description": tech.description[:150] + "..."  # 摘要显示
                    })
            logger.info(f"名称搜索 '{tech_name}' 找到 {len(results)} 个结果")
            return {"results": results, "count": len(results)}
            
        else:
            logger.error("请求缺少必要参数")
            raise HTTPException(status_code=400, detail="必须提供ID或名称参数")
            
    except Exception as e:
        logger.error(f"查询过程中发生错误: {str(e)}")
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")

def format_technique_data(tech, include_mitigations: bool = False):
    """标准化技术数据格式"""
    data = {
        "id": tech.external_references[0].external_id,
        "name": tech.name,
        "description": tech.description,
        "platforms": tech.x_mitre_platforms,
        "kill_chain": [phase.phase_name for phase in tech.kill_chain_phases],
        "references": [
            {
                "source": ref.source_name,
                "url": getattr(ref, "url", None)
            } for ref in tech.external_references
        ]
    }

    # 添加子技术信息
    # Use the technique's STIX ID to get subtechniques
    subtechniques = attack_data.get_subtechniques_of_technique(tech.id)
    if subtechniques:
        data["subtechniques"] = [{
            "id": st["object"].external_references[0].external_id,
            "name": st["object"].name
        } for st in subtechniques]

    if include_mitigations:
        mitigations = attack_data.get_mitigations_mitigating_technique(tech.id)
        if mitigations:
            data["mitigations"] = [{
                "id": m["object"].external_references[0].external_id,
                "name": m["object"].name,
                "description": m["object"].description,
            } for m in mitigations]

    return data

@mcp.tool(
    name="search_technique_full",
    description=(
        "通过技术ID精确查询或技术名称模糊搜索 ATT&CK 攻击技术的所有详尽信息。"
        "返回的数据包含 ID、名称、描述、适用平台、Kill Chain 阶段、参考资料、子技术及缓解措施。"
        "ID 查询返回单个技术的完整数据；名称搜索返回所有匹配技术的完整数据列表并包含结果数量。"
    ),
)
async def search_technique_full(
    technique_id: Optional[str] = None,
    tech_name: Optional[str] = None,
):
    """查询并返回 ATT&CK 技术的完整信息。

    - 当提供 ``technique_id`` 时 (例如 ``"T1059.001"``)，执行精确匹配并返回该技术的完整详情。
    - 当提供 ``tech_name`` 时，执行模糊匹配，返回所有匹配技术的完整详情列表。

    返回的每个技术详情都包含以下字段：
    ``id``、``name``、``description``、``platforms``、``kill_chain``、``references``、``subtechniques`` (若存在) 以及 ``mitigations`` (若存在)。

    参数:
        technique_id (Optional[str]): 要查询的 ATT&CK 技术 ID。若提供，将优先进行 ID 查询。
        tech_name (Optional[str]): 用于模糊搜索的技术名称关键词。

    返回:
        dict: 
            - ID 查询成功时返回单个技术的完整详情字典。
            - 名称搜索时返回 ``{"results": [...], "count": N}``，其中 ``results`` 是技术完整详情列表，``count`` 为匹配数量。
    """
    await ensure_attack_data_loaded()
    logger.info(f"收到详细查询请求 - ID: {technique_id}, 名称: {tech_name}")
    try:
        if technique_id:
            if technique_id.upper() not in TECH_CACHE:
                logger.warning(f"未找到技术ID: {technique_id}")
                return {"error": f"未找到技术ID {technique_id}"}

            tech = TECH_CACHE[technique_id.upper()]
            logger.info(f"成功查询到技术: {tech.name}")
            return format_technique_data(tech, include_mitigations=True)

        elif tech_name:
            results = []
            search_term = tech_name.lower()
            for tid, name_lower in TECH_NAME_CACHE.items():
                if search_term in name_lower:
                    tech = TECH_CACHE[tid]
                    results.append(format_technique_data(tech, include_mitigations=True))
            logger.info(f"名称搜索 '{tech_name}' 返回 {len(results)} 个结果")
            return {"results": results, "count": len(results)}

        else:
            logger.error("请求缺少必要参数")
            raise HTTPException(status_code=400, detail="必须提供ID或名称参数")

    except Exception as e:
        logger.error(f"查询过程中发生错误: {str(e)}")
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")

@mcp.tool(
    name="query_mitigations",
    description="根据ATT&CK技术ID查询相关的缓解措施列表。为每个缓解措施提供ID、名称和描述。"
)
async def query_mitigations(technique_id: str):
    """
    根据指定的ATT&CK技术ID查询并返回所有相关的缓解措施。

    参数:
        technique_id (str): 要查询缓解措施的ATT&CK技术ID (例如 "T1059.001")。ID必须精确匹配。

    返回:
        list: 一个包含缓解措施对象的列表。每个对象包含 "id", "name", 和 "description"。
              如果技术ID无效或未找到，返回一个包含 "error" 键的字典，例如: {"error": "未找到技术ID TXXXX"}。
    """
    await ensure_attack_data_loaded()
    if technique_id.upper() not in TECH_CACHE:
        return {"error": f"未找到技术ID {technique_id}"}
    
    tech = TECH_CACHE[technique_id.upper()]
    mitigations = attack_data.get_mitigations_mitigating_technique(tech.id)
    return [{
        "id": m["object"].external_references[0].external_id,
        "name": m["object"].name,
        "description": m["object"].description
    } for m in mitigations]

@mcp.tool(
    name="query_detections",
    description="根据ATT&CK技术ID查询相关的检测方法或数据组件。为每个检测方法提供其来源(数据组件名称)和描述。"
)
async def query_detections(technique_id: str):
    """
    根据指定的ATT&CK技术ID查询并返回所有相关的数据组件，这些组件可用于检测该技术的应用。

    参数:
        technique_id (str): 要查询检测方法的ATT&CK技术ID (例如 "T1059.001")。ID必须精确匹配。

    返回:
        list: 一个包含检测数据组件对象的列表。每个对象包含 "source" (数据组件名称) 和 "description"。
              如果技术ID无效或未找到，返回一个包含 "error" 键的字典，例如: {"error": "未找到技术ID TXXXX"}。
    """
    await ensure_attack_data_loaded()
    if technique_id.upper() not in TECH_CACHE:
        return {"error": f"未找到技术ID {technique_id}"}
    
    tech = TECH_CACHE[technique_id.upper()]
    detections = attack_data.get_datacomponents_detecting_technique(tech.id)
    return [{
        "source": d["object"].name,
        "description": d["object"].description
    } for d in detections]

# 附加功能：战术列表查询
@mcp.tool(
    name="list_tactics",
    description="获取并列出MITRE ATT&CK框架中定义的所有战术。为每个战术提供ID、名称和描述。"
)
async def get_all_tactics():
    """
    获取并返回MITRE ATT&CK框架中定义的所有战术的列表。

    参数:
        无

    返回:
        list: 一个包含战术对象的列表。每个对象包含 "id", "name", 和 "description"。
    """
    await ensure_attack_data_loaded()
    logger.info("正在获取所有战术列表")
    tactics = [{
        "id": t.external_references[0].external_id,
        "name": t.name,
        "description": t.description
    } for t in attack_data.get_tactics()]
    logger.info(f"返回 {len(tactics)} 个战术")
    return tactics


@mcp.tool(
    name="server_info",
    description="返回项目工程、MCP库与ATT&CK数据集版本及维护信息，包括Git状态。",
)
async def server_info():
    """获取服务和数据集的版本、维护者及Git信息。"""
    import importlib.metadata

    info = {
        "intro": "Provides project, MCP library, ATT&CK dataset and git version details.",
        "project": {
            "name": PROJECT_NAME,
            "version": PROJECT_VERSION,
            "description": PROJECT_DESCRIPTION,
            "maintainer": "Alex louis <ycliu912@126.com>",
        },
        "mcp": {
            "library_version": importlib.metadata.version("mcp"),
        },
        "attack_dataset": {},
        "git": {},
    }

    try:
        data_path = os.path.join(os.path.dirname(__file__), "enterprise-attack.json")
        with open(data_path, "r") as f:
            data = json.load(f)
        info["attack_dataset"] = {
            "spec_version": data.get("spec_version"),
            "attack_spec_version": data.get("objects", [{}])[0].get("x_mitre_attack_spec_version"),
        }
    except Exception as e:
        info["attack_dataset"] = {"error": str(e)}

    commit_id = read_commit_hash(os.path.dirname(__file__))
    if commit_id:
        info["git"] = {"commit_id": commit_id}
    else:
        info["git"] = {"error": "git metadata not found"}

    return info

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ATT&CK Query Service")
    parser.add_argument(
        "--version",
        action="store_true",
        help="显示版本信息并退出",
    )
    parser.add_argument(
        "--mode",
        choices=["http", "stdio"],
        default=None,
        help="选择运行模式: http 或 stdio。默认会根据环境变量或回退到 stdio。",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="HTTP 模式下监听的主机地址 (默认: 0.0.0.0 或 $HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8081,
        help="HTTP 模式下监听的端口 (默认: 8081)",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        help="HTTP 模式下的日志等级 (默认: info)",
    )
    return parser.parse_args(argv)

def normalize_mode(cli_mode: Optional[str]) -> str:
    """Resolve the execution mode from CLI arguments and environment variables.

    Some remote runtimes (for example Smithery) require an HTTP/SSE transport and
    communicate this requirement through the ``MCP_TRANSPORT`` environment
    variable.  Historically only ``"stdio"`` and ``"http"`` were supported, but
    new values such as ``"streaming"`` or ``"streamable"`` are now emitted.  To
    avoid hard failures we normalise a wider range of aliases to one of the two
    execution modes supported by the server.
    """

    env_mode = (
        os.getenv("ATTACK_MCP_MODE")
        or os.getenv("TRANSPORT")
        or os.getenv("MCP_TRANSPORT")
    )
    raw_mode = (cli_mode or env_mode or "").strip().lower()

    def _canonicalise(value: str) -> str:
        """Return a normalised key containing only lowercase alpha-numerics."""

        return "".join(ch for ch in value if ch.isalnum())

    canonical_mode = _canonicalise(raw_mode)

    mode_aliases = {
        "": None,
        "stdio": "stdio",
        "http": "http",
        "https": "http",
        "sse": "http",
        "stream": "http",
        "streaming": "http",
        "streamable": "http",
        "streamablehttp": "http",
        "streamablehttptransport": "http",
        "streamablehttps": "http",
        "httpstreaming": "http",
        "stdionotsupported": "http",
    }

    if raw_mode in mode_aliases:
        resolved_mode = mode_aliases[raw_mode]
    else:
        resolved_mode = mode_aliases.get(canonical_mode)

    if not resolved_mode:
        # If the canonical form still contains hints of http/streaming we fall
        # back to the HTTP server.  This allows values such as "streamable-http"
        # or "streamable http" to work without having to list every variant.
        if canonical_mode:
            if "http" in canonical_mode or "sse" in canonical_mode or "stream" in canonical_mode:
                resolved_mode = "http"
            elif "stdio" in canonical_mode:
                resolved_mode = "stdio"

    if raw_mode and resolved_mode is None:
        raise ValueError(
            f"Unsupported mode '{raw_mode}'. Use 'stdio' or 'http'."
        )

    if resolved_mode:
        return resolved_mode

    # No explicit mode was provided. Default to HTTP when a port hint is
    # available (common on remote deployments), otherwise fall back to stdio.
    if (
        os.getenv("ATTACK_MCP_PORT")
        or os.getenv("PORT")
        or os.getenv("SMITHERY_PORT")
    ):
        return "http"

    return "stdio"


def resolve_host(cli_host: Optional[str]) -> str:
    return (
        cli_host
        or os.getenv("ATTACK_MCP_HOST")
        or os.getenv("HOST")
        or "0.0.0.0"
    )


def resolve_port(cli_port: Optional[int]) -> int:
    if cli_port is not None:
        return cli_port

    for env_var in ("ATTACK_MCP_PORT", "PORT", "SMITHERY_PORT"):
        value = os.getenv(env_var)
        if value:
            try:
                return int(value)
            except ValueError:
                raise ValueError(f"环境变量 {env_var} 的值 '{value}' 不是有效的端口号") from None

    return 8081


def resolve_log_level(cli_log_level: Optional[str]) -> str:
    return (cli_log_level or os.getenv("ATTACK_MCP_LOG_LEVEL") or "info").lower()


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)

    if args.version:
        print(f"{PROJECT_NAME} v{PROJECT_VERSION}")
        sys.exit(0)

    try:
        mode = normalize_mode(args.mode)
        host = resolve_host(args.host)
        port = resolve_port(args.port)
        log_level = resolve_log_level(args.log_level)
    except ValueError as exc:
        logger.error(str(exc))
        sys.exit(2)

    logger.info("启动模式: %s", mode)

    if mode == "stdio":
        mcp.run()
        return

    app = create_http_app()
    uvicorn.run(
        app=app,
        host=host,
        port=port,
        log_level=log_level,
    )


def create_http_app():
    """Create the FastMCP HTTP application with permissive CORS headers."""

    sse_transport = SseServerTransport(MESSAGE_ENDPOINT_PATH)

    async def handle_sse(request):
        async with sse_transport.connect_sse(
            request.scope,
            request.receive,
            request._send,  # type: ignore[attr-defined]
        ) as streams:
            await mcp._mcp_server.run(  # type: ignore[attr-defined]
                streams[0],
                streams[1],
                mcp._mcp_server.create_initialization_options(),  # type: ignore[attr-defined]
            )

    app = Starlette(
        debug=mcp.settings.debug,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount(MESSAGE_ENDPOINT_PATH, app=sse_transport.handle_post_message),
        ],
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["mcp-session-id", "mcp-protocol-version"],
        max_age=86400,
    )

    return MessageEndpointAliasMiddleware(app, MESSAGE_ENDPOINT_PATH)


class MessageEndpointAliasMiddleware:
    """ASGI middleware that rewrites HTTP scope paths for message aliases.

    Some MCP clients encode the ``/messages/`` path multiple times or fall back
    to posting messages to ``/`` with only a ``session_id`` query parameter.  The
    FastMCP transport expects requests to target the canonical ``/messages/``
    endpoint, so this middleware normalises the incoming path and forwards the
    request to the expected route without requiring the client to be
    implementation-aware.
    """

    def __init__(self, app, message_path: str):
        self._app = app
        self._message_path = self._ensure_trailing_slash(message_path)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type != "http":
            await self._app(scope, receive, send)
            return

        method = scope.get("method") or ""
        path = scope.get("path", "")
        query_string = scope.get("query_string", b"")
        logger.debug(
            "HTTP request received: method=%s path='%s' query='%s'",
            method,
            path or "/",
            query_string.decode("utf-8", "ignore") if isinstance(query_string, (bytes, bytearray)) else query_string,
        )

        if self._should_rewrite(scope):
            patched_scope = dict(scope)
            patched_scope["path"] = self._message_path
            patched_scope["raw_path"] = self._message_path.encode()
            logger.debug(
                "Rewriting message alias '%s' to '%s'",
                scope.get("path"),
                self._message_path,
            )
            await self._app(patched_scope, receive, send)
            return

        logger.debug(
            "Forwarding request without rewrite: method=%s path='%s'",
            method,
            path or "/",
        )
        await self._app(scope, receive, send)

    def _should_rewrite(self, scope: Scope) -> bool:
        path = scope.get("path", "")
        if not path and scope.get("raw_path"):
            try:
                path = scope["raw_path"].decode("utf-8", "ignore")
            except Exception:
                path = ""

        normalized = self._normalize_path(path)

        if normalized == self._message_path:
            return True

        if normalized.rstrip("/") == self._message_path.rstrip("/"):
            return True

        if normalized == "/":
            method = (scope.get("method") or "").upper()
            if method == "POST":
                # Check if this is a JSON-RPC request (like from Smithery)
                if self._is_jsonrpc_request(scope):
                    logger.debug(
                        "Rewriting JSON-RPC request '%s %s' to message endpoint '%s'",
                        method,
                        scope.get("path", "/"),
                        self._message_path,
                    )
                    return True
                # Check if it has session identifier
                elif self._has_session_identifier(scope):
                    logger.debug(
                        "Rewriting session request '%s %s' to message endpoint '%s'",
                        method,
                        scope.get("path", "/"),
                        self._message_path,
                    )
                    return True

        return False

    def _normalize_path(self, path: str) -> str:
        candidate = path or "/"

        for _ in range(5):
            decoded = unquote(candidate)
            if decoded == candidate:
                break
            candidate = decoded

        candidate = candidate.replace("\\", "/")

        if not candidate.startswith("/"):
            candidate = f"/{candidate}"

        while "//" in candidate:
            candidate = candidate.replace("//", "/")

        if candidate != "/" and not candidate.endswith("/"):
            candidate = f"{candidate}/"

        return candidate

    def _is_jsonrpc_request(self, scope: Scope) -> bool:
        """Check if this is a JSON-RPC request by examining headers and content type."""
        headers = scope.get("headers") or []
        for key, value in headers:
            if key.decode("utf-8", "ignore").lower() == "content-type":
                content_type = value.decode("utf-8", "ignore").lower()
                if "application/json" in content_type:
                    return True
        return False

    def _has_session_identifier(self, scope: Scope) -> bool:
        query_string = scope.get("query_string", b"")
        if query_string:
            params = parse_qs(query_string.decode("utf-8", "ignore"), keep_blank_values=True)
            if params.get("session_id") or params.get("sessionId"):
                return True

        headers = scope.get("headers") or []
        for key, value in headers:
            if key.decode("utf-8", "ignore").lower() == "mcp-session-id" and value:
                return True

        return False

    @staticmethod
    def _ensure_trailing_slash(path: str) -> str:
        if not path.startswith("/"):
            path = f"/{path}"
        if not path.endswith("/"):
            path = f"{path}/"
        return path


if __name__ == "__main__":
    main()
