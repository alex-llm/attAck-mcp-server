# 导入核心库
from mcp.server.fastmcp import FastMCP
from mitreattack.stix20 import MitreAttackData
from fastapi import HTTPException
import uvicorn
import json
from typing import Optional
import asyncio
import logging
import threading
import os

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 初始化MCP服务器
logger.info("正在初始化MCP服务器...")
mcp = FastMCP(
    name="ATT&CK_Query_Service",
    description="提供MITRE ATT&CK技术、战术及缓解措施的查询服务",
    version="2.1"
)

attack_data = None
TECH_CACHE = None
attack_data_lock = threading.Lock()

def ensure_attack_data_loaded():
    global attack_data, TECH_CACHE
    if attack_data is None or TECH_CACHE is None:
        with attack_data_lock:
            if attack_data is None or TECH_CACHE is None:
                from mitreattack.stix20 import MitreAttackData
                logger.info("首次加载ATT&CK数据集，可能需要几秒...")
                attack_data = MitreAttackData("enterprise-attack.json")
                TECH_CACHE = {t.external_references[0].external_id: t for t in attack_data.get_techniques()}
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
    ensure_attack_data_loaded()
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
            for tech in TECH_CACHE.values():
                if search_term in tech.name.lower():
                    results.append({
                        "id": tech.external_references[0].external_id,
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

def format_technique_data(tech):
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
                "url": ref.url
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
    
    return data

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
    ensure_attack_data_loaded()
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
    ensure_attack_data_loaded()
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
    ensure_attack_data_loaded()
    logger.info("正在获取所有战术列表")
    tactics = [{
        "id": t.external_references[0].external_id,
        "name": t.name,
        "description": t.description
    } for t in attack_data.get_tactics()]
    logger.info(f"返回 {len(tactics)} 个战术")
    return tactics

app = mcp.sse_app()

if __name__ == "__main__":
    # 只需切换下方注释即可选择 stdio 或 http 模式
    # --- MCP stdio 模式（Smithery/本地集成推荐）---
    mcp.run()
    # --- HTTP/SSE 模式（开发/调试/远程部署推荐）---
    # import uvicorn
    # uvicorn.run(
    #     "main:app",
    #     host="127.0.0.1",
    #     port=8001,
    #     log_level="info"
    # )
