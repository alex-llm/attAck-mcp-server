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
    description="通过ID或名称查询攻击技术详情"
)
async def query_attack_technique(
    technique_id: Optional[str] = None, 
    tech_name: Optional[str] = None
):
    """支持精确ID查询和名称模糊搜索的ATT&CK技术查询"""
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
    subtechniques = attack_data.get_subtechniques_of(tech)
    if subtechniques:
        data["subtechniques"] = [{
            "id": st.external_references[0].external_id,
            "name": st.name
        } for st in subtechniques]
    
    return data

@mcp.tool(name="query_mitigations")
async def query_mitigations(technique_id: str):
    """查询技术的缓解措施"""
    ensure_attack_data_loaded()
    if technique_id.upper() not in TECH_CACHE:
        return {"error": f"未找到技术ID {technique_id}"}
    
    tech = TECH_CACHE[technique_id.upper()]
    mitigations = attack_data.get_mitigations_by_technique(tech.id)
    return [{
        "id": m.external_references[0].external_id,
        "name": m.name,
        "description": m.description
    } for m in mitigations]

@mcp.tool(name="query_detections") 
async def query_detections(technique_id: str):
    """查询技术的检测方法"""
    ensure_attack_data_loaded()
    if technique_id.upper() not in TECH_CACHE:
        return {"error": f"未找到技术ID {technique_id}"}
    
    tech = TECH_CACHE[technique_id.upper()]
    detections = attack_data.get_detections_by_technique(tech.id)
    return [{
        "source": d.source_name,
        "description": d.description
    } for d in detections]

# 附加功能：战术列表查询
@mcp.tool(name="list_tactics")
async def get_all_tactics():
    """获取所有ATT&CK战术分类"""
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
