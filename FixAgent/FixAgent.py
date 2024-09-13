from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
import RAG
app = FastAPI(
    title="Fix Agent API",
    description="An API to manage remediation and generate VEX documents for SBOMs.",
    version="1.0.0"
)

# Reusing existing SBOM models from the Security Agent
class Cpe(BaseModel):
    cpe: str
    source: Optional[str]

class Artifact(BaseModel):
    id: str
    name: str
    version: str
    type: str
    foundBy: str
    locations: List[Dict]
    licenses: List
    language: str
    cpes: List[Cpe]
    purl: str
    metadataType: str
    metadata: Dict

class AnalyzeSbom(BaseModel):
    artifacts: List[Artifact]
    artifactRelationships: List[Dict]
    files: List[Dict]
    source: Dict
    distro: Dict
    descriptor: Dict
    schema: Dict

# Request model for fix agent operations
class FixRequest(BaseModel):
    vulnerability_ids:str
    Discription: str


# Endpoint to generate a fix plan
@app.post('/generate_fix_plan')
async def generate_fix_plan(request: FixRequest):
    """
    Generate a plan for fixing the given vulnerabilities.
    """
    fixplan = RAG.main(request.vulnerability_ids,request.Discription)

    # # Example fix plan generation logic
    # fix_plan = {}
    # for vuln_id in request.vulnerability_ids:
    #     fix_plan[vuln_id] = {
    #         "fix_action": f"Patch for {vuln_id}",
    #         "estimated_completion": "2 weeks"  # Placeholder value
    #     }
    
    return {"product_id": request.vulnerability_ids, "fix_plan": fixplan}

# Endpoint to generate VEX document
@app.post('/generate_vex')
async def generate_vex(request: FixRequest):
    """
    Generate a VEX (Vulnerability Exploitability eXchange) document.
    """
    # Example VEX document generation logic
    vex_document = {
        "product_id": request.product_id,
        "vulnerabilities": [],
        "fix_status": request.fix_status or "Pending"
    }
    
    for vuln_id in request.vulnerability_ids:
        vex_document["vulnerabilities"].append({
            "vulnerability_id": vuln_id,
            "status": request.fix_status or "Pending"
        })
    
    return vex_document

# Endpoint to update SBOM based on applied fixes
@app.post('/update_sbom')
async def update_sbom(sbom: AnalyzeSbom, fixes: Dict[str, str]):
    """
    Update an SBOM based on applied fixes.
    
    Args:
        sbom (AnalyzeSbom): The SBOM to be updated.
        fixes (Dict): A dictionary mapping vulnerability IDs to their fix status.
    
    Returns:
        dict: Updated SBOM reflecting the applied fixes.
    """
    updated_sbom = sbom.dict()  # Convert SBOM to a dict for easy manipulation
    
    # Update each artifact's CPEs based on the applied fixes
    for artifact in updated_sbom['artifacts']:
        for cpe in artifact['cpes']:
            cpe_id = cpe['cpe']
            if cpe_id in fixes:
                # Apply the fix and mark it in the SBOM
                cpe['fix_status'] = fixes[cpe_id]
    
    return {"updated_sbom": updated_sbom}
