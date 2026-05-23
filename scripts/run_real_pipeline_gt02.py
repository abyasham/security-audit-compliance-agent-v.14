import sys
from pathlib import Path

from dotenv import load_dotenv
from pypdf import PdfReader

ROOT = Path("c:/saca/saca14/apps/core-py").resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.llm_gateway import LiteLLMGateway
from agents.policy_agent import PolicyAgent
from agents.network_agent import NetworkAgent
from agents.compliance_judge import ComplianceJudge
from eval.ragas_runner import RagasRunner
from schema.models import ParsedPolicy


def main() -> None:
    load_dotenv("c:/saca/saca14/.env")

    policy_pdf = Path("c:/saca/saca14/media/en_303645v030103p.pdf")
    reader = PdfReader(str(policy_pdf))

    pages_to_read = min(20, len(reader.pages))
    policy_text = "\n\n".join(reader.pages[i].extract_text() or "" for i in range(pages_to_read))
    policy_text = policy_text.strip()

    llm = LiteLLMGateway()
    policy_agent = PolicyAgent(llm_gateway=llm)
    network_agent = NetworkAgent(llm_gateway=llm)
    judge = ComplianceJudge(llm_gateway=llm)
    ragas = RagasRunner()

    parsed_policy = ParsedPolicy(
        policyName="ETSI EN 303 645 (v3.1.1)",
        framework="ETSI EN 303 645",
        sourceFormat="pdf",
        rawText=policy_text,
    )

    policy_output = policy_agent.analyze(parsed_policy, llm_config={"provider": "openrouter"})
    rules = policy_output.get("rules", [])
    print({"rules_extracted": len(rules)})

    pcap_path = "c:/saca/saca14/media/GT_02.pcap"

    import subprocess, json as json_mod

    runner_path = Path("c:/saca/saca14/apps/core-py/network_analyzer_tshark.py")
    result = subprocess.run(
        ["c:/saca/saca14/.venv/Scripts/python.exe", str(runner_path), pcap_path],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"NetworkAnalyzer failed: {result.stderr}")
    network_output = json_mod.loads(result.stdout)

    # LLM payload anomaly detection (direct tshark packet context)
    from schema.models import ExpertInfoSummary
    expert_info = ExpertInfoSummary(errors=0, warnings=0, info=[], debugMessages=[])
    llm_anomalies = network_agent._identify_anomalies_with_llm(
        pcap_path, [], expert_info, [], [], llm_config={"provider": "openrouter"},
    )
    if llm_anomalies:
        existing = network_output.get("anomalies", [])
        existing.extend([a.__dict__ for a in llm_anomalies])
        network_output["anomalies"] = existing

    judge_result = judge.evaluate(
        policy_rules=rules,
        network_output=network_output,
        llm_config={"provider": "openrouter"},
        capture_file_path=pcap_path,
    )

    ragas_result = ragas.evaluate_sync(
        findings=judge_result.get("findings", []),
        policy_text=policy_text,
        session_id="GT-02",
        capture_file_path=pcap_path,
    )

    print({
        "session_id": "GT-02",
        "findings": len(judge_result.get("findings", [])),
        "avg_faithfulness": ragas_result.get("avg_faithfulness"),
        "avg_answer_relevancy": ragas_result.get("avg_answer_relevancy"),
        "provider_used": ragas_result.get("provider_used"),
        "heuristic_fallback": ragas_result.get("heuristic_fallback"),
    })


if __name__ == "__main__":
    main()
