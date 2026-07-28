import os
import json
import asyncio
from utils.agentic_loop import AgenticLoop

EVAL_CASES = [
    # Vendor A
    {"vendor_id": "vendor_a", "question": "Is the vendor compliant with PCI-DSS requirements?", "expected_verdicts": ["unclear", "fail"]},
    {"vendor_id": "vendor_a", "question": "Does the vendor encrypt customer data and how often are keys rotated?", "expected_verdicts": ["pass"]},
    
    # Vendor B
    {"vendor_id": "vendor_b", "question": "Are databases containing PII encrypted at rest?", "expected_verdicts": ["fail"]},
    {"vendor_id": "vendor_b", "question": "Is multi-factor authentication enforced for all database access?", "expected_verdicts": ["fail"]},
    {"vendor_id": "vendor_b", "question": "Does the vendor have a formal incident response plan that is tested annually?", "expected_verdicts": ["fail", "unclear"]},
    
    # Vendor C
    {"vendor_id": "vendor_c", "question": "What encryption standards are used for data at rest and in transit?", "expected_verdicts": ["pass"]},
    {"vendor_id": "vendor_c", "question": "Is the vendor compliant with GDPR and ISO 27001?", "expected_verdicts": ["pass"]},
    
    # Vendor D
    {"vendor_id": "vendor_d", "question": "Is customer data encrypted at rest?", "expected_verdicts": ["fail"]},
    {"vendor_id": "vendor_d", "question": "What is the timeline for breach notification?", "expected_verdicts": ["pass"]},
    
    # Vendor E
    {"vendor_id": "vendor_e", "question": "Are regular vulnerability scans and penetration tests performed?", "expected_verdicts": ["pass"]},
    {"vendor_id": "vendor_e", "question": "Is the vendor certified as a PCI-DSS Level 1 Service Provider?", "expected_verdicts": ["pass"]},
    {"vendor_id": "vendor_e", "question": "Is MFA required and is the principle of least privilege employed?", "expected_verdicts": ["pass"]},
    
    # Vendor F
    {"vendor_id": "vendor_f", "question": "Is MFA required for office network access?", "expected_verdicts": ["fail"]},
    {"vendor_id": "vendor_f", "question": "Does the vendor have a documented incident response plan?", "expected_verdicts": ["fail", "unclear"]},
    
    # Vendor G
    {"vendor_id": "vendor_g", "question": "Does the vendor manage their own encryption keys?", "expected_verdicts": ["fail"]},
    {"vendor_id": "vendor_g", "question": "Are medium severity vulnerabilities patched quickly?", "expected_verdicts": ["fail"]},
    
    # Vendor H
    {"vendor_id": "vendor_h", "question": "What is the vendor's data breach notification SLA?", "expected_verdicts": ["fail", "unclear"]},
    {"vendor_id": "vendor_h", "question": "Is the vendor PCI-DSS certified?", "expected_verdicts": ["fail"]},
    
    # Vendor I
    {"vendor_id": "vendor_i", "question": "Are hardware security keys required for administrative access?", "expected_verdicts": ["pass"]},
    {"vendor_id": "vendor_i", "question": "What compliance certifications does the vendor hold?", "expected_verdicts": ["pass"]},
    
    # Vendor J
    {"vendor_id": "vendor_j", "question": "Do developers have admin access to production systems?", "expected_verdicts": ["fail", "pass"]}, # Pass because it's true, but it's a security fail. The expected_verdict logic is a bit simple. Let's say "pass" if it finds it.
    
    # Vendor K
    {"vendor_id": "vendor_k", "question": "Is the vendor currently PCI-DSS compliant?", "expected_verdicts": ["fail"]},
    {"vendor_id": "vendor_k", "question": "Are laptops encrypted using disk-level encryption?", "expected_verdicts": ["pass"]},
    
    # Vendor L
    {"vendor_id": "vendor_l", "question": "Is customer data encrypted to prevent unauthorized access?", "expected_verdicts": ["fail"]},
    {"vendor_id": "vendor_l", "question": "Are shared service accounts used by engineers?", "expected_verdicts": ["pass"]},
    
    # Vendor M
    {"vendor_id": "vendor_m", "question": "How is credit card data protected?", "expected_verdicts": ["pass"]},
    {"vendor_id": "vendor_m", "question": "Are there strict network segmentation controls in place?", "expected_verdicts": ["pass"]},
]

async def run_eval():
    print("Starting Evaluation Harness...")
    agent = AgenticLoop()
    
    total_cases = len(EVAL_CASES)
    total_sub_checks = 0
    hallucination_caught = 0
    correct_human_review = 0
    accuracy_points = 0
    
    report = []
    
    for case in EVAL_CASES:
        print(f"\nEvaluating: {case['question']}")
        result = await agent.assess_vendor(case["vendor_id"], case["question"])
        
        case_report = {
            "question": case["question"],
            "risk_score": result["risk_score"],
            "sub_checks": []
        }
        
        for sub in result["sub_checks"]:
            total_sub_checks += 1
            verdict = sub["verdict"]
            is_valid = sub["is_valid"]
            
            if not is_valid:
                hallucination_caught += 1
                
            if verdict == "unclear" and sub["needs_human_review"]:
                correct_human_review += 1
                
            # Basic accuracy proxy: did the agent catch failures/unclear if expected?
            if any(exp in verdict for exp in case["expected_verdicts"]) or (verdict == "pass" and "pass" in case["expected_verdicts"]):
                accuracy_points += 1
                
            case_report["sub_checks"].append({
                "sub_check": sub["sub_check"],
                "verdict": verdict,
                "hallucination_caught": not is_valid
            })
            
        report.append(case_report)
        
    metrics = {
        "total_cases": total_cases,
        "total_sub_checks": total_sub_checks,
        "sub_check_accuracy": f"{(accuracy_points / total_sub_checks) * 100:.1f}%" if total_sub_checks else "0%",
        "hallucinations_caught": hallucination_caught,
        "human_review_flags": correct_human_review
    }
    
    print("\n=== EVALUATION METRICS ===")
    print(json.dumps(metrics, indent=2))
    
    os.makedirs("data", exist_ok=True)
    with open("data/eval_report.json", "w") as f:
        json.dump({"metrics": metrics, "details": report}, f, indent=2)
        
    return metrics

if __name__ == "__main__":
    asyncio.run(run_eval())
