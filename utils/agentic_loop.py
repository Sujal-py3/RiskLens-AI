import asyncio
from .groq_client import GroqClient
from .retrieval import VendorRAG

class AgenticLoop:
    def __init__(self):
        self.llm = GroqClient()
        self.rag = VendorRAG()
        
    async def assess_vendor(self, vendor_id: str, main_question: str) -> dict:
        """
        Runs the full Plan-Act-Check loop for a given vendor and question.
        """
        print(f"PLAN: Decomposing question: {main_question}")
        sub_checks = self.llm.plan_sub_checks_json(main_question)
        print(f"Sub-checks generated: {sub_checks}")
        
        # ACT phase: concurrently process sub-checks
        tasks = [self._process_sub_check(vendor_id, check) for check in sub_checks]
        results = await asyncio.gather(*tasks)
        
        # AGGREGATE phase
        print("AGGREGATE: Calculating final risk score and remediation.")
        final_assessment = self.llm.aggregate_results(main_question, results)
        
        final_assessment["sub_checks"] = results
        return final_assessment

    async def _process_sub_check(self, vendor_id: str, sub_check: str) -> dict:
        print(f"ACT: Retrieving context for '{sub_check}' (Vendor: {vendor_id})")
        # Retrieve context from RAG
        context_chunks = self.rag.retrieve(vendor_id, sub_check, top_k=3)
        context_text = "\n\n".join([c["text"] for c in context_chunks])
        
        if not context_text:
            context_text = "No relevant documentation found."
            
        print(f"ACT: Extracting verdict for '{sub_check}'")
        act_result = self.llm.act_extract_verdict(sub_check, context_text)
        
        verdict = act_result.get("verdict", "unclear")
        citation = act_result.get("citation", "")
        
        is_valid = True
        needs_human_review = False
        
        if verdict != "unclear" and citation:
            print(f"CHECK: Cross-validating citation for '{sub_check}'")
            is_valid = self.llm.check_cross_validate(sub_check, verdict, citation)
            if not is_valid:
                print(f"CHECK FAILED: Hallucination detected for '{sub_check}'. Retrying with Reasoning Model...")
                # SMART RETRY
                act_result = self.llm.act_extract_verdict_reasoning(sub_check, context_text)
                verdict = act_result.get("verdict", "unclear")
                citation = act_result.get("citation", "")
                
                # Cross-validate the retry result
                if verdict != "unclear" and citation:
                    is_valid = self.llm.check_cross_validate(sub_check, verdict, citation)
                    if not is_valid:
                        print(f"RETRY FAILED: Hallucination detected again for '{sub_check}'. Downgrading to unclear/human review.")
                        verdict = "unclear"
                        needs_human_review = True
                
        if verdict == "unclear":
            needs_human_review = True
            
        return {
            "sub_check": sub_check,
            "verdict": verdict,
            "citation": citation,
            "is_valid": is_valid,
            "needs_human_review": needs_human_review
        }
