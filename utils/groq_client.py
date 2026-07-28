import os
import json
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# Models
REASONING_MODEL = "llama-3.3-70b-versatile"
CHEAP_MODEL = "llama-3.1-8b-instant"

class GroqRateLimitError(Exception):
    pass

class GroqClient:
    def __init__(self):
        api_key = os.getenv("GROQ_API_KEY", "")
        self.client = None
        if api_key and "your_groq_api_key" not in api_key and len(api_key.strip()) > 10:
            try:
                self.client = Groq(api_key=api_key.strip())
            except Exception as e:
                print(f"Error initializing Groq client: {e}")
        else:
            print("WARNING: Groq API key not configured or invalid.")
            
    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(Exception),
        reraise=True
    )
    def _call_llm(self, model: str, system_prompt: str, user_prompt: str, response_format=None, temperature=0.1):
        if not self.client:
            raise ValueError("Groq client not initialized (missing API key)")
            
        try:
            kwargs = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": temperature,
                "max_tokens": 1024,
            }
            if response_format:
                kwargs["response_format"] = response_format
                
            resp = self.client.chat.completions.create(**kwargs)
            return resp.choices[0].message.content.strip()
        except Exception as e:
            if "rate limit" in str(e).lower() or "429" in str(e):
                raise GroqRateLimitError(f"Rate limited by Groq: {e}")
            raise e

    def plan_sub_checks_json(self, question: str) -> list:
        system = (
            "You are a compliance planning assistant. Given a main compliance question, "
            "decompose it into 2-5 concrete sub-checks that can be answered as 'pass', 'fail', or 'unclear'. "
            "Return ONLY a JSON object with a single key 'sub_checks' which is a list of strings."
        )
        try:
            res = self._call_llm(REASONING_MODEL, system, question, response_format={"type": "json_object"})
            data = json.loads(res)
            return data.get("sub_checks", [question])
        except Exception as e:
            print(f"Plan error: {e}")
            return [question]

    def act_extract_verdict(self, sub_check: str, context: str) -> dict:
        system = (
            "You are an extremely strict extraction assistant. Given a compliance sub-check and a context document snippet, "
            "determine if the context satisfies the check. "
            "CRITICAL: Do NOT guess, infer, or paraphrase. If the exact answer or explicit proof is not present in the context, "
            "you MUST return 'unclear'. "
            "Return a JSON object with two keys: 'verdict' (must be exactly 'pass', 'fail', or 'unclear') "
            "and 'citation' (exact word-for-word quote from the context supporting the verdict, or empty string if unclear/fail)."
        )
        user_prompt = f"Sub-check: {sub_check}\n\nContext:\n{context}"
        try:
            res = self._call_llm(CHEAP_MODEL, system, user_prompt, response_format={"type": "json_object"})
            return json.loads(res)
        except Exception as e:
            print(f"Act error: {e}")
            return {"verdict": "unclear", "citation": ""}

    def act_extract_verdict_reasoning(self, sub_check: str, context: str) -> dict:
        system = (
            "You are a senior compliance extraction assistant capable of advanced reasoning. "
            "Given a compliance sub-check and a context document snippet, determine if the context satisfies the check. "
            "You may use logical deduction (e.g., if a policy requires 'at least annual' updates, and context says '90 days', that is a 'pass'). "
            "If the information is completely missing, return 'unclear'. "
            "Return a JSON object with two keys: 'verdict' (must be exactly 'pass', 'fail', or 'unclear') "
            "and 'citation' (exact word-for-word quote from the context supporting your deduction, or empty string if unclear)."
        )
        user_prompt = f"Sub-check: {sub_check}\n\nContext:\n{context}"
        try:
            res = self._call_llm(REASONING_MODEL, system, user_prompt, response_format={"type": "json_object"})
            return json.loads(res)
        except Exception as e:
            print(f"Act reasoning error: {e}")
            return {"verdict": "unclear", "citation": ""}
            
    def check_cross_validate(self, sub_check: str, verdict: str, citation: str) -> bool:
        if verdict == "unclear" or not citation:
            return True # Nothing to validate
            
        system = (
            "You are a strict cross-validation assistant. You will be given a sub-check, a verdict (pass/fail), "
            "and a citation quote. Determine if the citation quote actually supports the verdict for the given sub-check. "
            "Return ONLY a JSON object with a single boolean key 'is_valid' (true if it supports, false if it is a hallucination)."
        )
        user_prompt = f"Sub-check: {sub_check}\nVerdict: {verdict}\nCitation: {citation}"
        try:
            res = self._call_llm(CHEAP_MODEL, system, user_prompt, response_format={"type": "json_object"})
            data = json.loads(res)
            return data.get("is_valid", False)
        except Exception as e:
            print(f"Check error: {e}")
            return False

    def aggregate_results(self, main_question: str, verified_results: list) -> dict:
        system = (
            "You are a senior compliance reviewer. Given a main question and a list of verified sub-check results, "
            "calculate a risk score from 0.0 (perfectly compliant) to 1.0 (highly non-compliant), "
            "and generate a list of concrete remediation actions (e.g. 'Request updated SOC2 report from vendor'). "
            "Return a JSON object with 'risk_score' (float) and 'remediation_actions' (list of strings)."
        )
        user_prompt = f"Main Question: {main_question}\n\nResults:\n" + json.dumps(verified_results, indent=2)
        try:
            res = self._call_llm(REASONING_MODEL, system, user_prompt, response_format={"type": "json_object"})
            return json.loads(res)
        except Exception as e:
            print(f"Aggregate error: {e}")
            return {"risk_score": 0.5, "remediation_actions": ["Manual review required due to LLM error."]}
