"""Debug RAGAS Faithfulness for a single finding."""
import asyncio
import os
import sys
from dotenv import load_dotenv

load_dotenv('c:/saca/saca14/.env')

from openai import AsyncOpenAI
from ragas.llms import llm_factory
from ragas.embeddings import embedding_factory
from ragas.metrics.collections.faithfulness import Faithfulness

async def test():
    print("Testing RAGAS Faithfulness with real finding data...")
    
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("No OPENAI_API_KEY")
        return
    
    client = AsyncOpenAI(api_key=api_key)
    llm = llm_factory("gpt-4o-mini", provider="openai", client=client)
    
    faithfulness_metric = Faithfulness(llm=llm)
    
    # Mimic what the pipeline does for finding F-R002 (Brute-Force Attack Resistance)
    user_input = "Brute-Force Attack Resistance"  # rule name
    response = "Detected 45 failed login attempts from 192.168.1.100 to 192.168.1.1:23 using TCP SYN scans. This indicates a brute-force attack against Telnet service."  # finding reasoning
    contexts = [
        "Packet 123: 192.168.1.100 -> 192.168.1.1:23 [TCP] Flags [SYN]",
        "Packet 124: 192.168.1.100 -> 192.168.1.1:23 [TCP] Flags [SYN]",
        "Packet 125: 192.168.1.100 -> 192.168.1.1:23 [TCP] Flags [SYN]",
        "Policy rule: Brute-Force Attack Resistance - Devices must resist brute-force attacks",
        "Finding reasoning: Detected 45 failed login attempts from 192.168.1.100 to 192.168.1.1:23 using TCP SYN scans."
    ]
    
    print(f"\nInput:")
    print(f"  user_input: {user_input}")
    print(f"  response: {response}")
    print(f"  contexts ({len(contexts)}):")
    for ctx in contexts:
        print(f"    - {ctx}")
    
    try:
        f_result = await faithfulness_metric.ascore(
            user_input=user_input,
            response=response,
            retrieved_contexts=contexts,
        )
        print(f"\nResult: {f_result}")
        print(f"  Value: {f_result.value if hasattr(f_result, 'value') else 'N/A'}")
        
        # Check intermediate steps
        print("\nDebugging intermediate steps...")
        
        # Step 1: Create statements
        from ragas.metrics.collections.faithfulness.util import StatementGeneratorPrompt, StatementGeneratorInput
        input_data = StatementGeneratorInput(question=user_input, answer=response)
        prompt_str = faithfulness_metric.statement_generator_prompt.to_string(input_data)
        print(f"  Statement generator prompt length: {len(prompt_str)}")
        
        statements_result = await faithfulness_metric.llm.agenerate(prompt_str, faithfulness_metric.statement_generator_prompt.output_cls)
        print(f"  Statements: {statements_result.statements}")
        
        if not statements_result.statements:
            print("  ERROR: No statements generated!")
            return
        
        # Step 2: NLI verdicts
        from ragas.metrics.collections.faithfulness.util import NLIStatementPrompt, NLIStatementInput
        context_str = "\n".join(contexts)
        nli_input = NLIStatementInput(context=context_str, statements=statements_result.statements)
        nli_prompt = faithfulness_metric.nli_statement_prompt.to_string(nli_input)
        print(f"  NLI prompt length: {len(nli_prompt)}")
        
        nli_result = await faithfulness_metric.llm.agenerate(nli_prompt, faithfulness_metric.nli_statement_prompt.output_cls)
        print(f"  NLI verdicts: {[(s.statement, s.verdict) for s in nli_result.statements]}")
        
        # Step 3: Compute score
        faithful = sum(1 if s.verdict else 0 for s in nli_result.statements)
        total = len(nli_result.statements)
        score = faithful / total if total > 0 else float("nan")
        print(f"  Faithful: {faithful}/{total} = {score}")
        
    except Exception as exc:
        print(f"\nERROR: {exc}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
