"""Minimal test to debug RAGAS Faithfulness scoring."""
import asyncio
import os
import sys

# Load .env file
env_path = "c:/saca/saca14/.env"
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

import math
from openai import AsyncOpenAI
from ragas.llms import llm_factory
from ragas.embeddings import embedding_factory
from ragas.metrics.collections.faithfulness import Faithfulness
from ragas.metrics.collections.answer_relevancy import AnswerRelevancy

async def test():
    print("Testing RAGAS Faithfulness...")
    
    # Use OpenAI directly
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("No OPENAI_API_KEY")
        return
    
    client = AsyncOpenAI(api_key=api_key)
    llm = llm_factory("gpt-4o-mini", provider="openai", client=client)
    emb = embedding_factory("openai", model="text-embedding-3-small", client=client, interface="modern")
    
    faithfulness_metric = Faithfulness(llm=llm)
    answer_relevancy_metric = AnswerRelevancy(llm=llm, embeddings=emb)
    
    # Test with a simple case
    user_input = "Where was Einstein born?"
    response = "Einstein was born in Germany on 14th March 1879."
    contexts = ["Albert Einstein was born in Ulm, Germany in 1879."]
    
    print(f"\nTesting Faithfulness...")
    print(f"  user_input: {user_input}")
    print(f"  response: {response}")
    print(f"  contexts: {contexts}")
    
    try:
        f_result = await faithfulness_metric.ascore(
            user_input=user_input,
            response=response,
            retrieved_contexts=contexts,
        )
        print(f"  Faithfulness result: {f_result}")
        print(f"  Faithfulness value: {f_result.value if hasattr(f_result, 'value') else 'NO VALUE ATTR'}")
        print(f"  Faithfulness type: {type(f_result)}")
        if hasattr(f_result, 'value'):
            val = f_result.value
            print(f"  Value type: {type(val)}")
            print(f"  Value is NaN: {val != val if isinstance(val, float) else 'N/A'}")
    except Exception as exc:
        print(f"  Faithfulness ERROR: {exc}")
        import traceback
        traceback.print_exc()
    
    print(f"\nTesting AnswerRelevancy...")
    try:
        r_result = await answer_relevancy_metric.ascore(
            user_input=user_input,
            response=response,
        )
        print(f"  AnswerRelevancy result: {r_result}")
        print(f"  AnswerRelevancy value: {r_result.value if hasattr(r_result, 'value') else 'NO VALUE ATTR'}")
    except Exception as exc:
        print(f"  AnswerRelevancy ERROR: {exc}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
