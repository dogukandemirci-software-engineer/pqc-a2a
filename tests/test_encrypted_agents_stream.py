import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
from examples.encrypted_agents_stream import run_demo


def test_fake_gpt_and_gemma_exchange_encrypted_fragmented_greetings():
    result = asyncio.run(run_demo(frame_delay_ms=0, mtu=180))
    assert result["status"] == "ok"
    assert result["gpt_received"]["model"] == "gemma-sim"
    assert result["gemma_received"]["model"] == "gpt-sim"
    assert result["gpt_received"]["fake_embedding"] == [-0.1, 0.2, 0.3, -0.4]
    assert result["gemma_received"]["fake_embedding"] == [0.1, -0.2, 0.3, 0.4]
    assert result["frames"]["gpt_to_gemma"] > 1
    assert result["frames"]["gemma_to_gpt"] > 1
