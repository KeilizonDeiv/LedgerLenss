"""LLM provider factory (OpenAI / Anthropic Claude / local Ollama).

Imports are lazy so a deployment only needs the SDK of the provider it uses, and
switching providers is a config change (LL_LLM_PROVIDER), not a code change.
temperature=0 because extraction must be deterministic, not creative.
"""
from langchain_core.language_models.chat_models import BaseChatModel

from app.core.config import Settings


def build_chat_model(settings: Settings) -> BaseChatModel:
    match settings.llm_provider:
        case "openai":
            from langchain_openai import ChatOpenAI

            return ChatOpenAI(model=settings.llm_model, api_key=settings.openai_api_key,
                              temperature=0, timeout=settings.llm_timeout_seconds, max_retries=2)
        case "anthropic":
            from langchain_anthropic import ChatAnthropic

            return ChatAnthropic(model=settings.llm_model, api_key=settings.anthropic_api_key,
                                 temperature=0, timeout=settings.llm_timeout_seconds, max_retries=2)
        case "ollama":
            from langchain_ollama import ChatOllama

            return ChatOllama(model=settings.llm_model, base_url=settings.ollama_base_url, temperature=0)
    raise ValueError(f"Unknown LLM provider: {settings.llm_provider}")
