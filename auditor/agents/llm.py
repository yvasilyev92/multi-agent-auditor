"""Shared LCEL helpers for ChatOpenAI structured-output chains."""

from __future__ import annotations

import logging
from typing import TypeVar

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from auditor.config import get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


def make_llm(*, temperature: float = 0) -> ChatOpenAI:
    """Construct the configured ChatOpenAI client."""
    settings = get_settings()
    return ChatOpenAI(
        model=settings.openai_model,
        api_key=settings.openai_api_key,
        temperature=temperature,
    )


def structured_invoke(
    schema: type[T],
    *,
    system: str,
    human: str,
    temperature: float = 0,
) -> T:
    """Run a one-shot LCEL chain: messages | structured ChatOpenAI.

    Prompts are already-formatted strings so Solidity braces cannot be
    mistaken for template variables. Prefers OpenAI json_schema structured
    outputs and falls back to function calling.
    """
    llm = make_llm(temperature=temperature)
    try:
        structured = llm.with_structured_output(schema, method="json_schema")
    except Exception as exc:  # pragma: no cover - depends on model/sdk combo
        logger.warning("json_schema structured output unavailable (%s); using function_calling", exc)
        structured = llm.with_structured_output(schema, method="function_calling")

    messages = [SystemMessage(content=system), HumanMessage(content=human)]
    result = structured.invoke(messages)
    if not isinstance(result, schema):
        return schema.model_validate(result)
    return result
