"""
LLM Client - Cliente base para múltiples proveedores

Soporta:
- Claude (Anthropic)
- GPT-4 (OpenAI)
- Local (Ollama/LMStudio)
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import os
import json
import aiohttp
import asyncio


@dataclass
class LLMResponse:
    """Respuesta del LLM"""
    content: str
    model: str
    tokens_used: int
    raw_response: Optional[Dict] = None


class BaseLLMClient(ABC):
    """Cliente base abstracto"""
    
    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096
    ) -> LLMResponse:
        pass
    
    @abstractmethod
    async def complete_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        schema: Optional[Dict] = None
    ) -> Dict:
        """Retorna respuesta parseada como JSON"""
        pass


class ClaudeClient(BaseLLMClient):
    """Cliente para Claude (Anthropic)"""
    
    def __init__(self, config: Dict[str, Any]):
        self.api_key = config.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")
        self.model = config.get("model", "claude-sonnet-4-20250514")
        self.base_url = "https://api.anthropic.com/v1"
        self.timeout = config.get("timeout", 120)
        
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")
    
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096
    ) -> LLMResponse:
        
        headers = {
            "x-api-key": self.api_key,
            "content-type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        if system:
            payload["system"] = system
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/messages",
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                data = await resp.json()
                
                if resp.status != 200:
                    raise Exception(f"Claude API error: {data}")
                
                content = data["content"][0]["text"]
                tokens = data.get("usage", {}).get("input_tokens", 0) + \
                         data.get("usage", {}).get("output_tokens", 0)
                
                return LLMResponse(
                    content=content,
                    model=self.model,
                    tokens_used=tokens,
                    raw_response=data
                )
    
    async def complete_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        schema: Optional[Dict] = None
    ) -> Dict:
        
        json_system = (system or "") + "\n\nResponde SOLO con JSON válido, sin markdown ni explicaciones."
        
        response = await self.complete(prompt, json_system, temperature=0.0)
        
        # Limpiar respuesta
        content = response.content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        
        return json.loads(content)


class OpenAIClient(BaseLLMClient):
    """Cliente para GPT-4 (OpenAI)"""
    
    def __init__(self, config: Dict[str, Any]):
        self.api_key = config.get("api_key") or os.environ.get("OPENAI_API_KEY")
        self.model = config.get("model", "gpt-4-turbo-preview")
        self.base_url = "https://api.openai.com/v1"
        self.timeout = config.get("timeout", 120)
        
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not set")
    
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096
    ) -> LLMResponse:
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                data = await resp.json()
                
                if resp.status != 200:
                    raise Exception(f"OpenAI API error: {data}")
                
                content = data["choices"][0]["message"]["content"]
                tokens = data.get("usage", {}).get("total_tokens", 0)
                
                return LLMResponse(
                    content=content,
                    model=self.model,
                    tokens_used=tokens,
                    raw_response=data
                )
    
    async def complete_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        schema: Optional[Dict] = None
    ) -> Dict:
        
        json_system = (system or "") + "\n\nResponde SOLO con JSON válido."
        
        response = await self.complete(prompt, json_system, temperature=0.0)
        
        content = response.content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        
        return json.loads(content)


class OllamaClient(BaseLLMClient):
    """Cliente para modelos locales (Ollama)"""
    
    def __init__(self, config: Dict[str, Any]):
        self.model = config.get("model", "llama3:70b")
        self.base_url = config.get("base_url", "http://localhost:11434")
        self.timeout = config.get("timeout", 300)
    
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096
    ) -> LLMResponse:
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                data = await resp.json()
                
                return LLMResponse(
                    content=data.get("response", ""),
                    model=self.model,
                    tokens_used=data.get("eval_count", 0),
                    raw_response=data
                )
    
    async def complete_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        schema: Optional[Dict] = None
    ) -> Dict:
        
        json_system = (system or "") + "\n\nResponde SOLO con JSON válido."
        response = await self.complete(prompt, json_system, temperature=0.0)
        
        content = response.content.strip()
        # Extraer JSON si está envuelto
        start = content.find("{")
        end = content.rfind("}") + 1
        if start != -1 and end > start:
            content = content[start:end]
        
        return json.loads(content)


def create_llm_client(config: Dict[str, Any]) -> BaseLLMClient:
    """Factory para crear el cliente correcto"""
    
    provider = config.get("provider", "claude").lower()
    
    if provider == "claude" or provider == "anthropic":
        return ClaudeClient(config)
    elif provider == "openai" or provider == "gpt":
        return OpenAIClient(config)
    elif provider == "ollama" or provider == "local":
        return OllamaClient(config)
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")
