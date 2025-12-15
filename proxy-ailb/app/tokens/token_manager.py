"""
MarchProxy AILB Token Manager
Manages token counting, conversion, and quota enforcement for AI/LLM proxy
Ported from WaddleAI with adaptations for MarchProxy architecture
"""

import json
import logging
from typing import Dict, Tuple, Optional, Any, List
from datetime import datetime, date, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
from threading import Lock
import hashlib

logger = logging.getLogger(__name__)


class TokenType(Enum):
    """Types of tokens"""
    MARCHPROXY = "marchproxy"  # Normalized tokens
    LLM_INPUT = "llm_input"
    LLM_OUTPUT = "llm_output"


@dataclass
class TokenUsage:
    """Token usage record"""
    marchproxy_tokens: int
    llm_tokens_input: int
    llm_tokens_output: int
    llm_tokens_breakdown: Dict[str, Dict[str, int]]
    cost_estimate_marchproxy: float
    cost_estimate_usd: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "marchproxy_tokens": self.marchproxy_tokens,
            "llm_tokens_input": self.llm_tokens_input,
            "llm_tokens_output": self.llm_tokens_output,
            "llm_tokens_breakdown": self.llm_tokens_breakdown,
            "cost_estimate_marchproxy": self.cost_estimate_marchproxy,
            "cost_estimate_usd": self.cost_estimate_usd
        }


@dataclass
class ConversionRate:
    """Token conversion rate configuration"""
    provider: str
    model: str
    input_rate: float  # LLM tokens per MarchProxy token
    output_rate: float
    base_cost_per_token: float  # USD per MarchProxy token

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class QuotaConfig:
    """Quota configuration for an API key or user"""
    daily_limit: int = 100000  # MarchProxy tokens per day
    monthly_limit: int = 1000000  # MarchProxy tokens per month
    rate_limit_rpm: int = 60  # Requests per minute
    rate_limit_tpm: int = 10000  # Tokens per minute
    enabled: bool = True


@dataclass
class UsageRecord:
    """Usage tracking record"""
    api_key_id: str
    user_id: str
    date: str  # YYYY-MM-DD
    marchproxy_tokens: int = 0
    llm_tokens_input: int = 0
    llm_tokens_output: int = 0
    llm_breakdown: Dict[str, Dict[str, int]] = field(default_factory=dict)
    request_count: int = 0
    last_updated: str = ""


class TokenManager:
    """Manages token counting, conversion, and quota enforcement"""

    # Default conversion rates for common models
    DEFAULT_CONVERSION_RATES = {
        "openai:gpt-4": ConversionRate("openai", "gpt-4", 10.0, 20.0, 0.003),
        "openai:gpt-4-turbo": ConversionRate("openai", "gpt-4-turbo", 10.0, 20.0, 0.001),
        "openai:gpt-4o": ConversionRate("openai", "gpt-4o", 10.0, 20.0, 0.0005),
        "openai:gpt-4o-mini": ConversionRate("openai", "gpt-4o-mini", 10.0, 10.0, 0.00015),
        "openai:gpt-3.5-turbo": ConversionRate("openai", "gpt-3.5-turbo", 10.0, 10.0, 0.0002),
        "anthropic:claude-3-opus": ConversionRate("anthropic", "claude-3-opus", 10.0, 20.0, 0.0075),
        "anthropic:claude-3-sonnet": ConversionRate("anthropic", "claude-3-sonnet", 10.0, 20.0, 0.0015),
        "anthropic:claude-3-haiku": ConversionRate("anthropic", "claude-3-haiku", 10.0, 10.0, 0.00025),
        "anthropic:claude-3.5-sonnet": ConversionRate("anthropic", "claude-3.5-sonnet", 10.0, 20.0, 0.003),
        "ollama:llama2": ConversionRate("ollama", "llama2", 10.0, 10.0, 0.0),
        "ollama:mistral": ConversionRate("ollama", "mistral", 10.0, 10.0, 0.0),
        "ollama:codellama": ConversionRate("ollama", "codellama", 10.0, 10.0, 0.0),
    }

    def __init__(self, redis_client=None, config: Optional[Dict] = None):
        """
        Initialize token manager

        Args:
            redis_client: Optional Redis client for persistent storage
            config: Optional configuration dictionary
        """
        self.redis = redis_client
        self.config = config or {}
        self._lock = Lock()

        # In-memory storage (fallback when Redis unavailable)
        self._usage_cache: Dict[str, UsageRecord] = {}
        self._quota_cache: Dict[str, QuotaConfig] = {}
        self._minute_usage: Dict[str, Dict[str, int]] = {}  # For rate limiting

        # Load conversion rates
        self.conversion_rates = dict(self.DEFAULT_CONVERSION_RATES)
        self._load_custom_rates()

        # Token encoder (simple estimation without tiktoken dependency)
        self._encoder_cache: Dict[str, Any] = {}

        logger.info("TokenManager initialized with %d conversion rates",
                   len(self.conversion_rates))

    def _load_custom_rates(self):
        """Load custom conversion rates from config or Redis"""
        # From config
        custom_rates = self.config.get("conversion_rates", {})
        for key, rate_data in custom_rates.items():
            if isinstance(rate_data, dict):
                self.conversion_rates[key] = ConversionRate(**rate_data)

        # From Redis if available
        if self.redis:
            try:
                rates_json = self.redis.get("ailb:token:conversion_rates")
                if rates_json:
                    rates_data = json.loads(rates_json)
                    for key, rate_data in rates_data.items():
                        self.conversion_rates[key] = ConversionRate(**rate_data)
            except Exception as e:
                logger.warning("Failed to load conversion rates from Redis: %s", e)

    def count_tokens(
        self,
        text: str,
        provider: str = "openai",
        model: str = "gpt-3.5-turbo"
    ) -> int:
        """
        Count tokens in text

        Uses simple estimation (4 chars = 1 token) for portability.
        For production, consider adding tiktoken dependency.
        """
        if not text:
            return 0

        # Simple estimation based on character count
        # Average English: ~4 chars per token
        # Code/technical: ~3 chars per token
        chars_per_token = 4

        # Adjust for known model characteristics
        if "claude" in model.lower():
            chars_per_token = 3.5  # Claude tends to have smaller tokens
        elif "gpt-4" in model.lower():
            chars_per_token = 4

        return max(1, int(len(text) / chars_per_token))

    def count_messages_tokens(
        self,
        messages: List[Dict[str, str]],
        provider: str = "openai",
        model: str = "gpt-3.5-turbo"
    ) -> int:
        """Count tokens in a list of messages"""
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            role = msg.get("role", "")
            # Add overhead for message structure (~4 tokens per message)
            total += self.count_tokens(content, provider, model) + 4
            total += self.count_tokens(role, provider, model)

        # Add conversation overhead (~3 tokens)
        total += 3
        return total

    def calculate_marchproxy_tokens(
        self,
        input_tokens: int,
        output_tokens: int,
        provider: str,
        model: str
    ) -> int:
        """Convert LLM tokens to MarchProxy normalized tokens"""
        rate_key = f"{provider}:{model}"

        if rate_key not in self.conversion_rates:
            # Try partial match
            for key in self.conversion_rates:
                if model in key or key.split(":")[1] in model:
                    rate_key = key
                    break
            else:
                logger.warning("No conversion rate for %s:%s, using default",
                             provider, model)
                # Default: output tokens weighted 2x
                return max(1, (input_tokens + output_tokens * 2) // 10)

        rate = self.conversion_rates[rate_key]

        # Convert using rates (LLM tokens per MarchProxy token)
        mp_input = max(1, int(input_tokens / rate.input_rate)) if input_tokens > 0 else 0
        mp_output = max(1, int(output_tokens / rate.output_rate)) if output_tokens > 0 else 0

        return mp_input + mp_output

    def calculate_cost(
        self,
        marchproxy_tokens: int,
        provider: str,
        model: str
    ) -> Tuple[float, float]:
        """
        Calculate cost in MarchProxy tokens and USD

        Returns:
            Tuple of (marchproxy_token_cost, usd_cost)
        """
        rate_key = f"{provider}:{model}"

        cost_mp = float(marchproxy_tokens)  # 1:1 for normalized tokens

        if rate_key in self.conversion_rates:
            rate = self.conversion_rates[rate_key]
            cost_usd = marchproxy_tokens * rate.base_cost_per_token
        else:
            cost_usd = marchproxy_tokens * 0.001  # Default $0.001 per token

        return cost_mp, cost_usd

    def process_usage(
        self,
        input_text: str,
        output_text: str,
        provider: str,
        model: str,
        api_key_id: str,
        user_id: str = "",
        metadata: Optional[Dict] = None
    ) -> TokenUsage:
        """
        Process token usage for a request

        Args:
            input_text: Input prompt text
            output_text: Output response text
            provider: LLM provider (openai, anthropic, ollama)
            model: Model name
            api_key_id: API key identifier
            user_id: Optional user identifier
            metadata: Optional additional metadata

        Returns:
            TokenUsage record
        """
        # Count LLM tokens
        input_tokens = self.count_tokens(input_text, provider, model)
        output_tokens = self.count_tokens(output_text, provider, model)

        # Convert to MarchProxy tokens
        mp_tokens = self.calculate_marchproxy_tokens(
            input_tokens, output_tokens, provider, model
        )

        # Calculate costs
        cost_mp, cost_usd = self.calculate_cost(mp_tokens, provider, model)

        # Create breakdown
        model_key = f"{provider}_{model.replace('-', '_').replace('.', '_')}"
        llm_breakdown = {
            model_key: {
                "input": input_tokens,
                "output": output_tokens
            }
        }

        usage = TokenUsage(
            marchproxy_tokens=mp_tokens,
            llm_tokens_input=input_tokens,
            llm_tokens_output=output_tokens,
            llm_tokens_breakdown=llm_breakdown,
            cost_estimate_marchproxy=cost_mp,
            cost_estimate_usd=cost_usd
        )

        # Update records
        self._update_usage_records(usage, api_key_id, user_id, provider, model)

        logger.debug(
            "Processed usage: api_key=%s, mp_tokens=%d, llm_in=%d, llm_out=%d",
            api_key_id[:8] + "..." if len(api_key_id) > 8 else api_key_id,
            mp_tokens, input_tokens, output_tokens
        )

        return usage

    def _update_usage_records(
        self,
        usage: TokenUsage,
        api_key_id: str,
        user_id: str,
        provider: str,
        model: str
    ):
        """Update usage records in storage"""
        today = date.today().isoformat()
        now = datetime.utcnow().isoformat()
        cache_key = f"{api_key_id}:{today}"

        with self._lock:
            # Update in-memory cache
            if cache_key in self._usage_cache:
                record = self._usage_cache[cache_key]
                record.marchproxy_tokens += usage.marchproxy_tokens
                record.llm_tokens_input += usage.llm_tokens_input
                record.llm_tokens_output += usage.llm_tokens_output
                record.request_count += 1
                record.last_updated = now

                # Merge LLM breakdown
                for model_key, tokens in usage.llm_tokens_breakdown.items():
                    if model_key in record.llm_breakdown:
                        record.llm_breakdown[model_key]["input"] += tokens["input"]
                        record.llm_breakdown[model_key]["output"] += tokens["output"]
                    else:
                        record.llm_breakdown[model_key] = tokens
            else:
                self._usage_cache[cache_key] = UsageRecord(
                    api_key_id=api_key_id,
                    user_id=user_id,
                    date=today,
                    marchproxy_tokens=usage.marchproxy_tokens,
                    llm_tokens_input=usage.llm_tokens_input,
                    llm_tokens_output=usage.llm_tokens_output,
                    llm_breakdown=dict(usage.llm_tokens_breakdown),
                    request_count=1,
                    last_updated=now
                )

            # Update minute-level tracking for rate limiting
            minute_key = datetime.utcnow().strftime("%Y-%m-%d-%H-%M")
            rate_key = f"{api_key_id}:{minute_key}"
            if rate_key not in self._minute_usage:
                self._minute_usage[rate_key] = {"requests": 0, "tokens": 0}
            self._minute_usage[rate_key]["requests"] += 1
            self._minute_usage[rate_key]["tokens"] += usage.marchproxy_tokens

        # Persist to Redis if available
        if self.redis:
            self._persist_to_redis(cache_key)

    def _persist_to_redis(self, cache_key: str):
        """Persist usage record to Redis"""
        if not self.redis:
            return

        try:
            record = self._usage_cache.get(cache_key)
            if record:
                redis_key = f"ailb:usage:{cache_key}"
                self.redis.set(
                    redis_key,
                    json.dumps({
                        "api_key_id": record.api_key_id,
                        "user_id": record.user_id,
                        "date": record.date,
                        "marchproxy_tokens": record.marchproxy_tokens,
                        "llm_tokens_input": record.llm_tokens_input,
                        "llm_tokens_output": record.llm_tokens_output,
                        "llm_breakdown": record.llm_breakdown,
                        "request_count": record.request_count,
                        "last_updated": record.last_updated
                    }),
                    ex=86400 * 7  # 7 day TTL
                )
        except Exception as e:
            logger.warning("Failed to persist usage to Redis: %s", e)

    def set_quota(self, api_key_id: str, quota: QuotaConfig):
        """Set quota configuration for an API key"""
        with self._lock:
            self._quota_cache[api_key_id] = quota

        if self.redis:
            try:
                self.redis.set(
                    f"ailb:quota:{api_key_id}",
                    json.dumps(asdict(quota)),
                    ex=86400  # 1 day TTL
                )
            except Exception as e:
                logger.warning("Failed to persist quota to Redis: %s", e)

    def get_quota(self, api_key_id: str) -> QuotaConfig:
        """Get quota configuration for an API key"""
        # Check in-memory cache
        if api_key_id in self._quota_cache:
            return self._quota_cache[api_key_id]

        # Check Redis
        if self.redis:
            try:
                quota_json = self.redis.get(f"ailb:quota:{api_key_id}")
                if quota_json:
                    data = json.loads(quota_json)
                    quota = QuotaConfig(**data)
                    self._quota_cache[api_key_id] = quota
                    return quota
            except Exception as e:
                logger.warning("Failed to load quota from Redis: %s", e)

        # Return default quota
        return QuotaConfig()

    def check_quota(
        self,
        api_key_id: str,
        estimated_tokens: int = 0
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if API key is within quota limits

        Args:
            api_key_id: API key identifier
            estimated_tokens: Estimated tokens for upcoming request

        Returns:
            Tuple of (allowed, quota_info)
        """
        quota = self.get_quota(api_key_id)

        if not quota.enabled:
            return True, {"status": "disabled", "message": "Quota checking disabled"}

        today = date.today().isoformat()
        month_start = date.today().replace(day=1).isoformat()

        # Get current usage
        daily_used = 0
        monthly_used = 0

        with self._lock:
            # Daily usage
            cache_key = f"{api_key_id}:{today}"
            if cache_key in self._usage_cache:
                daily_used = self._usage_cache[cache_key].marchproxy_tokens

            # Monthly usage (sum all days in month)
            for key, record in self._usage_cache.items():
                if key.startswith(api_key_id) and record.date >= month_start:
                    monthly_used += record.marchproxy_tokens

        # Check rate limits
        minute_key = datetime.utcnow().strftime("%Y-%m-%d-%H-%M")
        rate_key = f"{api_key_id}:{minute_key}"
        minute_requests = self._minute_usage.get(rate_key, {}).get("requests", 0)
        minute_tokens = self._minute_usage.get(rate_key, {}).get("tokens", 0)

        # Evaluate limits
        daily_ok = (daily_used + estimated_tokens) <= quota.daily_limit
        monthly_ok = (monthly_used + estimated_tokens) <= quota.monthly_limit
        rpm_ok = minute_requests < quota.rate_limit_rpm
        tpm_ok = (minute_tokens + estimated_tokens) <= quota.rate_limit_tpm

        quota_info = {
            "daily": {
                "used": daily_used,
                "limit": quota.daily_limit,
                "remaining": max(0, quota.daily_limit - daily_used),
                "ok": daily_ok
            },
            "monthly": {
                "used": monthly_used,
                "limit": quota.monthly_limit,
                "remaining": max(0, quota.monthly_limit - monthly_used),
                "ok": monthly_ok
            },
            "rate_limits": {
                "requests_this_minute": minute_requests,
                "rpm_limit": quota.rate_limit_rpm,
                "rpm_ok": rpm_ok,
                "tokens_this_minute": minute_tokens,
                "tpm_limit": quota.rate_limit_tpm,
                "tpm_ok": tpm_ok
            }
        }

        allowed = daily_ok and monthly_ok and rpm_ok and tpm_ok

        if not allowed:
            reasons = []
            if not daily_ok:
                reasons.append("daily_quota_exceeded")
            if not monthly_ok:
                reasons.append("monthly_quota_exceeded")
            if not rpm_ok:
                reasons.append("rate_limit_rpm_exceeded")
            if not tpm_ok:
                reasons.append("rate_limit_tpm_exceeded")
            quota_info["rejection_reasons"] = reasons

        return allowed, quota_info

    def get_usage_stats(
        self,
        api_key_id: Optional[str] = None,
        user_id: Optional[str] = None,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get detailed usage statistics"""

        since = (datetime.utcnow().date() - timedelta(days=days)).isoformat()

        stats = {
            "total_marchproxy_tokens": 0,
            "total_llm_input_tokens": 0,
            "total_llm_output_tokens": 0,
            "total_requests": 0,
            "llm_breakdown": {},
            "daily_usage": {},
            "average_daily": 0,
            "period_days": days
        }

        with self._lock:
            for key, record in self._usage_cache.items():
                # Filter by API key or user
                if api_key_id and record.api_key_id != api_key_id:
                    continue
                if user_id and record.user_id != user_id:
                    continue
                if record.date < since:
                    continue

                stats["total_marchproxy_tokens"] += record.marchproxy_tokens
                stats["total_llm_input_tokens"] += record.llm_tokens_input
                stats["total_llm_output_tokens"] += record.llm_tokens_output
                stats["total_requests"] += record.request_count

                # Daily breakdown
                stats["daily_usage"][record.date] = {
                    "marchproxy_tokens": record.marchproxy_tokens,
                    "llm_input": record.llm_tokens_input,
                    "llm_output": record.llm_tokens_output,
                    "requests": record.request_count
                }

                # LLM model breakdown
                for model_key, tokens in record.llm_breakdown.items():
                    if model_key not in stats["llm_breakdown"]:
                        stats["llm_breakdown"][model_key] = {"input": 0, "output": 0}
                    stats["llm_breakdown"][model_key]["input"] += tokens.get("input", 0)
                    stats["llm_breakdown"][model_key]["output"] += tokens.get("output", 0)

        # Calculate averages
        if stats["total_requests"] > 0:
            stats["average_daily"] = stats["total_marchproxy_tokens"] // max(1, days)
            stats["average_tokens_per_request"] = (
                stats["total_marchproxy_tokens"] // stats["total_requests"]
            )

        return stats

    def add_conversion_rate(self, provider: str, model: str, rate: ConversionRate):
        """Add or update a conversion rate"""
        key = f"{provider}:{model}"
        self.conversion_rates[key] = rate

        # Persist to Redis
        if self.redis:
            try:
                all_rates = {k: v.to_dict() for k, v in self.conversion_rates.items()}
                self.redis.set(
                    "ailb:token:conversion_rates",
                    json.dumps(all_rates)
                )
            except Exception as e:
                logger.warning("Failed to persist conversion rates to Redis: %s", e)

    def get_conversion_rates(self) -> Dict[str, ConversionRate]:
        """Get all conversion rates"""
        return dict(self.conversion_rates)

    def cleanup_old_records(self, days_to_keep: int = 90):
        """Clean up old usage records from in-memory cache"""
        cutoff = (datetime.utcnow().date() - timedelta(days=days_to_keep)).isoformat()

        with self._lock:
            # Clean usage cache
            keys_to_remove = [
                key for key, record in self._usage_cache.items()
                if record.date < cutoff
            ]
            for key in keys_to_remove:
                del self._usage_cache[key]

            # Clean minute usage (keep only last hour)
            hour_ago = (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%d-%H")
            rate_keys_to_remove = [
                key for key in self._minute_usage.keys()
                if not key.split(":")[1].startswith(hour_ago)
            ]
            for key in rate_keys_to_remove:
                del self._minute_usage[key]

        logger.info(
            "Cleaned up %d usage records and %d rate limit entries",
            len(keys_to_remove), len(rate_keys_to_remove)
        )


def create_token_manager(
    redis_client=None,
    config: Optional[Dict] = None
) -> TokenManager:
    """Factory function to create token manager"""
    return TokenManager(redis_client=redis_client, config=config)
