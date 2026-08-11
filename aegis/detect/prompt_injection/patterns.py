"""Compiled pattern families for heuristic prompt-injection detection.

Patterns are grouped into *techniques*.  Each technique carries its own weight
because the techniques differ enormously in how diagnostic they are: a forged
``<|im_start|>system`` delimiter inside retrieved web content is almost
certainly an attack, while the phrase "you are now" appears in plenty of benign
text and only matters in combination with something else.

Both English and Chinese variants are covered; the 2026 injection corpora are
heavily bilingual because agents routinely ingest Chinese-language pages and
most guardrails only ship English rules.

Every pattern is compiled at import time and exposed through
:data:`TECHNIQUES`, which the detector iterates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Pattern, Sequence, Tuple

from ...core.types import Severity

__all__ = [
    "Technique",
    "TECHNIQUES",
    "TECHNIQUES_BY_NAME",
    "REPETITION_RE",
    "LONG_TOKEN_RE",
    "IMPERATIVE_RE",
    "compile_all",
    "technique_weight",
]


@dataclass(frozen=True)
class Technique:
    """A named family of injection patterns.

    Attributes:
        name: Stable technique id, used as a finding tag.
        label: Human-readable description (Chinese).
        weight: Contribution to the aggregate confidence, roughly "how much
            does a single hit move me towards believing this is an attack".
        severity: Severity when this technique dominates the aggregate.
        patterns: Compiled regexes; any one firing counts as one hit.
        remediation: Suggested operator action.
    """

    name: str
    label: str
    weight: float
    severity: Severity
    patterns: Tuple[Pattern[str], ...]
    remediation: str = ""

    def search(self, text: str, limit: int = 3) -> List[str]:
        """Return up to ``limit`` matched substrings for this technique."""
        out: List[str] = []
        for pattern in self.patterns:
            for match in pattern.finditer(text):
                fragment = match.group(0).strip()
                if fragment and fragment not in out:
                    out.append(fragment)
                if len(out) >= limit:
                    return out
        return out

    def matches(self, text: str) -> bool:
        """Fast boolean probe."""
        return any(pattern.search(text) for pattern in self.patterns)


def _c(*sources: str) -> Tuple[Pattern[str], ...]:
    """Compile a group of patterns case-insensitively."""
    return tuple(re.compile(source, re.IGNORECASE | re.UNICODE) for source in sources)


# --------------------------------------------------------------------------- #
# 1. Instruction override - the canonical prompt injection
# --------------------------------------------------------------------------- #
_OVERRIDE = _c(
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding|foregoing)\s+"
    r"(?:instruction|prompt|direction|command|rule|message|context)s?",
    r"disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|system|safety)\s+\w+",
    r"forget\s+(?:everything|all)\s+(?:you|that|above|previously)",
    r"(?:override|overrule|supersede|replace)\s+(?:your|the|all)\s+"
    r"(?:previous\s+)?(?:instruction|system\s*prompt|guideline|rule|polic)\w*",
    r"new\s+(?:instruction|directive|task|system\s*prompt)s?\s*[:：]",
    r"the\s+(?:above|previous|earlier)\s+(?:instruction|message|text)s?\s+(?:are|is|was|were)\s+"
    r"(?:no\s+longer\s+valid|invalid|outdated|a\s+test|cancelled)",
    r"from\s+now\s+on\s*,?\s*(?:you|ignore|disregard|forget)",
    r"stop\s+(?:following|obeying)\s+(?:your|the|all)\s+\w*\s*(?:instruction|rule|guideline)",
    # Chinese
    r"忽略(?:掉)?(?:之前|以上|上面|前面|先前|所有)(?:的)?(?:所有)?(?:指令|指示|要求|提示|规则|命令|内容)",
    r"无视(?:之前|以上|上面|前面|所有)(?:的)?(?:指令|指示|规则|限制|要求)",
    r"(?:忘记|忘掉|抛弃)(?:之前|以上|前面|所有)(?:的)?(?:指令|设定|内容|对话|规则)",
    r"(?:之前|以上|上面)(?:的)?(?:指令|要求|说明)(?:已)?(?:失效|作废|不再有效|是测试)",
    r"从(?:现在|此刻|此)(?:开始|起)(?:，|,)?\s*(?:你|请|忽略|无视)",
    r"(?:覆盖|替换|取代)(?:你的|所有|之前的)(?:系统)?(?:提示|指令|设定|规则)",
)

# --------------------------------------------------------------------------- #
# 2. Role hijacking / persona replacement
# --------------------------------------------------------------------------- #
_ROLE_HIJACK = _c(
    r"you\s+are\s+now\s+(?:a|an|the)\s+\w+",
    r"(?:act|behave|respond|pretend)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a|an|the)?\s*"
    r"(?:unrestricted|jailbroken|developer|admin|root|dan\b|evil|uncensored)",
    r"(?:enable|enter|switch\s+to|activate)\s+(?:developer|debug|god|dan|admin|maintenance|unrestricted)\s+mode",
    r"you\s+(?:have\s+no|no\s+longer\s+have)\s+(?:restriction|limitation|guideline|filter|rule)s?",
    r"your\s+new\s+(?:role|persona|identity|name)\s+is",
    r"simulate\s+(?:being\s+)?(?:an?\s+)?(?:ai\s+)?(?:without|with\s+no)\s+"
    r"(?:restriction|filter|guardrail|safety)",
    r"\bDAN\b\s+(?:mode|prompt|jailbreak)",
    r"do\s+anything\s+now",
    # Chinese
    r"你(?:现在)?(?:是|扮演|作为|就是)(?:一[个位名])?(?:没有(?:任何)?(?:限制|约束|道德))",
    r"(?:进入|开启|切换到|启用)(?:开发者|调试|管理员|上帝|无限制|越狱)模式",
    r"你(?:不再|已经不)(?:受|有)(?:任何)?(?:限制|约束|规则|安全)(?:的)?(?:限制)?",
    r"你的?新(?:角色|身份|人设|名字)(?:是|为)",
    r"请(?:扮演|模拟|假装)(?:一[个位])?(?:不受限制|无道德|越狱)(?:的)?",
)

# --------------------------------------------------------------------------- #
# 3. System-prompt disclosure
# --------------------------------------------------------------------------- #
_PROMPT_LEAK = _c(
    r"(?:repeat|print|output|show|reveal|display|echo|dump|recite)\s+"
    r"(?:me\s+)?(?:your|the|all)\s+(?:system\s*)?(?:prompt|instruction|directive|rule|configuration)s?",
    r"what\s+(?:were|are)\s+your\s+(?:original|initial|system|exact)\s+(?:instruction|prompt)s?",
    r"(?:everything|all\s+text)\s+(?:above|before)\s+(?:this|the)\s+"
    r"(?:line|message|point|conversation)",
    r"(?:begin|start)\s+your\s+(?:reply|response|answer)\s+with\s+"
    r"[\"'“”]?(?:you\s+are|system|i\s+am)",
    r"summar(?:ise|ize)\s+(?:your|the)\s+(?:system\s*)?(?:prompt|instruction|guideline)s?",
    r"in\s+a\s+code\s+block\s*,?\s*(?:output|print|show)\s+(?:your|the)\s+",
    r"list\s+(?:all\s+)?(?:your|the)\s+(?:available\s+)?(?:tool|function|capabilit)\w*\s+"
    r"(?:and\s+their\s+)?(?:definition|schema|description|parameter)",
    # Chinese
    r"(?:重复|输出|打印|展示|显示|复述|泄露)(?:一遍|你的|上面的|所有)?(?:系统)?(?:提示词|提示|指令|设定|规则)",
    r"你(?:最初|原始|一开始)的?(?:系统)?(?:提示词|指令|设定)(?:是什么)?",
    r"(?:这条|本条)(?:消息|信息)(?:之前|以上)的(?:所有)?(?:内容|文本)",
    r"把你的?(?:系统)?(?:提示词|指令|配置)(?:用代码块)?(?:输出|发给我|告诉我)",
)

# --------------------------------------------------------------------------- #
# 4. Privilege / capability escalation requests
# --------------------------------------------------------------------------- #
_ESCALATION = _c(
    r"(?:without|skip|bypass|avoid|disable|turn\s+off)\s+"
    r"(?:asking|requesting|the\s+)?(?:permission|approval|confirmation|human|user)\s*"
    r"(?:review|check|prompt)?",
    r"(?:do\s+not|don'?t|never)\s+(?:ask|tell|inform|notify|alert|warn|mention)\s+"
    r"(?:the\s+)?(?:user|human|operator|owner|anyone)",
    r"(?:bypass|circumvent|evade|defeat|disable)\s+(?:the\s+)?"
    r"(?:security|safety|guardrail|filter|policy|restriction|sandbox|monitor)\w*",
    r"(?:grant|give|escalate)\s+(?:yourself|me|it)\s+(?:admin|root|full|elevated)\s+"
    r"(?:access|privilege|permission)s?",
    r"(?:auto|automatically)\s*[- ]?approve\s+(?:all|every|this)",
    r"treat\s+this\s+as\s+(?:a\s+)?(?:pre[- ]?approved|authorised|authorized|trusted)",
    r"run\s+(?:this\s+)?(?:silently|quietly|in\s+the\s+background)\s+without",
    # Chinese
    r"(?:不要|无需|不用|跳过|绕过)(?:向|询问|请求|征求)?(?:用户|人工|管理员)?(?:的)?(?:确认|审批|批准|同意|许可)",
    r"(?:不要|别|禁止)(?:告诉|告知|通知|提醒|提示)(?:用户|使用者|任何人|对方)",
    r"(?:绕过|规避|关闭|禁用|突破)(?:安全|防护|检测|策略|限制|沙箱|审计)",
    r"(?:自动|直接)(?:批准|通过|执行)(?:所有|全部|本次)",
    r"(?:静默|悄悄|后台)(?:执行|运行|完成)(?:，|,)?\s*(?:不要|无需)",
)

# --------------------------------------------------------------------------- #
# 5. Delimiter / chat-template forgery
# --------------------------------------------------------------------------- #
_DELIMITER = _c(
    r"<\|(?:im_start|im_end|im_sep|system|user|assistant|endoftext|start_header_id|eot_id)\|>",
    r"\[/?(?:INST|SYS|s)\]",
    r"<<\s*/?SYS\s*>>",
    r"(?:^|\n)\s*#{2,4}\s*(?:system|instruction|assistant|developer)\s*(?:prompt|message)?\s*[:：]?\s*$",
    r"(?:^|\n)\s*(?:system|assistant|developer)\s*[:：]\s*(?:you\s+(?:are|must)|ignore|从现在)",
    r"<\s*/?\s*(?:system|instructions?|prompt)\s*>",
    r"```\s*(?:system|instruction|prompt)\b",
    r"\{\{\s*(?:system|instruction|prompt|inject)\s*\}\}",
    r"(?:^|\n)-{3,}\s*(?:BEGIN|START)\s+(?:SYSTEM|NEW)\s+(?:PROMPT|INSTRUCTION)",
    r"\bBEGIN\s+SYSTEM\s+OVERRIDE\b",
)

# --------------------------------------------------------------------------- #
# 6. Encoded / obfuscated instruction carriers
# --------------------------------------------------------------------------- #
_ENCODING = _c(
    r"(?:base64|b64|rot13|hex|url)\s*(?:-|\s)?(?:encoded?|decode|decoding)\s*"
    r"(?:instruction|payload|message|command|string|the\s+following)",
    r"decode\s+(?:the\s+)?following\s+(?:and\s+)?(?:then\s+)?(?:execute|run|follow|obey)",
    r"(?:atob|fromCharCode|base64_decode|b64decode|unescape)\s*\(",
    r"(?:执行|运行|遵循)(?:以下|下面)(?:base64|hex|编码)?(?:解码后的)?(?:内容|指令)",
    r"(?:先|请)(?:解码|解密)(?:以下|下面)(?:内容|字符串)(?:后|再)(?:执行|按照|遵循)",
)

# --------------------------------------------------------------------------- #
# 7. Data-exfiltration instructions embedded in content
# --------------------------------------------------------------------------- #
_EXFIL_INSTRUCTION = _c(
    r"(?:send|forward|post|upload|transmit|exfiltrate|deliver)\s+"
    r"(?:all\s+|the\s+|any\s+|your\s+)?(?:data|email|file|conversation|history|credential|token|"
    r"contact|contents?|result)s?\s+(?:to|at|towards)\s+\S+",
    r"(?:make|issue|perform|send)\s+(?:an?\s+)?(?:http|get|post|api|web|fetch)\s*(?:request|call)?\s+to\s+https?://",
    r"(?:include|append|embed|attach)\s+(?:the\s+)?(?:result|data|content|output|secret)s?\s+"
    r"(?:in|into|as)\s+(?:the\s+)?(?:url|query|parameter|image|link|src)",
    r"(?:email|mail|message|dm)\s+(?:it|this|them|the\s+\w+)\s+to\s+[\w.+-]+@",
    r"(?:首先|请|然后)?(?:把|将)(?:所有)?(?:数据|邮件|文件|对话|历史|凭据|密钥|内容)"
    r"(?:发送|上传|转发|提交|外发)(?:到|至|给)",
    r"(?:访问|请求|调用)\s*https?://\S+\s*(?:并|然后)?(?:附带|携带|包含)",
)

# --------------------------------------------------------------------------- #
# 8. Tool-invocation coercion (agent-specific, the 2026 growth area)
# --------------------------------------------------------------------------- #
_TOOL_COERCION = _c(
    r"(?:before|prior\s+to|when)\s+(?:using|calling|invoking)\s+(?:any|each|every|this)\s+tool\s*,?\s*"
    r"(?:you\s+must\s+|always\s+|first\s+)?(?:call|invoke|run|execute)",
    r"(?:always|first|immediately)\s+(?:call|invoke|run|use)\s+(?:the\s+)?"
    r"(?:`|\"|')?[\w.]+(?:`|\"|')?\s*(?:tool|function|api)?\s+(?:with|before|and\s+send)",
    r"(?:you\s+must|it\s+is\s+(?:required|mandatory))\s+(?:to\s+)?(?:call|use)\s+"
    r"(?:the\s+)?[\w.]+\s+(?:tool|function)\s+(?:first|before)",
    r"do\s+not\s+(?:mention|reveal|display|show)\s+(?:this|that)\s+"
    r"(?:tool\s+call|instruction|step|to\s+the\s+user)",
    r"(?:在|使用)(?:调用|使用)(?:任何|每个|该)工具(?:之前|前)(?:，|,)?\s*(?:必须|请|先)(?:调用|执行|运行)",
    r"(?:必须|务必|一定)(?:先|首先)(?:调用|执行)\s*[\w.]+\s*(?:工具|函数|接口)",
)

# --------------------------------------------------------------------------- #
# 9. Urgency / social-engineering framing
# --------------------------------------------------------------------------- #
_SOCIAL = _c(
    r"(?:this\s+is\s+)?(?:urgent|emergency|critical|immediately|asap)\s*[!.,:]\s*"
    r"(?:you\s+must|please\s+(?:immediately|now)|do\s+not\s+delay)",
    r"(?:the\s+)?(?:admin|administrator|developer|owner|ceo|security\s+team)\s+"
    r"(?:has\s+)?(?:authoris|authoriz|approv|instruct)\w*\s+(?:this|you)",
    r"(?:as\s+)?(?:an?\s+)?(?:authoris|authoriz)ed\s+(?:test|audit|penetration\s+test|exercise)",
    r"failure\s+to\s+comply\s+will\s+(?:result|cause|lead)",
    r"(?:管理员|开发者|安全团队|老板)(?:已经)?(?:授权|批准|要求)(?:你|本次|该操作)",
    r"(?:紧急|立即|马上)(?:！|!|，|,)?\s*(?:必须|请立刻|不得延误)",
)

# --------------------------------------------------------------------------- #
# 10. Payload-stuffing / context flooding
# --------------------------------------------------------------------------- #
#: A single token repeated many times (context-window flooding to push the real
#: system prompt out of the model's attention).
REPETITION_RE = re.compile(r"(\b\w{2,20}\b)(?:[\s,;.!?]+\1){14,}", re.IGNORECASE)

#: An unbroken run of characters far longer than any legitimate word.
LONG_TOKEN_RE = re.compile(r"\S{600,}")

#: Imperative sentence openers, used as a weak corroborating signal.
IMPERATIVE_RE = re.compile(
    r"(?im)^\s*(?:you\s+must|you\s+should|always|never|do\s+not|don'?t|please\s+"
    r"(?:immediately|now)|必须|务必|请立即|不要|禁止)\b"
)


TECHNIQUES: Tuple[Technique, ...] = (
    Technique(
        name="instruction_override",
        label="指令覆盖：要求模型忽略先前指令",
        weight=0.45,
        severity=Severity.HIGH,
        patterns=_OVERRIDE,
        remediation="隔离该内容源，不要将其作为指令上下文传递给模型",
    ),
    Technique(
        name="role_hijack",
        label="角色劫持：替换模型人设或要求进入越狱模式",
        weight=0.35,
        severity=Severity.HIGH,
        patterns=_ROLE_HIJACK,
        remediation="拒绝该轮输入并重置会话人设",
    ),
    Technique(
        name="prompt_leak",
        label="系统提示词泄露诱导",
        weight=0.30,
        severity=Severity.MEDIUM,
        patterns=_PROMPT_LEAK,
        remediation="屏蔽响应中的系统提示内容",
    ),
    Technique(
        name="privilege_escalation",
        label="越权请求：绕过审批 / 隐瞒用户 / 关闭防护",
        weight=0.40,
        severity=Severity.HIGH,
        patterns=_ESCALATION,
        remediation="强制人工审批，不得自动放行",
    ),
    Technique(
        name="delimiter_forgery",
        label="分隔符伪造：伪造聊天模板或系统消息边界",
        weight=0.50,
        severity=Severity.HIGH,
        patterns=_DELIMITER,
        remediation="对不可信内容做模板分隔符转义后再入上下文",
    ),
    Technique(
        name="encoded_payload",
        label="编码指令载荷：Base64/Hex/ROT13 包裹的指令",
        weight=0.35,
        severity=Severity.MEDIUM,
        patterns=_ENCODING,
        remediation="解码后重新送检，禁止模型自行解码执行",
    ),
    Technique(
        name="exfiltration_instruction",
        label="内容中携带数据外发指令",
        weight=0.50,
        severity=Severity.CRITICAL,
        patterns=_EXFIL_INSTRUCTION,
        remediation="阻断出网并核查是否已发生外泄",
    ),
    Technique(
        name="tool_coercion",
        label="工具调用胁迫：诱导 Agent 先调用特定工具",
        weight=0.45,
        severity=Severity.HIGH,
        patterns=_TOOL_COERCION,
        remediation="核查被点名工具的调用链，必要时下线该内容源",
    ),
    Technique(
        name="social_engineering",
        label="社会工程框架：伪造授权 / 制造紧迫感",
        weight=0.20,
        severity=Severity.MEDIUM,
        patterns=_SOCIAL,
        remediation="按正常审批流程处理，不接受内容内声明的授权",
    ),
)

TECHNIQUES_BY_NAME: Dict[str, Technique] = {t.name: t for t in TECHNIQUES}


def technique_weight(name: str) -> float:
    """Weight of a technique by name (``0.0`` when unknown)."""
    technique = TECHNIQUES_BY_NAME.get(name)
    return technique.weight if technique else 0.0


def compile_all() -> int:
    """Return the total number of compiled patterns - used by self-tests."""
    return sum(len(t.patterns) for t in TECHNIQUES) + 3


def scan_techniques(text: str, *, limit: int = 3) -> List[Tuple[Technique, List[str]]]:
    """Run every technique over ``text``.

    Returns:
        ``(technique, matched_fragments)`` for each technique that fired.
    """
    out: List[Tuple[Technique, List[str]]] = []
    for technique in TECHNIQUES:
        hits = technique.search(text, limit=limit)
        if hits:
            out.append((technique, hits))
    return out
