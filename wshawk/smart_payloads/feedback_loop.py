#!/usr/bin/env python3
"""
WSHawk Feedback Loop
Real-time learning from scan responses to adapt attack strategy

Author: Regaan (@regaan)
"""

import re
import json
import time
from typing import Deque, List, Dict, Optional, Any, Tuple
from collections import defaultdict, deque
from datetime import datetime

from ..console import Logger


class ResponseSignal:
    """Classification of a server response."""
    INTERESTING = "interesting"    # Potential vulnerability indicator
    BLOCKED = "blocked"           # WAF/filter rejection
    ERROR = "error"               # Server error (may indicate injection worked)
    REFLECTED = "reflected"       # Input reflected in output
    DELAYED = "delayed"           # Response delay (time-based injection)
    NORMAL = "normal"             # No notable behavior
    DIFFERENT = "different"       # Response differs from baseline


class FeedbackLoop:
    """
    Learn from server responses in real-time and adapt strategy.
    
    The feedback loop:
    1. Observes baseline server behavior
    2. Classifies each response against the baseline
    3. When an "interesting" response is found, generates mutations
    4. Tracks which payload categories are effective
    5. Adjusts payload priority dynamically
    
    This gives WSHawk "intelligence" — it focuses effort on what works.
    """
    
    def __init__(
        self,
        response_threshold: float = 0.5,
        max_history: int = 500,
        max_interesting: int = 500,
    ):
        """
        Args:
            response_threshold: Time ratio threshold for delay detection (1.5x baseline = delayed)
        """
        # Baseline tracking
        self.baseline_responses: Deque[str] = deque(maxlen=3)
        self.baseline_length: float = 0
        self.baseline_time: float = 0
        self.baseline_established = False
        
        # Response tracking
        self.max_history = max(1, int(max_history))
        self.response_history: Deque[Dict] = deque(maxlen=self.max_history)
        self.signal_counts: Dict[str, int] = defaultdict(int)
        
        # Effectiveness tracking by category
        self.category_scores: Dict[str, float] = defaultdict(lambda: 1.0)
        self.category_attempts: Dict[str, int] = defaultdict(int)
        self.category_hits: Dict[str, int] = defaultdict(int)
        
        # Interesting findings queue
        self.max_interesting = max(1, int(max_interesting))
        self.interesting_payloads: Deque[Dict] = deque(maxlen=self.max_interesting)
        
        # Settings
        self.response_threshold = response_threshold
        
        # Error patterns that indicate injection worked
        self.error_patterns = [
            r'sql\s*(?:syntax|error)',
            r'mysql|postgres|sqlite|oracle|mssql',
            r'syntax\s*error',
            r'unterminated\s*string',
            r'unexpected\s*(?:token|end)',
            r'stack\s*trace',
            r'internal\s*server\s*error',
            r'exception',
            r'traceback',
            r'fatal\s*error',
            r'warning:',
            r'error\s*at\s*line',
            r'parse\s*error',
            r'segmentation\s*fault',
        ]
        
        # Block patterns (WAF/filter)
        self.block_patterns = [
            r'blocked', r'forbidden', r'not\s*allowed',
            r'access\s*denied', r'waf', r'firewall',
            r'attack\s*detected', r'malicious',
            r'invalid.*input', r'request\s*rejected',
            r'rate\s*limit', r'too\s*many\s*requests',
        ]
    
    def establish_baseline(self, response: str, response_time: float):
        """Record a baseline (normal) response."""
        self.baseline_responses.append(response)
        
        if len(self.baseline_responses) >= 3:
            self.baseline_length = sum(len(r) for r in self.baseline_responses) / len(self.baseline_responses)
            self.baseline_time = response_time
            self.baseline_established = True
            Logger.info(
                f"Baseline established: avg length={self.baseline_length:.0f}, "
                f"avg time={self.baseline_time:.3f}s"
            )
    
    def analyze_response(self,
                         payload: str,
                         response: str,
                         response_time: float,
                         category: str = 'unknown') -> Tuple[str, float]:
        """
        Analyze a server response against the baseline.
        
        Args:
            payload: The payload that was sent
            response: Server response content
            response_time: Time to receive response (seconds)
            category: Payload category (sqli, xss, cmdi, etc.)
            
        Returns:
            Tuple of (signal_type, confidence_score)
        """
        self.category_attempts[category] += 1
        
        signal = ResponseSignal.NORMAL
        confidence = 0.0
        details = []
        
        # Check for errors (potential injection success)
        for pattern in self.error_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                signal = ResponseSignal.ERROR
                confidence = max(confidence, 0.7)
                details.append(f"Error pattern: {pattern}")
                break
        
        # Check for blocks (WAF/filter)
        for pattern in self.block_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                signal = ResponseSignal.BLOCKED
                confidence = max(confidence, 0.8)
                details.append(f"Block pattern: {pattern}")
                break
        
        # Check for reflection
        if signal == ResponseSignal.NORMAL:
            # Check if payload content appears in response
            payload_escapes = [
                payload,
                payload.replace('<', '&lt;').replace('>', '&gt;'),
                payload.replace('"', '&quot;'),
            ]
            for escaped in payload_escapes:
                if escaped and len(escaped) > 3 and escaped in response:
                    signal = ResponseSignal.REFLECTED
                    confidence = max(confidence, 0.6)
                    details.append("Payload reflected in response")
                    break
        
        # Check for time-based indicators
        if self.baseline_established and response_time > 0:
            time_ratio = response_time / max(self.baseline_time, 0.001)
            if time_ratio > 3.0:
                signal = ResponseSignal.DELAYED
                confidence = max(confidence, 0.8)
                details.append(f"Response {time_ratio:.1f}x slower than baseline")
            elif time_ratio > 1.5 + self.response_threshold:
                signal = ResponseSignal.DELAYED
                confidence = max(confidence, 0.5)
                details.append(f"Response {time_ratio:.1f}x slower")
        
        # Check for response size anomaly
        if self.baseline_established and signal == ResponseSignal.NORMAL:
            length_diff = abs(len(response) - self.baseline_length)
            if length_diff > self.baseline_length * 0.5 and self.baseline_length > 0:
                signal = ResponseSignal.DIFFERENT
                confidence = max(confidence, 0.4)
                details.append(f"Response length differs by {length_diff:.0f} chars")
        
        # Is this interesting?
        is_interesting = signal in (
            ResponseSignal.INTERESTING, ResponseSignal.ERROR,
            ResponseSignal.REFLECTED, ResponseSignal.DELAYED
        )
        
        if is_interesting:
            self.category_hits[category] += 1
            self.interesting_payloads.append({
                'payload': payload,
                'response': response[:500],
                'signal': signal,
                'confidence': confidence,
                'category': category,
                'details': details,
                'timestamp': datetime.now().isoformat(),
            })
            Logger.success(
                f"Interesting response! Signal={signal}, "
                f"Category={category}, Confidence={confidence:.0%}"
            )
        
        # Update signal counts
        self.signal_counts[signal] += 1
        
        # Record history (capped)
        self.response_history.append({
            'payload': payload[:200],
            'signal': signal,
            'confidence': confidence,
            'category': category,
            'time': response_time,
        })
        # Update category effectiveness
        self._update_category_score(category, is_interesting)
        
        return signal, confidence
    
    def get_priority_categories(self) -> List[Tuple[str, float]]:
        """
        Get payload categories ranked by effectiveness.
        
        Returns:
            List of (category, score) tuples, highest score first
        """
        scored = []
        for cat, attempts in self.category_attempts.items():
            if attempts > 0:
                hits = self.category_hits.get(cat, 0)
                score = self.category_scores[cat]
                scored.append((cat, score, hits, attempts))
        
        scored.sort(key=lambda x: x[1], reverse=True)
        return [(cat, score) for cat, score, _, _ in scored]
    
    def should_continue_category(self, category: str) -> bool:
        """
        Decide whether to continue testing a payload category.
        
        Returns False if the category has been consistently blocked.
        """
        attempts = self.category_attempts.get(category, 0)
        if attempts < 5:
            return True  # Not enough data
        
        score = self.category_scores.get(category, 1.0)
        return score > 0.1  # Stop if effectiveness drops below 10%
    
    def generate_mutations(self, payload: str, count: int = 10) -> List[str]:
        """
        Generate mutations of a successful payload.
        
        Args:
            payload: Successful payload to mutate
            count: Number of mutations to generate
            
        Returns:
            List of mutated payloads
        """
        mutations = []
        
        # Encoding mutations
        mutations.extend(self._encoding_mutations(payload))
        
        # Case mutations
        mutations.extend(self._case_mutations(payload))
        
        # Whitespace mutations
        mutations.extend(self._whitespace_mutations(payload))
        
        # Comment insertion
        mutations.extend(self._comment_mutations(payload))
        
        # Concatenation mutations
        mutations.extend(self._concat_mutations(payload))
        
        return mutations[:count]
    
    def _encoding_mutations(self, payload: str) -> List[str]:
        """Generate encoding-based mutations."""
        mutations = []
        
        # URL encoding
        url_encoded = ''.join(f'%{ord(c):02x}' if not c.isalnum() else c for c in payload)
        mutations.append(url_encoded)
        
        # Double URL encoding
        double_encoded = ''.join(
            f'%25{ord(c):02x}' if not c.isalnum() else c for c in payload
        )
        mutations.append(double_encoded)
        
        # Unicode escapes
        unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in payload)
        mutations.append(unicode_encoded)
        
        # HTML entities for key characters
        html_map = {'<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '&': '&amp;'}
        html_encoded = ''.join(html_map.get(c, c) for c in payload)
        if html_encoded != payload:
            mutations.append(html_encoded)
        
        return mutations
    
    def _case_mutations(self, payload: str) -> List[str]:
        """Generate case-based mutations."""
        mutations = []
        
        # Mixed case
        mixed = ''.join(
            c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)
        )
        mutations.append(mixed)
        
        # Key SQL keywords in different cases
        sql_keywords = ['SELECT', 'UNION', 'DROP', 'INSERT', 'UPDATE', 'DELETE', 'OR', 'AND']
        result = payload
        for kw in sql_keywords:
            if kw.lower() in result.lower():
                # sElEcT style
                mixed_kw = ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(kw))
                result = re.sub(kw, mixed_kw, result, flags=re.IGNORECASE)
        if result != payload:
            mutations.append(result)
        
        return mutations
    
    def _whitespace_mutations(self, payload: str) -> List[str]:
        """Generate whitespace-based mutations."""
        mutations = []
        
        # Tab instead of space
        mutations.append(payload.replace(' ', '\t'))
        
        # Multiple spaces
        mutations.append(payload.replace(' ', '  '))
        
        # Newlines
        mutations.append(payload.replace(' ', '\n'))
        
        # No spaces (where possible)
        mutations.append(payload.replace(' ', ''))
        
        # SQL-specific: comments as whitespace
        mutations.append(payload.replace(' ', '/**/'))
        
        return mutations
    
    def _comment_mutations(self, payload: str) -> List[str]:
        """Insert comments to bypass pattern matching."""
        mutations = []
        
        # SQL inline comments
        if any(kw in payload.upper() for kw in ['SELECT', 'UNION', 'DROP', 'OR', 'AND']):
            # Insert /**/ in SQL keywords
            for kw in ['SELECT', 'UNION', 'DROP']:
                if kw in payload.upper():
                    idx = payload.upper().index(kw)
                    original_kw = payload[idx:idx+len(kw)]
                    mid = len(original_kw) // 2
                    commented = original_kw[:mid] + '/**/' + original_kw[mid:]
                    mutations.append(payload[:idx] + commented + payload[idx+len(kw):])
        
        # HTML comment insertion for XSS
        if '<script' in payload.lower():
            mutations.append(payload.replace('<script', '<scr<!---->ipt'))
        
        return mutations
    
    def _concat_mutations(self, payload: str) -> List[str]:
        """Generate string concatenation mutations."""
        mutations = []
        
        # SQL string concatenation
        if "'" in payload:
            mutations.append(payload.replace("'", "'+'" ))
            mutations.append(payload.replace("'", "' + '"))
            mutations.append(payload.replace("'", "'||'"))
        
        # JavaScript concatenation for XSS
        if 'alert' in payload:
            mutations.append(payload.replace('alert', 'al'+'ert'))
            mutations.append(payload.replace('alert(1)', "eval('al'+'ert(1)')"))
            mutations.append(payload.replace('alert(1)', 'Function("al"+"ert(1)")()'))
        
        return mutations
    
    def _update_category_score(self, category: str, is_hit: bool):
        """Update category effectiveness score using exponential moving average."""
        alpha = 0.3  # Learning rate
        current = self.category_scores[category]
        observation = 1.0 if is_hit else 0.0
        self.category_scores[category] = alpha * observation + (1 - alpha) * current
    
    def get_stats(self) -> Dict[str, Any]:
        """Get feedback loop statistics."""
        return {
            'total_analyzed': len(self.response_history),
            'signal_counts': dict(self.signal_counts),
            'interesting_count': len(self.interesting_payloads),
            'category_effectiveness': {
                cat: {
                    'score': round(self.category_scores[cat], 3),
                    'attempts': self.category_attempts[cat],
                    'hits': self.category_hits.get(cat, 0),
                }
                for cat in self.category_attempts
            },
            'priority_order': self.get_priority_categories(),
            'baseline_established': self.baseline_established,
        }
