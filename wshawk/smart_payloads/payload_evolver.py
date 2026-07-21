#!/usr/bin/env python3
"""
WSHawk Payload Evolver
Combines and mutates successful payloads to create novel attack strings

Author: Regaan (@regaan)
"""

import re
import random
import hashlib
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime

from ..console import Logger


class PayloadEvolver:
    """
    Evolutionary payload generation — combines successful mutations.
    
    Inspired by genetic algorithms:
    1. Takes a "population" of payloads that worked
    2. "Crossover" — combines parts from different successful payloads
    3. "Mutation" — randomly modifies payloads to discover new bypasses
    4. "Selection" — keeps payloads that produce interesting responses
    5. "Elitism" — always keeps the best performers
    
    This creates novel attack strings not found in any wordlist.
    """
    
    # WAF evasion fragments for mixing
    WAF_BYPASS_FRAGMENTS = {
        'encodings': [
            '%00', '%0a', '%0d', '%09', '%20',
            '\\x00', '\\n', '\\r', '\\t',
            '\u0000', '\u000a', '\u000d',
        ],
        'sql_comments': [
            '/**/', '--', '#', '-- -',
            '/*!*/', '/*!50000*/', '/**//**/',
        ],
        'html_breaks': [
            '<!--', '-->', '<![CDATA[', ']]>',
            '\n', '\r', '\t', '\x00',
        ],
        'case_tricks': [
            lambda s: s.swapcase(),
            lambda s: ''.join(c.upper() if i%2 else c.lower() for i,c in enumerate(s)),
            lambda s: s.upper(),
        ],
        'string_concat': {
            'sql': ["'+'"," + ", "||", "CONCAT(", "CHR("],
            'js': ["'+'",'"+"+""', "String.fromCharCode(", "eval(", "Function("],
        }
    }
    
    def __init__(self,
                 population_size: int = 50,
                 mutation_rate: float = 0.3,
                 crossover_rate: float = 0.5):
        """
        Args:
            population_size: Max payloads to keep in population
            mutation_rate: Probability of random mutation (0-1)
            crossover_rate: Probability of crossover (0-1)
        """
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        
        # Population: payload → fitness score
        self.population: Dict[str, float] = {}
        
        # Hall of fame: best payloads ever seen
        self.hall_of_fame: List[Dict] = []
        
        # Generation counter
        self.generation = 0
        
        # Track seen payloads to avoid duplicates
        self.seen_hashes: Set[str] = set()
    
    def seed(self, payloads: List[str], initial_fitness: float = 0.5):
        """
        Seed the population with initial payloads.
        
        Args:
            payloads: List of initial payloads
            initial_fitness: Starting fitness score
        """
        for payload in payloads:
            h = self._hash(payload)
            if h not in self.seen_hashes:
                self.population[payload] = initial_fitness
                self.seen_hashes.add(h)
        
        # Trim to population size
        self._trim_population()
        Logger.info(f"Population seeded with {len(self.population)} payloads")
    
    def update_fitness(self, payload: str, score: float):
        """
        Update fitness score based on server response.
        
        Args:
            payload: The payload tested
            score: Fitness score (0=useless, 1=highly effective)
        """
        if payload in self.population:
            # Exponential moving average
            old = self.population[payload]
            self.population[payload] = 0.4 * score + 0.6 * old
            
            if score >= 0.7:
                self.hall_of_fame.append({
                    'payload': payload,
                    'score': score,
                    'generation': self.generation,
                })
    
    def evolve(self, count: int = 20) -> List[str]:
        """
        Generate next generation of payloads.
        
        Args:
            count: Number of new payloads to generate
            
        Returns:
            List of evolved payloads
        """
        self.generation += 1
        new_payloads = []
        
        if not self.population:
            Logger.warning("Empty population — seed with initial payloads first")
            return []
        
        # Get sorted population (best first)
        sorted_pop = sorted(self.population.items(), key=lambda x: x[1], reverse=True)
        parents = [p[0] for p in sorted_pop[:max(10, len(sorted_pop)//2)]]
        
        attempts = 0
        max_attempts = count * 5
        
        while len(new_payloads) < count and attempts < max_attempts:
            attempts += 1
            
            r = random.random()
            
            if r < self.crossover_rate and len(parents) >= 2:
                # Crossover
                p1, p2 = random.sample(parents, 2)
                child = self._crossover(p1, p2)
            elif r < self.crossover_rate + self.mutation_rate:
                # Mutation
                parent = random.choice(parents)
                child = self._mutate(parent)
            else:
                # WAF bypass injection
                parent = random.choice(parents)
                child = self._inject_bypass(parent)
            
            # Deduplicate
            h = self._hash(child)
            if h not in self.seen_hashes and child and len(child) < 2000:
                new_payloads.append(child)
                self.seen_hashes.add(h)
                self.population[child] = 0.5  # Neutral initial fitness
        
        # Trim
        self._trim_population()
        
        Logger.info(
            f"Generation {self.generation}: {len(new_payloads)} new payloads "
            f"(population: {len(self.population)})"
        )
        
        return new_payloads
    
    def _crossover(self, parent1: str, parent2: str) -> str:
        """Combine two payloads."""
        strategy = random.choice(['split', 'interleave', 'wrap', 'inject'])
        
        if strategy == 'split':
            # Split each parent and swap halves
            mid1 = len(parent1) // 2
            mid2 = len(parent2) // 2
            if random.random() < 0.5:
                return parent1[:mid1] + parent2[mid2:]
            else:
                return parent2[:mid2] + parent1[mid1:]
        
        elif strategy == 'interleave':
            # Take alternating chunks
            chunk_size = random.randint(2, 8)
            result = []
            for i in range(0, max(len(parent1), len(parent2)), chunk_size):
                if i % (chunk_size * 2) < chunk_size:
                    result.append(parent1[i:i+chunk_size])
                else:
                    result.append(parent2[i:i+chunk_size])
            return ''.join(result)
        
        elif strategy == 'wrap':
            # Wrap one payload around another
            if len(parent1) > 4:
                mid = len(parent1) // 2
                return parent1[:mid] + parent2 + parent1[mid:]
            return parent1 + parent2
        
        elif strategy == 'inject':
            # Inject parent2 at a random position in parent1
            if parent1:
                pos = random.randint(0, len(parent1))
                return parent1[:pos] + parent2 + parent1[pos:]
            return parent2
        
        return parent1 + parent2
    
    def _mutate(self, payload: str) -> str:
        """Apply random mutation to a payload."""
        if not payload:
            return payload
            
        mutation = random.choice([
            'char_swap', 'char_delete', 'char_insert', 'char_replace',
            'case_change', 'encode_char', 'duplicate_segment',
            'reverse_segment', 'null_insert',
        ])
        
        if mutation == 'char_swap' and len(payload) >= 2:
            i = random.randint(0, len(payload) - 2)
            return payload[:i] + payload[i+1] + payload[i] + payload[i+2:]
        
        elif mutation == 'char_delete' and len(payload) > 1:
            i = random.randint(0, len(payload) - 1)
            return payload[:i] + payload[i+1:]
        
        elif mutation == 'char_insert':
            i = random.randint(0, len(payload))
            c = random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789<>"\'/\\'))
            return payload[:i] + c + payload[i:]
        
        elif mutation == 'char_replace':
            i = random.randint(0, len(payload) - 1)
            c = random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789<>"\'/\\'))
            return payload[:i] + c + payload[i+1:]
        
        elif mutation == 'case_change':
            func = random.choice(self.WAF_BYPASS_FRAGMENTS['case_tricks'])
            return func(payload)
        
        elif mutation == 'encode_char':
            i = random.randint(0, len(payload) - 1)
            encoded = f'%{ord(payload[i]):02x}'
            return payload[:i] + encoded + payload[i+1:]
        
        elif mutation == 'duplicate_segment':
            if len(payload) >= 4:
                start = random.randint(0, len(payload) - 4)
                end = start + random.randint(2, min(8, len(payload) - start))
                segment = payload[start:end]
                return payload[:end] + segment + payload[end:]
            return payload
        
        elif mutation == 'reverse_segment':
            if len(payload) >= 4:
                start = random.randint(0, len(payload) - 4)
                end = start + random.randint(2, min(8, len(payload) - start))
                return payload[:start] + payload[start:end][::-1] + payload[end:]
            return payload
        
        elif mutation == 'null_insert':
            i = random.randint(0, len(payload))
            null = random.choice(['%00', '\x00', '%0a'])
            return payload[:i] + null + payload[i:]
        
        return payload
    
    def _inject_bypass(self, payload: str) -> str:
        """Inject WAF bypass techniques into a payload."""
        technique = random.choice([
            'comment_inject', 'encoding_wrap', 'null_padding',
            'concat_break', 'newline_inject',
        ])
        
        if technique == 'comment_inject':
            # Insert SQL comment in random position
            comment = random.choice(self.WAF_BYPASS_FRAGMENTS['sql_comments'])
            words = payload.split(' ')
            if len(words) > 1:
                pos = random.randint(0, len(words) - 1)
                words.insert(pos + 1, comment)
                return ' '.join(words)
            return payload
        
        elif technique == 'encoding_wrap':
            # Encode random character
            if payload:
                i = random.randint(0, len(payload) - 1)
                encoding = random.choice(self.WAF_BYPASS_FRAGMENTS['encodings'])
                return payload[:i] + encoding + payload[i+1:]
            return payload
        
        elif technique == 'null_padding':
            # Add null bytes around key characters
            result = payload
            for char in ['<', '>', '"', "'", '=']:
                if char in result:
                    result = result.replace(char, f'%00{char}', 1)
                    break
            return result
        
        elif technique == 'concat_break':
            # Break strings with concatenation
            if "'" in payload:
                concat = random.choice(self.WAF_BYPASS_FRAGMENTS['string_concat']['sql'])
                return payload.replace("'", f"'{concat}'", 1)
            return payload
        
        elif technique == 'newline_inject':
            # Add newlines to break pattern matching
            words = payload.split(' ')
            if len(words) > 1:
                pos = random.randint(0, len(words) - 1)
                words[pos] = words[pos] + '\n'
                return ' '.join(words)
            return payload
        
        return payload
    
    def _trim_population(self):
        """Keep only the best payloads within population size."""
        if len(self.population) > self.population_size:
            sorted_pop = sorted(
                self.population.items(), key=lambda x: x[1], reverse=True
            )
            self.population = dict(sorted_pop[:self.population_size])
    
    def _hash(self, payload: str) -> str:
        """Hash a payload for deduplication."""
        return hashlib.md5(payload.encode('utf-8', errors='replace')).hexdigest()
    
    def get_best(self, n: int = 10) -> List[Tuple[str, float]]:
        """Get top N payloads by fitness."""
        sorted_pop = sorted(
            self.population.items(), key=lambda x: x[1], reverse=True
        )
        return sorted_pop[:n]
    
    def get_stats(self) -> Dict:
        """Get evolver statistics."""
        scores = list(self.population.values())
        return {
            'generation': self.generation,
            'population_size': len(self.population),
            'avg_fitness': sum(scores) / len(scores) if scores else 0,
            'best_fitness': max(scores) if scores else 0,
            'worst_fitness': min(scores) if scores else 0,
            'hall_of_fame_size': len(self.hall_of_fame),
            'unique_payloads_seen': len(self.seen_hashes),
        }
