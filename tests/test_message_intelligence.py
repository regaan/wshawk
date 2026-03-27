#!/usr/bin/env python3
"""Tests for WSHawk Message Analyzer Module."""

import unittest

from wshawk.message_intelligence import MessageAnalyzer, MessageFormat


class MessageAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = MessageAnalyzer()

    def test_detects_message_formats(self):
        self.assertEqual(self.analyzer.detect_message_format('{"action": "login", "user": "test"}'), MessageFormat.JSON)
        self.assertEqual(self.analyzer.detect_message_format('[{"id": 1}, {"id": 2}]'), MessageFormat.JSON)
        self.assertEqual(self.analyzer.detect_message_format('<message><type>login</type></message>'), MessageFormat.XML)
        self.assertEqual(self.analyzer.detect_message_format('hello world'), MessageFormat.PLAIN_TEXT)
        self.assertEqual(self.analyzer.detect_message_format('hello\x00\x01\x02world'), MessageFormat.BINARY)

    def test_learning_builds_schema_and_caps_samples(self):
        messages = [
            '{"action": "chat", "message": "hello"}',
            '{"action": "chat", "message": "world"}',
            '{"action": "ping", "timestamp": 123}',
        ]
        self.analyzer.learn_from_messages(messages)
        self.assertEqual(self.analyzer.detected_format, MessageFormat.JSON)
        self.assertTrue(self.analyzer.json_schema)

        analyzer = MessageAnalyzer()
        analyzer.learn_from_messages([f'{{"id": {i}}}' for i in range(50)])
        self.assertEqual(len(analyzer.sample_messages), 20)

    def test_learning_handles_empty_messages_and_field_types(self):
        self.analyzer.learn_from_messages([])
        self.assertIsNone(self.analyzer.detected_format)

        analyzer = MessageAnalyzer()
        analyzer.learn_from_messages(['{"name": "Alice", "age": 30}', '{"name": "Bob", "age": 25}'])
        self.assertIn("name", analyzer.json_schema)
        self.assertEqual(analyzer.json_schema["name"]["type"], "str")

    def test_payload_injection_supports_multiple_formats(self):
        analyzer = MessageAnalyzer()
        analyzer.learn_from_messages(['{"action": "search", "query": "test"}'])
        json_results = analyzer.inject_payload_into_message('{"action": "search", "query": "test"}', "' OR 1=1--")
        self.assertTrue(any("OR 1=1" in result for result in json_results))

        analyzer = MessageAnalyzer()
        analyzer.learn_from_messages(['<request><query>test</query></request>'])
        xml_results = analyzer.inject_payload_into_message('<request><query>test</query></request>', "<script>alert(1)</script>")
        self.assertTrue(xml_results)

        analyzer = MessageAnalyzer()
        analyzer.learn_from_messages(['hello world'])
        text_results = analyzer.inject_payload_into_message("hello world", "INJECTED")
        self.assertTrue(any("INJECTED" in result for result in text_results))

    def test_injectable_fields_and_format_info(self):
        analyzer = MessageAnalyzer()
        analyzer.learn_from_messages([
            '{"username": "test", "age": 25, "active": true}',
            '{"username": "admin", "age": 30, "active": false}',
        ])
        self.assertIn("username", analyzer.get_injectable_fields())

        unknown_info = MessageAnalyzer().get_format_info()
        self.assertEqual(unknown_info["format"], "unknown")

        info = analyzer.get_format_info()
        self.assertIn("format", info)
        self.assertIn("schema", info)
        self.assertIn("injectable_fields", info)
        self.assertIn("sample_count", info)


if __name__ == "__main__":
    unittest.main()
