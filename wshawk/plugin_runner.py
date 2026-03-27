#!/usr/bin/env python3
"""
Subprocess execution helper for isolated plugin method calls.
"""

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict


MAX_INPUT_BYTES = 128 * 1024
MAX_OUTPUT_BYTES = 256 * 1024
ALLOWED_METHODS = frozenset({"detect", "get_payloads", "handle_message"})


def _read_request() -> Dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("plugin request too large")
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _validate_request(request: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(request, dict):
        raise TypeError("request payload must be a JSON object")

    action = str(request.get("action") or "invoke").strip().lower()
    plugin_path = Path(str(request.get("plugin_path") or "")).expanduser().resolve()
    if not plugin_path.is_file() or plugin_path.suffix != ".py":
        raise FileNotFoundError("plugin file not found")

    if action == "inspect":
        return {
            "action": action,
            "plugin_path": str(plugin_path),
        }
    if action != "invoke":
        raise ValueError("plugin action is not allowed")

    class_name = str(request.get("class_name") or "").strip()
    method_name = str(request.get("method_name") or "").strip()
    if not class_name:
        raise ValueError("plugin class name is required")
    if method_name not in ALLOWED_METHODS:
        raise ValueError("plugin method is not allowed")

    args = request.get("args", [])
    kwargs = request.get("kwargs", {})
    if not isinstance(args, list):
        raise TypeError("plugin args must be a list")
    if not isinstance(kwargs, dict):
        raise TypeError("plugin kwargs must be a dict")

    return {
        "action": action,
        "plugin_path": str(plugin_path),
        "class_name": class_name,
        "method_name": method_name,
        "args": args,
        "kwargs": kwargs,
    }


def _load_plugin_module(plugin_path: str):
    module_name = f"wshawk_plugin_subprocess_{Path(plugin_path).stem}"
    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load plugin module from {plugin_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _load_plugin_class(plugin_path: str, class_name: str):
    module = _load_plugin_module(plugin_path)
    plugin_class = getattr(module, class_name, None)
    if plugin_class is None:
        raise AttributeError(f"Plugin class {class_name} not found")
    return plugin_class


def _write_response(payload: Dict[str, Any]) -> None:
    encoded = json.dumps(payload).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError("plugin response too large")
    sys.stdout.buffer.write(encoded)


def _inspect_plugins(plugin_path: str):
    from wshawk.plugin_system import DetectorPlugin, PayloadPlugin, PluginBase, ProtocolPlugin

    plugin_module = _load_plugin_module(plugin_path)
    inspected = []
    for attr_name in dir(plugin_module):
        attr = getattr(plugin_module, attr_name)
        if (isinstance(attr, type)
            and issubclass(attr, PluginBase)
            and attr not in (PluginBase, PayloadPlugin, DetectorPlugin, ProtocolPlugin)):
            plugin = attr()
            metadata = plugin.get_metadata()
            plugin_type = "payload" if isinstance(plugin, PayloadPlugin) else (
                "detector" if isinstance(plugin, DetectorPlugin) else "protocol"
            )
            inspected.append({
                "class_name": attr.__name__,
                "plugin_type": plugin_type,
                "metadata": metadata.to_dict(),
                "protocol_name": plugin.get_protocol_name() if isinstance(plugin, ProtocolPlugin) else "",
            })
    return inspected


def main():
    request = _validate_request(_read_request())
    if request.get("action") == "inspect":
        result = _inspect_plugins(request["plugin_path"])
    else:
        plugin_class = _load_plugin_class(request["plugin_path"], request["class_name"])
        plugin = plugin_class()
        method = getattr(plugin, request["method_name"])
        args = request["args"]
        kwargs = request["kwargs"]

        if asyncio.iscoroutinefunction(method):
            result = asyncio.run(method(*args, **kwargs))
        else:
            result = method(*args, **kwargs)

    _write_response({"ok": True, "result": result})


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover - subprocess failure path
        try:
            _write_response({"ok": False, "error": str(exc)})
        except Exception:
            sys.stdout.buffer.write(json.dumps({"ok": False, "error": "plugin subprocess failed"}).encode("utf-8"))
        sys.exit(1)
