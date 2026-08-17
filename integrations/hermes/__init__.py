"""Directory-plugin entry point for Hermes Agent."""

if __package__:
    from .hermes_plugin_airlock import register
else:  # Pytest imports a hyphenated plugin root as a top-level ``__init__``.
    from hermes_plugin_airlock import register

__all__ = ["register"]
