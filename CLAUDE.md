# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`mcp-detection-kb` is an MCP (Model Context Protocol) server that exposes a detection engineering knowledge base to Claude. It allows Claude to browse Sigma detection rules, query ATT&CK technique mappings, assess detection coverage, and combine results with Hayabusa log scanning (from the `mcp-hayabusa` module).

## Goals

- Expose Sigma rules as browsable MCP resources
- Expose MITRE ATT&CK technique-to-rule mappings
- Allow Claude to query detection coverage gaps
- Integrate with Hayabusa scanning results from `../mcp-hayabusa`

## Repository Structure

```
rules/       # Sigma detection rules (YAML format)
mappings/    # ATT&CK technique ID → rule mappings (JSON or YAML)
server.py    # MCP server — defines resources and tools
```

## Running the Server

```bash
python server.py
```

The server speaks the MCP protocol over stdio and is intended to be registered with Claude Code via `.claude/settings.json` or `~/.claude/settings.json` under `mcpServers`.

## MCP Server Design (`server.py`)

- **Resources** — static/browsable data exposed to Claude:
  - Sigma rules (one resource per rule file, or a directory listing resource)
  - ATT&CK mappings index
- **Tools** — callable functions Claude can invoke:
  - Query rules by ATT&CK technique ID
  - Check coverage for a technique or tactic
  - Cross-reference Hayabusa scan hits against rules in this KB

## Sigma Rule Format

Rules in `rules/` follow the [Sigma specification](https://sigmahq.io/docs/basics/rules.html). Each YAML file includes `title`, `id`, `status`, `logsource`, `detection`, and `tags` (used for ATT&CK technique IDs in `attack.tXXXX` form).

## ATT&CK Mappings

Files in `mappings/` link ATT&CK technique IDs (e.g., `T1059.001`) to one or more Sigma rule IDs. Used by the coverage query tool to answer "do we have a rule for this technique?"

## Integration with Hayabusa (`../mcp-hayabusa`)

The Hayabusa MCP module scans Windows event logs and returns hits. Tools in this server can accept those hits and map them back to Sigma rule IDs and ATT&CK techniques, enabling end-to-end triage inside a Claude conversation.
