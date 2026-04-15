# security-privacy-skills

A [Claude Code plugin](https://docs.claude.com/en/docs/claude-code/plugins) packaging a collection of security and privacy skills.

## Skills

- **[owasp-ai-risks-and-mitigations-2026](skills/owasp-ai-risks-and-mitigations-2026/SKILL.md)** — Assess and remediate all 21 OWASP GenAI data-security risks (DSGAI 2026). Covers data protection, agent & pipeline security, and governance compliance with tiered mitigations, a 6-step assessment workflow, and regulatory mapping for GDPR, HIPAA, CCPA, the EU AI Act, and the Colorado AI Act.

## Installation

Add this plugin to Claude Code via a marketplace or by pointing at this repository directly:

```
/plugin install SkyflowFoundry/security-privacy-skills
```

Once installed, Claude will invoke the relevant skill automatically when a conversation matches its description. You can also invoke a skill explicitly — for example:

> Run an OWASP GenAI data security assessment on my RAG pipeline.

## Repository layout

```
.
├── .claude-plugin/
│   └── plugin.json         # Plugin manifest
└── skills/
    └── owasp-ai-risks-and-mitigations-2026/
        ├── SKILL.md        # Skill entry point
        └── references/     # Per-risk reference material (DSGAI01–21)
```

## Contributing

New security and privacy skills are welcome. Drop a new skill under `skills/<skill-name>/` with a `SKILL.md` that follows the [Claude Code skill format](https://docs.claude.com/en/docs/claude-code/skills) and open a PR.

## License

[MIT](LICENSE)
