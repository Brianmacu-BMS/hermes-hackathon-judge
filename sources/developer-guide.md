# Build a Hermes Plugin

This guide walks through building a complete Hermes plugin from scratch. By the end you'll have a working plugin with multiple tools, lifecycle hooks, shipped data files, and a bundled skill — everything the plugin system supports.

Not sure which guide you need?

Hermes has several distinct pluggable interfaces — some use Python `register_*` APIs, others are config-driven or drop-in directories. Use this map first:

| If you want to add… | Read |
|---|---|
| Custom tools, hooks, slash commands, skills, or CLI subcommands | **This guide** (the general plugin surface) |
| A **native desktop app** extension (panes, pages, status bar, palette, themes) | [Desktop Plugin SDK](/docs/developer-guide/desktop-plugin-sdk) |
| A **web dashboard** extension (tabs, shell slots, themes) | [Extending the Dashboard](/docs/user-guide/features/extending-the-dashboard) |
| An **LLM / inference backend** (new provider) | [Model Provider Plugins](/docs/developer-guide/model-provider-plugin) |
| A **gateway channel** (Discord/Telegram/IRC/Teams/etc.) | [Adding Platform Adapters](/docs/developer-guide/adding-platform-adapters) |
| A **memory backend** (Honcho/Mem0/Supermemory/etc.) | [Memory Provider Plugins](/docs/developer-guide/memory-provider-plugin) |
| A **context-compression engine** | [Context Engine Plugins](/docs/developer-guide/context-engine-plugin) |
| An **image-generation backend** | [Image Generation Provider Plugins](/docs/developer-guide/image-gen-provider-plugin) |
| A **video-generation backend** | [Video Generation Provider Plugins](/docs/developer-guide/video-gen-provider-plugin) |
| A **web-search / extract backend** | [Web Search Provider Plugins](/docs/developer-guide/web-search-provider-plugin) |
| A **cloud browser backend** (Browserbase-style CDP session provider) | [Browser Provider Plugins](/docs/developer-guide/browser-provider-plugin) |
| A **delegation strategy** (pick a profile or a named model per subagent) | [Delegation Provider Plugins](/docs/developer-guide/delegation-provider-plugin) — `ctx.register_delegation_provider()` |
| A **computer-use driver** (desktop control behind the `computer_use` tool) | Computer-use backend plugins — `ctx.register_computer_use_provider()` |
| A **secret-manager backend** (vault / password manager / OS keystore) | [Secret Source Plugins](/docs/developer-guide/secret-source-plugin) |
| A **dashboard OIDC/auth provider** | [Web Dashboard — custom providers](/docs/user-guide/features/web-dashboard#custom-providers) — `ctx.register_dashboard_auth_provider()` |
| A **TTS backend** (any CLI — Piper, VoxCPM, Kokoro, voice cloning, …) | [TTS custom command providers](/docs/user-guide/features/tts#custom-command-providers) — config-driven, no Python needed |
| An **STT backend** (custom whisper / ASR CLI) | [Voice Message Transcription](/docs/user-guide/features/tts#voice-message-transcription-stt) — set `HERMES_LOCAL_STT_COMMAND` to an argv-tokenized template |
| **External tools via MCP** (filesystem, GitHub, Linear, any MCP server) | [MCP](/docs/user-guide/features/mcp) — declare `mcp_servers.<name>` in `config.yaml` |
| **Gateway event hooks** (fire on startup, session events, commands) | [Event Hooks](/docs/user-guide/features/hooks#gateway-event-hooks) — drop `HOOK.yaml` + `handler.py` into `~/.hermes/hooks/<name>/` |
| **Shell hooks** (run a shell command on events) | [Shell Hooks](/docs/user-guide/features/hooks#shell-hooks) — declare under `hooks:` in `config.yaml` |
| **Additional skill sources** (custom GitHub repos, private skill indexes) | [Skills](/docs/user-guide/features/skills) — `hermes skills tap add <repo>` · [Publishing a tap](/docs/user-guide/features/skills#publishing-a-custom-skill-tap) |
| A first-class **core** inference provider (not a plugin) | [Adding Providers](/docs/developer-guide/adding-providers) |
See the full [Pluggable interfaces table](/docs/user-guide/features/plugins#pluggable-interfaces--where-to-go-for-each) for a consolidated view of every extension surface including config-driven (TTS, STT, MCP, shell hooks) and drop-in directory (gateway hooks) styles.

Third-party-product plugins ship standalone — not into the core tree

Plugins that integrate **someone else's product or project** — observability/metrics backends, vendor SaaS connectors, analytics dashboards, paid-service tie-ins — are built and distributed as **standalone plugin repos**, not merged into `NousResearch/hermes-agent`. Users install them into `~/.hermes/plugins/` or via a pip entry point; everything in this guide works the same way from a standalone repo. This is a coupling-and-maintenance decision (the core moves fast and we don't own your backend), not a quality bar — a plugin can be excellent and still belong in its own repo. Promote it in the Nous Research Discord `#plugins-skills-and-skins` channel. See [CONTRIBUTING.md](https://github.com/NousResearch/hermes-agent/blob/main/CONTRIBUTING.md) for the policy.

Already built in: check here before you hand-roll it

Hermes already ships these for plugin authors:

- **Run the catalog check locally:** `hermes plugins validate /path/to/your-plugin --install-deps` runs the same check catalog CI runs. See [Submitting to the Plugin Catalog](/docs/developer-guide/plugins/catalog-submission).
- **Test your plugin in isolation:** `hermes plugins doctor [path-or-id]` runs the same discovery, manifest parser, `register(ctx)` and registries Hermes uses, with a temporary `HERMES_HOME`. See Validate with Plugin Doctor.
- **Keep state across updates:** `plugin_data_dir()` and `plugin_db()` give your plugin a data directory that survives `hermes plugins update` and `remove` and follows the active profile. See Store durable state.
- **Declare Python dependencies:** list them under `python_dependencies` in `plugin.yaml`, or in a `pyproject.toml` next to it. See Python dependencies.
- **Ship skills with your plugin:** register them with `ctx.register_skill()`. See Bundle skills.
- **Ask for privileged host surfaces:** declare them under `capabilities:` so users get a single consent screen. See Declaring capabilities.
- **Make LLM calls:** use `ctx.llm`, which comes with host-owned credentials and a fail-closed trust gate. See [Plugin LLM Access](/docs/developer-guide/plugin-llm-access).

Hermes can also install and load directory packages that target the Agent Plugins v1.0.0 format. This is a compatibility adapter for the portable components Hermes already owns. It does not replace native `plugin.yaml` plus `register(ctx)` plugins.

```
my-portable-plugin/
├── plugin.json
├── skills/
│   └── summarize/
│       ├── SKILL.md
│       └── references/
└── mcp.json
```

Install and activate a portable package through the normal workflow:

```
hermes plugins install owner/repository --no-enable
hermes plugins list
hermes plugins enable <plugin-name>
```

Portable packages are disabled after installation unless you explicitly enable them. An enabled package may provide immediate `skills/*/SKILL.md` directories and stdio MCP servers from root `mcp.json`. Skills are read-only, namespaced, and loaded through `skills_list` plus `skill_view`. MCP commands are passed as one executable token with a separate argument list, never through a shell. A portable package's skills are named after the plugin, `<plugin-name>:<skill>` (`blender:blender`), the same form as a native plugin's; when two loaded plugins would register the same qualified name, the second one's skill is skipped with a warning naming both. Its data directory, `plugin-data/agent-plugin-<slug>-<hash>`, keeps a name derived from the discovered plugin key so sanitized names cannot collide on disk. A portable package's MCP servers keep the names their `mcp.json` gives them, the same rule as a user's own `mcp_servers` block, so the model-facing `mcp__<server>__<tool>` name keeps the tool verb inside the 64-character provider cap. A duplicate server name is a load-time conflict: a `config.yaml` server wins over a package, and the first-loaded package wins over the next; the loser is skipped with a warning naming both.

Hermes validates `plugin.json`, Agent Skills frontmatter, fixed component locations, `mcp.json`, resolved paths, and symlink containment locally. It does not fetch JSON schemas while loading a package. A bad skill or MCP entry is skipped at its own boundary when valid sibling components can still load. `PLUGIN_ROOT` points to the resolved package root. `PLUGIN_DATA` points to a profile-scoped writable directory managed by Hermes. Values declared in portable MCP `env` are visible package data, not a secret storage mechanism. Do not place credentials in `mcp.json`. To pass a user's variable through to a stdio server (Hermes otherwise hands MCP servers a filtered environment), declare it as `"NAME": "${NAME}"`. The value comes from the user's shell or profile `.env`; when the variable is unset (or empty), the entry is treated as if it weren't there: the server doesn't get the literal `${NAME}`, and `NAME` keeps whatever value the server would have without that line (usually unset). Optional variables are safe to forward.

The current portable subset supports stdio and Streamable HTTP MCP entries. Portable `streamable-http` entries are routed through Hermes' existing native remote MCP client (the same runtime that powers URL-based `mcp_servers` config), with the v1 boundary rules enforced: the URL must be absolute http(s) with no user information or fragment, plain HTTP is accepted only for `localhost`/loopback hosts, and configured headers are never forwarded across a cross-origin redirect. Legacy `sse` entries are reported and skipped. Agent Plugins v1 does not define trust, permissions, provenance, or a sandbox. Enabling a package grants its instructions and local executable the same full-trust posture as other installed Hermes plugins.

A package can ask Hermes to gate one of its MCP servers, the same way a user's `trust: untrusted` does in `config.yaml`. Use it for servers whose tools spend money, trade, send messages or change accounts, so the user approves each write-capable call instead of relying on the skill's instructions alone:

```
{
  "extensions": {
    "com.nousresearch.hermes": {
      "servers": {
        "trade": { "trust": "untrusted" }
      }
    }
  }
}
```

The server name must match an `mcp.json` entry. With `untrusted`, every tool call to that server that is not annotated `readOnlyHint: true` asks the user first (Once, Session or Always, per tool), and fails closed where nobody can answer (cron, unattended runs). The only other accepted value is `full`, the default, so a package can narrow access but never widen it. A `config.yaml` server with the same name replaces the package's entry, including its trust, but keeps the package's declared costs and spend limit (below) unless it sets its own. Other harnesses ignore this extension. `trust` can sit beside `app`, `requires` and `liveness` in the same server entry (see [Application declarations](/docs/developer-guide/plugins/application-declarations)).

A server whose tools spend money or credits can declare what each call costs and a budget per chat. Hermes then names the cost in the approval prompt along with the chat's running total, and a call that would take the chat past `spend_limit` asks first even when the user has made the server trusted:

```
{
  "extensions": {
    "com.nousresearch.hermes": {
      "servers": {
        "renders": {
          "trust": "untrusted",
          "costs": {
            "create_image": 20,
            "animate": { "credits": [5, 20], "note": "per animation" }
          },
          "spend_limit": 100,
          "cost_unit": "credits"
        }
      }
    }
  }
}
```

Keys of `costs` are MCP tool names as the server lists them. A cost is a non-negative number, a `[min, max]` range, or an object with `credits` (number or range) and a short `note`. `spend_limit` is optional (`0` or absent = no limit) and `cost_unit` defaults to `credits`. A malformed table makes the package fail to load with an error naming the key. These map to the native `tool_costs`, `spend_limit` and `cost_unit` keys (see [Tool costs and spend limits](/docs/user-guide/features/mcp#tool-costs-and-spend-limits)). Costs are facts about the server, so they survive a user's same-name `config.yaml` entry (the way a user widens trust) unless that entry sets the key itself; the user's `spend_limit` wins, including `0` to turn it off.

A long-running server can also declare a Hermes-specific tool-call `timeout` (in seconds) in `plugin.json`, without changing other servers' defaults:

```
{
  "extensions": {
    "com.nousresearch.hermes": {
      "servers": { "analysis": { "timeout": 1000 } }
    }
  }
}
```

The value must be a positive finite number within the platform's thread-wait limit. It maps to the native per-server `timeout`; omission preserves the existing `timeouts.mcp.tool_call` fallback. A same-name native `mcp_servers` entry still replaces the entire package entry, including its timeout. This extends the wait budget, not the cancellation or permission policy. Configure any server-internal analysis deadline separately and leave time for its result to reach the client. Other harnesses ignore this extension.

A server entry key this Hermes does not know (one a newer release added) is ignored with a warning, which `hermes plugins validate` lists, and the package still installs. Releases from before this rule reject the package instead, and a release that ignores a key may behave less safely than intended, so declare a new key together with a catalog `requires_hermes` floor. `plugin.json` has no `requires_hermes` field, so that catalog floor is a portable package's only one: an install by catalog name refuses on an older Hermes, and `hermes plugins update` keeps the installed pin until Hermes is updated.

An explicit per-server MCP call budget also reaches Hermes' outer tool executor. A call whose budget exceeds the shared concurrent-batch deadline becomes a sequential barrier, whether called directly or through tool search. It gets its own budget without extending unrelated tools in the same model response. Existing shorter MCP calls retain their normal parallel-admission policy; interruption and approval handling are unchanged.

The [rendered specification](https://agent-plugins.org/specification) currently labels v1.0.0 a Working Draft, while the [versioned specification repository](https://github.com/agentplugins/agent-plugins-spec/blob/main/spec/1.0.0.md) records it as Published. Hermes keys behavior on the canonical v1.0.0 schema identifiers and normative text, not either mutable status label. This is an explicit supported subset, not a claim of full Agent Plugins conformance.

Native `plugin.yaml` plus `register(ctx)` plugins are protected by behavior, not by one global plugin API number. Hermes does not expose a `PLUGIN_API_VERSION`, require a manifest-wide `api:` match, or attach an API version to unrelated values. A plugin that uses a documented behavior should continue to work after a normal Hermes upgrade.

The compatibility rules are:

- **Evolve additively.** Documented `PluginContext` methods are not removed or renamed. New parameters are optional, have defaults, and should be keyword-only. Existing return fields are not removed or silently retyped.
- **Hook payloads are keyword payloads.** New hook data is added as keyword fields, never by changing the meaning or position of an existing field. Hermes inspects callback signatures: a legacy callback receives the fields it declares, while a callback with `**kwargs` receives the complete current payload. New plugins should accept `**kwargs` so they can opt into additive data without another signature change.
- **Manifests are open to additions.** Unknown `plugin.yaml` fields are ignored. Older Hermes releases can therefore load a plugin whose manifest contains metadata introduced by a newer release, provided the plugin code itself uses supported runtime behavior.
- **Provider interfaces grow through defaults.** New provider methods have a default implementation. New callback context is optional and forwarded only when signature inspection shows that a provider accepts it. Adding an abstract method or an unconditionally forwarded argument requires a migration window rather than a flag-day signature change.
- **Version the contract that crosses a boundary.** A capability may carry its own schema version when it defines a wire payload or persisted format (for example, observer payloads or secret-source state). Keep fields additive within that local schema. Persisted plugin state and config must remain readable, or ship an explicit migration; resumed sessions written by the old format must still replay. Do not add version literals to unrelated callback or context values.
The contract covers documented surfaces only. Replacing or wrapping core functions, methods, module attributes or private tables at runtime (assigning `AIAgent.<method>`, `setattr` on a Hermes module, writing into `sys.modules` or a core dict) is not a supported extension point. It breaks whenever the internals move, and it collides with every other plugin patching the same seam. The plugin catalog refuses it at admission (`hermes plugins validate`, `no core override` check). If a public hook you need is missing, open an issue describing it.

A documented native plugin behavior may be deprecated only with all of the following:

1. a replacement and migration instructions in the plugin guide and release notes;
2. a warning emitted at most once per process, naming the replacement and the earliest removal release;
3. support for the old behavior through at least two subsequent minor releases; and
4. behavior-based compatibility coverage for both the legacy path and the replacement throughout that window.
Removal after the window must include any migration needed for persisted data or resumable sessions. In practice, additive aliases and adapters are preferred to removal.

Hermes enforces this contract with frozen external-plugin fixtures discovered from an isolated `HERMES_HOME`. Those tests load and invoke the plugin through `PluginManager`; they assert real registration and callback outcomes rather than internal symbol lists or source-code shape.

Hermes's internals were split into `<stem>_<topic>` sibling modules in Sep 2026 (PR #102117). **Internal import paths were never part of the plugin contract** above. A temporary compatibility layer kept the old paths resolving until 2026-09-14; it has been removed, so a plugin that still imports an old path fails to load with an `ImportError` (the reason shows in `hermes plugins list`).

To fix such a plugin, import the name from the module that defines it now, or better, use `ctx` and the documented ABCs instead of internals. The full old-to-new map is the [`COMPAT_MANIFEST.md`](https://github.com/NousResearch/hermes-agent/blob/5912ed81ed9/COMPAT_MANIFEST.md) from the last commit that shipped the layer.

A **calculator** plugin with two tools:

- `calculate` — evaluate math expressions (`2**16`, `sqrt(144)`, `pi * 5**2`)
- `unit_convert` — convert between units (`100 F → 37.78 C`, `5 km → 3.11 mi`)
Plus a hook that logs every tool call, and a bundled skill file.

Create a directory and continue with Step 2:

```
mkdir -p ~/.hermes/plugins/calculator
cd ~/.hermes/plugins/calculator
```

`hermes plugins doctor [path-or-id]` runs the same directory discovery, manifest parser, namespaced import, `register(ctx)`, hook registry, and tool registry used by Hermes itself. It reports invalid hook names, callbacks that do not accept `**kwargs`, registration failures, and drift between declared and registered tools/hooks. For a package with a `desktop/plugin.js`, it also warns when the Desktop app is running a stale copy of it (see [Developing a unified package](/docs/developer-guide/desktop-plugin-sdk#developing-a-unified-package)). Pass `--ci` to exit non-zero on an error:

```
hermes plugins doctor . --ci
```

Doctor uses a temporary `HERMES_HOME`, restores plugin registration state after the check, and blocks direct Python socket connections to catch accidental network access while registration runs. This is not a sandbox: plugin code still executes in-process with the current user's permissions and can spawn subprocesses, so only run Doctor on code you trust enough to import.

Create `plugin.yaml`:

```
name: calculator
version: 1.0.0
description: Math calculator — evaluate expressions and convert units
provides_tools:
  - calculate
  - unit_convert
provides_hooks:
  - post_tool_call
```

This tells Hermes: "I'm a plugin called calculator, I provide tools and hooks." The `provides_tools` and `provides_hooks` fields are lists of what the plugin registers.

List every tool your `register()` registers in `provides_tools`. The field does **not** decide whether a user-installed plugin's tools load: once the plugin is enabled, everything `register()` registers is available, declared or not. What it does drive:

- **`hermes plugins validate`**: the "declared tools" check fails when the registered tools don't match the list, which blocks catalog admission.
- **Catalog listing**: the "N tools" chips and tool-name search in the catalog and the dashboard/Desktop Plugins page.
- **Dashboard auth hint**: only declared tools' availability checks are used to show "needs auth" and the `hermes auth <name>` command.
- **Bundled `kind: platform` plugins only**: the field is the switch that loads `tools.py` in CLI/TUI sessions while the adapter stays deferred. See [Outbound client tools](/docs/developer-guide/adding-platform-adapters#outbound-client-tools-provides_tools).
Optional fields you could add:

```
author: Your Name
requires_env:          # gate loading on env vars; prompted during install
  - SOME_API_KEY       # simple format — plugin disabled if missing
  - name: OTHER_KEY    # rich format — shows description/url during install
    description: "Key for the Other service"
    url: "https://other.com/keys"
    secret: true
capabilities:          # privileged host surfaces you request (consent flow)
  - tools.override     # replace built-in tools (needs user consent)
  - llm.model_override # choose the model for host-owned LLM calls
```

If your plugin needs a privileged host surface — overriding a built-in tool, picking the model for `ctx.llm` calls, etc. — declare it in `capabilities:`. At install/enable time the user sees the list and consents once; if a later version adds a capability, the update flow asks again for just the addition. Undeclared or unconsented capabilities are simply off (fail closed), so **probe before using them and degrade gracefully**:

```
def register(ctx):
    if ctx.has_capability("tools.override"):
        ctx.register_tool(..., override=True)
    else:
        ctx.register_tool(...)   # register under a non-conflicting name
```

Known capability ids: `tools.override`, `llm.provider_override`, `llm.model_override`, `llm.agent_id_override`, `llm.profile_override`, `llm.task_override`, `llm.side_question` (ask the session's own agent after a turn, see [Plugin LLM Access](/docs/developer-guide/plugin-llm-access#asking-the-sessions-own-agent-ctxside_question)), `gateway.platform_actions` (see `hermes_cli/plugin_capabilities.py` for the canonical registry). Unknown ids are ignored. The older per-capability config keys (`plugins.entries.<id>.allow_tool_override`, …) still work but are deprecated — declare capabilities instead so users get a single, auditable consent screen. Capabilities are consent + audit, **not a sandbox**: they gate host API surfaces, nothing more.

**Pip-distributed plugins** have no `plugin.yaml` directory once installed, so declare capabilities in distribution metadata instead, via the companion `hermes_agent.plugin_capabilities` entry-point group. Each declaration is named `<plugin-id>.<capability-id>` and points at the same object as your `hermes_agent.plugins` entry point:

```
[project.entry-points."hermes_agent.plugins"]
calculator = "my_pkg:register"

[project.entry-points."hermes_agent.plugin_capabilities"]
"calculator.tools.override" = "my_pkg:register"
```

Hermes reads these from installed metadata without importing your code, so `hermes plugins capabilities` and the consent flow stay accurate for pip installs.

A plugin that needs the user's ChatGPT / Codex subscription (minting an OpenAI Realtime client secret, calling a Codex backend endpoint) must **not** read, refresh or rewrite `~/.codex/auth.json` or Hermes's `auth.json`. Codex refresh tokens are single-use: a plugin that refreshes on its own races Hermes's locked refresh, and the loser's rotation chain gets revoked, signing the user out. Ask Hermes to make the request instead. Hermes resolves the credential through its own refresh path, attaches `Authorization` itself and returns only the response. Your code never sees the token.

Declare the sign-in in `plugin.yaml`:

```
name: live-voice
requires_auth:
  - openai-codex
```

Then call the public helper. It is a plain function, so dashboard plugins (`dashboard/plugin_api.py`) and vendored modules can import it as well as `register(ctx)` code:

```
from hermes_cli.plugin_provider_requests import ProviderNotSignedIn, credentialed_provider_request

def mint_client_secret(session: dict) -> dict:
    try:
        resp = credentialed_provider_request(
            "openai-codex", "POST", "https://api.openai.com/v1/realtime/client_secrets",
            json={"session": session}, timeout=15)
    except ProviderNotSignedIn as exc:
        return {"ok": False, "error": str(exc)}  # tells the user how to sign in
    if resp.status != 200:
        return {"ok": False, "error": f"client secret failed ({resp.status}): {resp.text[:300]}"}
    return {"ok": True, **resp.json()}
```

This replaces a hand-rolled helper that read `~/.codex/auth.json`, POSTed to `auth.openai.com/oauth/token` when the token was near expiry and wrote the result back. Delete that code; there is no refresh step left for the plugin.

`credentialed_provider_request(provider, method, url, *, json=None, headers=None, timeout=30.0)` returns a `ProviderResponse` (`status`, `headers`, `body`, `.text`, `.json()`). The rules:

- **Declared plugins only.** The caller is the plugin whose file is on the call stack. Hermes finds it under the plugins directory and reads its `plugin.yaml`. A plugin that does not list the provider in `requires_auth`, and code outside any installed plugin, gets `PermissionError`. Call the helper from your own function. Handing the bare helper to `run_in_executor` leaves no plugin frame on the stack, so the call is refused.
- **Provider origins only.** For `openai-codex` the token is sent only to `https://chatgpt.com` and `https://api.openai.com`. Any other URL raises `PermissionError` before a request is made. A profile whose Codex credential routes to a custom gateway is refused too, because that key belongs to the gateway.
- **No redirects.** A 3xx response comes back as-is and is never followed, so the header cannot reach a third host.
- **Profile-scoped.** The credential is the active profile's Codex sign-in, the same one chat uses (`hermes auth add openai-codex`, or the Codex sign-in in the desktop app). When there is none you get `ProviderNotSignedIn`, whose message names the sign-in command.
- Your own `headers` are sent too, except any that would replace the `Authorization` (or account) headers Hermes attaches.
`requires_auth` appears in `hermes plugins show <name>` and at install time, and a catalog re-pin that adds it asks the user before updating. Like capabilities, this is consent and visibility. It is **not a sandbox**: in-process plugin code can still read any file the user can, and reviewers reject plugins that do.

**Usage panels:** don't call the usage endpoints yourself. Use `agent.account_usage.fetch_account_usage("openai-codex", read_only=True)`. It returns an `AccountUsageSnapshot` (plan, session/weekly windows with `used_percent` and `reset_at`) and never refreshes or rotates a credential. **Sign-out** belongs to Hermes, not to a plugin: point users at `hermes auth logout openai-codex` instead of deleting credential files.

A plugin that calls a third-party API with the user's own OAuth client (a Google Cloud "Desktop app" client, for example) does not run the consent flow, store the refresh token or refresh it. Declare the client and Hermes owns the grant:

```
name: gemini-voice
requires_env:
  - name: GEMINI_VOICE_CLIENT_ID
  - name: GEMINI_VOICE_CLIENT_SECRET
    secret: true
oauth:
  - id: google
    authorize_url: https://accounts.google.com/o/oauth2/v2/auth
    token_url: https://oauth2.googleapis.com/token
    scopes:
      - https://www.googleapis.com/auth/calendar.events.owned
      - https://www.googleapis.com/auth/documents
    client_id_env: GEMINI_VOICE_CLIENT_ID
    client_secret_env: GEMINI_VOICE_CLIENT_SECRET  # optional: a public PKCE client has none
    hosts: [www.googleapis.com, docs.googleapis.com]
    authorize_params: {access_type: offline, prompt: consent}  # Google issues a refresh token only with these
```

The user signs in once from a terminal with `hermes auth add gemini-voice:google` (the plugin's key, a colon, the entry's `id`). That is the same PKCE login the model-provider helper runs: a loopback redirect on `127.0.0.1`, with an SSH tunnel hint when Hermes runs on a remote host. If the IdP grants fewer scopes than declared, nothing is saved. `hermes auth status|refresh|logout gemini-voice:google` show, refresh and remove the grant. It lives in the active profile's `auth.json`; Hermes refreshes it on use once less than two minutes remain and never starts a sign-in under the gateway or cron.

The plugin calls the API through the same helper, with the entry's `id` as the provider:

```
from hermes_cli.auth_constants import AuthError
from hermes_cli.plugin_provider_requests import ProviderNotSignedIn, credentialed_provider_request

def create_document(title: str) -> dict:
    try:
        resp = credentialed_provider_request(
            "google", "POST", "https://docs.googleapis.com/v1/documents", json={"title": title}, timeout=20)
    except ProviderNotSignedIn as exc:
        return {"ok": False, "error": str(exc)}  # names `hermes auth add gemini-voice:google`
    except AuthError as exc:
        return {"ok": False, "error": f"{exc.code}: {exc}"}
    return {"ok": resp.status < 300, "status": resp.status, "body": resp.json()}
```

The Codex rules above apply, plus:

- **HTTPS only.** `authorize_url`, `token_url` and every `hosts` entry are `https` (there is no loopback exception); `hermes plugins validate` and catalog admission fail anything else.
- **Declared hosts only.** The bearer goes to `https://<host>` (port 443) for the entry's `hosts`, matched exactly (no subdomains). Any other URL, `http`, or a URL with user info raises `PermissionError` before a request is made. A host outside the sign-in provider's domains is a warning reviewers check.
- **Your own client variables.** `client_id_env` and `client_secret_env` name the plugin's own variables; a variable Hermes itself uses (a provider API key, a platform token) is refused, since Hermes sends these to `token_url`.
- **The plugin's own grant.** The grant is stored under the calling plugin's key, so another plugin declaring the same `id` cannot use it, and the plugin's own entry wins over a Hermes sign-in of the same name.
- **The grant follows the declaration.** It remembers the entry it was made for: a plugin version that changes the token URL, hosts, scopes or client variables gets `ProviderNotSignedIn` until the user signs in again, and a catalog re-pin that adds an `oauth` entry or changes its authorize host, token host, hosts or scopes asks before updating.
- **Errors.** `ProviderNotSignedIn`: not signed in, revoked, or the entry changed since sign-in. `AuthError` codes: `oauth_client_id_missing` and `oauth_client_secret_missing` (the variable is not set), `invalid_client`, `unauthorized_client` and `invalid_scope` (the IdP rejected the client; the user has to fix it), `oauth_refresh_failed` (network or server error; try later). A revoked grant (`invalid_grant`) is retired: nothing goes to the network until the next sign-in. Errors reach the plugin without a traceback, chain or request object, so none leads back to the token, refresh token or client secret.
- **Sign-in and removal.** `hermes auth add` prints which hosts get the code, the client secret and the token before opening the browser, and refuses to run from the gateway, cron or an agent session. `hermes plugins remove` drops the plugin's grants, and `hermes auth logout <plugin>:<id>` still works after the plugin is gone.
`hermes plugins validate` checks the `oauth:` block and that its client variables are declared, and warns when plugin code names the token URL. Like `requires_auth`, this is consent and visibility, not a sandbox.

`plugin.yaml` also supports an additive **v2 schema** (#64165). Every field is optional; a manifest without `manifest_version` is a v1 manifest and stays fully supported forever. Unknown fields never break loading — they are ignored with a warning (forward compatibility), and a `manifest_version` newer than this Hermes understands still loads with a warning.

| Field | Type | Meaning |
|---|---|---|
| `manifest_version` | int | Manifest **file-format** version. Absent = `1`. Current max: `2`. Independent from `api_version`. |
| `api_version` | int | Runtime **plugin API generation** the plugin targets (ctx surface / hook signatures). Deliberately a separate axis from `manifest_version` — an `api_version: 1` plugin can use a v2 manifest. |
| `requires_plugins` | list | Inter-plugin dependencies: `- id: other-plugin` with optional `version_range: ">=1.0,<2"`. **Advisory**: a missing dependency logs a clear warning but the plugin still loads — probe at runtime with `ctx.has_plugin("other-plugin")`. Load **order** honors these edges: when A requires B, B's `register()` runs before A's (topological sort, alphabetical tiebreak; cycles warn and fall back to alphabetical order). |
| `python_dependencies` | list of str | Declared Python requirements (e.g. `"requests>=2.0,<3"`). Installation requests consent; enabling admits the candidate through PM with the existing core, extras, and enabled-plugin union. Successful preparation publishes the environment and configuration transactionally; failure preserves the previous selection and enabled set. Declining leaves the installed plugin disabled. Pin upper bounds. |
| `python_runtime` | str | `external` — the plugin manages its own interpreter/venv (sidecar pattern); Hermes installs nothing and leaves any `pyproject.toml` alone. |
| `config_schema` | mapping | JSON-schema-ish description of keys under `plugins.entries.<id>.settings`: `api_url: {type: str, default: "", description: "...", required: false}`. Validated at load; mismatches log actionable warnings naming the key and expected type — never load failures. Types: `str`, `int`, `float`, `bool`, `list`, `dict` (plus JSON-schema aliases) and `secret`. Also drives the settings form in the Desktop Plugins tab — see Settings form in the Desktop. |
| `license` | str | SPDX-style license id (e.g. `MIT`). |
| `homepage` | str | Project URL. |
| `tags` | list of str | Free-form discovery tags (e.g. `[gateway, telegram]`). |
| `provides_locales` | list | Language pack declaration: ids (`- pl`) or `{id, endonym, rtl}` mappings whose `locales/<id>[.tui|.desktop].yaml` the loader registers automatically — see Ship a language pack. |
| `requires_auth` | list of str | Providers whose sign-in the plugin uses through Hermes (today: `openai-codex`). Required by `credentialed_provider_request`; shown at install and in `hermes plugins show`. See Use the user's Codex sign-in. |
| `oauth` | list of mappings | OAuth clients the plugin uses through Hermes: `id`, `authorize_url`, `token_url`, `scopes`, `client_id_env`, optional `client_secret_env`, `hosts`, optional `authorize_params`. Signed in with `hermes auth add <plugin>:<id>`, used through `credentialed_provider_request`. See Use your own OAuth client. |

```
# plugin.yaml — manifest v2 example
name: my-plugin
version: 1.2.0
manifest_version: 2
api_version: 1
license: MIT
homepage: https://github.com/owner/my-plugin
tags: [gateway, demo]
requires_plugins:
  - id: other-plugin
    version_range: ">=1.0,<2"
python_dependencies:
  - "somepkg>=1.0,<2"     # consent before PM admission
config_schema:
  api_url: {type: str, default: "", description: "Service endpoint"}
```

Shared dependency admission

Plugin installation requests Python dependency consent. Enabling the plugin prepares its requirements with core dependencies, extras, and enabled plugins through PM. Pack enables use the same admission transaction. Reinstalling an active plugin requests consent against its staged declaration before publication. A refusal preserves the installed plugin and selected environment.

The installer and PM admission reject unsupported `manifest_version` values and unmet `requires_hermes` constraints before publication.

A directory plugin can bring its own PyPI packages. Declare them either in the manifest (`python_dependencies`, above) or, preferably, in a `pyproject.toml` next to `plugin.yaml`:

```
[project]
name = "my-plugin"
version = "1.0.0"
requires-python = ">=3.11"
dependencies = [
    "somepkg>=1.0,<2",
    "other[extra]>=3.11",
]
```

When both exist the `pyproject.toml` wins. What Hermes does with them:

- **Install / enable** — PM resolves core, selected extras, and the enabled plugin union across every profile sharing the dependency home, including custom `HERMES_HOME` roots. A new plugin is downloaded disabled; Python dependency consent precedes enablement. `pyproject.toml` takes precedence over `python_dependencies` and legacy `pip_dependencies`.
- **Atomic publication** — PM prepares a fresh environment generation before publishing an enablement or an active plugin replacement. Resolution, download, or build failure preserves the previous environment and plugin selection; no existing plugin is sacrificed.
- **Updates retain the union** — `hermes update` includes enabled plugins while preparing its new generation. There is no post-update pip reinstall. `hermes plugins update` prepares active replacements before swapping their code and dependency generation together.
- **Requirement hygiene** — malformed PEP 508 requirements are refused. Environment markers remain intact for the target interpreter to evaluate. `hermes-agent` self-dependencies are omitted because the checkout supplies Hermes. Direct-URL requirements are not managed; use a plugin-owned external runtime for them.
- **`--no-deps`** downloads a new plugin without dependency consent and leaves it disabled, even with `--enable`. It cannot bypass PM admission when replacing an active plugin.
- **`--yes-deps`** answers the dependency question up front, so a headless install (CI, SSH automation, a container entrypoint) prepares the declared dependencies instead of being refused. It is mutually exclusive with `--no-deps`.
- **A `pyproject.toml` that installs nothing** (`dependencies = []`, no `[build-system]`, extras or dependency groups) counts as no declaration: no dependency question, and enabling or updating the plugin leaves the dependency environment as it is.
- **`python_runtime: external`** keeps a sidecar's dependencies out of the shared union. Hermes does not install that Python runtime or modify its declaration.
- **Nothing to load is an error** — `hermes plugins validate` rejects `plugin.yaml` without `__init__.py`, `desktop/plugin.js`, or `plugin.json` beside it. Pip-layout packages need a directory-plugin wrapper.
- `security.allow_lazy_installs: false` blocks on-demand acquisition. Explicit dependency consent and explicit enablement authorize PM preparation; discovery never installs.
`HERMES_HOME/plugins/` survives `hermes update` and Desktop updates: the updater only rebuilds the venv and the checkout, never the home directory.

Hermes checks the age of **its own** dependencies when it locks them: the checkout's `[tool.uv] exclude-newer = "3 days"` keeps any release younger than three days out of `uv.lock`, so a hijacked upload has time to be caught upstream before it reaches users. Users install from that vetted lock; their machines never re-check dates. **The check does not apply to your plugin's dependencies.** When Hermes resolves your plugin into its environment, Hermes's exact pins stay put, other packages Hermes uses may move within the ranges Hermes declares, and everything else follows your requirements, so a plugin can floor on a release published yesterday and install today. The plugin's author, not Hermes, is responsible for what that pulls in. A plugin that requires a different version of a package Hermes pins exactly fails to install until Hermes's pin moves.

Set your own policy and hold yourself to it. Strongly recommended:

- **Upper bounds on every dependency** — `>=floor,<next_major` for stable packages, `>=0.29,<0.32` for pre-1.0 ones. A bare `>=X.Y` adopts every future release unreviewed.
- **Floor on the oldest API-compatible version**, not the release of the week. A floor on a fresh wheel forces every installer onto it the day it appears; `>=old,!=broken,<next` keeps the wide range and skips the one bad release.
- **Adopt a release-age check of your own**: wait a few days before floors move to a new release, and resolve with `uv --exclude-newer "3 days"` (or `UV_EXCLUDE_NEWER`) in your own CI so the lock you test is the one users get.
- **Pin your lock, review your bumps.** Treat a dependency bump as a code change: read the upstream diff, then re-pin.
The plugin catalog review reads your dependency list at the pinned SHA (`plugin.yaml` or `pyproject.toml`) and flags bare floors and missing bounds; an entry is not held for a floor that is merely recent.

Create `schemas.py` — this is what the LLM reads to decide when to call your tools:

```
"""Tool schemas — what the LLM sees."""

CALCULATE = {
    "name": "calculate",
    "description": (
        "Evaluate a mathematical expression and return the result. "
        "Supports arithmetic (+, -, *, /, **), functions (sqrt, sin, cos, "
        "log, abs, round, floor, ceil), and constants (pi, e). "
        "Use this for any math the user asks about."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "expression": {
                "type": "string",
                "description": "Math expression to evaluate (e.g., '2**10', 'sqrt(144)')",
            },
        },
        "required": ["expression"],
    },
}

UNIT_CONVERT = {
    "name": "unit_convert",
    "description": (
        "Convert a value between units. Supports length (m, km, mi, ft, in), "
        "weight (kg, lb, oz, g), temperature (C, F, K), data (B, KB, MB, GB, TB), "
        "and time (s, min, hr, day)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "value": {
                "type": "number",
                "description": "The numeric value to convert",
            },
            "from_unit": {
                "type": "string",
                "description": "Source unit (e.g., 'km', 'lb', 'F', 'GB')",
            },
            "to_unit": {
                "type": "string",
                "description": "Target unit (e.g., 'mi', 'kg', 'C', 'MB')",
            },
        },
        "required": ["value", "from_unit", "to_unit"],
    },
}
```

**Why schemas matter:** The `description` field is how the LLM decides when to use your tool. Be specific about what it does and when to use it. The `parameters` define what arguments the LLM passes.

Create `tools.py` — this is the code that actually executes when the LLM calls your tools:

```
"""Tool handlers — the code that runs when the LLM calls each tool."""

import json
import math

# Safe globals for expression evaluation — no file/network access
_SAFE_MATH = {
    "abs": abs, "round": round, "min": min, "max": max,
    "pow": pow, "sqrt": math.sqrt, "sin": math.sin, "cos": math.cos,
    "tan": math.tan, "log": math.log, "log2": math.log2, "log10": math.log10,
    "floor": math.floor, "ceil": math.ceil,
    "pi": math.pi, "e": math.e,
    "factorial": math.factorial,
}


def calculate(args: dict, **kwargs) -> str:
    """Evaluate a math expression safely.

    Rules for handlers:
    1. Receive args (dict) — the parameters the LLM passed
    2. Do the work
    3. Return a JSON string — ALWAYS, even on error
    4. Accept **kwargs for forward compatibility
    """
    expression = args.get("expression", "").strip()
    if not expression:
        return json.dumps({"error": "No expression provided"})

    try:
        result = eval(expression, {"__builtins__": {}}, _SAFE_MATH)
        return json.dumps({"expression": expression, "result": result})
    except ZeroDivisionError:
        return json.dumps({"expression": expression, "error": "Division by zero"})
    except Exception as e:
        return json.dumps({"expression": expression, "error": f"Invalid: {e}"})


# Conversion tables — values are in base units
_LENGTH = {"m": 1, "km": 1000, "mi": 1609.34, "ft": 0.3048, "in": 0.0254, "cm": 0.01}
_WEIGHT = {"kg": 1, "g": 0.001, "lb": 0.453592, "oz": 0.0283495}
_DATA = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
_TIME = {"s": 1, "ms": 0.001, "min": 60, "hr": 3600, "day": 86400}


def _convert_temp(value, from_u, to_u):
    # Normalize to Celsius
    c = {"F": (value - 32) * 5/9, "K": value - 273.15}.get(from_u, value)
    # Convert to target
    return {"F": c * 9/5 + 32, "K": c + 273.15}.get(to_u, c)


def unit_convert(args: dict, **kwargs) -> str:
    """Convert between units."""
    value = args.get("value")
    from_unit = args.get("from_unit", "").strip()
    to_unit = args.get("to_unit", "").strip()

    if value is None or not from_unit or not to_unit:
        return json.dumps({"error": "Need value, from_unit, and to_unit"})

    try:
        # Temperature
        if from_unit.upper() in {"C","F","K"} and to_unit.upper() in {"C","F","K"}:
            result = _convert_temp(float(value), from_unit.upper(), to_unit.upper())
            return json.dumps({"input": f"{value} {from_unit}", "result": round(result, 4),
                             "output": f"{round(result, 4)} {to_unit}"})

        # Ratio-based conversions
        for table in (_LENGTH, _WEIGHT, _DATA, _TIME):
            lc = {k.lower(): v for k, v in table.items()}
            if from_unit.lower() in lc and to_unit.lower() in lc:
                result = float(value) * lc[from_unit.lower()] / lc[to_unit.lower()]
                return json.dumps({"input": f"{value} {from_unit}",
                                 "result": round(result, 6),
                                 "output": f"{round(result, 6)} {to_unit}"})

        return json.dumps({"error": f"Cannot convert {from_unit} → {to_unit}"})
    except Exception as e:
        return json.dumps({"error": f"Conversion failed: {e}"})
```

**Key rules for handlers:**

1. **Signature:** `def my_handler(args: dict, **kwargs) -> str`
2. **Return:** Always a JSON string. Success and errors alike.
3. **Never raise:** Catch all exceptions, return error JSON instead.
4. **Accept `**kwargs`:** Hermes injects context keywords (`task_id`, `session_id`, `user_task`, `parent_agent`, ...) and only forwards the ones your signature names, so `def handler(args)` works; `**kwargs` is how you opt into the full, additively growing context.
Create `__init__.py` — this wires schemas to handlers:

```
"""Calculator plugin — registration."""

import logging

from . import schemas, tools

logger = logging.getLogger(__name__)

# Track tool usage via hooks
_call_log = []

def _on_post_tool_call(tool_name, args, result, task_id, **kwargs):
    """Hook: runs after every tool call (not just ours)."""
    _call_log.append({"tool": tool_name, "session": task_id})
    if len(_call_log) > 100:
        _call_log.pop(0)
    logger.debug("Tool called: %s (session %s)", tool_name, task_id)


def register(ctx):
    """Wire schemas to handlers and register hooks."""
    ctx.register_tool(name="calculate",    toolset="calculator",
                      schema=schemas.CALCULATE,    handler=tools.calculate)
    ctx.register_tool(name="unit_convert", toolset="calculator",
                      schema=schemas.UNIT_CONVERT, handler=tools.unit_convert)

    # This hook fires for ALL tool calls, not just ours
    ctx.register_hook("post_tool_call", _on_post_tool_call)
```

**What `register()` does:**

- Called exactly once at startup
- `ctx.register_tool()` puts your tool in the registry — the model sees it immediately
- `ctx.register_hook()` subscribes to lifecycle events
- `ctx.register_cli_command()` registers a CLI subcommand (e.g. `hermes my-plugin <subcommand>`)
- `ctx.register_command()` registers an in-session slash command (e.g. `/myplugin <args>` inside CLI / gateway chat) — see Register slash commands below
- `ctx.dispatch_tool(name, arguments)` — call any other tool (built-in or from another plugin) with the parent agent's context (approvals, credentials, task_id) wired up automatically. Useful from slash-command handlers that need to invoke `terminal`, `read_file`, or any other tool as if the model had called it directly.
- `ctx.get_config()` / `ctx.set_config()` access only this plugin's settings namespace; `ctx.state` stores plugin-owned runtime data under the active profile.
- If this function crashes, the plugin is disabled but Hermes continues fine
**`dispatch_tool` example — a slash command that runs a tool:**

```
def handle_scan(ctx, raw_args: str):
    """Implement /scan by invoking the terminal tool through the registry."""
   

..._This content has been truncated to stay below 50000 characters_...