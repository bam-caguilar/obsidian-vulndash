# Copilot Instructions

## Project Identity

This repository is a production-grade TypeScript Obsidian plugin for vulnerability intelligence, SBOM analysis, vulnerability feed synchronization, triage, reporting, and project-level security visibility.

The codebase must be treated as a DDD-oriented, Clean Architecture codebase with clear boundaries, explicit naming, and single-responsibility modules.

Copilot must prioritize:

- Clear architectural boundaries
- Explicit names
- Low ambiguity
- Single responsibility
- Testable domain and application logic
- Thin UI and infrastructure adapters
- No vague shared modules
- No layer leakage
- Secure rendering and defensive parsing
- Performance-aware data processing

This project should evolve like a maintainable security product, not a collection of scripts.

---

# Core Architecture Rules

## Dependency Direction

The intended dependency flow is:

```text
presentation -> application -> domain
infrastructure -> application/domain
```

The domain layer must not depend on application, infrastructure, presentation, Obsidian APIs, browser APIs, IndexedDB APIs, request clients, or UI rendering code.

The application layer may depend on domain abstractions and coordinate use cases, but must not contain Obsidian UI logic or low-level HTTP/storage details.

The infrastructure layer implements technical details such as feed clients, persistence, IndexedDB access, HTTP adapters, file parsing, external API mappers, and worker adapters.

The presentation layer handles Obsidian views, settings tabs, modals, DOM rendering, user actions, and UI orchestration. It must remain thin.

---

# Expected Folder Responsibilities

## `src/domain/`

The domain layer contains the business concepts and rules of the vulnerability dashboard.

Allowed in `src/domain/`:

* Entities
* Value objects
* Domain models
* Domain events
* Domain policies
* Domain enums
* Domain-specific interfaces/ports
* Domain validation rules
* Pure domain services when behavior does not naturally belong to one entity

Examples:

```text
src/domain/vulnerabilities/
src/domain/components/
src/domain/sbom/
src/domain/feeds/
src/domain/projects/
src/domain/triage/
src/domain/remediation/
src/domain/value-objects/
src/domain/interfaces/
```

Domain code must be pure TypeScript whenever possible.

Domain code must not:

* Import from `obsidian`
* Access the DOM
* Call `requestUrl`, `fetch`, IndexedDB, localStorage, or filesystem APIs
* Render markdown or HTML
* Know about settings tabs, views, modals, notices, or CSS classes
* Know about external API payload shapes unless represented by explicit domain models

Good domain names:

* `Vulnerability`
* `AffectedPackage`
* `PackageUrl`
* `Severity`
* `CvssScore`
* `VulnerabilityRange`
* `UpgradePathResolution`
* `TriageState`
* `ProjectInventory`
* `FeedSyncCheckpoint`

Suspicious domain names:

* `DataHelper`
* `CommonUtils`
* `Processor`
* `Manager`
* `ParserService`
* `AppService`

---

## `src/application/`

The application layer contains use cases and orchestration logic.

Allowed in `src/application/`:

* Use cases
* Application services that coordinate use cases
* Command/query models
* Application DTOs
* Workflow coordination
* Transaction-like orchestration
* Ports required by use cases
* Application-level result objects
* Application errors

Examples:

```text
src/application/vulnerabilities/SyncVulnerabilitiesUseCase.ts
src/application/sbom/ImportSbomUseCase.ts
src/application/projects/AssignSbomProjectUseCase.ts
src/application/reports/GenerateProjectBriefingUseCase.ts
src/application/triage/UpdateTriageStateUseCase.ts
```

Application code may coordinate:

* Domain models
* Repositories
* Feed clients via interfaces
* Checkpoint stores
* Importers
* Mappers
* Render request models

Application code must not:

* Build DOM nodes
* Directly call Obsidian APIs
* Contain CSS class names
* Directly access IndexedDB
* Directly parse external HTTP responses unless delegated to infrastructure
* Contain hardcoded UI text unrelated to use-case results

Preferred naming:

* `SyncVulnerabilitiesUseCase`
* `ImportSbomUseCase`
* `GenerateDailyBriefingUseCase`
* `CompareProjectVersionsUseCase`
* `ResolveAffectedComponentsUseCase`
* `UpdateFeedSyncCheckpointUseCase`

Avoid:

* `VulnerabilityService`
* `SyncManager`
* `DataProcessor`
* `ReportHelper`

Use `UseCase` when the class represents an application action.

---

## `src/infrastructure/`

The infrastructure layer contains implementation details for external systems and technical adapters.

Allowed in `src/infrastructure/`:

* HTTP clients
* Feed clients
* Obsidian request adapters
* IndexedDB repositories
* Cache implementations
* Parser implementations
* External API mappers
* File readers
* Worker adapters
* Persistence stores
* Serialization/deserialization
* Retry and rate-limit handling
* Source-specific normalization logic before mapping into domain/application models

Examples:

```text
src/infrastructure/http/ObsidianHttpClient.ts
src/infrastructure/feeds/nvd/NvdClient.ts
src/infrastructure/feeds/github/GitHubAdvisoryClient.ts
src/infrastructure/feeds/osv/OsvClient.ts
src/infrastructure/persistence/indexeddb/VulnCacheDb.ts
src/infrastructure/persistence/FeedSyncCheckpointIndexedDbStore.ts
src/infrastructure/sbom/CycloneDxSbomParser.ts
src/infrastructure/sbom/SpdxSbomParser.ts
src/infrastructure/mappers/OsvVulnerabilityMapper.ts
src/infrastructure/mappers/NvdVulnerabilityMapper.ts
```

Infrastructure code may depend on domain/application contracts.

Infrastructure code must not:

* Contain presentation rendering logic
* Create Obsidian views or modals
* Decide UI state
* Store domain rules that belong in `src/domain`
* Contain generic catch-all helpers

External API payload types should be isolated here unless they are stable domain concepts.

Good infrastructure names:

* `NvdClient`
* `GitHubAdvisoryClient`
* `OsvClient`
* `CycloneDxSbomParser`
* `SpdxSbomParser`
* `IndexedDbVulnerabilityRepository`
* `FeedSyncCheckpointStore`
* `VulnerabilityMapper`
* `PackageUrlMapper`

Avoid:

* `ApiHelper`
* `FetchUtils`
* `ParserService`
* `DataClient`
* `ExternalManager`

---

## `src/presentation/`

The presentation layer contains Obsidian plugin UI code.

Allowed in `src/presentation/`:

* Obsidian views
* Settings tabs
* Modals
* UI controllers
* Renderers
* View models
* DOM event wiring
* User interaction handling
* CSS class usage
* Markdown rendering adapters
* UI-specific formatting

Examples:

```text
src/presentation/views/VulnDashView.ts
src/presentation/settings/VulnDashSettingsTab.ts
src/presentation/modals/SbomManagerModal.ts
src/presentation/rendering/VulnerabilityTableRenderer.ts
src/presentation/rendering/SeverityBadgeRenderer.ts
src/presentation/controllers/SettingsController.ts
```

Presentation code must remain thin.

Presentation code may:

* Call application use cases
* Convert application result models into view models
* Render secure DOM
* Render markdown through approved rendering adapters
* Handle Obsidian notices and commands

Presentation code must not:

* Call external vulnerability APIs directly
* Parse feed payloads
* Contain vulnerability matching rules
* Contain severity normalization rules
* Contain CVSS calculation logic
* Directly manipulate persistence schemas
* Contain business rules that belong in domain/application

Good presentation names:

* `VulnDashView`
* `SbomManagerModal`
* `SettingsController`
* `VulnerabilityTableRenderer`
* `ComponentDetailRenderer`
* `ObsidianNoteRenderer`
* `DailyBriefingRenderer`

Avoid:

* `UiHelper`
* `RenderUtils`
* `DataManager`
* `MainProcessor`

---

## `src/shared/`

Avoid creating `shared`, `common`, `utils`, `helpers`, or `misc` folders by default.

A shared module is only allowed when it represents a real architectural concept that is intentionally reused across layers.

Allowed shared concepts may include:

```text
src/shared/result/Result.ts
src/shared/errors/AppError.ts
src/shared/logging/Logger.ts
src/shared/time/Clock.ts
src/shared/ids/IdGenerator.ts
```

Do not place business logic in shared modules.

Do not create vague files such as:

```text
src/shared/utils.ts
src/common/helpers.ts
src/utils/data.ts
src/misc/index.ts
```

If logic has a domain meaning, place it in the appropriate domain module.

If logic is technical infrastructure, place it in infrastructure.

If logic is UI-specific, place it in presentation.

---

# Naming Rules

## General Naming

Names must be explicit, intention-revealing, and aligned with responsibility.

File names should match the primary exported class, function, or type.

Good:

```text
NvdClient.ts
GitHubAdvisoryClient.ts
VulnerabilityRepository.ts
SyncVulnerabilitiesUseCase.ts
VulnerabilityMapper.ts
FeedSyncCheckpointStore.ts
ObsidianNoteRenderer.ts
SettingsController.ts
```

Suspicious:

```text
DataHelper.ts
AppService.ts
CommonUtils.ts
ParserService.ts
Manager.ts
Processor.ts
Stuff.ts
FinalHandler.ts
```

Do not use vague names unless the concept is explicitly justified and documented.

---

## Interface Naming

Interfaces should be named by role, not implementation.

Good:

```text
VulnerabilityRepository
FeedClient
SbomParser
CheckpointStore
NoteRenderer
Clock
Logger
```

Avoid implementation-flavored interfaces:

```text
IIndexedDbVulnerabilityRepository
INvdClientImpl
IObsidianRenderer
```

Use implementation names for concrete classes:

```text
IndexedDbVulnerabilityRepository
NvdClient
OsvClient
ObsidianNoteRenderer
SystemClock
ConsoleLogger
```

---

## Class Naming

Classes should describe what they are responsible for.

Good:

```text
SyncVulnerabilitiesUseCase
ImportSbomUseCase
CycloneDxSbomParser
OsvVulnerabilityMapper
FeedSyncCheckpointIndexedDbStore
SeverityBadgeRenderer
```

Avoid names that hide responsibility:

```text
VulnerabilityManager
SbomProcessor
DataService
RenderHelper
AppHandler
```

---

## Function Naming

Functions should use verbs and describe the action.

Good:

```text
parseCycloneDxSbom()
mapOsvVulnerability()
resolveDisplaySeverity()
calculateUpgradePath()
loadProjectInventory()
generateDailyBriefing()
```

Avoid:

```text
handle()
process()
doWork()
runStuff()
parseData()
manage()
```

Generic verbs are only acceptable in very small local scopes where the context is obvious.

---

# Placement Rules by Responsibility

## Vulnerability Normalization

Vulnerability normalization belongs in domain/application/infrastructure depending on the kind of normalization.

External payload normalization belongs in infrastructure mappers:

```text
src/infrastructure/mappers/OsvVulnerabilityMapper.ts
src/infrastructure/mappers/NvdVulnerabilityMapper.ts
src/infrastructure/mappers/GitHubAdvisoryMapper.ts
```

Canonical severity, CVSS, affected package, range, and remediation rules belong in domain:

```text
src/domain/value-objects/Severity.ts
src/domain/value-objects/CvssScore.ts
src/domain/vulnerabilities/Vulnerability.ts
src/domain/remediation/VulnerabilityRange.ts
```

Use-case orchestration belongs in application:

```text
src/application/vulnerabilities/NormalizeVulnerabilitiesUseCase.ts
src/application/remediation/ResolveUpgradePathUseCase.ts
```

Do not put severity, CVSS, or vulnerability matching rules in presentation renderers.

---

## SBOM Parsing

SBOM format parsing belongs in infrastructure:

```text
src/infrastructure/sbom/CycloneDxSbomParser.ts
src/infrastructure/sbom/SpdxSbomParser.ts
```

SBOM domain concepts belong in domain:

```text
src/domain/sbom/SbomDocument.ts
src/domain/sbom/SbomComponent.ts
src/domain/sbom/ComponentIdentity.ts
```

SBOM import workflows belong in application:

```text
src/application/sbom/ImportSbomUseCase.ts
src/application/sbom/LoadSbomComponentsUseCase.ts
```

SBOM UI interactions belong in presentation:

```text
src/presentation/modals/SbomManagerModal.ts
src/presentation/views/ComponentInventoryView.ts
```

---

## Feed Synchronization

Feed client implementations belong in infrastructure:

```text
src/infrastructure/feeds/nvd/NvdClient.ts
src/infrastructure/feeds/github/GitHubAdvisoryClient.ts
src/infrastructure/feeds/osv/OsvClient.ts
```

Feed sync workflows belong in application:

```text
src/application/feeds/SyncFeedUseCase.ts
src/application/feeds/SyncAllFeedsUseCase.ts
```

Checkpoint and cursor concepts belong in domain/application contracts:

```text
src/domain/feeds/FeedSyncCheckpoint.ts
src/domain/feeds/FeedSource.ts
src/application/ports/FeedSyncCheckpointStore.ts
```

Checkpoint storage implementations belong in infrastructure:

```text
src/infrastructure/persistence/FeedSyncCheckpointIndexedDbStore.ts
```

Do not advance feed checkpoints until the full sync cycle has completed successfully.

---

## Persistence

Repository interfaces belong in domain or application ports, depending on who owns the abstraction.

Concrete persistence belongs in infrastructure.

Good:

```text
src/domain/repositories/VulnerabilityRepository.ts
src/application/ports/SbomRepository.ts
src/infrastructure/persistence/indexeddb/IndexedDbVulnerabilityRepository.ts
```

Do not put IndexedDB logic in application use cases or presentation views.

Do not leak database schemas into domain entities.

Use explicit persistence mappers when converting between persistence records and domain/application models.

---

## Rendering

Rendering belongs in presentation.

Markdown composition may be split into dedicated composers/renderers, but must not contain domain rules.

Good:

```text
src/presentation/rendering/DailyBriefingMarkdownComposer.ts
src/presentation/rendering/VulnerabilityMarkdownComposer.ts
src/presentation/rendering/ComponentMarkdownComposer.ts
src/presentation/rendering/ObsidianNoteRenderer.ts
```

Renderers may format already-computed values.

Renderers must not compute vulnerability truth, severity truth, remediation truth, or feed synchronization truth.

---

## Settings

Settings UI belongs in presentation.

Settings models may live in application or domain if they affect behavior.

Settings persistence adapters belong in infrastructure if the logic becomes non-trivial.

Good:

```text
src/presentation/settings/VulnDashSettingsTab.ts
src/presentation/settings/SettingsController.ts
src/application/settings/UpdateFeedSettingsUseCase.ts
src/domain/settings/FeedConfig.ts
```

Avoid putting all settings behavior into one large settings tab file.

Settings UI should delegate behavior to controllers or use cases.

---

# Coding Conventions

## TypeScript

Use strict TypeScript.

Prefer explicit types at architectural boundaries.

Avoid `any`.

If unknown external data is received, validate it before mapping.

Allowed:

```typescript
unknown
ReadonlyArray<T>
Record<string, unknown>
```

Avoid:

```typescript
any
object
Function
```

Use discriminated unions for state machines and result variants.

Use enums or literal unions only when they improve clarity and domain safety.

---

## Error Handling

Do not swallow errors silently.

Use explicit application/domain error types where useful.

Infrastructure errors should be translated into meaningful application errors before reaching presentation.

Presentation may display concise user-facing messages, but detailed technical information should be logged.

Good error concepts:

```text
FeedSyncFailedError
UnsupportedSbomFormatError
InvalidPackageUrlError
CheckpointPersistenceError
UnsupportedVersionSchemeError
```

Avoid throwing raw strings.

Avoid generic errors such as:

```text
SomethingWentWrongError
ProcessingError
DataError
```

---

## Results and State

Prefer explicit result objects for meaningful workflows.

Good:

```text
SyncResult
ImportSbomResult
UpgradePathResolution
TriageUpdateResult
ProjectBriefingResult
```

Use diagnostic states instead of ambiguous booleans.

Good:

```text
resolved
not_affected
unknown_version
unsupported_version_scheme
missing_package_identity
no_known_patch
```

Avoid:

```text
success: true
valid: false
status: "done"
```

unless the surrounding model is explicit and well-documented.

---

## Comments

Comments should explain why, not restate what the code does.

Good comments explain:

* Architectural decisions
* Security-sensitive behavior
* Non-obvious external API behavior
* Compatibility constraints
* Performance tradeoffs

Avoid noisy comments that simply repeat the code.

---

# Security Rules

This is a security-focused application. Treat all external data as untrusted.

External data includes:

* Vulnerability feed payloads
* SBOM files
* Package names
* Versions
* URLs
* Advisory descriptions
* Markdown content
* User-provided project names
* Cached records

Rules:

* Never render untrusted HTML directly.
* Prefer safe DOM creation APIs.
* Sanitize or escape user-controlled content.
* Validate external payloads before mapping.
* Avoid unsafe URL construction.
* Avoid path traversal risks when reading or writing files.
* Do not store secrets in code.
* Do not log sensitive tokens or credentials.
* Keep rendering separate from parsing and domain logic.

Markdown rendering must use approved Obsidian-safe rendering paths or dedicated sanitizing renderers.

---

# Performance Rules

The plugin must remain responsive inside Obsidian.

Avoid blocking the UI thread with large SBOMs, feed syncs, or large vulnerability datasets.

Preferred patterns:

* Incremental rendering
* Virtualized tables for large datasets
* Web Workers for large JSON parsing
* IndexedDB-backed caching
* Bounded retention policies
* Debounced UI refreshes
* Stable DOM updates instead of full teardown/rebuild
* Explicit loading and stale-data states

Do not rebuild large DOM trees on every refresh unless the dataset is small and the tradeoff is justified.

Do not parse large SBOMs synchronously in presentation code.

---

# Testing Expectations

Tests should mirror architectural boundaries.

Preferred test locations:

```text
tests/domain/
tests/application/
tests/infrastructure/
tests/presentation/
```

Domain tests should be pure and fast.

Application tests should mock ports and verify orchestration.

Infrastructure tests should validate mappers, parsers, persistence adapters, and API edge cases.

Presentation tests should focus on rendering behavior, UI state transitions, and safe output.

Add tests when changing:

* Severity normalization
* CVSS calculation
* Vulnerability matching
* SBOM parsing
* Feed sync checkpoint logic
* Remediation calculation
* Project filtering
* Markdown rendering
* Security-sensitive rendering
* Cache behavior
* Async task coordination

---

# Do's

Do:

* Keep domain logic in the domain layer.
* Keep use-case orchestration in the application layer.
* Keep external integrations in infrastructure.
* Keep Obsidian UI code in presentation.
* Use explicit names.
* Keep files small and focused.
* Prefer role-based interfaces.
* Prefer concrete implementation names.
* Use mappers at boundaries.
* Validate unknown input.
* Use result objects for meaningful workflows.
* Preserve dependency direction.
* Add tests for architectural and domain behavior.
* Keep UI renderers thin.
* Keep persistence details out of domain models.
* Use domain value objects for important concepts.
* Prefer cohesive modules over shared utility dumping grounds.

---

# Don'ts

Do not:

* Put business rules in views, modals, or renderers.
* Put Obsidian API calls in domain or application logic.
* Put IndexedDB calls in domain or presentation.
* Put HTTP calls directly in use cases when a port/client abstraction is expected.
* Create vague files like `utils.ts`, `helpers.ts`, `common.ts`, or `misc.ts`.
* Create catch-all classes named `Manager`, `Processor`, `Handler`, or `Service` without clear architectural justification.
* Duplicate severity, CVSS, package identity, or vulnerability matching logic.
* Use `any` to bypass type safety.
* Render untrusted HTML.
* Swallow errors silently.
* Advance sync checkpoints before a sync successfully completes.
* Couple external API payloads directly to domain models.
* Add random shared modules without a real architectural concept.
* Mix parsing, mapping, persistence, and rendering in one file.
* Create god classes.
* Make presentation responsible for domain decisions.

---

# Preferred Patterns

## Use Case Pattern

Use cases should represent application actions.

Example naming:

```text
SyncVulnerabilitiesUseCase
ImportSbomUseCase
GenerateProjectBriefingUseCase
ResolveAffectedComponentsUseCase
UpdateTriageStateUseCase
```

A use case should:

* Accept explicit input models
* Call domain logic and ports
* Return explicit result models
* Avoid UI concerns
* Avoid infrastructure details

---

## Repository Pattern

Use repositories for persistence abstractions.

Interfaces should describe storage intent:

```text
VulnerabilityRepository
SbomRepository
ProjectRepository
FeedSyncCheckpointStore
```

Implementations should describe technology:

```text
IndexedDbVulnerabilityRepository
IndexedDbSbomRepository
ObsidianDataJsonSettingsStore
```

---

## Mapper Pattern

Use mappers to cross boundaries.

Examples:

```text
OsvVulnerabilityMapper
NvdVulnerabilityMapper
CycloneDxComponentMapper
PersistenceVulnerabilityMapper
```

Mappers should be explicit about source and target.

Avoid generic `DataMapper`.

---

## Parser Pattern

Use parsers for file or payload parsing.

Examples:

```text
CycloneDxSbomParser
SpdxSbomParser
GitHubAdvisoryResponseParser
```

Parsing should not perform unrelated persistence, rendering, or UI updates.

---

## Client Pattern

Use clients for external systems.

Examples:

```text
NvdClient
OsvClient
GitHubAdvisoryClient
ObsidianHttpClient
```

Clients should handle:

* Request construction
* Pagination details
* Retry-aware behavior
* Rate-limit metadata
* Response retrieval

Clients should not own domain decisions.

---

## Renderer Pattern

Use renderers for presentation output.

Examples:

```text
VulnerabilityTableRenderer
SeverityBadgeRenderer
ComponentDetailRenderer
DailyBriefingMarkdownComposer
ObsidianNoteRenderer
```

Renderers should receive already-computed view models or application result models.

Renderers should not perform feed sync, persistence, vulnerability matching, or severity normalization.

---

## Factory Pattern

Use factories when object construction is non-trivial or must centralize valid construction.

Examples:

```text
FeedClientFactory
SbomParserFactory
RepositoryFactory
UseCaseFactory
```

Factories should not become service locators or god objects.

---

# Boundary Examples

## Correct Flow: Sync Vulnerabilities

```text
Presentation command
  -> SyncVulnerabilitiesUseCase
    -> FeedClient port
      -> NvdClient / OsvClient / GitHubAdvisoryClient
    -> VulnerabilityMapper
    -> VulnerabilityRepository
    -> FeedSyncCheckpointStore
  -> SyncResult
  -> Presentation updates UI
```

The UI starts the sync, but does not perform the sync itself.

---

## Correct Flow: Import SBOM

```text
SbomManagerModal
  -> ImportSbomUseCase
    -> SbomParser port
      -> CycloneDxSbomParser / SpdxSbomParser
    -> Component mapper
    -> SbomRepository
    -> ComponentRepository
  -> ImportSbomResult
  -> Presentation renders import summary
```

The modal handles user interaction, not parsing or persistence rules.

---

## Correct Flow: Render Vulnerability Severity

```text
Domain Severity / CvssScore
  -> Application result model
    -> Presentation view model
      -> SeverityBadgeRenderer
```

The renderer displays severity. It does not decide canonical severity.

---

# Refactoring Guidance

When modifying existing code:

1. Preserve behavior first.
2. Identify the responsibility of the code being changed.
3. Move logic to the correct layer if it is clearly misplaced.
4. Avoid introducing new vague shared modules.
5. Prefer small, explicit files over large mixed-responsibility files.
6. Add tests around moved logic.
7. Keep public behavior stable unless the task explicitly requires a behavior change.

When a file becomes too large, split by responsibility, not by arbitrary private method grouping.

Good splits:

```text
VulnerabilityTableRenderer
VulnerabilityTableColumns
VulnerabilityTableRowRenderer
VulnerabilityTableEvents
```

Bad splits:

```text
VulnerabilityHelpers
VulnerabilityUtils
VulnerabilityStuff
```

---

# Review Checklist for Copilot

Before suggesting or generating code, verify:

* Does this file belong in the selected directory?
* Does the name clearly describe the responsibility?
* Is the class/function doing one thing?
* Is domain logic free of UI, HTTP, and persistence concerns?
* Is presentation free of domain decisions?
* Is infrastructure free of UI decisions?
* Are external payloads mapped before entering domain logic?
* Are errors explicit and useful?
* Are types specific?
* Is untrusted content handled safely?
* Is performance acceptable for large SBOM/feed datasets?
* Are tests needed for the change?
* Did this introduce a vague helper, manager, processor, or service?
* Refer to the architecture diagram in docs/ARCHITECTURE.md for expected dependencies and layer responsibilities.

If the answer reveals boundary leakage, refactor before adding more behavior.

---

# Mermaid Diagram Conventions

When generating or updating Mermaid `flowchart` diagrams in this repository, always apply the following `classDef` declarations and assign every node to the appropriate class.

```
%% Styling Classes
classDef ui fill:#f9f2ec,stroke:#b26b00,stroke-width:1.5px,color:#333
classDef application fill:#eaf4fa,stroke:#005b96,stroke-width:1.5px,color:#333
classDef infrastructure fill:#f4f4f4,stroke:#666,stroke-width:1.5px,color:#333
classDef storage fill:#e1f7e7,stroke:#2d7a42,stroke-width:2px,color:#333
classDef dataNode fill:#ffffff,stroke:#888,stroke-width:1px,stroke-dasharray: 4 4,color:#333

%% Line / edge color coding
%% NOTE: Mermaid linkStyle indexes are order-sensitive. If new arrows are inserted above, update these groups.

%% External API traffic
linkStyle 0,1,2,3 stroke:#64748b,stroke-width:2px;

%% Shared HTTP adapter calls
linkStyle 4,5,6 stroke:#475569,stroke-width:1.8px;

%% Feed ports into application sync
linkStyle 7,8,9 stroke:#2563eb,stroke-width:2.5px;

%% Sync / ingestion pipeline
linkStyle 10,11,13,14 stroke:#0284c7,stroke-width:2.5px;

%% Worker offload paths
linkStyle 12,19,21,69 stroke:#7c3aed,stroke-width:2.5px,stroke-dasharray:5 5;

%% SBOM import flow
linkStyle 15,16,17,18 stroke:#c2410c,stroke-width:2.5px;

%% OSV lazy hydration flow
linkStyle 20,22,23,24 stroke:#9333ea,stroke-width:2.5px;

%% Persistence / IndexedDB
linkStyle 25,26,27,28,29 stroke:#15803d,stroke-width:2.5px;

%% Application composition and internal use cases
linkStyle 30,31,32,33,34,35,36,37,38,39,40,41,42 stroke:#0369a1,stroke-width:2px;

%% Domain model / policy usage
linkStyle 43,44,45,46,47,48,49,50,51,52 stroke:#0f766e,stroke-width:2.25px;

%% Sanitization boundary
linkStyle 53,54,55 stroke:#b91c1c,stroke-width:2.75px;

%% Presentation wiring
linkStyle 56,57,58,59,60,61,62,63,64,65,66,67 stroke:#b45309,stroke-width:2.25px;

%% Rollup / note generation
linkStyle 68,70,71 stroke:#6d28d9,stroke-width:2.25px;

%% Vault / settings access
linkStyle 72,73,74,75,76 stroke:#4b5563,stroke-width:2px;
```

Class assignment rules:

| Class | Applies to |
|---|---|
| `ui` | All `presentation/` nodes — views, modals, settings tabs, commands, renderers |
| `application` | All `application/` nodes — use cases, services, pipeline, ports; also all `domain/` nodes |
| `infrastructure` | All `infrastructure/` nodes — clients, repositories, parsers, workers, adapters |
| `storage` | IndexedDB / persistent store nodes (cylindrical shape recommended: `[("…")]`) |
| `dataNode` | External API boundaries, vault files, and other data-at-rest nodes outside the plugin |

---

# Final Instruction

When in doubt, prefer explicit architecture over convenience.

Do not optimize for fewer files if it weakens responsibility boundaries.

Do not hide important concepts inside generic helpers.

This repository should remain understandable by reading the folder structure, file names, and class names alone.
