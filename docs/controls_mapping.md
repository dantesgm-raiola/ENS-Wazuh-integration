# ENS Controls Mapping — Wazuh

Full reference mapping between ENS (Real Decreto 311/2022) controls and Wazuh SCA checks and detection rules.

Every check and rule below is also tagged with its equivalent ISO/IEC 27001:2022 Annex A control — see [`iso27001_mapping.md`](iso27001_mapping.md) for the full ENS ↔ ISO 27001 correspondence table and how to filter by it on Wazuh 5.x.

Detection rules marked ¹ ship with `enabled: false` (too noisy to enable by default). Rule-by-rule port notes, including the 4.x rules that were dropped, are in [`detection_rules_5x.md`](detection_rules_5x.md).

| ENS Control | Description | Level | SCA Check IDs (Linux) | SCA Check IDs (Windows) | Detection rules (`rules/`) | Type |
|-------------|-------------|-------|-----------------------|-------------------------|----------|------|
| **op.acc.1** | Identificación | Básico | 30001–30006 | — | `ens-op-acc-1-ssh-session-opened`, `ens-op-acc-6-authentication-failure`¹ | SCA + Rules |
| **op.acc.2** | Requisitos de acceso | Básico | 30010–30014 | 31010, 31011 | `ens-op-acc-2-password-changed-or-reset` | SCA + Rules |
| **op.acc.3** | Segregación de funciones | Básico | 30020–30022 | 31034 | `ens-op-acc-3-sudo-authentication-failure`, `ens-op-acc-3-sudo-command-executed`, `ens-op-acc-4-user-added-to-privileged-group` | SCA + Rules |
| **op.acc.4** | Gestión de derechos de acceso | Básico | — | — | `ens-op-acc-4-user-account-created`, `ens-op-acc-4-user-account-deleted`, `ens-op-acc-4-user-account-modified`, `ens-op-acc-4-user-added-to-privileged-group`, `ens-op-exp-3-critical-system-file-changed` | Rules |
| **op.acc.6** | Autenticación (usuarios org.) | Básico/Medio | 30030–30035 | 31030, 31032, 31033, 31035, 31036 | `ens-op-acc-3-sudo-authentication-failure`, `ens-op-acc-6-account-locked-out`, `ens-op-acc-6-authentication-failure`¹ | SCA + Rules |
| **op.acc.7** | Acceso remoto | Medio | 30040–30042 | — | `ens-op-acc-1-ssh-session-opened` | SCA + Rules |
| **op.exp.2** | Configuración de seguridad | Básico/Medio | 30100–30108 | 31102 | — | SCA |
| **op.exp.3** | Gestión de la configuración | Básico | — | — | `ens-op-exp-3-critical-system-file-changed` | Rules |
| **op.exp.5** | Gestión de cambios | Básico | — | — | `ens-op-exp-3-critical-system-file-changed`, `ens-op-exp-5-windows-service-installed` | Rules |
| **op.exp.6** | Protección frente a código dañino | Básico | 30110 | 31100 | `ens-op-exp-6-rootkit-hidden-process-or-port` | SCA + Rules |
| **op.exp.7** | Gestión de incidentes | Básico | — | — | `ens-op-acc-6-account-locked-out` | Rules |
| **op.exp.8** | Registro de actividad de usuarios | Básico/Medio | 30120–30126 | 31120, 31121, 31200 | `ens-op-acc-3-sudo-command-executed`, `ens-op-exp-8-audit-daemon-stopped` | SCA + Rules |
| **op.exp.9** | Registro de gestión de incidentes | Básico | — | — | — | — |
| **op.exp.10** | Protección de registros | Medio | 30123, 30130, 30131 | — | `ens-op-exp-10-windows-event-log-cleared`, `ens-op-exp-8-audit-daemon-stopped` | SCA + Rules |
| **op.mon.1** | Detección de intrusión | Básico | 30200, 30201 | 31031 | `ens-op-exp-6-rootkit-hidden-process-or-port` | SCA + Rules |
| **mp.com.2** | Protección de la confidencialidad | Medio | 30300, 30301 | 31302 | — | SCA |
| **mp.com.3** | Autenticidad e integridad | Básico | 30310 | — | — | SCA |
| **mp.com.4** | Segregación de redes | Básico | 30320–30325 | — | — | SCA |
| **mp.eq.2** | Bloqueo de puesto de trabajo | Básico | 30400 | 31400 | — | SCA |
| **mp.info.3** | Cifrado de la información | Medio | 30500 | — | — | SCA |
| **mp.info.9** | Copias de seguridad | Básico | 30510 | — | — | SCA |
| **mp.s.2** | Protección de servicios web | Básico | 30600–30602 | — | `ens-op-exp-5-windows-service-installed` | SCA + Rules |
| **mp.s.3** | Protección frente a DoS | Básico | 30320, 30324 | — | — | SCA |
| **mp.sw.2** | Aceptación y puesta en servicio | Básico | 30700 | 31700 | — | SCA |

## Controls requiring manual evidence

The following ENS controls cannot be automatically audited by Wazuh and require manual documentation, evidence collection, or process review:

| ENS Control | Description | Notes |
|-------------|-------------|-------|
| org.1 | Política de seguridad | Document required |
| org.2 | Normativa de seguridad | Document required |
| org.3 | Procedimientos de seguridad | Document required |
| org.4 | Proceso de autorización | Process + records required |
| op.pl.1 | Análisis de riesgos | Risk assessment document |
| op.pl.2 | Arquitectura de seguridad | Architecture document |
| op.acc.5 | Autenticación (usuarios externos) | MFA/PKI configuration review |
| op.cont.1 | Análisis de impacto | BIA document |
| op.cont.2 | Plan de continuidad | BCP document |
| op.cont.3 | Pruebas periódicas | Test records |
| op.ext.1 | Contratación y SLAs | Contract review |
| mp.if.1–7 | Protección de instalaciones | Physical audit |
| mp.per.1–5 | Gestión del personal | HR process review |
| mp.si.1–5 | Protección de soportes | Physical media audit |
| mp.info.1 | Datos de carácter personal | RGPD/DPO review |
| mp.info.4 | Firma electrónica | PKI review |
| mp.info.5 | Sellos de tiempo | Timestamp service review |

## Level filter reference (Wazuh 5.x)

SCA results live in the `wazuh-states-sca` index (current state, one document per agent and
check). ENS metadata is in `check.references`; see the README section *How ENS data is stored
on Wazuh 5.x* for why it isn't in `check.compliance`.

- **Básico**: `check.references: "ens-level:basico"`
- **Medio**: `check.references: ("ens-level:basico" or "ens-level:medio")`
- **Alto**: all checks (`policy.id: (ens_linux or ens_windows)`)
- One control: `check.references: "ens:op.acc.6"`; a family: `check.references: ens\:op.acc.*`

For detection rules, filter findings (`wazuh-findings-v5-*`) on `wazuh.rule.tags`:
- `wazuh.rule.tags: ens.op.acc.*`, `ens.op.exp.*`, `ens.mp.*`
- `wazuh.rule.tags: iso27001-2022.5.*` / `iso27001-2022.8.*`

## NIS2 mapping used in `check.compliance.nis2`

`nis2` is one of the compliance keys the 5.x SCA schema accepts, so each ENS check also carries
the NIS2 Directive Art. 21.2 measure its ENS family supports. The mapping is at family level and
approximate: it helps filtering alongside Wazuh's own policies, it is not a legal crosswalk.

| ENS family / control | NIS2 Art. 21.2 | Measure |
|---|---|---|
| op.acc.*, mp.eq.* | 21.2.i | Human resources security, access control, asset management |
| op.exp.2, op.exp.6, mp.com.4, mp.s.*, mp.sw.* | 21.2.e | Security in acquisition, development and maintenance, incl. vulnerability handling |
| op.exp.6 | 21.2.g | Basic cyber hygiene |
| op.exp.8, op.exp.10, op.mon.* | 21.2.b | Incident handling |
| mp.com.2, mp.com.3, mp.info.3 | 21.2.h | Cryptography and encryption |
| mp.info.9 | 21.2.c | Business continuity, backup management |
