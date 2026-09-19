# MP Android Security — Threat Intelligence

Fluxo: fontes -> backend/API -> banco -> feed versionado -> Android -> cache SQLite -> correlação local.

Implementado nesta etapa:
- feed JSON versionado;
- HTTPS;
- WorkManager a cada 12 horas com rede;
- cache SQLite com até 3 snapshots;
- fallback local;
- rejeição de feed vazio;
- rejeição de versão antiga;
- preservação do último snapshot em falhas;
- endpoint isolado para futura API própria.

Backend de produção recomendado:
- PostgreSQL: threats, threat_versions, iocs, app_fingerprints, detection_rules, sources, sync_runs;
- ingestão, normalização, deduplicação e enriquecimento no backend;
- chaves de provedores somente no backend;
- snapshots assinados antes de usar a fonte como alta confiança.

Correlação futura:
package name, SHA-256 do APK, certificado, installer, permissões, acessibilidade/admin, indicadores comportamentais e domínios/URLs.

Resultados: Sem correspondência / Suspeito / Ameaça conhecida. Heurística não é prova de infecção.
