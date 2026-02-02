# API Documentation

Documentation complète de l'API REST ETC Collector.

## Fichiers

- **openapi.yaml** - Spécification OpenAPI 3.0.3 complète des 11 endpoints

## Visualiser la documentation

### Option 1: Swagger UI (Recommandé)

Ouvrir la documentation interactive dans le navigateur:

```bash
npx @redocly/cli preview-docs docs/api/openapi.yaml
```

Ou utiliser Swagger Editor en ligne:
1. Aller sur https://editor.swagger.io
2. Coller le contenu de `openapi.yaml`

### Option 2: Redoc

Générer une documentation HTML statique avec Redoc:

```bash
npx @redocly/cli build-docs docs/api/openapi.yaml -o docs/api/index.html
```

## Endpoints disponibles

### Health
- `GET /health` - Health check (pas d'auth)

### Authentication
- `POST /api/v1/auth/token` - Générer un JWT token
- `POST /api/v1/auth/validate` - Valider un token
- `POST /api/v1/auth/revoke` - Révoquer un token
- `GET /api/v1/auth/tokens` - Lister tous les tokens

### Audit
- `POST /api/v1/audit/ad` - Lancer un audit Active Directory
- `GET /api/v1/audit/ad/status` - Tester la connexion LDAP
- `POST /api/v1/audit/azure` - Lancer un audit Azure AD
- `GET /api/v1/audit/azure/status` - Tester la connexion Microsoft Graph

### Export
- `POST /api/v1/export/ad` - Exporter les résultats AD (JSON/CSV)
- `POST /api/v1/export/azure` - Exporter les résultats Azure (JSON/CSV)

## Authentification

Tous les endpoints (sauf `/health`) nécessitent un JWT Bearer token:

```bash
# 1. Générer un token
curl -X POST http://localhost:8443/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"name": "my-token", "expiresIn": 3600}'

# 2. Utiliser le token
curl http://localhost:8443/api/v1/audit/ad/status \
  -H "Authorization: Bearer <votre-token>"
```

## Rate Limiting

- **Endpoints généraux**: 100 requêtes/minute
- **Endpoints d'audit**: 10 audits/5 minutes

## Format des réponses

### Succès
```json
{
  "success": true,
  "data": { ... }
}
```

### Erreur
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable message",
    "details": [
      { "field": "fieldName", "message": "error" }
    ]
  }
}
```

## Exemples d'utilisation

### 1. Audit Active Directory

```bash
# Lancer un audit AD
curl -X POST http://localhost:8443/api/v1/audit/ad \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "includeDetails": true,
    "maxUsers": 1000
  }'
```

### 2. Exporter en JSON

```bash
curl -X POST http://localhost:8443/api/v1/export/ad \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "auditResult": { ... },
    "format": "json",
    "domain": "example.com"
  }' > audit-results.json
```

### 3. Exporter en CSV

```bash
curl -X POST http://localhost:8443/api/v1/export/ad \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "auditResult": { ... },
    "format": "csv",
    "domain": "example.com",
    "includeAffectedEntities": true
  }' > audit-results.csv
```

## Codes d'erreur

| Code | Description |
|------|-------------|
| `VALIDATION_ERROR` | Validation Zod échouée |
| `UNAUTHORIZED` | Token manquant ou invalide |
| `TOKEN_EXPIRED` | Token expiré |
| `TOKEN_REVOKED` | Token révoqué |
| `USAGE_LIMIT_EXCEEDED` | Quota d'utilisation dépassé |
| `RATE_LIMIT_EXCEEDED` | Limite de taux dépassée (général) |
| `AUDIT_RATE_LIMIT_EXCEEDED` | Limite de taux dépassée (audit) |
| `INTERNAL_ERROR` | Erreur serveur interne |

## Validation des requêtes

Toutes les requêtes POST sont validées avec Zod:

- **maxUsers/maxGroups/maxComputers/maxApps**: Entiers positifs
- **format**: Enum ["json", "csv"]
- **delimiter**: 1 caractère
- **auditResult**: Structure complète validée

## Développement

### Valider la spec OpenAPI

```bash
npx @redocly/cli lint docs/api/openapi.yaml
```

### Générer des types TypeScript

```bash
npx openapi-typescript docs/api/openapi.yaml -o src/types/api.generated.ts
```

## Ressources

- [OpenAPI Specification](https://spec.openapis.org/oas/v3.0.3)
- [Swagger Editor](https://editor.swagger.io)
- [Redocly CLI](https://redocly.com/docs/cli/)
