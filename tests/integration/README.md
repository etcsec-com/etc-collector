# Tests d'Intégration

## Configuration

Les tests d'intégration nécessitent:
- Un serveur Active Directory réel (pour tests LDAP)
- Un tenant Azure AD avec une application configurée (pour tests Azure)

### 1. Créer le fichier de configuration

Copier `.env.test.example` vers `.env.test.local` à la racine du projet :

```bash
cp .env.test.example .env.test.local
```

### 2. Configurer les credentials

Éditer `.env.test.local` avec vos credentials :

```env
# LDAP / Active Directory
TEST_LDAP_URL=ldaps://your-dc:636
TEST_LDAP_BIND_DN=CN=service-user,CN=Users,DC=domain,DC=com
TEST_LDAP_BIND_PASSWORD=your-password
TEST_LDAP_BASE_DN=DC=domain,DC=com
TEST_LDAP_TLS_VERIFY=false

# Azure AD / Microsoft Graph
TEST_AZURE_TENANT_ID=your-tenant-id
TEST_AZURE_CLIENT_ID=your-client-id
TEST_AZURE_CLIENT_SECRET=your-client-secret
```

⚠️ **Sécurité** : `.env.test.local` est gitignored et ne sera jamais commité.

## Lancer les Tests

### Tests Unitaires LDAP (127 tests)

```bash
npm test -- tests/unit/providers/ldap/
```

✅ Ne nécessitent pas d'AD, toujours disponibles

### Tests d'Intégration (10 tests)

Sans configuration (tests skippés) :
```bash
npm test -- tests/integration/providers/
```

Avec configuration (tests exécutés) :
```bash
# Charger les variables d'environnement
export $(cat .env.test.local | xargs)

# Lancer les tests
npm test -- tests/integration/providers/ldap-basic.integration.test.ts
```

### Tests d'Intégration Azure (10 tests)

Sans configuration (tests skippés) :
```bash
npm test -- tests/integration/providers/azure-basic.integration.test.ts
```

Avec configuration (tests exécutés) :
```bash
# Charger les variables d'environnement
export $(cat .env.test.local | xargs)

# Lancer les tests
npm test -- tests/integration/providers/azure-basic.integration.test.ts
```

### Tests Complets

```bash
# Tous les tests LDAP
npm test -- ldap

# Tous les tests Azure
npm test -- azure

# Tous les tests d'intégration
npm test -- tests/integration
```

## Tests Disponibles

### ldap-connectivity.test.ts
- Test de connexion basique
- Vérifie bind/unbind
- ~100ms

### ldap-basic.integration.test.ts (10 tests)
- IT1: Connexion LDAPS
- IT2: Test connection
- IT3: Search users
- IT4: Search user by CN
- IT5: Search groups
- IT6: Search Domain Users
- IT7: Search OUs
- IT8: Generic search
- IT9: Injection prevention
- IT10: Invalid credentials

### ldap-provider.integration.test.ts (30+ tests)
- Tests exhaustifs
- Tous les types de recherches
- Filtres complexes
- Gestion d'erreurs
- Performance

### azure-basic.integration.test.ts (10 tests)
- AZ1: Authentication with Microsoft Graph
- AZ2: Test connection
- AZ3: Get Azure AD users
- AZ4: Get users with filter
- AZ5: Get users with select
- AZ6: Get Azure AD groups
- AZ7: Get security groups only
- AZ8: Get Azure AD applications
- AZ9: Handle pagination
- AZ10: Handle invalid credentials

## Résultats Attendus

```
PASS tests/integration/providers/ldap-basic.integration.test.ts
  ✓ IT1: should connect to LDAPS server (29 ms)
  ✓ IT2: should test connection successfully
  ✓ IT3: should search for users (1372 ms)
  ...

Tests: 10 passed, 10 total
```

## Troubleshooting

### Tests skippés
→ Vérifier que `.env.test.local` existe et contient `TEST_LDAP_URL`

### Connection failed
→ Vérifier firewall / connectivité réseau vers le DC
→ Vérifier que le port 636 (LDAPS) est ouvert

### Invalid credentials
→ Vérifier `TEST_LDAP_BIND_DN` et `TEST_LDAP_BIND_PASSWORD`
→ Le compte de service doit avoir les permissions de lecture AD

### Certificate errors
→ Mettre `TEST_LDAP_TLS_VERIFY=false` pour dev/test
