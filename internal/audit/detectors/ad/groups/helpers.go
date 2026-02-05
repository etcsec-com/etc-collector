package groups

import "github.com/etcsec-com/etc-collector/pkg/types"

// toAffectedGroupEntities converts group names to affected entities
func toAffectedGroupEntities(names []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(names))
	for i, name := range names {
		entities[i] = types.AffectedEntity{
			Type: "group",
			Name: name,
		}
	}
	return entities
}
