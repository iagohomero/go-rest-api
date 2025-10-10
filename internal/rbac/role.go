package rbac

// Role represents a user role with its associated permissions.
type Role struct {
	Name        string
	Permissions []string
}

// HasPermission checks if the role has a specific permission.
func (r Role) HasPermission(permission string) bool {
	for _, p := range r.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the role has all specified permissions.
func (r Role) HasAllPermissions(permissions []string) bool {
	permSet := make(map[string]struct{}, len(r.Permissions))
	for _, p := range r.Permissions {
		permSet[p] = struct{}{}
	}

	for _, required := range permissions {
		if _, exists := permSet[required]; !exists {
			return false
		}
	}
	return true
}

// HasAnyPermission checks if the role has at least one of the specified permissions.
func (r Role) HasAnyPermission(permissions []string) bool {
	permSet := make(map[string]struct{}, len(r.Permissions))
	for _, p := range r.Permissions {
		permSet[p] = struct{}{}
	}

	for _, required := range permissions {
		if _, exists := permSet[required]; exists {
			return true
		}
	}
	return false
}
