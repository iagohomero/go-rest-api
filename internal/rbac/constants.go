package rbac

import "sync"

const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

// getDefaultRoles returns the default role definitions.
func getDefaultRoles() map[string]Role {
	return map[string]Role{
		RoleUser: {
			Name:        RoleUser,
			Permissions: []string{},
		},
		RoleAdmin: {
			Name:        RoleAdmin,
			Permissions: []string{PermissionGetUsers, PermissionManageUsers},
		},
	}
}

type roleRegistry struct {
	roles map[string]Role
	mux   sync.RWMutex
}

// getRegistry returns the singleton role registry instance.
func getRegistry() *roleRegistry {
	var instance *roleRegistry
	var once sync.Once
	once.Do(func() {
		instance = &roleRegistry{
			roles: getDefaultRoles(),
		}
	})
	return instance
}

// GetRole returns a role by name.
func GetRole(name string) (Role, bool) {
	r := getRegistry()
	r.mux.RLock()
	defer r.mux.RUnlock()
	role, exists := r.roles[name]
	return role, exists
}

// GetAllRoles returns all available role names.
func GetAllRoles() []string {
	r := getRegistry()
	r.mux.RLock()
	defer r.mux.RUnlock()
	roles := make([]string, 0, len(r.roles))
	for name := range r.roles {
		roles = append(roles, name)
	}
	return roles
}

// GetPermissions returns permissions for a role by name.
func GetPermissions(roleName string) []string {
	r := getRegistry()
	r.mux.RLock()
	defer r.mux.RUnlock()
	if role, exists := r.roles[roleName]; exists {
		return role.Permissions
	}
	return []string{}
}

// IsValidRole checks if a role name exists in the registry.
func IsValidRole(roleName string) bool {
	r := getRegistry()
	r.mux.RLock()
	defer r.mux.RUnlock()
	_, exists := r.roles[roleName]
	return exists
}

// RegisterRole dynamically registers a new role.
func RegisterRole(role Role) {
	r := getRegistry()
	r.mux.Lock()
	defer r.mux.Unlock()
	r.roles[role.Name] = role
}
