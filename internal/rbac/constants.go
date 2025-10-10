package rbac

const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

var (
	UserRole = Role{
		Name:        RoleUser,
		Permissions: []string{},
	}

	AdminRole = Role{
		Name:        RoleAdmin,
		Permissions: []string{PermissionGetUsers, PermissionManageUsers},
	}
)

var roleRegistry = map[string]Role{
	RoleUser:  UserRole,
	RoleAdmin: AdminRole,
}

// GetRole returns a role by name.
func GetRole(name string) (Role, bool) {
	role, exists := roleRegistry[name]
	return role, exists
}

// GetAllRoles returns all available role names.
func GetAllRoles() []string {
	roles := make([]string, 0, len(roleRegistry))
	for name := range roleRegistry {
		roles = append(roles, name)
	}
	return roles
}

// GetPermissions returns permissions for a role by name.
func GetPermissions(roleName string) []string {
	if role, exists := roleRegistry[roleName]; exists {
		return role.Permissions
	}
	return []string{}
}

// IsValidRole checks if a role name exists in the registry.
func IsValidRole(roleName string) bool {
	_, exists := roleRegistry[roleName]
	return exists
}

// RegisterRole dynamically registers a new role.
func RegisterRole(role Role) {
	roleRegistry[role.Name] = role
}
