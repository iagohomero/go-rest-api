package rbac

const (
	PermissionGetUsers    = "getUsers"
	PermissionManageUsers = "manageUsers"
)

// GetAllPermissions returns all available permissions in the system.
func GetAllPermissions() []string {
	return []string{
		PermissionGetUsers,
		PermissionManageUsers,
	}
}
