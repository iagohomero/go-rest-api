package user

// Response represents a single user response.
type Response struct {
	Code    int    `json:"code"    example:"200"`
	Status  string `json:"status"  example:"success"`
	Message string `json:"message" example:"Operation completed successfully"`
	User    User   `json:"user"`
}

// UsersListResponse represents a paginated list of users.
type UsersListResponse struct {
	Code         int    `json:"code"          example:"200"`
	Status       string `json:"status"        example:"success"`
	Message      string `json:"message"       example:"Get all users successfully"`
	Results      []User `json:"results"`
	Page         int    `json:"page"          example:"1"`
	Limit        int    `json:"limit"         example:"10"`
	TotalPages   int64  `json:"total_pages"   example:"1"`
	TotalResults int64  `json:"total_results" example:"1"`
}
