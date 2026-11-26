package controllers

import (
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lnb/HRPAuth-Backend-Go/config"
	"github.com/lnb/HRPAuth-Backend-Go/database"
	"github.com/lnb/HRPAuth-Backend-Go/models"
	"github.com/lnb/HRPAuth-Backend-Go/services"
	"github.com/lnb/HRPAuth-Backend-Go/utils"
	"gorm.io/gorm"
)

var (
	emailRegex     = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	captchaRegex   = regexp.MustCompile(`^[a-zA-Z0-9]{4}$`)
	emailCodeRegex = regexp.MustCompile(`^[0-9]{4}$`)
)

type AuthController struct{}

func NewAuthController() *AuthController {
	return &AuthController{}
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email        string `json:"email"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captcha_token"`
	CaptchaCode  string `json:"captcha_code"`
}

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func (ac *AuthController) VerifyToken(c *gin.Context) {
	if !RequireAuthLevel(c, SecurityLevelOps) {
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, CodeInvalidJSONBody, "Invalid request body")
		return
	}

	oauth2Service := services.NewOAuth2Service()
	tokenCtx, err := oauth2Service.ResolveAccessToken(req.Token)
	if err != nil {
		respondError(c, http.StatusUnauthorized, CodeOAuthInvalidGrant, "Invalid or expired token")
		return
	}

	if tokenCtx.IsService {
		respondOK(c, "Token verified", gin.H{
			"is_service": true,
			"scopes":     tokenCtx.Scopes,
		})
		return
	}

	if tokenCtx.User == nil {
		respondError(c, http.StatusUnauthorized, CodeOAuthInvalidGrant, "Token is not associated with a user")
		return
	}

	respondOK(c, "Token verified", gin.H{
		"uid":        tokenCtx.User.UID,
		"uuid":       tokenCtx.User.UUID,
		"email":      tokenCtx.User.Email,
		"username":   tokenCtx.User.Username,
		"is_service": false,
		"scopes":     tokenCtx.Scopes,
	})
}

func (ac *AuthController) VerifyCredentials(c *gin.Context) {
	if !RequireAuthLevel(c, SecurityLevelOps) {
		return
	}

	var req struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	authService := services.NewAuthService()
	userInfo := authService.VerifyCredentials(req.Identifier, req.Password, true)
	if userInfo == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, userInfo)
}

// UserExists handles POST /internal/user-exists. It reports whether a core
// user with the given email exists. Ops-level (service-token) auth only; it
// lets a satellite service gate outbound mail on real accounts — e.g. the
// HASkinProxy password-reset flow — without exposing an email-enumeration
// surface to end users (the public forgot-password endpoint always answers
// success instead). Idempotent read.
func (ac *AuthController) UserExists(c *gin.Context) {
	if !RequireAuthLevel(c, SecurityLevelOps) {
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, CodeInvalidJSONBody, "Invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !emailRegex.MatchString(email) {
		respondError(c, http.StatusBadRequest, CodeInvalidEmail, "Invalid email format")
		return
	}
	if utils.IsPlaceholderEmail(email) {
		respondOK(c, "user existence checked", gin.H{"exists": false})
		return
	}

	var count int64
	if err := database.DB.Model(&models.User{}).Where("email = ?", email).Count(&count).Error; err != nil {
		respondError(c, http.StatusInternalServerError, CodeInternalError, "Database error")
		return
	}

	respondOK(c, "user existence checked", gin.H{"exists": count > 0})
}

func (ac *AuthController) ClaimUserInternal(c *gin.Context) {
	if !RequireAuthLevel(c, SecurityLevelOps) {
		return
	}

	var req struct {
		Username    string  `json:"username"`
		Email       *string `json:"email"`
		Password    string  `json:"password"`
		MigrationID string  `json:"migration_id"`
		EmailMode   string  `json:"email_mode"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, CodeInvalidJSONBody, "Invalid request body")
		return
	}

	username := strings.TrimSpace(req.Username)
	if len(username) < 3 {
		respondError(c, http.StatusBadRequest, CodeUsernameTooShort, "Username too short")
		return
	}
	if len(req.Password) < 6 {
		respondError(c, http.StatusBadRequest, CodePasswordTooShort, "Password too short")
		return
	}

	mode := strings.TrimSpace(req.EmailMode)
	if mode == "" {
		mode = "provided"
	}
	if mode != "provided" && mode != "placeholder" {
		respondError(c, http.StatusBadRequest, CodeInvalidRequest, "Invalid email mode")
		return
	}
	migrationID := strings.TrimSpace(req.MigrationID)
	if migrationID != "" {
		parsed, err := uuid.Parse(migrationID)
		if err != nil {
			respondError(c, http.StatusBadRequest, CodeInvalidRequest, "Invalid migration ID")
			return
		}
		migrationID = parsed.String()
	}

	var email string
	verified := true
	if mode == "placeholder" {
		if migrationID == "" || req.Email != nil {
			respondError(c, http.StatusBadRequest, CodeInvalidRequest, "Placeholder email requires a migration ID and omitted email")
			return
		}
		email = "migration-" + migrationID + "@placeholder.invalid"
		verified = false
	} else {
		if req.Email == nil {
			respondError(c, http.StatusBadRequest, CodeInvalidEmail, "Invalid email")
			return
		}
		email = strings.ToLower(strings.TrimSpace(*req.Email))
		if !isValidEmail(email) || utils.IsPlaceholderEmail(email) {
			respondError(c, http.StatusBadRequest, CodeInvalidEmail, "Invalid email")
			return
		}
	}

	result, err := services.NewMigrationService().ClaimUser(services.ClaimUserInput{
		Username: username, Email: email, Password: req.Password, MigrationID: migrationID, Verified: verified,
	})
	if err != nil {
		switch {
		case errors.Is(err, services.ErrMigrationConflict):
			respondError(c, http.StatusConflict, CodeMigrationConflict, "Migration identity conflicts with an existing claim")
		case errors.Is(err, services.ErrMigrationInvalidState):
			respondError(c, http.StatusConflict, CodeMigrationInvalidState, "Migration ID is not claimable")
		case errors.Is(err, services.ErrUsernameAlreadyBound):
			respondError(c, http.StatusConflict, CodeUsernameAlreadyBound, "Username already bound")
		case errors.Is(err, services.ErrEmailAlreadyRegistered):
			respondError(c, http.StatusConflict, CodeEmailAlreadyRegistered, "Email already registered")
		default:
			respondError(c, http.StatusInternalServerError, CodeInternalError, "Failed to claim user")
		}
		return
	}

	respondOK(c, "User claimed", gin.H{
		"uid": result.UID, "uuid": result.UUID, "email": result.Email, "created": result.Created,
	})
}

func (ac *AuthController) MigrationStatusInternal(c *gin.Context) {
	if !RequireAuthLevel(c, SecurityLevelOps) {
		return
	}
	migrationID, ok := migrationIDFromPath(c)
	if !ok {
		return
	}
	result, err := services.NewMigrationService().Status(migrationID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrMigrationNotFound):
			respondError(c, http.StatusNotFound, CodeMigrationNotFound, "Migration not found")
		default:
			respondError(c, http.StatusInternalServerError, CodeInternalError, "Failed to read migration state")
		}
		return
	}
	respondOK(c, "Migration state retrieved", result)
}

func (ac *AuthController) MigrationRollbackInternal(c *gin.Context) {
	if !RequireAuthLevel(c, SecurityLevelOps) {
		return
	}
	migrationID, ok := migrationIDFromPath(c)
	if !ok {
		return
	}
	result, err := services.NewMigrationService().Rollback(migrationID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrMigrationNotFound):
			respondError(c, http.StatusNotFound, CodeMigrationNotFound, "Migration not found")
		case errors.Is(err, services.ErrMigrationRollbackNotAllowed):
			respondError(c, http.StatusConflict, CodeMigrationRollbackNotAllowed, "Migration rollback is not allowed")
		default:
			respondError(c, http.StatusInternalServerError, CodeMigrationRollbackFailed, "Failed to roll back migration")
		}
		return
	}
	respondOK(c, "Migration rolled back", result)
}

func migrationIDFromPath(c *gin.Context) (string, bool) {
	parsed, err := uuid.Parse(strings.TrimSpace(c.Param("migration_id")))
	if err != nil {
		respondError(c, http.StatusBadRequest, CodeInvalidRequest, "Invalid migration ID")
		return "", false
	}
	return parsed.String(), true
}

// Register handles POST /register.
func (ac *AuthController) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, CodeInvalidJSONBody, "Invalid request body")
		return
	}

	// Username / password length always enforced.
	if len(req.Username) < 3 {
		respondError(c, http.StatusBadRequest, CodeUsernameTooShort, "Username too short")
		return
	}
	if len(req.Password) < 6 {
		respondError(c, http.StatusBadRequest, CodePasswordTooShort, "Password too short")
		return
	}

	// Email required and validated.
	email := req.Email
	if !isValidEmail(email) || utils.IsPlaceholderEmail(email) {
		respondError(c, http.StatusBadRequest, CodeInvalidEmail, "Invalid email")
		return
	}

	// Captcha check when enabled.
	if config.AppConfig.Security.EnableCaptcha {
		captchaService := services.NewCaptchaService()
		if req.CaptchaToken == "" || req.CaptchaCode == "" {
			respondError(c, http.StatusBadRequest, CodeCaptchaInvalid, "Invalid or expired captcha")
			return
		}
		if !captchaService.Verify(req.CaptchaToken, req.CaptchaCode) {
			respondError(c, http.StatusBadRequest, CodeCaptchaInvalid, "Invalid or expired captcha")
			return
		}
	}

	hash, err := utils.HashPassword(req.Password)
	if err != nil {
		respondError(c, http.StatusInternalServerError, CodeInternalError, "Password hashing failed")
		return
	}

	ip := c.ClientIP()
	now := time.Now()

	// Normal WebUI registration: enforce uniqueness, then create.
	var count int64
	database.DB.Model(&models.User{}).Where("email = ?", email).Count(&count)
	if count > 0 {
		respondError(c, http.StatusConflict, CodeEmailAlreadyRegistered, "Email already registered")
		return
	}
	database.DB.Model(&models.User{}).Where("username = ?", req.Username).Count(&count)
	if count > 0 {
		respondError(c, http.StatusConflict, CodeUsernameAlreadyTaken, "Username already taken")
		return
	}

	var maxUID uint
	database.DB.Model(&models.User{}).Select("COALESCE(MAX(uid), 0)").Scan(&maxUID)
	newUID := maxUID + 1
	uuid := utils.GenerateUnsignedUUID()

	user := models.User{
		UID:        newUID,
		UUID:       uuid,
		Email:      email,
		Username:   req.Username,
		Password:   hash,
		IP:         ip,
		RegIP:      ip,
		LastSignAt: &now,
		RegisterAt: &now,
		Verified:   false,
	}

	if err := database.DB.Create(&user).Error; err != nil {
		respondError(c, http.StatusInternalServerError, CodeInternalError, "Failed to create user")
		return
	}

	respondOK(c, "Register successful", gin.H{
		"uid":  user.UID,
		"uuid": user.UUID,
	})
}

type ForgotPasswordRequest struct {
	Email        string `json:"email"`
	CaptchaToken string `json:"captcha_token"`
	CaptchaCode  string `json:"captcha_code"`
}

type ResetPasswordRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

func (ac *AuthController) Logout(c *gin.Context) {
	accessToken := bearerTokenFromRequest(c)
	if accessToken == "" {
		respondError(c, http.StatusUnauthorized, CodeOAuthLoginRequired, "missing bearer token")
		return
	}
	if err := services.NewOAuth2Service().RevokeAccessToken(accessToken); err != nil {
		respondError(c, http.StatusInternalServerError, CodeInternalError, "Failed to revoke token")
		return
	}
	respondOK(c, "Logout successful", nil)
}

// ForgotPassword handles POST /forgot-password.
func (ac *AuthController) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, CodeInvalidJSONBody, "Invalid request body")
		return
	}

	email := strings.TrimSpace(req.Email)
	captchaCode := strings.TrimSpace(req.CaptchaCode)

	// 1. Strict Regex Validation
	if !emailRegex.MatchString(email) {
		respondError(c, http.StatusBadRequest, CodeInvalidEmail, "Invalid email format")
		return
	}
	if !captchaRegex.MatchString(captchaCode) {
		respondError(c, http.StatusBadRequest, CodeCaptchaInvalid, "Invalid captcha format")
		return
	}
	successMsg := "If the email is registered, a verification code has been sent."
	if utils.IsPlaceholderEmail(email) {
		respondOK(c, successMsg, nil)
		return
	}

	// 2. Captcha Verification
	captchaService := services.NewCaptchaService()
	if req.CaptchaToken == "" || !captchaService.Verify(req.CaptchaToken, captchaCode) {
		respondError(c, http.StatusBadRequest, CodeCaptchaInvalid, "Invalid or expired captcha")
		return
	}

	// 3. Check if email exists
	var user models.User
	err := database.DB.Where("email = ?", email).First(&user).Error

	// Always respond success to prevent email enumeration
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			respondOK(c, successMsg, nil)
			return
		}
		respondError(c, http.StatusInternalServerError, CodeInternalError, "Database error")
		return
	}
	if utils.IsPlaceholderEmail(user.Email) {
		respondOK(c, successMsg, nil)
		return
	}

	// 4. Generate and send 4-digit code
	codeStore := services.NewVerificationCodeStore()
	emailService := services.NewEmailService()

	code := codeStore.Generate4DigitCode()
	if !codeStore.Store(email, code) {
		respondError(c, http.StatusInternalServerError, CodeInternalError, "Failed to store verification code")
		return
	}

	subject := "Armorial - Password Recovery"
	message := "Your password recovery code is: " + code + "\n\nThe code is valid for 10 minutes. If you did not request this, please ignore this email."

	if err := emailService.SendMail(email, subject, message); err != nil {
		codeStore.Delete(email)
		respondError(c, http.StatusInternalServerError, CodeEmailSendFailed, "Failed to send recovery email")
		return
	}

	respondOK(c, successMsg, nil)
}

// ResetPassword handles POST /reset-password.
func (ac *AuthController) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, CodeInvalidJSONBody, "Invalid request body")
		return
	}

	email := strings.TrimSpace(req.Email)
	code := strings.TrimSpace(req.Code)

	// 1. Strict Regex Validation
	if !emailRegex.MatchString(email) {
		respondError(c, http.StatusBadRequest, CodeInvalidEmail, "Invalid email format")
		return
	}
	if !emailCodeRegex.MatchString(code) {
		respondError(c, http.StatusBadRequest, CodeVerificationCodeInvalid, "Invalid verification code format")
		return
	}

	if len(req.NewPassword) < 6 {
		respondError(c, http.StatusBadRequest, CodePasswordTooShort, "Password too short")
		return
	}

	if utils.IsPlaceholderEmail(email) {
		respondError(c, http.StatusBadRequest, CodeVerificationCodeInvalid, "Invalid or expired verification code")
		return
	}

	// 2. Verify Email Code
	codeStore := services.NewVerificationCodeStore()
	storedCode, found := codeStore.Get(email)
	if !found || storedCode != code {
		respondError(c, http.StatusBadRequest, CodeVerificationCodeInvalid, "Invalid or expired verification code")
		return
	}

	// 3. Update Password
	hash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		respondError(c, http.StatusInternalServerError, CodeInternalError, "Password hashing failed")
		return
	}

	result := database.DB.Model(&models.User{}).Where("email = ?", email).Update("password", hash)
	if result.Error != nil {
		respondError(c, http.StatusInternalServerError, CodeInternalError, "Failed to update password")
		return
	}

	if result.RowsAffected == 0 {
		respondError(c, http.StatusNotFound, CodeUserNotFound, "User not found")
		return
	}

	// 4. Cleanup
	codeStore.Delete(email)

	respondOK(c, "Password reset successful", nil)
}
