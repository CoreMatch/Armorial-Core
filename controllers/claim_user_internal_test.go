package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lnb/HRPAuth-Backend-Go/config"
	"github.com/lnb/HRPAuth-Backend-Go/database"
	"github.com/lnb/HRPAuth-Backend-Go/models"
	"github.com/lnb/HRPAuth-Backend-Go/services"
	"github.com/lnb/HRPAuth-Backend-Go/utils"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupClaimTestEnv prepares an in-memory sqlite users table, points
// database.DB at it, and configures a manage token so the ops-level auth
// check passes with a known bearer. It returns a router serving only the
// claim endpoint.
func setupClaimTestEnv(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "claim-test.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.CoreUserMigration{},
		&models.OAuth2AuthorizationCode{}, &models.OAuth2RefreshToken{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if err := db.Exec(`CREATE TABLE oauth2_access_tokens (
		id INTEGER PRIMARY KEY, access_token TEXT, client_id TEXT, user_id TEXT,
		scopes TEXT, subject_type TEXT, target_uid INTEGER, target_email TEXT,
		expires_at DATETIME, revoked_at DATETIME, created_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create access token table: %v", err)
	}
	database.DB = db

	config.AppConfig = &config.Config{}
	config.AppConfig.Manage.Token = "test-manage-token"

	r := gin.New()
	auth := NewAuthController()
	r.POST("/internal/claim-user", auth.ClaimUserInternal)
	r.GET("/internal/migrations/:migration_id", auth.MigrationStatusInternal)
	r.POST("/internal/migrations/:migration_id/rollback", auth.MigrationRollbackInternal)
	return r
}

func doClaimRequest(t *testing.T, r *gin.Engine, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/claim-user", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func doAuthRequest(t *testing.T, r *gin.Engine, token, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func doMigrationRequest(t *testing.T, r *gin.Engine, method, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func claimEnvelope(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return envelope
}

func TestClaimUserInternalCreatesVerifiedUser(t *testing.T) {
	r := setupClaimTestEnv(t)

	w := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"Steve@Example.com","password":"secret1"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var user models.User
	if err := database.DB.Where("username = ?", "steve").First(&user).Error; err != nil {
		t.Fatalf("user not persisted: %v", err)
	}
	if user.Email != "steve@example.com" {
		t.Fatalf("email not normalized: %q", user.Email)
	}
	if !user.Verified {
		t.Fatal("claimed user must be verified=true")
	}
	if user.Password == "secret1" {
		t.Fatal("password must be hashed")
	}
	envelope := claimEnvelope(t, w)
	if envelope["email"] != "steve@example.com" || envelope["created"] != true {
		t.Fatalf("claim response = %#v", envelope)
	}
}

func TestClaimUserInternalRejectsDuplicateEmail(t *testing.T) {
	r := setupClaimTestEnv(t)

	if err := database.DB.Create(&models.User{
		UID: 1, UUID: "aaaa", Email: "taken@example.com", Username: "other", Password: "x",
	}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	w := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"taken@example.com","password":"secret1"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", w.Code, w.Body.String())
	}
	if code, _ := claimEnvelope(t, w)["code"].(string); code != CodeEmailAlreadyRegistered {
		t.Fatalf("code = %q, want %q", code, CodeEmailAlreadyRegistered)
	}
}

func TestClaimUserInternalRejectsTakenUsernameWithOtherEmail(t *testing.T) {
	r := setupClaimTestEnv(t)

	if err := database.DB.Create(&models.User{
		UID: 1, UUID: "aaaa", Email: "owner@example.com", Username: "steve", Password: "x",
	}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	w := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"other@example.com","password":"secret1"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", w.Code, w.Body.String())
	}
	if code, _ := claimEnvelope(t, w)["code"].(string); code != CodeUsernameAlreadyBound {
		t.Fatalf("code = %q, want %q", code, CodeUsernameAlreadyBound)
	}
}

func TestClaimUserInternalIsIdempotentForSameUsernameAndEmail(t *testing.T) {
	r := setupClaimTestEnv(t)

	first := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"steve@example.com","password":"secret1"}`)
	if first.Code != http.StatusOK {
		t.Fatalf("first claim status = %d, body = %s", first.Code, first.Body.String())
	}

	second := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"steve@example.com","password":"secret1"}`)
	if second.Code != http.StatusOK {
		t.Fatalf("retry status = %d, body = %s", second.Code, second.Body.String())
	}

	var count int64
	database.DB.Model(&models.User{}).Where("username = ?", "steve").Count(&count)
	if count != 1 {
		t.Fatalf("user count = %d, want 1", count)
	}
	firstData := claimEnvelope(t, first)
	secondData := claimEnvelope(t, second)
	if firstData["created"] != true || secondData["created"] != false || firstData["uuid"] != secondData["uuid"] {
		t.Fatalf("idempotent claim responses = %#v, %#v", firstData, secondData)
	}
}

func TestClaimUserInternalCreatesPlaceholderMigrationUser(t *testing.T) {
	r := setupClaimTestEnv(t)
	migrationID := "00000000-0000-4000-8000-000000000001"
	body := `{"username":"steve","password":"secret1","migration_id":"` + migrationID + `","email_mode":"placeholder"}`

	w := doClaimRequest(t, r, "test-manage-token", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	envelope := claimEnvelope(t, w)
	email := "migration-" + migrationID + "@placeholder.invalid"
	if envelope["email"] != email || envelope["created"] != true {
		t.Fatalf("claim response = %#v", envelope)
	}

	var user models.User
	if err := database.DB.Where("username = ?", "steve").First(&user).Error; err != nil {
		t.Fatalf("user not persisted: %v", err)
	}
	if user.Email != email || user.Verified || !utils.CheckPasswordHash("secret1", user.Password) {
		t.Fatalf("placeholder user = %+v", user)
	}
	var journal models.CoreUserMigration
	if err := database.DB.Where("migration_id = ?", migrationID).First(&journal).Error; err != nil {
		t.Fatalf("migration journal missing: %v", err)
	}
	if journal.Status != "created" || journal.Ownership != "created_by_migration" || journal.UID != user.UID || journal.UUID != user.UUID {
		t.Fatalf("migration journal = %+v", journal)
	}
}

func TestClaimUserInternalMigrationRetryIsIdempotent(t *testing.T) {
	r := setupClaimTestEnv(t)
	body := `{"username":"steve","email":"steve@example.com","password":"secret1","migration_id":"00000000-0000-4000-8000-000000000001"}`

	first := doClaimRequest(t, r, "test-manage-token", body)
	second := doClaimRequest(t, r, "test-manage-token", body)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("claim statuses = %d, %d", first.Code, second.Code)
	}
	firstData := claimEnvelope(t, first)
	secondData := claimEnvelope(t, second)
	if firstData["created"] != true || secondData["created"] != false || firstData["uuid"] != secondData["uuid"] {
		t.Fatalf("migration retry responses = %#v, %#v", firstData, secondData)
	}
	var count int64
	database.DB.Model(&models.User{}).Where("username = ?", "steve").Count(&count)
	if count != 1 {
		t.Fatalf("user count = %d, want 1", count)
	}
}

func TestClaimUserInternalRejectsMigrationIdentityReuse(t *testing.T) {
	r := setupClaimTestEnv(t)
	first := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"steve@example.com","password":"secret1","migration_id":"00000000-0000-4000-8000-000000000001"}`)
	if first.Code != http.StatusOK {
		t.Fatalf("first claim status = %d, body = %s", first.Code, first.Body.String())
	}

	conflict := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"other@example.com","password":"secret1","migration_id":"00000000-0000-4000-8000-000000000001"}`)
	if conflict.Code != http.StatusConflict || claimEnvelope(t, conflict)["code"] != CodeMigrationConflict {
		t.Fatalf("identity reuse response = %d %s", conflict.Code, conflict.Body.String())
	}
}

func TestClaimUserInternalRecordsPreexistingMigrationUser(t *testing.T) {
	r := setupClaimTestEnv(t)
	if err := database.DB.Create(&models.User{
		UID: 7, UUID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Email: "steve@example.com", Username: "steve", Password: "hash", Verified: true,
	}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	w := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"steve@example.com","password":"secret1","migration_id":"00000000-0000-4000-8000-000000000001"}`)
	if w.Code != http.StatusOK || claimEnvelope(t, w)["created"] != false {
		t.Fatalf("preexisting claim = %d %s", w.Code, w.Body.String())
	}
	var journal models.CoreUserMigration
	if err := database.DB.Where("migration_id = ?", "00000000-0000-4000-8000-000000000001").First(&journal).Error; err != nil {
		t.Fatalf("migration journal missing: %v", err)
	}
	if journal.Status != "not_created" || journal.Ownership != "preexisting" || journal.UID != 7 {
		t.Fatalf("preexisting journal = %+v", journal)
	}
}

func TestClaimUserInternalRejectsRolledBackMigrationID(t *testing.T) {
	r := setupClaimTestEnv(t)
	migrationID := "00000000-0000-4000-8000-000000000001"
	if err := database.DB.Create(&models.CoreUserMigration{
		MigrationID: migrationID, Email: "steve@example.com", Username: "steve", Ownership: "created_by_migration", Status: "rolled_back",
	}).Error; err != nil {
		t.Fatalf("seed migration: %v", err)
	}

	w := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"steve@example.com","password":"secret1","migration_id":"`+migrationID+`"}`)
	if w.Code != http.StatusConflict || claimEnvelope(t, w)["code"] != CodeMigrationInvalidState {
		t.Fatalf("rolled-back claim = %d %s", w.Code, w.Body.String())
	}
}

func TestClaimUserInternalRequiresOpsAuth(t *testing.T) {
	r := setupClaimTestEnv(t)

	w := doClaimRequest(t, r, "", `{"username":"steve","email":"s@example.com","password":"secret1"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestClaimUserInternalValidation(t *testing.T) {
	r := setupClaimTestEnv(t)

	cases := []struct {
		name     string
		body     string
		wantCode string
	}{
		{"short username", `{"username":"ab","email":"a@example.com","password":"secret1"}`, CodeUsernameTooShort},
		{"invalid email", `{"username":"steve","email":"not-an-email","password":"secret1"}`, CodeInvalidEmail},
		{"short password", `{"username":"steve","email":"a@example.com","password":"123"}`, CodePasswordTooShort},
		{"missing email", `{"username":"steve","password":"secret1"}`, CodeInvalidEmail},
		{"invalid email mode", `{"username":"steve","email":"a@example.com","password":"secret1","email_mode":"other"}`, CodeInvalidRequest},
		{"placeholder without migration", `{"username":"steve","password":"secret1","email_mode":"placeholder"}`, CodeInvalidRequest},
		{"placeholder with email", `{"username":"steve","email":"a@example.com","password":"secret1","migration_id":"00000000-0000-4000-8000-000000000001","email_mode":"placeholder"}`, CodeInvalidRequest},
		{"invalid migration ID", `{"username":"steve","email":"a@example.com","password":"secret1","migration_id":"invalid"}`, CodeInvalidRequest},
		{"reserved placeholder address", `{"username":"steve","email":"migration-test@placeholder.invalid","password":"secret1"}`, CodeInvalidEmail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doClaimRequest(t, r, "test-manage-token", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
			}
			if code, _ := claimEnvelope(t, w)["code"].(string); code != tc.wantCode {
				t.Fatalf("code = %q, want %q", code, tc.wantCode)
			}
		})
	}
}

func TestPlaceholderAccountsCannotUseEmailRecovery(t *testing.T) {
	r := setupClaimTestEnv(t)
	codeDir := t.TempDir()
	config.AppConfig.VerificationCode = config.VerificationCodeConfig{CodeTTL: 600, StorageDir: codeDir}
	ac := NewAuthController()
	r.POST("/register", ac.Register)
	r.POST("/forgot-password", ac.ForgotPassword)
	r.POST("/reset-password", ac.ResetPassword)
	r.POST("/internal/user-exists", ac.UserExists)
	r.POST("/email-verification", NewEmailVerificationController().Handle)

	placeholder := "migration-00000000-0000-4000-8000-000000000001@placeholder.invalid"
	passwordHash, err := utils.HashPassword("secret1")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := database.DB.Create(&models.User{
		UID: 1, UUID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Email: placeholder, Username: "steve", Password: passwordHash,
	}).Error; err != nil {
		t.Fatalf("seed placeholder user: %v", err)
	}

	assertNoCodes := func(t *testing.T) {
		t.Helper()
		entries, err := os.ReadDir(codeDir)
		if err != nil {
			t.Fatalf("read code directory: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("placeholder flow persisted verification codes: %v", entries)
		}
	}

	t.Run("forgot password is generic success without mail", func(t *testing.T) {
		w := doAuthRequest(t, r, "", "/forgot-password", `{"email":"`+placeholder+`","captcha_token":"unused","captcha_code":"ABCD"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		assertNoCodes(t)
	})

	t.Run("reset password cannot update credentials", func(t *testing.T) {
		w := doAuthRequest(t, r, "", "/reset-password", `{"email":"`+placeholder+`","code":"1234","new_password":"secret2"}`)
		if w.Code != http.StatusBadRequest || claimEnvelope(t, w)["code"] != CodeVerificationCodeInvalid {
			t.Fatalf("reset response = %d %s", w.Code, w.Body.String())
		}
		var user models.User
		if err := database.DB.First(&user, 1).Error; err != nil {
			t.Fatalf("reload user: %v", err)
		}
		if !utils.CheckPasswordHash("secret1", user.Password) || utils.CheckPasswordHash("secret2", user.Password) {
			t.Fatal("placeholder password changed")
		}
	})

	t.Run("mail capability check reports false", func(t *testing.T) {
		w := doAuthRequest(t, r, "test-manage-token", "/internal/user-exists", `{"email":"`+placeholder+`"}`)
		if w.Code != http.StatusOK || userExistsFlag(t, w) {
			t.Fatalf("user-exists response = %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("public registration rejects reserved namespace", func(t *testing.T) {
		w := doAuthRequest(t, r, "", "/register", `{"username":"intruder","email":"MIGRATION-x@PLACEHOLDER.INVALID","password":"secret1"}`)
		if w.Code != http.StatusBadRequest || claimEnvelope(t, w)["code"] != CodeInvalidEmail {
			t.Fatalf("register response = %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("verification mail cannot target placeholder", func(t *testing.T) {
		w := doAuthRequest(t, r, "", "/email-verification", `{"action":"send-verification-code","email":"`+placeholder+`"}`)
		if w.Code != http.StatusBadRequest || claimEnvelope(t, w)["code"] != CodeInvalidEmail {
			t.Fatalf("verification response = %d %s", w.Code, w.Body.String())
		}
		assertNoCodes(t)
		if err := services.NewEmailService().SendMail(placeholder, "subject", "message"); err == nil {
			t.Fatal("mail service accepted a placeholder recipient")
		}
	})
}

func TestMigrationStatusInternalReportsCreatedUser(t *testing.T) {
	r := setupClaimTestEnv(t)
	migrationID := "00000000-0000-4000-8000-000000000001"
	claim := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","password":"secret1","migration_id":"`+migrationID+`","email_mode":"placeholder"}`)
	if claim.Code != http.StatusOK {
		t.Fatalf("claim = %d %s", claim.Code, claim.Body.String())
	}

	w := doMigrationRequest(t, r, http.MethodGet, "test-manage-token", "/internal/migrations/"+migrationID)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d %s", w.Code, w.Body.String())
	}
	data := claimEnvelope(t, w)["data"].(map[string]any)
	user := data["user"].(map[string]any)
	if data["status"] != "created" || data["ownership"] != "created_by_migration" || user["present"] != true || user["username"] != "steve" {
		t.Fatalf("unexpected status: %#v", data)
	}
}

func TestMigrationRollbackInternalCompensatesCreatedUserAndIsIdempotent(t *testing.T) {
	r := setupClaimTestEnv(t)
	migrationID := "00000000-0000-4000-8000-000000000001"
	claim := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","password":"secret1","migration_id":"`+migrationID+`","email_mode":"placeholder"}`)
	if claim.Code != http.StatusOK {
		t.Fatalf("claim = %d %s", claim.Code, claim.Body.String())
	}
	var user models.User
	if err := database.DB.Where("username = ?", "steve").First(&user).Error; err != nil {
		t.Fatal(err)
	}
	uid := user.UUID
	if err := database.DB.Create(&models.OAuth2AuthorizationCode{Code: "code", UserID: uid}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Create(&models.OAuth2AccessToken{AccessToken: "access", UserID: &uid}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Create(&models.OAuth2RefreshToken{RefreshToken: "refresh", UserID: uid}).Error; err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		w := doMigrationRequest(t, r, http.MethodPost, "test-manage-token", "/internal/migrations/"+migrationID+"/rollback")
		if w.Code != http.StatusOK {
			t.Fatalf("rollback attempt %d = %d %s", attempt, w.Code, w.Body.String())
		}
		data := claimEnvelope(t, w)["data"].(map[string]any)
		if data["status"] != "rolled_back" {
			t.Fatalf("rollback data = %#v", data)
		}
	}

	for _, model := range []any{&models.User{}, &models.OAuth2AuthorizationCode{}, &models.OAuth2AccessToken{}, &models.OAuth2RefreshToken{}} {
		var count int64
		if err := database.DB.Model(model).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%T count = %d, want 0", model, count)
		}
	}
	var journal models.CoreUserMigration
	if err := database.DB.Where("migration_id = ?", migrationID).First(&journal).Error; err != nil {
		t.Fatal(err)
	}
	if journal.Status != "rolled_back" || journal.RolledBackAt == nil {
		t.Fatalf("journal = %+v", journal)
	}
	status := doMigrationRequest(t, r, http.MethodGet, "test-manage-token", "/internal/migrations/"+migrationID)
	data := claimEnvelope(t, status)["data"].(map[string]any)
	if data["user"].(map[string]any)["present"] != false {
		t.Fatalf("rolled-back status = %#v", data)
	}
}

func TestMigrationRollbackInternalPreservesPreexistingUser(t *testing.T) {
	r := setupClaimTestEnv(t)
	migrationID := "00000000-0000-4000-8000-000000000001"
	if err := database.DB.Create(&models.User{
		UID: 7, UUID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Email: "steve@example.com", Username: "steve", Password: "hash",
	}).Error; err != nil {
		t.Fatal(err)
	}
	claim := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"steve@example.com","password":"secret1","migration_id":"`+migrationID+`"}`)
	if claim.Code != http.StatusOK {
		t.Fatalf("claim = %d %s", claim.Code, claim.Body.String())
	}

	w := doMigrationRequest(t, r, http.MethodPost, "test-manage-token", "/internal/migrations/"+migrationID+"/rollback")
	if w.Code != http.StatusConflict || claimEnvelope(t, w)["code"] != CodeMigrationRollbackNotAllowed {
		t.Fatalf("rollback = %d %s", w.Code, w.Body.String())
	}
	var count int64
	if err := database.DB.Model(&models.User{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("preexisting user count = %d, want 1", count)
	}
}

func TestMigrationRollbackInternalRejectsIdentityMismatch(t *testing.T) {
	r := setupClaimTestEnv(t)
	migrationID := "00000000-0000-4000-8000-000000000001"
	claim := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","email":"steve@example.com","password":"secret1","migration_id":"`+migrationID+`"}`)
	if claim.Code != http.StatusOK {
		t.Fatalf("claim = %d %s", claim.Code, claim.Body.String())
	}
	if err := database.DB.Model(&models.User{}).Where("username = ?", "steve").Update("email", "changed@example.com").Error; err != nil {
		t.Fatal(err)
	}

	w := doMigrationRequest(t, r, http.MethodPost, "test-manage-token", "/internal/migrations/"+migrationID+"/rollback")
	if w.Code != http.StatusConflict || claimEnvelope(t, w)["code"] != CodeMigrationRollbackNotAllowed {
		t.Fatalf("rollback = %d %s", w.Code, w.Body.String())
	}
	var user models.User
	if err := database.DB.Where("username = ?", "steve").First(&user).Error; err != nil {
		t.Fatalf("mismatched user was removed: %v", err)
	}
}

func TestMigrationRollbackInternalRejectsReusedUID(t *testing.T) {
	r := setupClaimTestEnv(t)
	migrationID := "00000000-0000-4000-8000-000000000001"
	claim := doClaimRequest(t, r, "test-manage-token",
		`{"username":"steve","password":"secret1","migration_id":"`+migrationID+`","email_mode":"placeholder"}`)
	if claim.Code != http.StatusOK {
		t.Fatalf("claim = %d %s", claim.Code, claim.Body.String())
	}
	var journal models.CoreUserMigration
	if err := database.DB.Where("migration_id = ?", migrationID).First(&journal).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Where("uuid = ?", journal.UUID).Delete(&models.User{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Create(&models.User{
		UID: journal.UID, UUID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Email: "other@example.com", Username: "other",
	}).Error; err != nil {
		t.Fatal(err)
	}

	w := doMigrationRequest(t, r, http.MethodPost, "test-manage-token", "/internal/migrations/"+migrationID+"/rollback")
	if w.Code != http.StatusConflict || claimEnvelope(t, w)["code"] != CodeMigrationRollbackNotAllowed {
		t.Fatalf("rollback = %d %s", w.Code, w.Body.String())
	}
	var replacement models.User
	if err := database.DB.Where("uid = ?", journal.UID).First(&replacement).Error; err != nil {
		t.Fatalf("replacement user was removed: %v", err)
	}
}

func TestMigrationInternalEndpointsValidationAndAuth(t *testing.T) {
	r := setupClaimTestEnv(t)
	migrationID := "00000000-0000-4000-8000-000000000001"

	if w := doMigrationRequest(t, r, http.MethodGet, "", "/internal/migrations/"+migrationID); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", w.Code)
	}
	if w := doMigrationRequest(t, r, http.MethodPost, "", "/internal/migrations/"+migrationID+"/rollback"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized rollback = %d", w.Code)
	}
	if w := doMigrationRequest(t, r, http.MethodGet, "test-manage-token", "/internal/migrations/not-a-uuid"); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid status ID = %d", w.Code)
	}
	if w := doMigrationRequest(t, r, http.MethodPost, "test-manage-token", "/internal/migrations/not-a-uuid/rollback"); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid rollback ID = %d", w.Code)
	}
	if w := doMigrationRequest(t, r, http.MethodGet, "test-manage-token", "/internal/migrations/"+migrationID); w.Code != http.StatusNotFound || claimEnvelope(t, w)["code"] != CodeMigrationNotFound {
		t.Fatalf("missing status = %d %s", w.Code, w.Body.String())
	}
	if w := doMigrationRequest(t, r, http.MethodPost, "test-manage-token", "/internal/migrations/"+migrationID+"/rollback"); w.Code != http.StatusNotFound || claimEnvelope(t, w)["code"] != CodeMigrationNotFound {
		t.Fatalf("missing rollback = %d %s", w.Code, w.Body.String())
	}
}
