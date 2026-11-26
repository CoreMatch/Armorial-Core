package services

import (
	"errors"
	"time"

	"github.com/lnb/HRPAuth-Backend-Go/database"
	"github.com/lnb/HRPAuth-Backend-Go/models"
	"github.com/lnb/HRPAuth-Backend-Go/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrMigrationConflict           = errors.New("migration_conflict")
	ErrMigrationInvalidState       = errors.New("migration_invalid_state")
	ErrMigrationNotFound           = errors.New("migration_not_found")
	ErrMigrationRollbackNotAllowed = errors.New("migration_rollback_not_allowed")
	ErrUsernameAlreadyBound        = errors.New("username_already_bound")
	ErrEmailAlreadyRegistered      = errors.New("email_already_registered")
)

type ClaimUserInput struct {
	Username    string
	Email       string
	Password    string
	MigrationID string
	Verified    bool
}

type ClaimUserResult struct {
	UID     uint
	UUID    string
	Email   string
	Created bool
}

type CoreMigrationUser struct {
	UID      uint   `json:"uid"`
	UUID     string `json:"uuid"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Present  bool   `json:"present"`
}

type MigrationStatusResult struct {
	MigrationID string             `json:"migration_id"`
	Status      string             `json:"status"`
	Ownership   string             `json:"ownership"`
	User        *CoreMigrationUser `json:"user,omitempty"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

type MigrationRollbackResult struct {
	MigrationID string `json:"migration_id"`
	Status      string `json:"status"`
	UID         uint   `json:"uid,omitempty"`
}

type MigrationService struct{}

func NewMigrationService() *MigrationService {
	return &MigrationService{}
}

func (s *MigrationService) ClaimUser(input ClaimUserInput) (ClaimUserResult, error) {
	hash, err := utils.HashPassword(input.Password)
	if err != nil {
		return ClaimUserResult{}, err
	}

	var result ClaimUserResult
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		if input.MigrationID != "" {
			journal := models.CoreUserMigration{
				MigrationID: input.MigrationID,
				Email:       input.Email,
				Username:    input.Username,
				Ownership:   "none",
				Status:      "not_created",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&journal).Error; err != nil {
				return err
			}
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("migration_id = ?", input.MigrationID).First(&journal).Error; err != nil {
				return err
			}
			if journal.Username != input.Username || journal.Email != input.Email {
				return ErrMigrationConflict
			}
			if journal.Status == "rolled_back" {
				return ErrMigrationInvalidState
			}
			if journal.Ownership != "none" {
				var err error
				result, err = existingMigrationUser(tx, journal)
				return err
			}
		}

		var existing models.User
		err := tx.Where("username = ?", input.Username).First(&existing).Error
		if err == nil {
			if existing.Email != input.Email {
				return ErrUsernameAlreadyBound
			}
			result = ClaimUserResult{UID: existing.UID, UUID: existing.UUID, Email: existing.Email}
			if input.MigrationID != "" {
				if err := tx.Model(&models.CoreUserMigration{}).Where("migration_id = ?", input.MigrationID).Updates(map[string]any{
					"uid": existing.UID, "uuid": existing.UUID, "ownership": "preexisting", "status": "not_created",
				}).Error; err != nil {
					return err
				}
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		var emailCount int64
		if err := tx.Model(&models.User{}).Where("email = ?", input.Email).Count(&emailCount).Error; err != nil {
			return err
		}
		if emailCount > 0 {
			return ErrEmailAlreadyRegistered
		}

		var maxUID uint
		if err := tx.Model(&models.User{}).Select("COALESCE(MAX(uid), 0)").Scan(&maxUID).Error; err != nil {
			return err
		}
		now := time.Now()
		user := models.User{
			UID:        maxUID + 1,
			UUID:       utils.GenerateUnsignedUUID(),
			Email:      input.Email,
			Username:   input.Username,
			Password:   hash,
			LastSignAt: &now,
			RegisterAt: &now,
			Verified:   input.Verified,
		}
		if len(user.UUID) != 32 {
			return errors.New("failed to generate user UUID")
		}
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		if input.MigrationID != "" {
			if err := tx.Model(&models.CoreUserMigration{}).Where("migration_id = ?", input.MigrationID).Updates(map[string]any{
				"uid": user.UID, "uuid": user.UUID, "ownership": "created_by_migration", "status": "created",
			}).Error; err != nil {
				return err
			}
		}
		result = ClaimUserResult{UID: user.UID, UUID: user.UUID, Email: user.Email, Created: true}
		return nil
	})
	return result, err
}

func existingMigrationUser(tx *gorm.DB, journal models.CoreUserMigration) (ClaimUserResult, error) {
	var user models.User
	if err := tx.Where("uuid = ?", journal.UUID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ClaimUserResult{}, ErrMigrationConflict
		}
		return ClaimUserResult{}, err
	}
	if user.UID != journal.UID || user.Email != journal.Email || user.Username != journal.Username {
		return ClaimUserResult{}, ErrMigrationConflict
	}
	return ClaimUserResult{UID: user.UID, UUID: user.UUID, Email: user.Email}, nil
}

func (s *MigrationService) Status(migrationID string) (MigrationStatusResult, error) {
	var journal models.CoreUserMigration
	if err := database.DB.Where("migration_id = ?", migrationID).First(&journal).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return MigrationStatusResult{}, ErrMigrationNotFound
		}
		return MigrationStatusResult{}, err
	}

	result := MigrationStatusResult{
		MigrationID: journal.MigrationID,
		Status:      journal.Status,
		Ownership:   journal.Ownership,
		UpdatedAt:   journal.UpdatedAt,
	}
	if journal.UUID != "" {
		result.User = &CoreMigrationUser{
			UID: journal.UID, UUID: journal.UUID, Email: journal.Email, Username: journal.Username,
		}
		var user models.User
		err := database.DB.Where("uuid = ?", journal.UUID).First(&user).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return MigrationStatusResult{}, err
		}
		if err == nil && user.DeletedAt == nil {
			result.User.UID = user.UID
			result.User.Email = user.Email
			result.User.Username = user.Username
			result.User.Present = true
		}
	}
	return result, nil
}

func (s *MigrationService) Rollback(migrationID string) (MigrationRollbackResult, error) {
	var result MigrationRollbackResult
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		var journal models.CoreUserMigration
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("migration_id = ?", migrationID).First(&journal).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrMigrationNotFound
			}
			return err
		}
		if journal.Ownership != "created_by_migration" {
			return ErrMigrationRollbackNotAllowed
		}
		if journal.Status != "created" && journal.Status != "rolled_back" {
			return ErrMigrationRollbackNotAllowed
		}
		if journal.UID == 0 || journal.UUID == "" || journal.Email == "" || journal.Username == "" {
			return ErrMigrationRollbackNotAllowed
		}

		var user models.User
		userErr := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("uuid = ?", journal.UUID).First(&user).Error
		if userErr != nil && !errors.Is(userErr, gorm.ErrRecordNotFound) {
			return userErr
		}
		if userErr == nil {
			if user.UID != journal.UID || user.Email != journal.Email || user.Username != journal.Username {
				return ErrMigrationRollbackNotAllowed
			}
			if journal.Status == "rolled_back" {
				return ErrMigrationRollbackNotAllowed
			}
		} else {
			var uidConflict models.User
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("uid = ?", journal.UID).First(&uidConflict).Error; err == nil {
				return ErrMigrationRollbackNotAllowed
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		}

		if err := tx.Where("user_id = ?", journal.UUID).Delete(&models.OAuth2AuthorizationCode{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", journal.UUID).Delete(&models.OAuth2AccessToken{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", journal.UUID).Delete(&models.OAuth2RefreshToken{}).Error; err != nil {
			return err
		}
		if userErr == nil {
			deletion := tx.Where("uuid = ? AND uid = ?", journal.UUID, journal.UID).Delete(&models.User{})
			if deletion.Error != nil {
				return deletion.Error
			}
			if deletion.RowsAffected != 1 {
				return ErrMigrationRollbackNotAllowed
			}
		}

		now := time.Now()
		if err := tx.Model(&models.CoreUserMigration{}).Where("migration_id = ?", migrationID).Updates(map[string]any{
			"status": "rolled_back", "rolled_back_at": now, "updated_at": now,
		}).Error; err != nil {
			return err
		}
		result = MigrationRollbackResult{MigrationID: migrationID, Status: "rolled_back", UID: journal.UID}
		return nil
	})
	return result, err
}
