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
	ErrMigrationConflict      = errors.New("migration_conflict")
	ErrMigrationInvalidState  = errors.New("migration_invalid_state")
	ErrUsernameAlreadyBound   = errors.New("username_already_bound")
	ErrEmailAlreadyRegistered = errors.New("email_already_registered")
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
