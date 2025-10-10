package healthcheck

import (
	"errors"
	"runtime"

	"go-rest-api/internal/common/logger"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Service defines health check operations.
type Service interface {
	DatabaseCheck() error
	MemoryCheck() error
}

type service struct {
	log *logrus.Logger
	db  *gorm.DB
}

// NewService creates a new health check service instance.
func NewService(db *gorm.DB) Service {
	return &service{
		log: logger.Log,
		db:  db,
	}
}

// DatabaseCheck verifies database connectivity.
func (s *service) DatabaseCheck() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		s.log.Errorf("Failed to access database connection pool: %v", err)
		return err
	}

	if err := sqlDB.Ping(); err != nil {
		s.log.Errorf("Failed to ping database: %v", err)
		return err
	}

	return nil
}

// MemoryCheck verifies memory usage is within acceptable limits (300 MB threshold).
func (s *service) MemoryCheck() error {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	heapAlloc := memStats.HeapAlloc
	heapThreshold := uint64(300 * 1024 * 1024)

	s.log.Debugf("Heap memory allocation: %v bytes", heapAlloc)

	if heapAlloc > heapThreshold {
		s.log.Warnf("Heap memory usage exceeds threshold: %v bytes", heapAlloc)
		return errors.New("heap memory usage too high")
	}

	return nil
}
