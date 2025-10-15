package healthcheck

import (
	"errors"
	"runtime"

	"go-rest-api/internal/common/logger"

	"gorm.io/gorm"
)

// Service defines health check operations.
type Service interface {
	DatabaseCheck() error
	MemoryCheck() error
}

type service struct {
	log *logger.Logger
	db  *gorm.DB
}

// NewService creates a new health check service instance.
func NewService(db *gorm.DB) Service {
	return &service{
		log: logger.New(),
		db:  db,
	}
}

// DatabaseCheck verifies database connectivity.
func (s *service) DatabaseCheck() error {
	if s.db == nil {
		s.log.Errorf("Database connection is nil")
		return errors.New("database connection is nil")
	}

	sqlDB, err := s.db.DB()
	if err != nil {
		s.log.Errorf("Failed to access database connection pool: %v", err)
		return err
	}

	if pingErr := sqlDB.Ping(); pingErr != nil {
		s.log.Errorf("Failed to ping database: %v", pingErr)
		return pingErr
	}

	return nil
}

// MemoryCheck verifies memory usage is within acceptable limits (300 MB threshold).
func (s *service) MemoryCheck() error {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	heapAlloc := memStats.HeapAlloc
	const (
		heapThresholdMB      = 300
		bytesPerKilobyte     = 1024
		kilobytesPerMegabyte = 1024
	)
	heapThreshold := uint64(heapThresholdMB * kilobytesPerMegabyte * bytesPerKilobyte)

	s.log.Debugf("Heap memory allocation: %v bytes", heapAlloc)

	if heapAlloc > heapThreshold {
		s.log.Warnf("Heap memory usage exceeds threshold: %v bytes", heapAlloc)
		return errors.New("heap memory usage too high")
	}

	return nil
}
