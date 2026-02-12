package embedded_test

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/embedded"
)

// Example demonstrates how to embed an I2P router in your application.
// This shows the basic lifecycle: create, configure, start, wait, and cleanup.
func Test_Example(t *testing.T) {
	// This integration test requires network access for reseeding.
	// In CI or isolated environments, skip it.
	if os.Getenv("GO_I2P_INTEGRATION") == "" {
		t.Skip("skipping integration test; set GO_I2P_INTEGRATION=1 to run")
	}

	// Load default configuration
	cfg := config.DefaultRouterConfig()
	cfg.I2CP.Address = net.JoinHostPort("localhost", "19876")

	// Create the embedded router (auto-configures with the provided config)
	router, err := embedded.NewStandardEmbeddedRouter(cfg)
	if err != nil {
		log.Fatalf("Failed to create router: %v", err)
	}

	// Start the router
	if err := router.Start(); err != nil {
		log.Fatalf("Failed to start router: %v", err)
	}

	// In a real application, you would call router.Wait() here to block until shutdown is requested.
	// Calling Wait() is not necessary if you have other application logic that keeps the program running.
	// For this example, we'll just log that the router has started.
	log.Println("Router started successfully.")
	log.Println("I2CP is running on", cfg.I2CP.Address)
	// And make a quick connection to the I2CP port to demonstrate it's running.
	conn, err := net.Dial("tcp", cfg.I2CP.Address)
	if err != nil {
		log.Fatalf("Failed to connect to I2CP port: %v", err)
	}
	conn.Close()
	log.Println("Successfully connected to I2CP port.")
	// If you have additional application logic, run it here.
	// The key thing to remember is that the router is running in background goroutines until you call Stop() or HardStop().
	log.Println("Router is running. Proceeding to shutdown...")
	// For this test, we'll let it run briefly before stopping.
	time.Sleep(2 * time.Second)

	// Stop the router gracefully
	if err := router.Stop(); err != nil {
		log.Printf("Error during stop: %v", err)
	}

	// Clean up resources
	if err := router.Close(); err != nil {
		log.Printf("Error during cleanup: %v", err)
	}
}

// Example_withSignalHandling demonstrates how to embed an I2P router
// with proper signal handling for graceful shutdown.
func Example_withSignalHandling() {
	cfg := config.DefaultRouterConfig()

	// Create the embedded router (auto-configures with the provided config)
	router, err := embedded.NewStandardEmbeddedRouter(cfg)
	if err != nil {
		log.Fatalf("Failed to create router: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, initiating shutdown...", sig)

		// Attempt graceful shutdown
		if err := router.Stop(); err != nil {
			log.Printf("Error during graceful stop: %v", err)
			log.Println("Forcing immediate shutdown...")
			router.HardStop()
		}
	}()

	// Start the router
	log.Println("Starting I2P router...")
	if err := router.Start(); err != nil {
		log.Fatalf("Failed to start router: %v", err)
	}

	log.Println("Router started successfully. Press Ctrl+C to stop.")

	// Wait for the router to shut down
	// This blocks until Stop() or HardStop() is called
	router.Wait()

	log.Println("Router has stopped. Cleaning up...")

	// Clean up resources
	if err := router.Close(); err != nil {
		log.Printf("Error during cleanup: %v", err)
		os.Exit(1)
	}

	log.Println("Router closed successfully. Exiting.")
}
