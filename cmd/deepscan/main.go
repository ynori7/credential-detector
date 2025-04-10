package main

import (
	"fmt"
	"log"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/parser"
	"github.com/ynori7/credential-detector/printer"
)

func main() {
	// Load the configuration
	conf, err := config.New()
	if err != nil {
		log.Fatal(err.Error())
	}

	if conf.DisableOutputColors {
		printer.DisableColors()
	}

	// Open the repository
	repo, commitIter, refHash := openGitRepo(config.ScanPath)

	// Iterate over the commits
	err = commitIter.ForEach(func(c *object.Commit) error {
		// Check out the commit
		fmt.Printf("Checking out commit: %s\n", c.Hash.String())

		// Checkout commit
		worktree, err := checkoutCommit(repo, c.Hash)
		if err != nil {
			return err
		}

		// Do the scan
		p := parser.NewParser(conf)
		if err := p.Scan(config.ScanPath); err != nil {
			log.Fatal(err.Error())
		}

		if len(p.Results) > 0 {
			fmt.Printf("Found %d results in commit %s:\n", len(p.Results), c.Hash.String())
			printer.PrintResults(p.Results)
			fmt.Printf("\n\n")
		} else {
			fmt.Printf("No results found in commit %s\n", c.Hash.String())
		}

		// Reset the working directory to the original state
		if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: refHash}); err != nil {
			return fmt.Errorf("failed to reset working directory: %v", err)
		}

		return nil
	})

	if err != nil {
		log.Fatalf("Error iterating over commits: %v", err)
	}
}

func openGitRepo(path string) (*git.Repository, object.CommitIter, plumbing.Hash) {
	// Open the repository
	repo, err := git.PlainOpen(path)
	if err != nil {
		log.Fatalf("Failed to open repository: %v", err)
	}

	// Get the reference to the HEAD
	ref, err := repo.Reference(plumbing.HEAD, true)
	if err != nil {
		log.Fatalf("Failed to get HEAD reference: %v", err)
	}

	// Get the commit object for the HEAD
	commitIter, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		log.Fatalf("Failed to get commit log: %v", err)
	}

	return repo, commitIter, ref.Hash()
}

func checkoutCommit(repo *git.Repository, commitHash plumbing.Hash) (*git.Worktree, error) {
	// Create a new worktree for each commit
	worktree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("failed to get worktree: %v", err)
	}

	// Checkout the commit
	checkoutOptions := &git.CheckoutOptions{
		Hash: commitHash,
		// Do not create a new branch, just check out the commit
		Create: false,
	}

	if err := worktree.Checkout(checkoutOptions); err != nil {
		return nil, fmt.Errorf("failed to checkout commit %s: %v", commitHash.String(), err)
	}

	return worktree, nil
}
