// git-lfs-authenticate
// Author: Christoph Hack <chack@mgit.at>
// (c) 2016 mgIT GmbH. All rights reserved.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Response struct {
	Header map[string]string `json:"header,omitempty"`
	HRef   string            `json:"href,omitempty"`
}

type Config struct {
	Secret string `json:secret,omitempty`
	HRef   string `json:"href,omitempty"`
}

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Fprintf(os.Stderr, "Usage: git-lfs-authenticate <repo> <operation> [oid]\n")
		os.Exit(1)
	}

	gitolitePath, err := exec.LookPath("gitolite")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to find gitolite command:", err)
		os.Exit(1)
	}

	var cfg Config
	file, err := os.Open(os.ExpandEnv("${HOME}/.git-lfs-authenticate"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to open config file:", err)
		os.Exit(1)
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to decode config:", err)
		os.Exit(1)
	}

	secret, err := base64.StdEncoding.DecodeString(cfg.Secret)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to decode secret key:", err)
		os.Exit(1)
	}

	repo := strings.TrimSpace(os.Args[1])
	if repo == "" {
		fmt.Fprintf(os.Stderr, "Error: invalid repo name %q\n", repo)
		os.Exit(1)
	}

	operation := strings.TrimSpace(os.Args[2])
	if operation != "upload" && operation != "download" {
		fmt.Fprintf(os.Stderr, "Error: invalid operation %q\n. Expected \"upload\" or \"download\".\n", operation)
		os.Exit(1)
	}

	if len(os.Args) >= 4 {
		data, err := hex.DecodeString(os.Args[3])
		if err != nil || len(data) != 32 {
			fmt.Fprintf(os.Stderr, "Error: invalid OID %q.\n", os.Args[3])
			os.Exit(1)
		}
	}

	user := strings.TrimSpace(os.Getenv("GL_USER"))
	if user == "" {
		fmt.Fprintln(os.Stderr, "Error: missing GL_USER environment variable.")
		os.Exit(1)
	}

	perm := "R"
	if operation == "upload" {
		perm = "W"
	}
	err = exec.Command(gitolitePath, "access", "-q", repo, user, perm).Run()
	if _, ok := err.(*exec.ExitError); ok {
		fmt.Fprintln(os.Stderr, "Error: LFS access denied!")
		os.Exit(1)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to check access:", err)
		os.Exit(1)
	}

	now := time.Now().UTC()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
		"repo": repo,
		"op":   operation,
		"exp":  now.Add(5 * time.Minute).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(secret)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to sign token:", err)
		os.Exit(1)
	}

	_ = tokenString

	resp := Response{
		Header: map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", tokenString),
		},
		HRef: cfg.HRef,
	}

	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(resp); err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to encode response:", err)
		os.Exit(1)
	}

	buf.WriteTo(os.Stdout)
}
