package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// --- Colors for Terminal Output ---
const (
	ColorReset  = "\033[0m"
	ColorClient = "\033[36m" // Cyan
	ColorServer = "\033[32m" // Green
	ColorAttacker = "\033[31m" // Red (Unused in secure flow, but good for context)
	ColorInfo   = "\033[33m" // Yellow
)

// --- Protocol Messages ---

type ClientHello struct {
	MsgType  string
	KeyShare []byte // Client's Ephemeral ML-KEM Public Key
}

type ServerHello struct {
	MsgType    string
	KeyShare   []byte // Server's ML-KEM Ciphertext
	StaticCert []byte // Server's Static ML-DSA Public Key
}

type CertificateVerify struct {
	MsgType   string
	Signature []byte // Signed Transcript Hash
}

// --- SIMULATED PQC PRIMITIVES (Wrappers to demonstrate flow) ---

// Simulate_MLKEM_KeyGen returns (pk, sk)
func Simulate_MLKEM_KeyGen() ([]byte, []byte) {
	// In reality: this involves lattice generation.
	// For demo: we generate random bytes to simulate keys.
	pk := make([]byte, 32)
	sk := make([]byte, 32)
	rand.Read(pk)
	rand.Read(sk)
	return pk, sk
}

// Simulate_MLKEM_Encaps returns (ciphertext, shared_secret)
func Simulate_MLKEM_Encaps(peerPubKey []byte) ([]byte, []byte) {
	// In reality: Encapsulates randomness against peerPubKey.
	ciphertext := make([]byte, 32)
	rand.Read(ciphertext)
	
	// We derive a secret "bound" to the ciphertext for this demo
	hash := sha256.Sum256(append(peerPubKey, ciphertext...))
	return ciphertext, hash[:]
}

// Simulate_MLKEM_Decaps returns shared_secret
func Simulate_MLKEM_Decaps(myPrivKey []byte, ciphertext []byte) []byte {
	// In reality: Decrypts ciphertext using myPrivKey.
	// For demo: We recreate the hash done in Encaps (simulating successful math)
	// Note: In a real simulation we'd need the matching public key here, 
	// but for this logic flow, we assume mathematical correctness.
	
	// To make the demo work "mathematically" without real lattice libs,
	// we cheat slightly by assuming the client knows their own pubkey 
	// corresponding to 'myPrivKey' to generate the matching hash.
	// In real ML-KEM, Decaps only needs sk and ct.
	// We will pass the 'derived secret' via a side channel or just trust the flow 
	// for the specific purpose of showing the AUTHENTICATION logic.
	
	// *Hack for Demo*: We won't re-calculate the secret here because we want 
	// to focus on the SIGNATURE verification. Let's assume the secret is established.
	return []byte("SHARED_SECRET_ESTABLISHED") 
}

// --- The Actors ---

func runClient(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()
	
	prefix := ColorClient + "[CLIENT]" + ColorReset
	
	fmt.Printf("%s Starting Handshake...\n", prefix)
	
	// 1. Initialize Transcript Hash
	transcript := sha256.New()

	// 2. Generate Ephemeral Keys (ML-KEM)
	pk_client, sk_client := Simulate_MLKEM_KeyGen()
	fmt.Printf("%s Generated Ephemeral ML-KEM Keypair.\n   PK: %x...\n", prefix, pk_client[:4])

	// 3. Send ClientHello
	ch := ClientHello{MsgType: "ClientHello", KeyShare: pk_client}
	chBytes, _ := json.Marshal(ch)
	
	// Update Transcript
	transcript.Write(chBytes)
	
	// Send
	fmt.Printf("%s Sending ClientHello...\n", prefix)
	enc := json.NewEncoder(conn)
	enc.Encode(ch)

	// 4. Receive ServerHello
	var sh ServerHello
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&sh); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s Received ServerHello.\n   Ciphertext: %x...\n   Server Static ID: %x...\n", prefix, sh.KeyShare[:4], sh.StaticCert[:4])

	// Update Transcript with what we received
	shBytes, _ := json.Marshal(sh)
	transcript.Write(shBytes)

	// 5. Derive Secret (ML-KEM Decaps)
	ss := Simulate_MLKEM_Decaps(sk_client, sh.KeyShare)
	fmt.Printf("%s Decapsulated Shared Secret: %s\n", prefix, ss)

	// 6. Receive CertificateVerify
	var cv CertificateVerify
	if err := dec.Decode(&cv); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s Received CertificateVerify (Signature).\n", prefix)

	// 7. Verify Signature
	// CRITICAL STEP: The client checks if the signature matches the Transcript Hash
	currentTranscriptHash := transcript.Sum(nil)
	fmt.Printf("%s Calculated Local Transcript Hash: %x...\n", prefix, currentTranscriptHash[:8])

	// Using Ed25519 to verify (Simulating ML-DSA Verify)
	isValid := ed25519.Verify(sh.StaticCert, currentTranscriptHash, cv.Signature)

	if isValid {
		fmt.Printf("%s %sSUCCESS: Signature Validated! Connection Secure.%s\n", prefix, ColorServer, ColorReset)
		fmt.Printf("%s The keys exchanged are bound to the Server's Identity.\n", prefix)
	} else {
		fmt.Printf("%s %sALERT: Signature Validation Failed! Possible MiTM.%s\n", prefix, ColorAttacker, ColorReset)
	}
}

func runServer(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	prefix := ColorServer + "[SERVER]" + ColorReset

	// 0. Server Static Identity (ML-DSA) setup
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	fmt.Printf("%s Booted. Loaded Static ML-DSA Identity: %x...\n", prefix, pubKey[:4])

	// 1. Initialize Transcript
	transcript := sha256.New()

	// 2. Receive ClientHello
	var ch ClientHello
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&ch); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s Received ClientHello.\n   Client PK: %x...\n", prefix, ch.KeyShare[:4])

	// Update Transcript
	chBytes, _ := json.Marshal(ch)
	transcript.Write(chBytes)

	// 3. Encapsulate (ML-KEM)
	// We use the Client's public key from the message
	ciphertext, _ := Simulate_MLKEM_Encaps(ch.KeyShare)
	fmt.Printf("%s Encapsulated Shared Secret against Client PK.\n", prefix)

	// 4. Send ServerHello
	sh := ServerHello{
		MsgType:    "ServerHello",
		KeyShare:   ciphertext,
		StaticCert: pubKey, // Sending our ID
	}
	shBytes, _ := json.Marshal(sh)
	
	// Update Transcript BEFORE sending (Standard practice vary, but usually included)
	transcript.Write(shBytes)

	fmt.Printf("%s Sending ServerHello (Ciphertext + ID).\n", prefix)
	enc := json.NewEncoder(conn)
	enc.Encode(sh)

	// 5. Sign the Transcript (Authentication)
	// This proves that the entity who saw ClientHello and generated ServerHello
	// owns the private key.
	currentTranscriptHash := transcript.Sum(nil)
	fmt.Printf("%s Signing Transcript Hash: %x...\n", prefix, currentTranscriptHash[:8])
	
	signature := ed25519.Sign(privKey, currentTranscriptHash)

	// 6. Send CertificateVerify
	cv := CertificateVerify{
		MsgType:   "CertificateVerify",
		Signature: signature,
	}
	fmt.Printf("%s Sending CertificateVerify.\n", prefix)
	enc.Encode(cv)
}

func main() {
	fmt.Println("---------------------------------------------------------")
	fmt.Println("  TLS 1.3 Hybrid PQC Handshake Demo (Go Simulation)")
	fmt.Println("  Goal: Prevent MiTM using ML-KEM + ML-DSA")
	fmt.Println("---------------------------------------------------------")

	// Create an in-memory network pipe (simulating TCP)
	clientConn, serverConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(2)

	// Start Server Process
	go runServer(serverConn, &wg)

	// Start Client Process (slight delay to ensure server is ready in logs)
	time.Sleep(100 * time.Millisecond)
	go runClient(clientConn, &wg)

	wg.Wait()
	fmt.Println("---------------------------------------------------------")
	fmt.Println("Demo Complete.")
}
