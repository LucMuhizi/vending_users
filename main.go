package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"errors"
	"regexp"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
	Deposit  int       `json:"deposit"`
	Role     string    `json:"role"` // "seller" or "buyer"
}

type Product struct {
	ID              uuid.UUID `json:"id"`
	ProductName     string    `json:"productName"`
	Cost            float64   `json:"cost"` // Updated to float64 to handle decimals
	AmountAvailable int       `json:"amountAvailable"`
	SellerEmail     string    `json:"sellerEmail"`
}

type ErrorResponse struct {
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	Field        string `json:"field,omitempty"`
}

var (
	users     = make(map[string]User) // Key is now email
	userMutex = &sync.Mutex{}
)

var (
	products     = make(map[string]Product) // Key is ProductName
	productMutex = &sync.Mutex{}
)

var validCoins = map[int]bool{
	5:   true,
	10:  true,
	20:  true,
	50:  true,
	100: true,
}

func main() {
	router := mux.NewRouter()

	// User endpoints
	router.HandleFunc("/users", createUser).Methods("POST")
	router.HandleFunc("/users", getAllUsers).Methods("GET")
	router.HandleFunc("/users/{email}", getUser).Methods("GET")
	router.HandleFunc("/users/{email}", updateUser).Methods("PUT")
	router.HandleFunc("/users/{email}", deleteUser).Methods("DELETE")

	// Product endpoints
	router.HandleFunc("/products", createProduct).Methods("POST")
	router.HandleFunc("/products", getAllProducts).Methods("GET")
	router.HandleFunc("/products/{productName}", getProduct).Methods("GET")
	router.HandleFunc("/products/{productName}", updateProduct).Methods("PUT")
	router.HandleFunc("/products/{productName}", deleteProduct).Methods("DELETE")

	// Buy product endpoint
	router.HandleFunc("/buy", buyProduct).Methods("POST")

	// Deposit coins endpoint
	router.HandleFunc("/deposit", depositCoins).Methods("POST")

	// Reset deposit endpoint
	router.HandleFunc("/reset", resetDeposit).Methods("POST")

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		respondWithError(w, "invalid_request", err.Error(), http.StatusBadRequest)
		return
	}

	// Validate the password
	if err := validatePassword(user.Password); err != nil {
		respondWithError(w, "invalid_password", err.Error(), http.StatusBadRequest)
		return
	}

	userMutex.Lock()
	defer userMutex.Unlock()

	if _, exists := users[user.Email]; exists {
		respondWithError(w, "email_exists", "An account with this email already exists.", http.StatusConflict)
		return
	}

	user.ID = uuid.New()
	users[user.Email] = user

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func respondWithError(w http.ResponseWriter, code, message string, status int, fields ...string) {
	w.WriteHeader(status)
	field := ""
	if len(fields) > 0 {
		field = fields[0]
	}
	json.NewEncoder(w).Encode(ErrorResponse{
		ErrorCode:    code,
		ErrorMessage: message,
		Field:        field,
	})
}

func getAllUsers(w http.ResponseWriter, r *http.Request) {
	userMutex.Lock()
	defer userMutex.Unlock()
	userList := make([]User, 0, len(users))
	for _, user := range users {
		userList = append(userList, user)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userList)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	email := params["email"]
	userMutex.Lock()
	defer userMutex.Unlock()
	user, exists := users[email]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(user)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	email := params["email"]
	userEmail := r.Header.Get("User-Email") // Assume the user's email is sent in the request headers

	var newUser User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if email != userEmail {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userMutex.Lock()
	defer userMutex.Unlock()

	if user, exists := users[email]; exists {
		newUser.ID = user.ID // Preserve UUID
		users[email] = newUser
		w.WriteHeader(http.StatusNoContent)
	} else {
		http.Error(w, "User not found", http.StatusNotFound)
	}
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	email := params["email"]
	userMutex.Lock()
	defer userMutex.Unlock()
	if _, exists := users[email]; exists {
		delete(users, email)
		w.WriteHeader(http.StatusNoContent)
	} else {
		http.Error(w, "User not found", http.StatusNotFound)
	}
}

func createProduct(w http.ResponseWriter, r *http.Request) {
	var product Product
	err := json.NewDecoder(r.Body).Decode(&product)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Lock the user map to read data safely
	userMutex.Lock()
	user, ok := users[product.SellerEmail]
	userMutex.Unlock()

	// Additional validation to ensure cost is not negative
	if product.Cost < 0 {
		http.Error(w, "Invalid cost: Cost cannot be negative", http.StatusBadRequest)
		return
	}

	if product.AmountAvailable < 0 {
		http.Error(w, "Invalid amount: Amount available cannot be negative", http.StatusBadRequest)
		return
	}

	if !ok {
		http.Error(w, "Invalid seller email: No such user", http.StatusBadRequest)
		return
	}

	if user.Role != "seller" {
		http.Error(w, "Unauthorized: Only sellers can create products", http.StatusUnauthorized)
		return
	}

	productMutex.Lock()
	defer productMutex.Unlock()

	if _, exists := products[product.ProductName]; exists {
		http.Error(w, "Product already exists", http.StatusConflict)
		return
	}

	product.ID = uuid.New()
	products[product.ProductName] = product

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(product)
}

func getProduct(w http.ResponseWriter, r *http.Request) {
	// Extract the product name from the URL path variables
	params := mux.Vars(r)
	productName := params["productName"]

	// Lock the product map and defer the unlock until the function returns
	productMutex.Lock()
	defer productMutex.Unlock()

	// Attempt to find the product with the given name
	product, exists := products[productName]
	if !exists {
		// If the product does not exist, return a 404 Not Found error
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	// If the product exists, encode it as JSON and send it in the response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(product)
}

func getAllProducts(w http.ResponseWriter, r *http.Request) {
	productMutex.Lock()
	defer productMutex.Unlock()
	var productList []Product
	for _, product := range products {
		productList = append(productList, product)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(productList)
}

func updateProduct(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	productName := params["productName"]
	sellerEmail := r.Header.Get("User-Email") // Authentication assumed

	var newProduct Product
	err := json.NewDecoder(r.Body).Decode(&newProduct)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if newProduct.AmountAvailable < 0 {
		http.Error(w, "Invalid amount: Amount available cannot be negative", http.StatusBadRequest)
		return
	}

	productMutex.Lock()
	defer productMutex.Unlock()

	product, exists := products[productName]
	if !exists {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	if product.SellerEmail != sellerEmail {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	newProduct.ID = product.ID // Preserve the product ID
	newProduct.SellerEmail = sellerEmail
	products[productName] = newProduct

	w.WriteHeader(http.StatusNoContent)
}

func deleteProduct(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	productName := params["productName"]
	sellerEmail := r.Header.Get("User-Email") // Authentication assumed

	productMutex.Lock()
	defer productMutex.Unlock()

	product, exists := products[productName]
	if !exists {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	if product.SellerEmail != sellerEmail {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	delete(products, productName)
	w.WriteHeader(http.StatusNoContent)
}

func buyProduct(w http.ResponseWriter, r *http.Request) {
	var purchase struct {
		Email       string `json:"email"`
		ProductName string `json:"productName"`
		Quantity    int    `json:"quantity"`
	}
	err := json.NewDecoder(r.Body).Decode(&purchase)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userMutex.Lock()
	user, userExists := users[purchase.Email]
	userMutex.Unlock()

	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if user.Role != "buyer" {
		http.Error(w, "Unauthorized: Only buyers can purchase products", http.StatusUnauthorized)
		return
	}

	productMutex.Lock()
	product, productExists := products[purchase.ProductName]
	productMutex.Unlock()

	if !productExists {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	if product.AmountAvailable < purchase.Quantity {
		http.Error(w, "Insufficient product stock", http.StatusBadRequest)
		return
	}

	totalCost := product.Cost * float64(purchase.Quantity) // Correct type conversion

	if float64(user.Deposit) < totalCost { // Ensure comparison is between same types
		http.Error(w, "Insufficient funds", http.StatusBadRequest)
		return
	}

	// Update product stock and user deposit
	product.AmountAvailable -= purchase.Quantity
	user.Deposit -= int(totalCost) // Convert back if necessary, assuming Deposit is int

	productMutex.Lock()
	products[purchase.ProductName] = product
	productMutex.Unlock()

	userMutex.Lock()
	users[purchase.Email] = user
	userMutex.Unlock()

	// Confirm the purchase
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Purchase successful",
		"product":  product.ProductName,
		"quantity": purchase.Quantity,
		"spent":    totalCost,
		"balance":  user.Deposit,
	})
}

func depositCoins(w http.ResponseWriter, r *http.Request) {
	var deposit struct {
		Email string `json:"email"`
		Coin  int    `json:"coin"`
	}
	err := json.NewDecoder(r.Body).Decode(&deposit)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if !validCoins[deposit.Coin] {
		http.Error(w, "Invalid coin denomination", http.StatusBadRequest)
		return
	}

	userMutex.Lock()
	user, exists := users[deposit.Email]
	userMutex.Unlock()

	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if user.Role != "buyer" {
		http.Error(w, "Unauthorized: Only buyers can deposit coins", http.StatusUnauthorized)
		return
	}

	user.Deposit += deposit.Coin

	userMutex.Lock()
	users[deposit.Email] = user
	userMutex.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Deposit successful",
		"balance": user.Deposit,
	})
}

func resetDeposit(w http.ResponseWriter, r *http.Request) {
	var resetRequest struct {
		Email string `json:"email"`
	}
	err := json.NewDecoder(r.Body).Decode(&resetRequest)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	userMutex.Lock()
	user, exists := users[resetRequest.Email]
	userMutex.Unlock()

	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if user.Role != "buyer" {
		http.Error(w, "Unauthorized: Only buyers can reset deposit", http.StatusUnauthorized)
		return
	}

	// Reset the deposit
	userMutex.Lock()
	user.Deposit = 0
	users[resetRequest.Email] = user
	userMutex.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Deposit reset successful",
		"balance": user.Deposit,
	})
}

// validatePassword checks if the provided password meets the defined criteria.
func validatePassword(password string) error {
	var (
		minLen  = 8
		upper   = `[A-Z]`      // Checks for uppercase letters
		lower   = `[a-z]`      // Checks for lowercase letters
		number  = `[0-9]`      // Checks for digits
		special = `[!@#$%^&*]` // Checks for special characters
	)

	if len(password) < minLen {
		return errors.New("password must be at least 8 characters long")
	}
	if match, _ := regexp.MatchString(upper, password); !match {
		return errors.New("password must include at least one uppercase letter")
	}
	if match, _ := regexp.MatchString(lower, password); !match {
		return errors.New("password must include at least one lowercase letter")
	}
	if match, _ := regexp.MatchString(number, password); !match {
		return errors.New("password must include at least one digit")
	}
	if match, _ := regexp.MatchString(special, password); !match {
		return errors.New("password must include at least one special character")
	}
	return nil
}
