package main

import (
	"fmt"
	"net/http"
	"io"
	"log"
	"encoding/json"
	"time"
	"strings"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	jwt "github.com/dgrijalva/jwt-go"
)

type Cat struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Dog struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Hamster struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type JwtClaims struct {
	Name string `json:"name"`
	jwt.StandardClaims
}

func hello(c echo.Context) error {
	return c.String(http.StatusOK, "Hello, World!")
}

func getCats(c echo.Context) error {
	catName := c.QueryParam("name")
	catType := c.QueryParam("type")
	data := c.Param("data")
	if data == "string" {
		return c.String(http.StatusOK, fmt.Sprintf("Cat Name: %s, Cat Type: %s", catName, catType))
	}
	if data == "json" {
		return c.JSON(http.StatusOK, map[string]string{
			"name": catName,
			"type": catType,
		})
	}

	return c.JSON(http.StatusBadRequest, map[string]string{
		"error": "Invalid data type",
	})
}

func addCat(c echo.Context) error {
	cat := Cat{}
	defer c.Request().Body.Close()
	b, err := io.ReadAll(c.Request().Body)
	if err != nil {
		log.Printf("Failed to read request body for addCats: %v", err)
		return c.String(http.StatusInternalServerError, "Failed to read request body")
	}
	err = json.Unmarshal(b, &cat)
	if err != nil {
		log.Printf("Failed unmarshaling in addCats: %v", err)
		return c.String(http.StatusInternalServerError, "Failed to read request body")
	}
	log.Printf("this is your cat: %#v", cat)
	return c.String(http.StatusOK, fmt.Sprintf("Cat Name: %s, Cat Type: %s", cat.Name, cat.Type))
}

func addDog(c echo.Context) error {
	dog := Dog{}
	defer c.Request().Body.Close()
	err := json.NewDecoder(c.Request().Body).Decode(&dog)
	if err != nil {
		log.Printf("Failed processing request body for addDog: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	log.Printf("this is your dog: %#v", dog)
	return c.String(http.StatusOK, fmt.Sprintf("Dog Name: %s, Dog Type: %s", dog.Name, dog.Type))
}

func addHamster(c echo.Context) error {
	hamster := Hamster{}
	err := c.Bind(&hamster)
	if err != nil {
		log.Printf("Failed processing request body for addHamster: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	log.Printf("this is your hamster: %#v", hamster)
	return c.String(http.StatusOK, fmt.Sprintf("Hamster Name: %s, Hamster Type: %s", hamster.Name, hamster.Type))
}

func mainAdmin(c echo.Context) error {
	return c.String(http.StatusOK, "Welcome to the admin page!")
}

func mainCookie(c echo.Context) error {
	return c.String(http.StatusOK, "Welcome to the cookie page!")
}

func login(c echo.Context) error {
	username := c.QueryParam("username")
	password := c.QueryParam("password")
	
	// check username and password against DB after hashing the password
	if username == "admin" && password == "1234" {
		cookie := &http.Cookie{}
		cookie.Name = "session_id"
		cookie.Value = "some_random_value"
		cookie.Expires = time.Now().Add(48 * time.Hour)
		c.SetCookie(cookie)
		token, err := createJwtToken()
		if err != nil {
			log.Println("Error creating JWT token", err)
			return c.String(http.StatusInternalServerError, "something went wrong")
		}
		return c.JSON(http.StatusOK, map[string]string{
			"message": "Login successful",
			"token":   token,
		})
	}
	return c.String(http.StatusUnauthorized, "Invalid username or password")
}

func createJwtToken() (string, error) {
	claims := JwtClaims{
		"admin",
		jwt.StandardClaims{
			Id:        "main_user_id",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}
	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	token, err := rawToken.SignedString([]byte("mySecret"))
	if err != nil {
		return "", err
	}
	return token, nil
}


//   	MIDDLEWARE SECTION 		//
func ServerHeader(next echo.HandlerFunc) echo.HandlerFunc{
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderServer, "Echo Server/1.0")
		return next(c)
	}
}

func checkCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie("session_id")
		if err != nil {
			if strings.Contains(err.Error(), "named cookie not present") {
				return c.String(http.StatusUnauthorized, "you don't have any cookie!")
			}
			log.Println("Error fetching cookie:", err)
			return err
		}

		if cookie != nil && cookie.Value == "some_random_value" {
			return next(c)
		}
		return c.String(http.StatusUnauthorized, "you don't have the right cookie.")
	}
}

func main() {
	fmt.Println("Welcome to the server!")
	e := echo.New()
	e.Use(ServerHeader)
	adminGroup := e.Group("/admin")
	cookieGroup := e.Group("/cookie")
	adminGroup.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `${time_rfc3339} ${status} ${method} ${host}${path} ${latency_human}` + "\n",
	}))

	// Define the basic authentication middleware with the correct function signature
	adminGroup.Use(middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
		// Check if the username and password are correct
		if username == "admin" && password == "1234" {
			return true, nil // Return true for successful authentication
		}
		return false, nil // Return false for failed authentication (no error)
	}))
	cookieGroup.Use(checkCookie)
	cookieGroup.GET("/main", mainCookie)

	adminGroup.GET("/main",mainAdmin)
	e.GET("/login", login)
	e.GET("/", hello)
	e.GET("/cats/:data",getCats)
	e.POST("/cats", addCat)
	e.POST("/dogs", addDog)
	e.POST("/hamsters", addHamster)
	e.Start(":8000")
}