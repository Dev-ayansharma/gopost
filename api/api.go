package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"postit/db"
	model "postit/models"
	"time"

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	// "github.com/gin-gonic/gin"
)

func createuser(userdata model.User) (model.User, error) {

	createduser := model.User{
		Name:     userdata.Name,
		Email:    userdata.Email,
		Password: userdata.Password,
	}
	result := db.DB.Create(&createduser)
	if result.Error != nil {
		log.Fatalf("Failed to create user: %v", result.Error)
	}
	fmt.Printf("Created user with ID: %d\n", createduser.ID)
	return createduser, result.Error
}
func authenticate(email string, password string) (string, error) {
	var user model.User
	result := db.DB.Where("email = ?", email).First(&user)

	if result.Error != nil || !verifyPassword(password, user.Password) {
		return "", fmt.Errorf("No username found or password not matched")

	}
	fmt.Println(user.ID)
	tokenstring, err := createToken(user.ID)
	if err != nil {
		return "", err
	}

	return tokenstring, nil
}
func createToken(id uint) (string, error) {
	secretKey := []byte(os.Getenv("SECRET_KEY"))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  id,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	tokensigned, err := token.SignedString(secretKey)
	if err != nil {
		panic(err)

	}
	return tokensigned, err
}
func verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
func verifytoken(tokenstring string) (jwt.MapClaims, error) {
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	token, err := jwt.Parse(tokenstring, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

func Authmiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenstring := cookie.Value

		claims, err := verifytoken(tokenstring)

		if err != nil {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}

		var userID uint

		switch v := claims["id"].(type) {
		case float64:
			userID = uint(v)
		case string:

			idInt, _ := strconv.Atoi(v)

			userID = uint(idInt)

		default:
			http.Error(w, "Invalid token ID type", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userId", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})

}

func LoginUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var u model.User
	json.NewDecoder(r.Body).Decode(&u)

	token, err := authenticate(u.Email, u.Password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"message": err.Error(),
		})
		return
	}
	cookie := &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,  // 🔥 most important security flag
		Secure:   false, // true in production (HTTPS)
		SameSite: http.SameSiteLaxMode,
		MaxAge:   24 * 60 * 60, // 1 day

	}

	http.SetCookie(w, cookie)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login successful",
	})
}
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // or your frontend URL
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	var user model.User
	_ = json.NewDecoder(r.Body).Decode(&user)
	createduser, err := createuser(user)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(createduser)
}
func Logout(w http.ResponseWriter, r *http.Request) {

	cookie := &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1, // 🔥 this deletes the cookie
	}

	http.SetCookie(w, cookie)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logout successful",
	})

}

func UploadToCloudinary(localpath string) (string, error) {

	cloudinaryURL := "cloudinary://385615731514317:yu3l8mXbx5MPZh_00g1saTl31gA@dpvkjwxxy"
	// put in ENV file
	cld, err := cloudinary.NewFromURL(cloudinaryURL)
	if err != nil {
		return "", err
	}

	ctx := context.Background()

	// Upload to Cloudinary
	resp, err := cld.Upload.Upload(ctx,
		localpath,
		uploader.UploadParams{
			PublicID: "avatar-" + uuid.NewString(),
		})

	if err != nil {
		return "", err
	}

	// Remove from local
	os.Remove(localpath)

	return resp.SecureURL, nil

}

func UploadLocal(r *http.Request, fieldName string, localDir string) (string, string, error) {
	// Parse form data (10 MB max)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		return "", "", fmt.Errorf("error parsing form: %v", err)
	}

	// Read uploaded file
	file, handler, err := r.FormFile(fieldName)
	if err != nil {
		return "", "", fmt.Errorf("unable to read file: %v", err)
	}
	defer file.Close()

	// ✅ Create directory if it doesn’t exist
	err = os.MkdirAll(localDir, os.ModePerm)
	if err != nil {
		return "", "", fmt.Errorf("failed to create directory: %v", err)
	}

	// Build full local path using filepath.Join (cross-platform safe)
	localPath := filepath.Join(localDir, handler.Filename)

	// Create file
	dst, err := os.Create(localPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to create file: %v", err)
	}
	defer dst.Close()

	// Copy uploaded data into new file
	_, err = io.Copy(dst, file)
	if err != nil {
		return "", "", fmt.Errorf("failed to save file: %v", err)
	}

	// Return local path & filename
	return localPath, handler.Filename, nil
}

func CreatePost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	title := r.FormValue("title")
	content := r.FormValue("content")
	if title == "" || content == "" {
		http.Error(w, "Title or content required", http.StatusBadRequest)
		return
	}

	localPath, _, err := UploadLocal(r, "image", "assets/uploads")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	imageURL, err := UploadToCloudinary(localPath)
	if err != nil {
		http.Error(w, "Cloudinary upload failed", http.StatusInternalServerError)
		return
	}

	userId := r.Context().Value("userId").(uint)

	post := model.Post{
		Title:   title,
		Content: content,
		Image:   imageURL,
		UserID:  userId,
	}

	result := db.DB.Create(&post)

	if result.Error != nil {
		log.Fatalf("Failed to create user: %v", result.Error)
	}

	var fullPost model.Post
	db.DB.Preload("User").Preload("User.Posts").First(&fullPost, post.ID)

	json.NewEncoder(w).Encode(fullPost)

}

func Updatepost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // or your frontend URL
	w.Header().Set("Access-Control-Allow-Methods", "PATCH")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	params := mux.Vars(r)
	id := params["id"]
	var post model.Post
	if err := db.DB.First(&post, id).Error; err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}
	var input model.Post
	_ = json.NewDecoder(r.Body).Decode(&input)

	post.Title = input.Title
	post.Content = input.Content

	db.DB.Save(&post)

	json.NewEncoder(w).Encode(post)
}

func DeletePost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // or your frontend URL
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	id := params["id"]
	result := db.DB.Unscoped().Delete(&model.Post{}, id)

	if result.Error != nil {
		http.Error(w, "Failed to update post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": " photo delete successfully",
	})
}

func SeeallPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	var posts []model.Post
	result := db.DB.Find(&posts)

	if result.Error != nil {
		http.Error(w, "Failed to fetch all post", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(posts)
}

func Allpostuser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userid := r.Context().Value("userId").(uint)
	var posts []model.Post
	result := db.DB.Where("user_id = ?", userid).Find(&posts)
	if result.Error != nil {
		http.Error(w, "Failed to find post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(posts)

}

func UpdateUserPhoto(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	id := params["id"]

	// 1. Upload file locally
	localPath, _, err := UploadLocal(r, "image", "assets/uploads")
	if err != nil {
		http.Error(w, fmt.Sprintf("File upload failed: %v", err), http.StatusBadRequest)
		return
	}

	// 2. Upload to Cloudinary
	imageURL, err := UploadToCloudinary(localPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cloudinary upload failed: %v", err), http.StatusInternalServerError)
		return
	}

	// 3. Update database
	var post model.Post
	if err := db.DB.First(&post, id).Error; err != nil {
		http.Error(w, "post not found", http.StatusNotFound)
		return
	}

	post.Image = imageURL
	if err := db.DB.Save(&post).Error; err != nil {
		http.Error(w, "Failed to update image in DB", http.StatusInternalServerError)
		return
	}

	// 4. Response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": " photo updated successfully",
		"Image":   imageURL,
	})
}
