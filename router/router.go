package router

import (
	"net/http"
	"postit/api"

	"github.com/gorilla/mux"
)

func Router() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/createuser", api.RegisterUser).Methods("POST")
	router.HandleFunc("/login", api.LoginUser).Methods("POST")
	router.HandleFunc("/logout", api.Logout).Methods("POST")
	router.Handle("/createpost", api.Authmiddleware(http.HandlerFunc(api.CreatePost))).Methods("POST")
	router.Handle("/updatepost/{id}", api.Authmiddleware(http.HandlerFunc(api.Updatepost))).Methods("PATCH")
	router.Handle("/deletepost/{id}", api.Authmiddleware(http.HandlerFunc(api.DeletePost))).Methods("DELETE")
	router.HandleFunc("/allpost", api.SeeallPost).Methods("GET")
	router.Handle("/alluserpost/{id}", api.Authmiddleware(http.HandlerFunc(api.Allpostuser))).Methods("GET")
	router.HandleFunc("/updatephoto/{id}", api.UpdateUserPhoto).Methods("PATCH")
	return router
}
