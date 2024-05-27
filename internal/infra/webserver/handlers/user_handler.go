package handlers

import (
	"encoding/json"
	"github.com/go-chi/jwtauth"
	"github.com/matheusvidal21/goexpert/API/ApiRest/internal/dto"
	"github.com/matheusvidal21/goexpert/API/ApiRest/internal/entity"
	"github.com/matheusvidal21/goexpert/API/ApiRest/internal/infra/database"
	"net/http"
	"time"
)

type Error struct {
	Message string `json:"message"`
}

type UserHandler struct {
	UserDB database.UserInterface
}

func NewUserHandler(db database.UserInterface) *UserHandler {
	return &UserHandler{
		UserDB: db,
	}
}

// GetJWT godoc
// @Summary 	Create a user JWT
// @Description Create a user JWT
// @Tags		users
// @Accept 		json
// @Produce 	json
// @Param 		request		body		dto.GetJWTInput		true	"user credentials"
// @Success		200		{object}	dto.GetJWTOutput
// @Failure 	404		{object}	Error
// @Failure 	500		{object}	Error
// @Router 		/users/generate_token [post]
func (h *UserHandler) GetJWT(w http.ResponseWriter, r *http.Request) {
	jwt := r.Context().Value("jwt").(*jwtauth.JWTAuth)
	jwtExperiesIn := r.Context().Value("jwtExperiesIn").(int)
	var user dto.GetJWTInput
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	u, err := h.UserDB.FindByEmail(user.Email)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		err := Error{Message: err.Error()}
		json.NewEncoder(w).Encode(err)
		return
	}
	if !u.ValidatePassword(user.Password) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	_, tokenString, _ := jwt.Encode(map[string]interface{}{
		"sub": u.ID.String(),
		"exp": time.Now().Add(time.Second * time.Duration(jwtExperiesIn)).Unix(),
	})

	acessToken := dto.GetJWTOutput{AccessToken: tokenString}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(acessToken)
}

// CreateUser Create user godoc
// @Summary 	Create user
// @Description Create user
// @Tags		users
// @Accept 		json
// @Produce 	json
// @Param 		request		body		dto.CreateUserInput		true	"user request"
// @Success		201
// @Failure 	500		{object}	Error
// @Router 		/users [post]
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user dto.CreateUserInput
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, err := entity.NewUser(user.Name, user.Email, user.Password)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errorStruct := Error{Message: err.Error()}
		json.NewEncoder(w).Encode(errorStruct)
		return
	}
	err = h.UserDB.Create(u)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorStruct := Error{Message: err.Error()}
		json.NewEncoder(w).Encode(errorStruct)
		return
	}
	w.WriteHeader(http.StatusCreated)
}
