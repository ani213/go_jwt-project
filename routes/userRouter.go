package routes

import (
	"github.com/ani213/go-jwt-project/controllers"
	"github.com/ani213/go-jwt-project/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	// incomingRoutes.GET("/user", controllers.GetUsers())
	incomingRoutes.GET("/user/:user_id", controllers.GetUser())

}
