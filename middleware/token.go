package middleware

import (
	"fmt"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"time"
	"trainee/model"
	"trainee/service"
)

func GinJwt() (authMiddleware *jwt.GinJWTMiddleware) {

	var identityKey = "id"

	// 定义一个Gin的中间件
	authMiddleware, _ = jwt.New(&jwt.GinJWTMiddleware{
		Realm:            "trainee zone",    //标识
		SigningAlgorithm: "HS256",           //加密算法
		Key:              []byte("trainee"), //密钥
		Timeout:          3 * 24 * time.Hour,
		MaxRefresh:       3 * 24 * time.Hour, //刷新最大延长时间
		IdentityKey:      identityKey,        //指定cookie的id
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			//负载，这里可以定义返回jwt中的payload数据
			if v, ok := data.(*service.UserLoginService); ok {
				return jwt.MapClaims{
					identityKey: v.UserName,
				}
			}
			return jwt.MapClaims{}
		},
		//IdentityHandler: func(c *gin.Context) interface{} {
		//	claims := jwt.ExtractClaims(c)
		//	fmt.Println("=============",claims)
		//	return &model.User{
		//		UserName: claims[identityKey].(string),
		//	}
		//},
		Authenticator: Authenticator,
		//在这里可以写我们的登录验证逻辑
		//Authorizator: func(data interface{}, c *gin.Context) bool {
		//	//当用户通过token请求受限接口时，会经过这段逻辑
		//	if v, ok := data.(*model.User); ok && v.UserName == "admin" {
		//		return true
		//	}
		//	return false
		//},
		//Unauthorized: func(c *gin.Context, code int, message string) {
		//	//错误时响应
		//	c.JSON(code, gin.H{
		//		"code":    code,
		//		"message": message,
		//	})
		//},
		// 指定从哪里获取token 其格式为："<source>:<name>" 如有多个，用逗号隔开
		TokenLookup:   "header: Authorization, query: token",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})

	return authMiddleware
}

func Authenticator(c *gin.Context) (interface{}, error) {

	var loginVals service.UserLoginService
	if err := c.ShouldBind(&loginVals); err != nil {
		return "", err
	}

	username := loginVals.UserName
	password := loginVals.Password

	fmt.Println(loginVals)
	if (username == "admin") || (username == "test" && password == "test") {
		return &model.UserPayload{
			UserId:   uint(1),
			UserName: "zhangfan",
		}, nil
	}

	return nil, jwt.ErrFailedAuthentication
}
