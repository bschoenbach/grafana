package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/metrics"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/models"
)

func (hs *HTTPServer) LoginServiceID4meGet(ctx *models.ReqContext) response.Response {
	var resp *response.NormalResponse

	loginInfo := models.LoginInfo{
		AuthModule: "oauth",
	}

	//login_hint := ctx.Params(":id")
	name := "id4me"
	loginInfo.AuthModule = name
	_, ok := social.SocialMap[name]
	if !ok {
		err := errors.New(fmt.Sprintf("No OAuth with name %s configured", name))
		resp = response.Error(401, err.Error(), err)
	}

	result := map[string]interface{}{
		"message": "Logged in",
	}

	metrics.MApiLoginPost.Inc()
	resp = response.JSON(http.StatusOK, result)
	return resp
}
