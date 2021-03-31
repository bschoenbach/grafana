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

	login_hint := ctx.Params(":id")
	name := "id4me"

	defer func() {
		err := resp.Err()
		if err == nil && resp.ErrMessage() != "" {
			err = errors.New(resp.ErrMessage())
		}
		hs.HooksService.RunLoginHook(&models.LoginInfo{
			AuthModule:    "oauth",
			User:          nil,
			LoginUsername: "cmd.User",
			HTTPStatus:    resp.Status(),
			Error:         err,
		}, ctx)
	}()

	current, ok := social.SocialMap[name]
	if !ok {
		err := errors.New(fmt.Sprintf("No ID4me with name %s configured", name))
		resp = response.Error(401, err.Error(), err)
		return resp
	}

	_, err := current.CustomAuthCodeURL("", login_hint)
	if err != nil {
		resp = response.Error(401, err.Error(), err)
		return resp
	}

	result := map[string]interface{}{
		"message": "Logged in",
	}

	metrics.MApiLoginPost.Inc()
	resp = response.JSON(http.StatusOK, result)
	return resp
}
