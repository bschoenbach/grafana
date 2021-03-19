/*Package api contains mock API implementation of unified alerting
 *
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 *
 * Need to remove unused imports.
 */
package api

import (
	"net/http"
	"time"

	"github.com/grafana/grafana/pkg/api/dtos"

	"github.com/grafana/grafana/pkg/components/securejsondata"
	"github.com/grafana/grafana/pkg/components/simplejson"

	"github.com/go-openapi/strfmt"
	apimodels "github.com/grafana/alerting-api/pkg/api"
	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/util"
	amv2 "github.com/prometheus/alertmanager/api/v2/models"
	"github.com/prometheus/alertmanager/config"
)

func toSimpleJSON(blob string) *simplejson.Json {
	json, _ := simplejson.NewJson([]byte(blob))
	return json
}

var alertmanagerReceiver = models.AlertNotification{
	Id:                    1,
	Uid:                   "alertmanager UID",
	OrgId:                 1,
	Name:                  "an alert manager receiver",
	Type:                  "prometheus-alertmanager",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "basicAuthUser": "user",
        "httpMethod": "POST",
        "severity": "critical",
        "uploadImage": false,
        "url": "http://localhost:9093"
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{
		"basicAuthPassword": "<basicAuthPassword>",
	}),
	Created: time.Now().Add(-time.Hour),
	Updated: time.Now().Add(-5 * time.Minute),
}
var alertmanagerReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&alertmanagerReceiver))

var dingdingReceiver = models.AlertNotification{
	Id:                    2,
	Uid:                   "dingding UID",
	OrgId:                 1,
	Name:                  "a dingding receiver",
	Type:                  "dingding",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "httpMethod": "POST",
        "msgType": "link",
        "severity": "critical",
        "uploadImage": false,
        "url": "https://oapi.dingtalk.com/robot/send?access_token=xxxxxxxxx"
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{}),
	Created:        time.Now().Add(-time.Hour),
	Updated:        time.Now().Add(-5 * time.Minute),
}
var dingdingReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&dingdingReceiver))

var discordReceiver = models.AlertNotification{
	Id:                    3,
	Uid:                   "discord UID",
	OrgId:                 1,
	Name:                  "a discord receiver",
	Type:                  "discord",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "content": "@user",
        "httpMethod": "POST",
        "severity": "critical",
        "uploadImage": false,
        "url": "http://"
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{}),
	Created:        time.Now().Add(-time.Hour),
	Updated:        time.Now().Add(-5 * time.Minute),
}
var discordReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&discordReceiver))

var emailReceiver = models.AlertNotification{
	Id:                    4,
	Uid:                   "email UID",
	OrgId:                 1,
	Name:                  "an email receiver",
	Type:                  "email",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "addresses": "<email>",
        "autoResolve": true,
        "httpMethod": "POST",
        "severity": "critical",
        "singleEmail": true,
        "uploadImage": false
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{}),
	Created:        time.Now().Add(-time.Hour),
	Updated:        time.Now().Add(-5 * time.Minute),
}
var emailReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&emailReceiver))

var googlechatReceiver = models.AlertNotification{
	Id:                    5,
	Uid:                   "googlechatReceiver UID",
	OrgId:                 1,
	Name:                  "a googlechat receiver",
	Type:                  "googlechat",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "httpMethod": "POST",
        "severity": "critical",
        "uploadImage": false,
        "url": "http://"
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{}),
	Created:        time.Now().Add(-time.Hour),
	Updated:        time.Now().Add(-5 * time.Minute),
}
var googlechatReceiverDTOs = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&googlechatReceiver))

var hipchatReceiver = models.AlertNotification{
	Id:                    6,
	Uid:                   "hipchat UID",
	OrgId:                 1,
	Name:                  "a hipchat receiver",
	Type:                  "hipchat",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "apiKey": "<apikey>",
        "autoResolve": true,
        "httpMethod": "POST",
        "roomid": "12345",
        "severity": "critical",
        "uploadImage": false,
        "url": "http://"
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{}),
	Created:        time.Now().Add(-time.Hour),
	Updated:        time.Now().Add(-5 * time.Minute),
}
var hipchatReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&hipchatReceiver))

var kafkaReceiver = models.AlertNotification{
	Id:                    7,
	Uid:                   "kafka UID",
	OrgId:                 1,
	Name:                  "a kafka receiver",
	Type:                  "kafka",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "httpMethod": "POST",
        "kafkaRestProxy": "http://localhost:8082",
        "kafkaTopic": "topic1",
        "severity": "critical",
        "uploadImage": false
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{}),
	Created:        time.Now().Add(-time.Hour),
	Updated:        time.Now().Add(-5 * time.Minute),
}
var kafkaReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&kafkaReceiver))

var lineReceiver = models.AlertNotification{
	Id:                    8,
	Uid:                   "line UID",
	OrgId:                 1,
	Name:                  "a line receiver",
	Type:                  "line",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`    "settings": {
        "autoResolve": true,
        "httpMethod": "POST",
        "severity": "critical",
        "uploadImage": false
    },`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{
		"token": "<token>",
	}),
	Created: time.Now().Add(-time.Hour),
	Updated: time.Now().Add(-5 * time.Minute),
}
var lineReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&lineReceiver))

var opsgenieReceiver = models.AlertNotification{
	Id:                    9,
	Uid:                   "opsgenie UID",
	OrgId:                 1,
	Name:                  "a opsgenie receiver",
	Type:                  "opsgenie",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`    "settings": {
        "apiUrl": "https://api.opsgenie.com/v2/alerts",
        "autoClose": true,
        "autoResolve": true,
        "httpMethod": "POST",
        "overridePriority": true,
        "severity": "critical",
        "uploadImage": false
    },`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{
		"apiKey": "<apiKey>",
	}),
	Created: time.Now().Add(-time.Hour),
	Updated: time.Now().Add(-5 * time.Minute),
}
var opsgenieReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&opsgenieReceiver))

var pagerdutyReceiver = models.AlertNotification{
	Id:                    10,
	Uid:                   "pagerduty UID",
	OrgId:                 1,
	Name:                  "a pagerduty receiver",
	Type:                  "pagerduty",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "httpMethod": "POST",
        "severity": "critical",
        "uploadImage": true
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{
		"integrationKey": "<integrationKey>",
	}),
	Created: time.Now().Add(-time.Hour),
	Updated: time.Now().Add(-5 * time.Minute),
}
var pagerdutyReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&pagerdutyReceiver))

var pushoverReceiver = models.AlertNotification{
	Id:                    11,
	Uid:                   "pushover UID",
	OrgId:                 1,
	Name:                  "a pushover receiver",
	Type:                  "pushover",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
		"apiToken": "",
		"autoResolve": true,
		"device": "",
		"expire": "",
		"httpMethod": "POST",
		"okPriority": "0",
		"okSound": "cosmic",
		"priority": "1",
		"retry": "30",
		"severity": "critical",
		"sound": "pushover",
		"uploadImage": true,
		"userKey": ""
	}`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{
		"apiToken": "<apiToken>",
		"userKey":  "<userKey>",
	}),
	Created: time.Now().Add(-time.Hour),
	Updated: time.Now().Add(-5 * time.Minute),
}
var pushoverReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&pushoverReceiver))

var sensuReceiver = models.AlertNotification{
	Id:                    12,
	Uid:                   "sensu UID",
	OrgId:                 1,
	Name:                  "a sensu receiver",
	Type:                  "sensu",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "handler": "",
        "httpMethod": "POST",
        "severity": "critical",
        "source": "",
        "uploadImage": false,
        "url": "http://sensu-api.local:4567/results",
        "username": ""
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{}),
	Created:        time.Now().Add(-time.Hour),
	Updated:        time.Now().Add(-5 * time.Minute),
}
var sensuReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&sensuReceiver))

var sensugoReceiver = models.AlertNotification{
	Id:                    13,
	Uid:                   "sensugo UID",
	OrgId:                 1,
	Name:                  "a sensugo receiver",
	Type:                  "sensugo",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "check": "",
        "entity": "",
        "handler": "",
        "httpMethod": "POST",
        "namespace": "",
        "severity": "critical",
        "uploadImage": false,
        "url": "http://sensu-api.local:8080"
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{
		"apikey": "<apikey>",
	}),
	Created: time.Now().Add(-time.Hour),
	Updated: time.Now().Add(-5 * time.Minute),
}
var sensugoReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&sensugoReceiver))

var slackReceiver = models.AlertNotification{
	Id:                    14,
	Uid:                   "slack UID",
	OrgId:                 1,
	Name:                  "a slack receiver",
	Type:                  "slack",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "httpMethod": "POST",
        "iconEmoji": "",
        "iconUrl": "",
        "mentionGroups": "",
        "mentionUsers": "",
        "recipient": "",
        "severity": "critical",
        "uploadImage": false,
        "username": ""
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{
		"token": "<token>",
		"url":   "<url>",
	}),
	Created: time.Now().Add(-time.Hour),
	Updated: time.Now().Add(-5 * time.Minute),
}
var slackReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&slackReceiver))

var teamsReceiver = models.AlertNotification{
	Id:                    15,
	Uid:                   "teams UID",
	OrgId:                 1,
	Name:                  "a teams receiver",
	Type:                  "teams",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "httpMethod": "POST",
        "severity": "critical",
        "uploadImage": false,
        "url": "http://"
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{}),
	Created:        time.Now().Add(-time.Hour),
	Updated:        time.Now().Add(-5 * time.Minute),
}
var teamsReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&teamsReceiver))

var telegramReceiver = models.AlertNotification{
	Id:                    16,
	Uid:                   "telegram UID",
	OrgId:                 1,
	Name:                  "a telegram receiver",
	Type:                  "telegram",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "chatid": "12345",
        "httpMethod": "POST",
        "severity": "critical",
        "uploadImage": false
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{
		"bottoken": "<bottoken>",
	}),
	Created: time.Now().Add(-time.Hour),
	Updated: time.Now().Add(-5 * time.Minute),
}
var telegramReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&telegramReceiver))

var threemaReceiver = models.AlertNotification{
	Id:                    17,
	Uid:                   "threema UID",
	OrgId:                 1,
	Name:                  "a threema receiver",
	Type:                  "threema",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "gateway_id": "*3MAGWID",
        "httpMethod": "POST",
        "recipient_id": "YOUR3MID",
        "severity": "critical",
        "uploadImage": false
    },`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{
		"api_secret": "<api_secret>",
	}),
	Created: time.Now().Add(-time.Hour),
	Updated: time.Now().Add(-5 * time.Minute),
}
var threemaDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&threemaReceiver))

var victoropsReceiver = models.AlertNotification{
	Id:                    18,
	Uid:                   "victorops UID",
	OrgId:                 1,
	Name:                  "a victorops receiver",
	Type:                  "victorops",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`{
        "autoResolve": true,
        "httpMethod": "POST",
        "severity": "critical",
        "uploadImage": false,
        "url": "http://"
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{}),
	Created:        time.Now().Add(-time.Hour),
	Updated:        time.Now().Add(-5 * time.Minute),
}
var victoropsReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&victoropsReceiver))

var webhookReceiver = models.AlertNotification{
	Id:                    19,
	Uid:                   "webhook UID",
	OrgId:                 1,
	Name:                  "a webhook receiver",
	Type:                  "webhook",
	SendReminder:          false,
	DisableResolveMessage: false,
	Frequency:             5 * time.Minute,
	IsDefault:             false,
	Settings: toSimpleJSON(`x{
        "autoResolve": true,
        "httpMethod": "POST",
        "password": "",
        "severity": "critical",
        "uploadImage": true,
        "url": "http://localhost:3010",
        "username": ""
    }`),
	SecureSettings: securejsondata.GetEncryptedJsonData(map[string]string{
		"password": "<password>",
	}),
	Created: time.Now().Add(-time.Hour),
	Updated: time.Now().Add(-5 * time.Minute),
}
var webhookReceiverDTO = apimodels.GettableGrafanaReceiver(*dtos.NewAlertNotification(&webhookReceiver))

type AlertmanagerApiMock struct {
	log log.Logger
}

func (mock AlertmanagerApiMock) RouteCreateSilence(c *models.ReqContext, body apimodels.SilenceBody) response.Response {
	datasourceID := c.Params(":DatasourceId")
	mock.log.Info("RouteCreateSilence: ", "DatasourceId", datasourceID)
	mock.log.Info("RouteCreateSilence: ", "body", body)
	return response.JSON(http.StatusAccepted, util.DynMap{"message": "silence created"})
}

func (mock AlertmanagerApiMock) RouteDeleteAlertingConfig(c *models.ReqContext) response.Response {
	datasourceID := c.Params(":DatasourceId")
	mock.log.Info("RouteDeleteAlertingConfig: ", "DatasourceId", datasourceID)
	return response.JSON(http.StatusOK, util.DynMap{"message": "config deleted"})
}

func (mock AlertmanagerApiMock) RouteDeleteSilence(c *models.ReqContext) response.Response {
	silenceID := c.Params(":SilenceId")
	mock.log.Info("RouteDeleteSilence: ", "SilenceId", silenceID)
	datasourceID := c.Params(":DatasourceId")
	mock.log.Info("RouteDeleteSilence: ", "DatasourceId", datasourceID)
	return response.JSON(http.StatusOK, util.DynMap{"message": "silence deleted"})
}

func (mock AlertmanagerApiMock) RouteGetAlertingConfig(c *models.ReqContext) response.Response {
	datasourceID := c.Params(":DatasourceId")
	mock.log.Info("RouteGetAlertingConfig: ", "DatasourceId", datasourceID)
	// now := time.Now()
	result := apimodels.GettableUserConfig{
		TemplateFiles: map[string]string{
			"tmpl1": "val1",
			"tmpl2": "val2",
		},
		AlertmanagerConfig: apimodels.GettableApiAlertingConfig{
			Config: config.Config{
				Global:       &config.GlobalConfig{},
				Route:        &config.Route{},
				InhibitRules: []*config.InhibitRule{},
				Receivers:    []*config.Receiver{},
				Templates:    []string{},
			},
			Receivers: []*apimodels.GettableApiReceiver{
				{
					GettableGrafanaReceivers: apimodels.GettableGrafanaReceivers{
						GrafanaManagedReceivers: []*apimodels.GettableGrafanaReceiver{
							&alertmanagerReceiverDTO,
							&dingdingReceiverDTO,
							&discordReceiverDTO,
							&emailReceiverDTO,
							&googlechatReceiverDTOs,
							&hipchatReceiverDTO,
							&kafkaReceiverDTO,
							&lineReceiverDTO,
							&opsgenieReceiverDTO,
							&pagerdutyReceiverDTO,
							&pushoverReceiverDTO,
							&sensuReceiverDTO,
							&sensugoReceiverDTO,
							&slackReceiverDTO,
							&teamsReceiverDTO,
							&telegramReceiverDTO,
							&threemaDTO,
							&victoropsReceiverDTO,
							&webhookReceiverDTO,
						},
					},
				},
			},
		},
	}
	return response.JSON(http.StatusOK, result)
}

func (mock AlertmanagerApiMock) RouteGetAmAlertGroups(c *models.ReqContext) response.Response {
	datasourceID := c.Params(":DatasourceId")
	mock.log.Info("RouteGetAmAlertGroups: ", "DatasourceId", datasourceID)
	now := time.Now()
	result := apimodels.AlertGroups{
		&amv2.AlertGroup{
			Alerts: []*amv2.GettableAlert{
				{
					Annotations: amv2.LabelSet{
						"annotation1-1": "value1",
						"annotation1-2": "value2",
					},
					EndsAt:      timePtr(strfmt.DateTime(now.Add(time.Hour))),
					Fingerprint: stringPtr("fingerprint 1"),
					Receivers: []*amv2.Receiver{
						{
							Name: stringPtr("receiver identifier 1-1"),
						},
						{
							Name: stringPtr("receiver identifier 1-2"),
						},
					},
					StartsAt: timePtr(strfmt.DateTime(now)),
					Status: &amv2.AlertStatus{
						InhibitedBy: []string{"inhibitedBy 1"},
						SilencedBy:  []string{"silencedBy 1"},
						State:       stringPtr(amv2.AlertStatusStateActive),
					},
					UpdatedAt: timePtr(strfmt.DateTime(now.Add(-time.Hour))),
					Alert: amv2.Alert{
						GeneratorURL: strfmt.URI("a URL"),
						Labels: amv2.LabelSet{
							"label1-1": "value1",
							"label1-2": "value2",
						},
					},
				},
				{
					Annotations: amv2.LabelSet{
						"annotation2-1": "value1",
						"annotation2-2": "value2",
					},
					EndsAt:      timePtr(strfmt.DateTime(now.Add(time.Hour))),
					Fingerprint: stringPtr("fingerprint 2"),
					Receivers: []*amv2.Receiver{
						{
							Name: stringPtr("receiver identifier 2-1"),
						},
						{
							Name: stringPtr("receiver identifier 2-2"),
						},
					},
					StartsAt: timePtr(strfmt.DateTime(now)),
					Status: &amv2.AlertStatus{
						InhibitedBy: []string{"inhibitedBy 2"},
						SilencedBy:  []string{"silencedBy 2"},
						State:       stringPtr(amv2.AlertStatusStateActive),
					},
					UpdatedAt: timePtr(strfmt.DateTime(now.Add(-time.Hour))),
					Alert: amv2.Alert{
						GeneratorURL: strfmt.URI("a URL"),
						Labels: amv2.LabelSet{
							"label2-1": "value1",
							"label2-2": "value2",
						},
					},
				},
			},
			Labels: amv2.LabelSet{
				"label1-1": "value1",
				"label1-2": "value2",
			},
			Receiver: &amv2.Receiver{
				Name: stringPtr("receiver identifier 2-1"),
			},
		},
		&amv2.AlertGroup{
			Alerts: []*amv2.GettableAlert{
				{
					Annotations: amv2.LabelSet{
						"annotation2-1": "value1",
						"annotation2-2": "value2",
					},
					EndsAt:      timePtr(strfmt.DateTime(now.Add(time.Hour))),
					Fingerprint: stringPtr("fingerprint 2"),
					Receivers: []*amv2.Receiver{
						{
							Name: stringPtr("receiver identifier 2-1"),
						},
						{
							Name: stringPtr("receiver identifier 2-2"),
						},
					},
					StartsAt: timePtr(strfmt.DateTime(now)),
					Status: &amv2.AlertStatus{
						InhibitedBy: []string{"inhibitedBy 2"},
						SilencedBy:  []string{"silencedBy 2"},
						State:       stringPtr(amv2.AlertStatusStateActive),
					},
					UpdatedAt: timePtr(strfmt.DateTime(now.Add(-time.Hour))),
					Alert: amv2.Alert{
						GeneratorURL: strfmt.URI("a URL"),
						Labels: amv2.LabelSet{
							"label2-1": "value1",
							"label2-2": "value2",
						},
					},
				},
			},
			Labels: amv2.LabelSet{
				"label2-1": "value1",
				"label2-2": "value2",
			},
			Receiver: &amv2.Receiver{
				Name: stringPtr("receiver identifier 2-1"),
			},
		},
	}
	return response.JSON(http.StatusOK, result)
}

func (mock AlertmanagerApiMock) RouteGetAmAlerts(c *models.ReqContext) response.Response {
	datasourceID := c.Params(":DatasourceId")
	mock.log.Info("RouteGetAmAlerts: ", "DatasourceId", datasourceID)
	now := time.Now()
	result := apimodels.GettableAlerts{
		&amv2.GettableAlert{
			Annotations: amv2.LabelSet{
				"annotation1-1": "value1",
				"annotation1-2": "value2",
			},
			EndsAt:      timePtr(strfmt.DateTime(now.Add(time.Hour))),
			Fingerprint: stringPtr("fingerprint 1"),
			Receivers: []*amv2.Receiver{
				{
					Name: stringPtr("receiver identifier 1-1"),
				},
				{
					Name: stringPtr("receiver identifier 1-2"),
				},
			},
			StartsAt: timePtr(strfmt.DateTime(now)),
			Status: &amv2.AlertStatus{
				InhibitedBy: []string{"inhibitedBy 1"},
				SilencedBy:  []string{"silencedBy 1"},
				State:       stringPtr(amv2.AlertStatusStateActive),
			},
			UpdatedAt: timePtr(strfmt.DateTime(now.Add(-time.Hour))),
			Alert: amv2.Alert{
				GeneratorURL: strfmt.URI("a URL"),
				Labels: amv2.LabelSet{
					"label1-1": "value1",
					"label1-2": "value2",
				},
			},
		},
		&amv2.GettableAlert{
			Annotations: amv2.LabelSet{
				"annotation2-1": "value1",
				"annotation2-2": "value2",
			},
			EndsAt:      timePtr(strfmt.DateTime(now.Add(time.Hour))),
			Fingerprint: stringPtr("fingerprint 2"),
			Receivers: []*amv2.Receiver{
				{
					Name: stringPtr("receiver identifier 2-1"),
				},
				{
					Name: stringPtr("receiver identifier 2-2"),
				},
			},
			StartsAt: timePtr(strfmt.DateTime(now)),
			Status: &amv2.AlertStatus{
				InhibitedBy: []string{"inhibitedBy 2"},
				SilencedBy:  []string{"silencedBy 2"},
				State:       stringPtr(amv2.AlertStatusStateActive),
			},
			UpdatedAt: timePtr(strfmt.DateTime(now.Add(-time.Hour))),
			Alert: amv2.Alert{
				GeneratorURL: strfmt.URI("a URL"),
				Labels: amv2.LabelSet{
					"label2-1": "value1",
					"label2-2": "value2",
				},
			},
		},
	}
	return response.JSON(http.StatusOK, result)
}

func (mock AlertmanagerApiMock) RouteGetSilence(c *models.ReqContext) response.Response {
	silenceID := c.Params(":SilenceId")
	mock.log.Info("RouteGetSilence: ", "SilenceId", silenceID)
	datasourceID := c.Params(":DatasourceId")
	mock.log.Info("RouteGetSilence: ", "DatasourceId", datasourceID)
	now := time.Now()
	result := apimodels.GettableSilence{
		ID: stringPtr("id"),
		Status: &amv2.SilenceStatus{
			State: stringPtr("active"),
		},
		UpdatedAt: timePtr(strfmt.DateTime(now.Add(-time.Hour))),
		Silence: amv2.Silence{
			Comment:   stringPtr("comment"),
			CreatedBy: stringPtr("created by"),
			EndsAt:    timePtr(strfmt.DateTime(now.Add(time.Hour))),
			StartsAt:  timePtr(strfmt.DateTime(now)),
			Matchers: []*amv2.Matcher{
				{
					IsRegex: boolPtr(false),
					Name:    stringPtr("name"),
					Value:   stringPtr("value"),
				},
				{
					IsRegex: boolPtr(false),
					Name:    stringPtr("name2"),
					Value:   stringPtr("value2"),
				},
			},
		},
	}
	return response.JSON(http.StatusOK, result)
}

func (mock AlertmanagerApiMock) RouteGetSilences(c *models.ReqContext) response.Response {
	datasourceID := c.Params(":DatasourceId")
	mock.log.Info("RouteGetSilences: ", "DatasourceId", datasourceID)
	now := time.Now()
	result := apimodels.GettableSilences{
		&amv2.GettableSilence{
			ID: stringPtr("silence1"),
			Status: &amv2.SilenceStatus{
				State: stringPtr("active"),
			},
			UpdatedAt: timePtr(strfmt.DateTime(now.Add(-time.Hour))),
			Silence: amv2.Silence{
				Comment:   stringPtr("silence1 comment"),
				CreatedBy: stringPtr("silence1 created by"),
				EndsAt:    timePtr(strfmt.DateTime(now.Add(time.Hour))),
				StartsAt:  timePtr(strfmt.DateTime(now)),
				Matchers: []*amv2.Matcher{
					{
						IsRegex: boolPtr(false),
						Name:    stringPtr("silence1 name"),
						Value:   stringPtr("silence1 value"),
					},
					{
						IsRegex: boolPtr(true),
						Name:    stringPtr("silence1 name2"),
						Value:   stringPtr("silence1 value2"),
					},
				},
			},
		},
		&amv2.GettableSilence{
			ID: stringPtr("silence2"),
			Status: &amv2.SilenceStatus{
				State: stringPtr("pending"),
			},
			UpdatedAt: timePtr(strfmt.DateTime(now.Add(-time.Hour))),
			Silence: amv2.Silence{
				Comment:   stringPtr("silence2 comment"),
				CreatedBy: stringPtr("silence2 created by"),
				EndsAt:    timePtr(strfmt.DateTime(now.Add(time.Hour))),
				StartsAt:  timePtr(strfmt.DateTime(now)),
				Matchers: []*amv2.Matcher{
					{
						IsRegex: boolPtr(false),
						Name:    stringPtr("silence2 name"),
						Value:   stringPtr("silence2 value"),
					},
					{
						IsRegex: boolPtr(true),
						Name:    stringPtr("silence2 name2"),
						Value:   stringPtr("silence2 value2"),
					},
				},
			},
		},
	}
	return response.JSON(http.StatusOK, result)
}

func (mock AlertmanagerApiMock) RoutePostAlertingConfig(c *models.ReqContext, body apimodels.PostableUserConfig) response.Response {
	datasourceID := c.Params(":DatasourceId")
	mock.log.Info("RoutePostAlertingConfig: ", "DatasourceId", datasourceID)
	mock.log.Info("RoutePostAlertingConfig: ", "body", body)
	return response.JSON(http.StatusAccepted, util.DynMap{"message": "configuration created"})
}

func (mock AlertmanagerApiMock) RoutePostAmAlerts(c *models.ReqContext, body apimodels.PostableAlerts) response.Response {
	datasourceID := c.Params(":DatasourceId")
	mock.log.Info("RoutePostAmAlerts: ", "DatasourceId", datasourceID)
	mock.log.Info("RoutePostAmAlerts: ", "body", body)
	return response.JSON(http.StatusOK, util.DynMap{"message": "alerts created"})
}
